/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	outbounddialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/control"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

func TestAdminWebSocketOriginAuthMultiplexAndZeroIdleCleanup(t *testing.T) {
	log := logrus.New()
	ring := newAdminLogRing()
	log.AddHook(ring)

	plane := &stubAdminPlane{
		metrics: control.AdminMetricsSnapshot{UploadRate: 777, DownloadRate: 888},
		connections: control.AdminConnectionsSnapshot{
			Total:       1,
			Connections: []control.AdminConnection{{ID: "tcp:1", Network: "tcp", Outbound: "proxy"}},
		},
		groups: []control.AdminGroup{{Name: "proxy", Policy: "fixed", Selected: "n1"}},
	}

	server := newAdminServer(log, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.setLogRing(ring)
	server.secret = "ws-secret"
	server.corsOrigins = buildCorsOriginSet([]string{"https://panel.example.com"})
	t.Cleanup(server.shutdown)

	ts := httptest.NewServer(server.withSecurityHeaders(server.withAdminCORS(server.buildMux())))
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"

	// Disallowed origin gets 403 before WebSocket upgrade.
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://evil.example.com"}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed WS origin, got err=%v resp=%v", err, resp)
	}

	// Allowed origin + invalid token gets auth_error.
	badConn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://panel.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = badConn.WriteJSON(wsClientFrame{Type: "auth", Token: "wrong-token"})
	var authErrFrame wsServerFrame
	if err := badConn.ReadJSON(&authErrFrame); err != nil {
		t.Fatal(err)
	}
	_ = badConn.Close()
	if authErrFrame.Type != "auth_error" || authErrFrame.Code != "unauthorized" {
		t.Fatalf("expected auth_error frame, got %+v", authErrFrame)
	}

	// Valid auth + sub/unsub across metrics, logs, flows, events.
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://panel.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(wsClientFrame{Type: "auth", Token: "ws-secret"}); err != nil {
		t.Fatal(err)
	}
	var authOK wsServerFrame
	if err := conn.ReadJSON(&authOK); err != nil {
		t.Fatal(err)
	}
	if authOK.Type != "auth_ok" || authOK.Ver != "v1" {
		t.Fatalf("expected auth_ok v1, got %+v", authOK)
	}

	// Subscribe to metrics, logs, flows, events, and send a ping.
	for _, topic := range []string{"metrics", "logs", "flows", "events"} {
		if err := conn.WriteJSON(wsClientFrame{Type: "sub", Topic: topic, IntervalMs: 500}); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.WriteJSON(wsClientFrame{Type: "ping", ID: "p1"}); err != nil {
		t.Fatal(err)
	}

	// Emit a log, closed flow, and system event.
	deadline := time.Now().Add(2 * time.Second)
	for plane.getClosedFlowObserver() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	observer := plane.getClosedFlowObserver()
	if observer == nil {
		t.Fatal("expected flows observer to be installed on sub")
	}
	log.Info("ws-live-log")
	observer(control.AdminClosedFlow{ID: "tcp:99", CloseReason: "normal"})
	server.emitWSEvent("reload_succeeded", nil)

	seen := map[string]bool{}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for !(seen["pong"] && seen["metrics"] && seen["logs"] && seen["flows"] && seen["events"]) {
		var f wsServerFrame
		if err := conn.ReadJSON(&f); err != nil {
			t.Fatalf("ReadJSON failed (seen=%v): %v", seen, err)
		}
		switch f.Type {
		case "pong":
			if f.ID == "p1" {
				seen["pong"] = true
			}
		case "data":
			seen[f.Topic] = true
		case "event":
			if f.Event == "reload_succeeded" {
				seen["events"] = true
			}
		}
	}

	// Closing the client must remove all active topics and clear the closed-flow observer.
	_ = conn.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.wsHub.ActiveClients() == 0 && len(server.wsHub.ActiveTopics()) == 0 && plane.getClosedFlowObserver() == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if server.wsHub.ActiveClients() != 0 || len(server.wsHub.ActiveTopics()) != 0 || plane.getClosedFlowObserver() != nil {
		t.Fatalf("expected clean zero-idle teardown: clients=%d topics=%v flowObserver=%v",
			server.wsHub.ActiveClients(), server.wsHub.ActiveTopics(), plane.getClosedFlowObserver() != nil)
	}

	// Verify slow client non-blocking queue overflow drops without blocking callers.
	c := &wsClient{
		sendCh: make(chan []byte, wsSendQueueSize),
		done:   make(chan struct{}),
	}
	for i := 0; i < wsSendQueueSize+20; i++ {
		c.enqueue([]byte(`{"type":"pong"}`))
	}
	if c.dropped.Load() != 20 {
		t.Fatalf("expected 20 dropped WS frames on full queue, got %d", c.dropped.Load())
	}
}

func TestAdminWebSocketWaitGroupCloseRace(t *testing.T) {
	for round := 0; round < 12; round++ {
		plane := &stubAdminPlane{}
		server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
		server.secret = "ws-secret"
		ts := httptest.NewServer(server.withSecurityHeaders(server.buildMux()))
		wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"

		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
				if err != nil {
					if resp != nil && resp.Body != nil {
						_ = resp.Body.Close()
					}
					return
				}
				defer conn.Close()
				_ = conn.WriteJSON(wsClientFrame{Type: "auth", Token: "ws-secret"})
				var f wsServerFrame
				_ = conn.ReadJSON(&f)
			}()
		}
		time.Sleep(5 * time.Millisecond)
		server.shutdown()
		wg.Wait()
		ts.Close()
	}
}

func TestAdminWebSocketDisconnectsOnSecretChangeAndListenDisable(t *testing.T) {
	addr := reserveTestLoopbackAddr(t)
	plane := &stubAdminPlane{}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	t.Cleanup(server.shutdown)

	server.refresh(addr, "sec1")
	wsURL := "ws://" + addr + "/api/v1/ws"

	dialAndAuth := func(secret string) (*websocket.Conn, error) {
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, err
		}
		if err := conn.WriteJSON(wsClientFrame{Type: "auth", Token: secret}); err != nil {
			_ = conn.Close()
			return nil, err
		}
		var okFrame wsServerFrame
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := conn.ReadJSON(&okFrame); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if okFrame.Type != "auth_ok" {
			_ = conn.Close()
			return nil, fmt.Errorf("unexpected auth frame: %+v", okFrame)
		}
		_ = conn.SetReadDeadline(time.Time{})
		return conn, nil
	}

	c1, err := dialAndAuth("sec1")
	if err != nil {
		t.Fatalf("initial WS dial/auth failed: %v", err)
	}
	defer c1.Close()
	for _, topic := range []string{"metrics", "flows", "events"} {
		if err := c1.WriteJSON(wsClientFrame{Type: "sub", Topic: topic, IntervalMs: 500}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for plane.getClosedFlowObserver() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if plane.getClosedFlowObserver() == nil {
		t.Fatal("expected flows observer to be installed")
	}

	// Secret change must immediately drop c1 and clear the flow observer.
	server.refresh(addr, "sec2")
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var f wsServerFrame
		if err := c1.ReadJSON(&f); err != nil {
			break
		}
	}
	if server.wsHub.ActiveClients() != 0 {
		t.Fatalf("expected 0 active clients after secret rotation, got %d", server.wsHub.ActiveClients())
	}
	if plane.getClosedFlowObserver() != nil {
		t.Fatal("expected closed flow observer to be cleared after secret rotation")
	}

	// New secret works on the refreshed server; disabling listen disconnects it too.
	c2, err := dialAndAuth("sec2")
	if err != nil {
		t.Fatalf("WS dial/auth with sec2 failed: %v", err)
	}
	defer c2.Close()

	server.refresh("", "sec2")
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var f wsServerFrame
		if err := c2.ReadJSON(&f); err != nil {
			break
		}
	}
	if server.wsHub.ActiveClients() != 0 {
		t.Fatalf("expected 0 active clients after disabling admin_listen, got %d", server.wsHub.ActiveClients())
	}
}

func TestAdminWebSocketPreUpgradeRateLimitPendingCapShutdownAndMalformedAuth(t *testing.T) {
	t.Run("malformed auth frame records failure and triggers pre-upgrade 429", func(t *testing.T) {
		server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return &stubAdminPlane{} }, nil)
		server.secret = "ws-secret"
		t.Cleanup(server.shutdown)
		ts := httptest.NewServer(server.withSecurityHeaders(server.buildMux()))
		t.Cleanup(ts.Close)
		wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"

		for i := 0; i < adminAuthMaxFailures; i++ {
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				t.Fatalf("dial %d failed: %v", i, err)
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte("not-json")); err != nil {
				_ = conn.Close()
				t.Fatalf("write malformed frame %d failed: %v", i, err)
			}
			var errFrame wsServerFrame
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if err := conn.ReadJSON(&errFrame); err != nil {
				_ = conn.Close()
				t.Fatalf("read auth_error %d failed: %v", i, err)
			}
			_ = conn.Close()
			if errFrame.Type != "auth_error" || errFrame.Code != "invalid_auth_frame" {
				t.Fatalf("expected invalid_auth_frame, got %+v", errFrame)
			}
		}

		// Subsequent attempt must be rejected with HTTP 429 BEFORE WebSocket upgrade.
		_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err == nil || resp == nil {
			t.Fatalf("expected handshake rejection, got err=%v resp=%v", err, resp)
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("expected HTTP 429 + Retry-After before upgrade, got status=%d headers=%+v", resp.StatusCode, resp.Header)
		}
	})

	t.Run("auth timeout sends auth_timeout and records failure", func(t *testing.T) {
		origTimeout := wsAuthTimeout
		wsAuthTimeout = 120 * time.Millisecond
		t.Cleanup(func() { wsAuthTimeout = origTimeout })

		server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return &stubAdminPlane{} }, nil)
		server.secret = "ws-secret"
		t.Cleanup(server.shutdown)
		ts := httptest.NewServer(server.withSecurityHeaders(server.buildMux()))
		t.Cleanup(ts.Close)
		wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"

		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		var errFrame wsServerFrame
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := conn.ReadJSON(&errFrame); err != nil {
			t.Fatalf("expected auth_error frame on timeout, got err=%v", err)
		}
		if errFrame.Type != "auth_error" || errFrame.Code != "auth_timeout" {
			t.Fatalf("expected auth_timeout frame, got %+v", errFrame)
		}

		host, _, _ := net.SplitHostPort(conn.LocalAddr().String())
		server.authLimiter.mu.Lock()
		entry := server.authLimiter.entries[normalizeAdminRemoteIP(host)]
		server.authLimiter.mu.Unlock()
		if entry.count != 1 {
			t.Fatalf("expected auth timeout to record 1 failure, got %d", entry.count)
		}
	})

	t.Run("pending unauthenticated connections honor wsMaxClients and shutdown interrupts cleanly", func(t *testing.T) {
		server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return &stubAdminPlane{} }, nil)
		server.secret = "ws-secret"
		ts := httptest.NewServer(server.withSecurityHeaders(server.buildMux()))
		defer ts.Close()
		wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"

		conns := make([]*websocket.Conn, 0, wsMaxClients)
		defer func() {
			for _, c := range conns {
				_ = c.Close()
			}
		}()
		for i := 0; i < wsMaxClients; i++ {
			c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				t.Fatalf("pending dial %d failed: %v", i, err)
			}
			conns = append(conns, c)
		}

		// 17th pending connection must be rejected with 503 too_many_clients.
		_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err == nil || resp == nil {
			t.Fatalf("expected 503 for 17th pending client, got err=%v resp=%v", err, resp)
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 too_many_clients, got %d", resp.StatusCode)
		}

		// Shutdown must interrupt all pending connections quickly without waiting for 3s wsAuthTimeout
		// and without charging auth failures to the client IP.
		start := time.Now()
		server.shutdown()
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("shutdown took too long with pending WS clients: %v", elapsed)
		}
		if server.authLimiter.hasFailures.Load() {
			t.Fatal("server shutdown must not record auth failures for interrupted pending WS clients")
		}
	})
}

func TestAdminWebSocketP0HealthAndControlEvents(t *testing.T) {
	plane := &stubAdminPlane{
		groups: []control.AdminGroup{
			{Name: "proxy", Policy: "fixed", Selected: "hk-01"},
		},
		stickyCleared: 1,
	}
	addr := reserveTestLoopbackAddr(t)
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.refreshWithCORS(addr, "ws-p0-secret", nil)
	t.Cleanup(server.shutdown)

	wsURL := "ws://" + addr + "/api/v1/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteJSON(wsClientFrame{Type: "auth", Token: "ws-p0-secret"}); err != nil {
		t.Fatal(err)
	}
	var authOK wsServerFrame
	if err := conn.ReadJSON(&authOK); err != nil || authOK.Type != "auth_ok" {
		t.Fatalf("auth_ok failed: %+v err=%v", authOK, err)
	}
	if err := conn.WriteJSON(wsClientFrame{Type: "sub", Topic: "events"}); err != nil {
		t.Fatal(err)
	}

	// Wait briefly until subscription is registered.
	deadline := time.Now().Add(2 * time.Second)
	for server.wsHub.ActiveTopics()["events"] == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Trigger node admission state transition on a real dialer and verify node_health_changed WS event.
	prop := &outbounddialer.Property{}
	prop.Name = "hk-01"
	prop.Protocol = "direct"
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	d := outbounddialer.NewDialer(
		nil,
		&outbounddialer.GlobalOption{Log: logger, CheckInterval: time.Second},
		outbounddialer.InstanceOption{DisableCheck: true},
		prop,
	)
	t.Cleanup(func() { _ = d.Close() })
	typ := &outbounddialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	// First degradation from default alive must emit node_health_changed without needing a warmup call.
	d.SetFailDegradedForTest(typ, true)

	// Trigger group_probe_triggered, group_sticky_changed, and system_suspended events.
	client := &http.Client{Timeout: 2 * time.Second}
	postProbe, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/api/v1/groups/probe", nil)
	postProbe.Header.Set("Authorization", "Bearer ws-p0-secret")
	if resp, rerr := client.Do(postProbe); rerr != nil {
		t.Fatal(rerr)
	} else {
		_ = resp.Body.Close()
	}

	delSticky, _ := http.NewRequest(http.MethodDelete, "http://"+addr+"/api/v1/groups/proxy/sticky/example.com", nil)
	delSticky.Header.Set("Authorization", "Bearer ws-p0-secret")
	if resp, rerr := client.Do(delSticky); rerr != nil {
		t.Fatal(rerr)
	} else {
		_ = resp.Body.Close()
	}

	server.markSuspended()

	seen := map[string]bool{}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for len(seen) < 4 {
		var frame wsServerFrame
		if err := conn.ReadJSON(&frame); err != nil {
			t.Fatalf("missing WS P0 events (seen=%v): %v", seen, err)
		}
		if frame.Type == "event" {
			seen[frame.Event] = true
		}
	}
	for _, ev := range []string{"node_health_changed", "group_probe_triggered", "group_sticky_changed", "system_suspended"} {
		if !seen[ev] {
			t.Fatalf("missing event %q in %v", ev, seen)
		}
	}
}
