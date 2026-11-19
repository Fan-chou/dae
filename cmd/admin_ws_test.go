/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
