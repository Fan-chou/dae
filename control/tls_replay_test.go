/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type funcNetproxyDialer struct {
	calls atomic.Int32
	fn    func(ctx context.Context, network, addr string) (netproxy.Conn, error)
}

func (d *funcNetproxyDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.calls.Add(1)
	return d.fn(ctx, network, addr)
}

type writeFailConn struct {
	netproxy.Conn
	writeErr error
}

func (c *writeFailConn) Write([]byte) (int, error) {
	return 0, c.writeErr
}

type resettableIngressConn struct {
	net.Conn
	resetOnEOF atomic.Bool
}

func (c *resettableIngressConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && c.resetOnEOF.Load() {
		return n, unix.ECONNRESET
	}
	return n, err
}

func newNamedProxyTestDialer(name, address string, fn func(context.Context, string, string) (netproxy.Conn, error)) (*componentdialer.Dialer, *funcNetproxyDialer) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	raw := &funcNetproxyDialer{fn: fn}
	d := componentdialer.NewDialerContext(context.Background(),
		raw,
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{},
	)
	if p := d.Property(); p != nil {
		p.Name = name
		p.Address = address
	}
	return d, raw
}

func newFallbackProxyGroup(dialers ...*componentdialer.Dialer) *ob.DialerGroup {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	annotations := make([]*componentdialer.Annotation, 0, len(dialers))
	for range dialers {
		annotations = append(annotations, &componentdialer.Annotation{})
	}
	return ob.NewDialerGroup(
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		"fallback-tls-replay",
		dialers,
		annotations,
		ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
}

func newTLSReplayControlPlane(group *ob.DialerGroup, sniff bool) *ControlPlane {
	c := newTestDialControlPlane(group)
	c.log = logrus.New()
	c.log.SetOutput(io.Discard)
	c.ctx = context.Background()
	c.drainTracker = newControlPlaneDrainTracker()
	if sniff {
		c.sniffingTimeout = time.Second
		c.dialMode = consts.DialMode_Domain
	}
	return c
}

func sampleTLSClientHello(sni string) []byte {
	// Valid TLS Handshake record (0x16 0x03 0x01) header with deterministic bytes.
	payload := append([]byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c, 0x03, 0x03}, []byte(sni)...)
	for len(payload) < 37 {
		payload = append(payload, 'x')
	}
	return payload
}

func prepareTLSReplayTask(
	t *testing.T,
	m *SessionManager,
	c *ControlPlane,
	ingress net.Conn,
) *establishedTCPTask {
	t.Helper()
	lease, ok := c.acquireIncomingConnectionLease(ingress)
	if !ok {
		t.Fatal("admission failed")
	}
	task, err := c.prepareConnWithRoutingResultOwned(
		c.ctx,
		ingress,
		netip.MustParseAddrPort("192.0.2.50:44444"),
		netip.MustParseAddrPort("198.51.100.50:443"),
		&bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin), Must: 1},
		lease,
	)
	if err != nil || task == nil {
		t.Fatalf("prepareConnWithRoutingResultOwned: task=%v err=%v", task, err)
	}
	return task
}

func TestTLSReplayTransparentFailoverOnEarlyEOFAndWriteReset(t *testing.T) {
	m := NewSessionManager(context.Background())
	defer m.Close()

	hello := sampleTLSClientHello("replay.example")
	serverHello := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 'S', 'H', 'O', 'K'}
	p1Got := make(chan []byte, 1)
	p3Got := make(chan []byte, 1)

	// Node 1: accepts ClientHello then immediately EOFs before sending any byte.
	p1, raw1 := newNamedProxyTestDialer("p1", "198.51.100.1:443", func(context.Context, string, string) (netproxy.Conn, error) {
		eConn, sConn := net.Pipe()
		go func() {
			defer sConn.Close()
			buf := make([]byte, len(hello))
			if _, err := io.ReadFull(sConn, buf); err == nil {
				p1Got <- buf
			}
		}()
		return eConn, nil
	})
	defer p1.Close()

	// Node 2: fails immediately on ClientHello Write (simulated RST).
	p2, raw2 := newNamedProxyTestDialer("p2", "198.51.100.2:443", func(context.Context, string, string) (netproxy.Conn, error) {
		_, dead := net.Pipe()
		return &writeFailConn{Conn: dead, writeErr: unix.ECONNRESET}, nil
	})
	defer p2.Close()

	// Node 3: succeeds, receives the replayed ClientHello, responds with ServerHello, and relays.
	p3ServerDone := make(chan struct{})
	var p3Server net.Conn
	p3, raw3 := newNamedProxyTestDialer("p3", "198.51.100.3:443", func(context.Context, string, string) (netproxy.Conn, error) {
		eConn, sConn := net.Pipe()
		p3Server = sConn
		go func() {
			defer close(p3ServerDone)
			buf := make([]byte, len(hello))
			if _, err := io.ReadFull(sConn, buf); err != nil {
				return
			}
			p3Got <- buf
			_, _ = sConn.Write(serverHello)
			echo := make([]byte, len("app-data"))
			if _, err := io.ReadFull(sConn, echo); err == nil {
				_, _ = sConn.Write(echo)
			}
			_ = sConn.Close()
		}()
		return eConn, nil
	})
	defer p3.Close()

	group := newFallbackProxyGroup(p1, p2, p3)
	defer group.Close()
	c := newTLSReplayControlPlane(group, false)
	if err := c.AttachSessionManager(m); err != nil {
		t.Fatal(err)
	}

	client, ingress := net.Pipe()
	defer client.Close()

	task := prepareTLSReplayTask(t, m, c, ingress)
	done := make(chan error, 1)
	go func() { done <- task.run() }()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write(hello); err != nil {
		t.Fatalf("client write ClientHello: %v", err)
	}
	gotResp := make([]byte, len(serverHello))
	if _, err := io.ReadFull(client, gotResp); err != nil {
		t.Fatalf("client read ServerHello after failover: %v", err)
	}
	if !bytes.Equal(gotResp, serverHello) {
		t.Fatalf("ServerHello mismatch: got %x, want %x", gotResp, serverHello)
	}

	if got := <-p1Got; !bytes.Equal(got, hello) {
		t.Fatalf("p1 received %x, want ClientHello %x", got, hello)
	}
	if got := <-p3Got; !bytes.Equal(got, hello) {
		t.Fatalf("p3 replayed %x, want ClientHello %x", got, hello)
	}
	if got := task.flow.Binding().Egress.Dialer; got != p3 {
		t.Fatalf("flow bound dialer = %v, want p3", got)
	}
	if snap := adminConnectionFromTCP(task.flow); snap.Dialer != "p3" {
		t.Fatalf("adminConnectionFromTCP dialer = %q, want p3", snap.Dialer)
	}
	if raw1.calls.Load() != 1 || raw2.calls.Load() != 1 || raw3.calls.Load() != 1 {
		t.Fatalf("dial counts p1=%d p2=%d p3=%d, want 1,1,1", raw1.calls.Load(), raw2.calls.Load(), raw3.calls.Load())
	}

	// Verify replay buffer was cleared after first server response byte.
	replayWrapper, ok := task.right.(*tlsReplayConn)
	if !ok {
		t.Fatal("expected *tlsReplayConn wrapper for multi-candidate TLS flow")
	}
	if !replayWrapper.answered.Load() || !replayWrapper.disabled.Load() {
		t.Fatal("expected replay state to be cleared after first server byte")
	}
	replayWrapper.opMu.Lock()
	sentAfterAnswer := replayWrapper.sent
	excludedAfterAnswer := replayWrapper.excluded
	replayWrapper.opMu.Unlock()
	if sentAfterAnswer != nil || excludedAfterAnswer != nil {
		t.Fatalf("expected replay buffer and exclusions nil after answer, got sent=%d excl=%d", len(sentAfterAnswer), len(excludedAfterAnswer))
	}

	// Bidirectional relay continues normally on p3, and subsequent EOF does not replay again.
	if _, err := client.Write([]byte("app-data")); err != nil {
		t.Fatalf("client write post-handshake: %v", err)
	}
	appResp := make([]byte, len("app-data"))
	if _, err := io.ReadFull(client, appResp); err != nil {
		t.Fatalf("client read post-handshake: %v", err)
	}
	if !bytes.Equal(appResp, []byte("app-data")) {
		t.Fatalf("post-handshake echo = %q", appResp)
	}
	<-p3ServerDone
	_ = p3Server
	_ = client.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("task.run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not terminate after completion")
	}

	for name, d := range map[string]*componentdialer.Dialer{"p1": p1, "p2": p2, "p3": p3} {
		if active := d.LoadContext(time.Now()).Active; active != 0 {
			t.Fatalf("%s active load count = %d, want 0 after finish", name, active)
		}
	}
}

func TestTLSReplaySkipsIneligiblePathsAndOversizedOrNonTLSPayloads(t *testing.T) {
	m := NewSessionManager(context.Background())
	defer m.Close()

	// 1) Direct dialer (Address == "") must never be wrapped.
	direct := newNamedTestEndpointDialer("direct", nil)
	defer direct.Close()
	p2, raw2 := newNamedProxyTestDialer("p2", "198.51.100.2:443", func(context.Context, string, string) (netproxy.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	})
	defer p2.Close()

	fbDirect := newFallbackProxyGroup(direct, p2)
	defer fbDirect.Close()
	cDirect := newTLSReplayControlPlane(fbDirect, false)
	_, dummyConn := net.Pipe()
	defer dummyConn.Close()
	directFlow := &FlowRuntime{}
	if got := cDirect.maybeWrapTLSReplay(directFlow, dummyConn, &proxyDialParam{}, &proxyDialResult{
		Dialer:   direct,
		Outbound: fbDirect,
	}, false); got != dummyConn {
		t.Fatal("direct dialer must not be wrapped by tlsReplayConn")
	}

	// 2) Single-node Fixed proxy group must never be wrapped.
	p1Single, _ := newNamedProxyTestDialer("p1-single", "198.51.100.1:443", func(context.Context, string, string) (netproxy.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	})
	defer p1Single.Close()
	fixedGroup := newTestFixedOutboundGroup(p1Single)
	defer fixedGroup.Close()
	cFixed := newTLSReplayControlPlane(fixedGroup, false)
	if got := cFixed.maybeWrapTLSReplay(directFlow, dummyConn, &proxyDialParam{}, &proxyDialResult{
		Dialer:             p1Single,
		Outbound:           fixedGroup,
		OrigNetworkTypeObj: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
	}, false); got != dummyConn {
		t.Fatal("single-node fixed group must not be wrapped by tlsReplayConn")
	}

	// 3) Pre-sniffed HTTP prefix must skip wrapping completely.
	p1HTTP, _ := newNamedProxyTestDialer("p1-http", "198.51.100.1:443", func(context.Context, string, string) (netproxy.Conn, error) {
		e, s := net.Pipe()
		go func() {
			_, _ = io.ReadAll(s)
			_ = s.Close()
		}()
		return e, nil
	})
	defer p1HTTP.Close()
	httpGroup := newFallbackProxyGroup(p1HTTP, p2)
	defer httpGroup.Close()
	cHTTP := newTLSReplayControlPlane(httpGroup, true)
	if err := cHTTP.AttachSessionManager(m); err != nil {
		t.Fatal(err)
	}
	clientHTTP, ingressHTTP := net.Pipe()
	defer clientHTTP.Close()
	go func() { _, _ = clientHTTP.Write([]byte("GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n")) }()
	taskHTTP := prepareTLSReplayTask(t, m, cHTTP, ingressHTTP)
	if _, isWrapped := taskHTTP.right.(*tlsReplayConn); isWrapped {
		t.Fatal("pre-sniffed plain HTTP flow must not be wrapped by tlsReplayConn")
	}
	_ = clientHTTP.Close()
	_ = taskHTTP.run()
	if raw2.calls.Load() != 0 {
		t.Fatalf("p2 called %d times for plain HTTP, want 0", raw2.calls.Load())
	}

	// 4) Oversized (>32 KiB) initial write drops replay buffer and disables failover.
	p1Big, _ := newNamedProxyTestDialer("p1-big", "198.51.100.11:443", func(context.Context, string, string) (netproxy.Conn, error) {
		e, s := net.Pipe()
		go func() {
			buf := make([]byte, tlsReplayMaxBytes+64)
			_, _ = io.ReadFull(s, buf)
			_ = s.Close() // EOF after receiving oversized payload before any response
		}()
		return e, nil
	})
	defer p1Big.Close()
	bigGroup := newFallbackProxyGroup(p1Big, p2)
	defer bigGroup.Close()
	cBig := newTLSReplayControlPlane(bigGroup, false)
	if err := cBig.AttachSessionManager(m); err != nil {
		t.Fatal(err)
	}
	clientBig, ingressBig := net.Pipe()
	defer clientBig.Close()
	taskBig := prepareTLSReplayTask(t, m, cBig, ingressBig)
	doneBig := make(chan error, 1)
	go func() { doneBig <- taskBig.run() }()

	bigHello := make([]byte, tlsReplayMaxBytes+64)
	bigHello[0] = 0x16
	bigHello[1] = 0x03
	_ = clientBig.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := clientBig.Write(bigHello); err != nil {
		t.Fatalf("write oversized payload: %v", err)
	}
	_ = clientBig.Close()
	select {
	case <-doneBig:
	case <-time.After(3 * time.Second):
		t.Fatal("oversized TLS test relay did not exit")
	}
	if raw2.calls.Load() != 0 {
		t.Fatalf("p2 called %d times after oversized payload exceeded 32 KiB cap, want 0", raw2.calls.Load())
	}
}

func TestTLSReplayDoesNotReplayOnClientCloseOrFlowAbort(t *testing.T) {
	m := NewSessionManager(context.Background())
	defer m.Close()

	hello := sampleTLSClientHello("abort.example")
	for _, scenario := range []string{"client_reset", "flow_abort"} {
		t.Run(scenario, func(t *testing.T) {
			p1Read := make(chan struct{})
			p1, _ := newNamedProxyTestDialer("p1", "198.51.100.21:443", func(context.Context, string, string) (netproxy.Conn, error) {
				e, s := net.Pipe()
				go func() {
					defer s.Close()
					buf := make([]byte, len(hello))
					if _, err := io.ReadFull(s, buf); err == nil {
						close(p1Read)
						// Keep server open until closed locally; no ServerHello sent.
						_, _ = io.Copy(io.Discard, s)
					}
				}()
				return e, nil
			})
			defer p1.Close()
			p2, raw2 := newNamedProxyTestDialer("p2", "198.51.100.22:443", func(context.Context, string, string) (netproxy.Conn, error) {
				c, _ := net.Pipe()
				return c, nil
			})
			defer p2.Close()

			group := newFallbackProxyGroup(p1, p2)
			defer group.Close()
			c := newTLSReplayControlPlane(group, false)
			if err := c.AttachSessionManager(m); err != nil {
				t.Fatal(err)
			}

			client, rawIngress := net.Pipe()
			defer client.Close()
			ingress := &resettableIngressConn{Conn: rawIngress}
			task := prepareTLSReplayTask(t, m, c, ingress)
			done := make(chan error, 1)
			go func() { done <- task.run() }()

			if _, err := client.Write(hello); err != nil {
				t.Fatalf("write ClientHello: %v", err)
			}
			<-p1Read
			if scenario == "client_reset" {
				ingress.resetOnEOF.Store(true)
				_ = client.Close()
			} else {
				_ = task.flow.abort()
			}

			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("relay did not stop on " + scenario)
			}
			if raw2.calls.Load() != 0 {
				t.Fatalf("%s unexpectedly dialed backup p2 (%d times)", scenario, raw2.calls.Load())
			}
		})
	}
}

func TestTLSReplayDoesNotRetainRetiredControlPlaneOrGroup(t *testing.T) {
	m := NewSessionManager(context.Background())
	defer m.Close()

	hello := sampleTLSClientHello("gc.example")
	helloArrived := make(chan struct{})
	releaseServer := make(chan struct{})
	var p1Conn *componentdialer.Dialer
	p1, _ := newNamedProxyTestDialer("p1", "198.51.100.31:443", func(context.Context, string, string) (netproxy.Conn, error) {
		e, s := net.Pipe()
		go func() {
			defer s.Close()
			buf := make([]byte, len(hello))
			if _, err := io.ReadFull(s, buf); err != nil {
				return
			}
			close(helloArrived)
			<-releaseServer
			_, _ = s.Write([]byte("OK"))
		}()
		return e, nil
	})
	p1Conn = p1
	defer p1Conn.Close()

	p2, _ := newNamedProxyTestDialer("p2", "198.51.100.32:443", func(context.Context, string, string) (netproxy.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	})
	defer p2.Close()

	buildAndStart := func() (*establishedTCPTask, net.Conn, weak.Pointer[ControlPlane], weak.Pointer[ob.DialerGroup]) {
		group := newFallbackProxyGroup(p1, p2)
		c := newTLSReplayControlPlane(group, false)
		c.egressRuntime = newEgressRuntime(c.log, nil)
		c.egressRuntime.configureResources([]*ob.DialerGroup{group}, []*componentdialer.Dialer{p1, p2}, nil)
		if err := c.AttachSessionManager(m); err != nil {
			t.Fatal(err)
		}
		client, ingress := net.Pipe()
		task := prepareTLSReplayTask(t, m, c, ingress)
		if err := c.egressRuntime.releaseOwner(); err != nil {
			t.Fatal(err)
		}
		return task, client, weak.Make(c), weak.Make(group)
	}

	task, client, weakPlane, weakGroup := buildAndStart()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- task.run() }()

	if _, err := client.Write(hello); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	<-helloArrived

	// While armed and awaiting ServerHello, ControlPlane and full DialerGroup must still GC.
	for range 15 {
		runtime.GC()
		if weakPlane.Value() == nil && weakGroup.Value() == nil {
			break
		}
	}
	if weakPlane.Value() != nil {
		t.Fatal("armed tlsReplayConn retains retired ControlPlane")
	}
	if weakGroup.Value() != nil {
		t.Fatal("armed tlsReplayConn retains full DialerGroup")
	}

	close(releaseServer)
	ack := make([]byte, 2)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read server response after GC: %v", err)
	}
	if !bytes.Equal(ack, []byte("OK")) {
		t.Fatalf("ack = %q, want OK", ack)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil && !stderrors.Is(err, io.EOF) {
			t.Fatalf("task.run error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not exit")
	}
}
