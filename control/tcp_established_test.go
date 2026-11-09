// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/observation"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Return only weak generation references. The test must not accidentally keep
// the plane alive via a cleanup closure or the frame performing GC.
func prepareDetachedTCPForTest(t *testing.T, manager *SessionManager, capture *observation.Collector, ingress, egress net.Conn, sniff ...bool) (*establishedTCPTask, weak.Pointer[ControlPlane], weak.Pointer[ob.DialerGroup]) {
	t.Helper()
	d := newTestEndpointDialer(egress)
	group := newTestFixedOutboundGroup(d)
	c := newTestDialControlPlane(group)
	c.log = logrus.New()
	c.log.SetOutput(io.Discard)
	c.log.SetLevel(logrus.DebugLevel)
	c.capture = capture
	if len(sniff) > 0 && sniff[0] {
		c.sniffingTimeout = time.Second
		c.dialMode = consts.DialMode_Domain
	}
	c.ctx = context.Background()
	c.drainTracker = newControlPlaneDrainTracker()
	c.egressRuntime = newEgressRuntime(c.log, nil)
	c.egressRuntime.configureResources([]*ob.DialerGroup{group}, []*dialer.Dialer{d}, nil)
	if err := c.AttachSessionManager(manager); err != nil {
		t.Fatal(err)
	}
	lease, ok := c.acquireIncomingConnectionLease(ingress)
	if !ok {
		t.Fatal("admission failed")
	}
	task, err := c.prepareConnWithRoutingResultOwned(c.ctx, ingress,
		netip.MustParseAddrPort("192.0.2.1:45678"), netip.MustParseAddrPort("198.51.100.1:443"),
		&bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin), Must: 1}, lease)
	if err != nil || task == nil {
		t.Fatalf("prepare: task=%v err=%v", task, err)
	}
	if lease.owner != nil || c.ActiveSessionCount() != 0 {
		t.Fatal("adoption did not detach ingress")
	}
	// Exercise resource-mode retirement; real flows keep the compact group only.
	if err := c.egressRuntime.releaseOwner(); err != nil {
		t.Fatal(err)
	}
	return task, weak.Make(c), weak.Make(group)
}

func TestEstablishedTCPReleasesGenerationWhileRelaying(t *testing.T) {
	for _, captureOn := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "capture"}[captureOn], func(t *testing.T) {
			m := NewSessionManager(context.Background())
			defer m.Close()
			var collector *observation.Collector
			if captureOn {
				var err error
				collector, err = observation.New(1000)
				if err != nil {
					t.Fatal(err)
				}
				defer collector.Close()
			}
			client, ingress := net.Pipe()
			egress, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			task, plane, group := prepareDetachedTCPForTest(t, m, collector, ingress, egress)
			done := make(chan error, 1)
			go func() { done <- task.run() }()
			exchange := func(from, to net.Conn, payload []byte) {
				t.Helper()
				_ = from.SetDeadline(time.Now().Add(3 * time.Second))
				_ = to.SetDeadline(time.Now().Add(3 * time.Second))
				written := make(chan error, 1)
				go func() { _, err := from.Write(payload); written <- err }()
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(to, got); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("payload changed")
				}
			}
			exchange(client, server, []byte("before retirement"))
			for range 10 {
				runtime.GC()
				if plane.Value() == nil && group.Value() == nil {
					break
				}
			}
			if plane.Value() != nil {
				t.Fatal("active relay retains old control plane")
			}
			if group.Value() != nil {
				t.Fatal("active relay retains full outbound group")
			}
			exchange(server, client, []byte("after GC"))
			if m.ActiveTCPConnections() != 1 {
				t.Fatal("flow lost during GC")
			}
			_ = m.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("relay did not stop")
			}
			if m.ActiveTCPConnections() != 0 {
				t.Fatal("flow registration leaked")
			}
			runtime.KeepAlive(task)
		})
	}
}

func TestEstablishedTCPAbortBeforeRun(t *testing.T) {
	m := NewSessionManager(context.Background())
	defer m.Close()
	client, ingress := net.Pipe()
	egress, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	task, _, _ := prepareDetachedTCPForTest(t, m, nil, ingress, egress)
	_ = m.Close()
	done := make(chan error, 1)
	go func() { done <- task.run() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pre-aborted task blocked")
	}
	if m.ActiveTCPConnections() != 0 {
		t.Fatal("pre-aborted task leaked")
	}
}

func TestEstablishedTCPFailedAdoptionClosesEgressOnce(t *testing.T) {
	m := NewSessionManager(context.Background())
	egress := &closeCountConn{}
	d := newTestEndpointDialer(egress)
	group := newTestFixedOutboundGroup(d)
	defer group.Close()
	defer d.Close()
	c := newTestDialControlPlane(group)
	c.log = logrus.New()
	c.log.SetOutput(io.Discard)
	if err := c.AttachSessionManager(m); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	client, ingress := net.Pipe()
	defer client.Close()
	defer ingress.Close()
	lease, ok := c.acquireIncomingConnectionLease(ingress)
	if !ok {
		t.Fatal("admission failed")
	}
	defer lease.release()
	task, err := c.prepareConnWithRoutingResultOwned(context.Background(), ingress,
		netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("198.51.100.1:443"),
		&bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin), Must: 1}, lease)
	if task != nil || err != nil {
		t.Fatalf("closed manager should abandon: %v %v", task, err)
	}
	if got := egress.closeCount.Load(); got != 1 {
		t.Fatalf("egress closed %d times", got)
	}
}

func TestEstablishedTCPSniffPrefixSurvivesHandoff(t *testing.T) {
	m := NewSessionManager(context.Background())
	defer m.Close()
	client, ingress := net.Pipe()
	egress, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	payload := []byte("GET / HTTP/1.1\r\nHost: handoff.example\r\n\r\n")
	sent := make(chan error, 1)
	go func() { _, err := client.Write(payload); sent <- err }()
	task, plane, _ := prepareDetachedTCPForTest(t, m, nil, ingress, egress, true)
	done := make(chan error, 1)
	go func() { done <- task.run() }()
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("sniffed prefix lost or duplicated")
	}
	for range 5 {
		runtime.GC()
	}
	if plane.Value() != nil {
		t.Fatal("sniffer retains plane")
	}
	_ = m.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("sniff relay did not stop")
	}
}

func prepareDetachedDNSForTest(t *testing.T, m *SessionManager, ingress net.Conn) (*establishedTCPTask, weak.Pointer[ControlPlane]) {
	t.Helper()
	c := &ControlPlane{log: logrus.New(), ctx: context.Background()}
	c.log.SetOutput(io.Discard)
	if err := c.AttachSessionManager(m); err != nil {
		t.Fatal(err)
	}
	lease, ok := c.acquireIncomingConnectionLease(ingress)
	if !ok {
		t.Fatal("admission failed")
	}
	task, handled, err := c.prepareTCPDnsFastPathOwned(c.ctx, ingress, bufio.NewReader(ingress),
		netip.MustParseAddrPort("192.0.2.1:2345"), netip.MustParseAddrPort("198.51.100.1:53"), &bpfRoutingResult{}, lease)
	if !handled || err != nil || task == nil {
		t.Fatalf("DNS prepare: %v %v", handled, err)
	}
	if task.dns.fallback != nil {
		t.Fatal("process-owned DNS task retained fallback")
	}
	return task, weak.Make(c)
}

func TestEstablishedTCPDNSReleasesGeneration(t *testing.T) {
	activeControlPlanePublication.mu.Lock()
	previous := activeControlPlanePublication.plane.Swap(nil)
	activeControlPlanePublication.mu.Unlock()
	defer func() {
		activeControlPlanePublication.mu.Lock()
		activeControlPlanePublication.plane.Store(previous)
		activeControlPlanePublication.mu.Unlock()
	}()

	m := NewSessionManager(context.Background())
	defer m.Close()
	client, ingress := net.Pipe()
	defer client.Close()
	q := new(dnsmessage.Msg)
	q.SetQuestion("handoff.invalid.", dnsmessage.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, len(wire)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	sent := make(chan error, 1)
	go func() { _, err := client.Write(frame); sent <- err }()
	task, plane := prepareDetachedDNSForTest(t, m, ingress)
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- task.run() }()
	// With no published DNS controller, each query returns framed SERVFAIL;
	// the persistent transport must remain usable across generation collection.
	readReply := func(wantCode int) {
		t.Helper()
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		var h [2]byte
		if _, err := io.ReadFull(client, h[:]); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, binary.BigEndian.Uint16(h[:]))
		if _, err := io.ReadFull(client, b); err != nil {
			t.Fatal(err)
		}
		var msg dnsmessage.Msg
		if err := msg.Unpack(b); err != nil {
			t.Fatal(err)
		}
		if !msg.Response || msg.Id != q.Id || msg.Rcode != wantCode {
			t.Fatal("bad response")
		}
	}
	readReply(dnsmessage.RcodeServerFailure)
	for range 5 {
		runtime.GC()
	}
	if plane.Value() != nil {
		t.Fatal("DNS loop retains old plane")
	}
	// A later query on the same transport resolves through the new active
	// controller, not through the generation that accepted the connection.
	ctrl := newCorpusControllerWithDefaultChooser(t, &config.Dns{Routing: config.DnsRouting{
		Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("asis")},
		Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")}}})
	installCorpusDnsForwarderFactory(t, func(*dns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return phase0TCPIngressAResponse("handoff.invalid.", "198.51.100.77"), nil
		}}, nil
	})
	successor := &ControlPlane{ctx: context.Background(), controlPlaneDNSRuntime: controlPlaneDNSRuntime{dnsController: ctrl}}
	activeControlPlanePublication.mu.Lock()
	activeControlPlanePublication.plane.Store(successor)
	activeControlPlanePublication.mu.Unlock()
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	readReply(dnsmessage.RcodeSuccess)
	_ = m.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("DNS task did not stop")
	}
}
