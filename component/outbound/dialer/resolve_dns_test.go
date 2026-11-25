/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestDialerResolveDNSCircuitBreakerLifecycle(t *testing.T) {
	d := newNamedTestDialer(t, "breaker")
	if snap := d.SnapshotResolveDNSHealth(time.Now()); snap != nil {
		t.Fatalf("expected nil snapshot when resolve_dns unset, got %+v", snap)
	}
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))

	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < consts.ResolveDNSCircuitFailureThreshold-1; i++ {
		if allow, halfOpen := d.AllowResolveDNS(base); !allow || halfOpen {
			t.Fatalf("step %d: Allow = (%v, %v), want (true, false)", i, allow, halfOpen)
		}
		if opened := d.RecordResolveDNSFailure(netutils.ErrResolveTimeout, base); opened {
			t.Fatalf("step %d: circuit opened early", i)
		}
	}

	if opened := d.RecordResolveDNSFailure(netutils.ErrResolveTimeout, base); !opened {
		t.Fatal("threshold failure should open circuit")
	}
	if allow, halfOpen := d.AllowResolveDNS(base.Add(time.Second)); allow || halfOpen {
		t.Fatalf("open circuit allowed call: (%v, %v)", allow, halfOpen)
	}
	d.RecordResolveDNSFailOpen()
	snap := d.SnapshotResolveDNSHealth(base.Add(time.Second))
	if snap == nil || snap.State != "open" || snap.TotalTimeout != uint64(consts.ResolveDNSCircuitFailureThreshold) || snap.TotalFailOpen != 1 {
		t.Fatalf("unexpected open snapshot: %+v", snap)
	}

	// Exactly one half-open probe is admitted after cooldown.
	afterCooldown := base.Add(consts.ResolveDNSCircuitOpenDuration)
	if allow, halfOpen := d.AllowResolveDNS(afterCooldown); !allow || !halfOpen {
		t.Fatalf("first post-cooldown Allow = (%v, %v), want (true, true)", allow, halfOpen)
	}
	if allow, halfOpen := d.AllowResolveDNS(afterCooldown); allow || halfOpen {
		t.Fatalf("concurrent half-open Allow = (%v, %v), want (false, false)", allow, halfOpen)
	}

	// Failed half-open probe re-opens circuit; ResetTransport clears it immediately.
	_ = d.RecordResolveDNSFailure(errors.New("still down"), afterCooldown)
	if allow, _ := d.AllowResolveDNS(afterCooldown.Add(time.Second)); allow {
		t.Fatal("failed half-open probe should re-open circuit")
	}
	d.ResetTransport()
	if allow, halfOpen := d.AllowResolveDNS(afterCooldown.Add(time.Second)); !allow || halfOpen {
		t.Fatalf("post-reset Allow = (%v, %v), want (true, false)", allow, halfOpen)
	}
	d.RecordResolveDNSSuccess(42 * time.Millisecond)
	snap = d.SnapshotResolveDNSHealth(afterCooldown.Add(time.Second))
	if snap.State != "closed" || snap.ConsecutiveFailures != 0 || snap.LastLatencyMs == nil || *snap.LastLatencyMs != 42 {
		t.Fatalf("post-success snapshot = %+v", snap)
	}
}

func TestDialerResolveDNSReferenceRTT(t *testing.T) {
	d := newNamedTestDialer(t, "rtt")
	if got := d.ResolveDNSReferenceRTT(); got != 0 {
		t.Fatalf("initial RTT = %v, want 0", got)
	}
	d.MustGetLatencies10(&NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}).AppendLatency(180 * time.Millisecond)
	d.MustGetLatencies10(&NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6}).AppendLatency(240 * time.Millisecond)
	if got := d.ResolveDNSReferenceRTT(); got != 180*time.Millisecond {
		t.Fatalf("ResolveDNSReferenceRTT = %v, want 180ms", got)
	}
}

type dialerTestDNSConn struct {
	reads   chan []byte
	closeCh chan struct{}
	closed  atomic.Bool
}

func newDialerTestDNSConn() *dialerTestDNSConn {
	return &dialerTestDNSConn{
		reads:   make(chan []byte, 16),
		closeCh: make(chan struct{}),
	}
}

func (c *dialerTestDNSConn) Read(p []byte) (int, error) {
	select {
	case <-c.closeCh:
		return 0, io.EOF
	case b := <-c.reads:
		return copy(p, b), nil
	}
}

func (c *dialerTestDNSConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	var req dnsmessage.Msg
	if err := req.Unpack(p); err == nil && len(req.Question) > 0 {
		resp := new(dnsmessage.Msg)
		resp.SetReply(&req)
		resp.Answer = []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: req.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
			A:   net.IPv4(198, 51, 100, 12).To4(),
		}}
		if raw, err := resp.Pack(); err == nil {
			select {
			case c.reads <- raw:
			case <-c.closeCh:
			}
		}
	}
	return len(p), nil
}

func (c *dialerTestDNSConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
	}
	return nil
}

func (c *dialerTestDNSConn) SetDeadline(time.Time) error      { return nil }
func (c *dialerTestDNSConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dialerTestDNSConn) SetWriteDeadline(time.Time) error { return nil }

type dialerTestPoolDialer struct {
	dials atomic.Int32
}

func (p *dialerTestPoolDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	p.dials.Add(1)
	return newDialerTestDNSConn(), nil
}

func TestDialerResolveDNSPoolResetAndClose(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	underlay := &dialerTestPoolDialer{}
	d := NewDialerContext(
		context.Background(),
		underlay,
		&GlobalOption{Log: log, CheckInterval: time.Minute},
		InstanceOption{DisableCheck: true},
		&Property{Property: D.Property{Name: "pool-test"}},
	)
	dns := netip.MustParseAddrPort("127.0.0.2:53")
	d.SetResolveDNS(dns)

	netStr := common.MagicNetwork("udp", 0, false)
	addrs1, _, reused1, err := d.ResolveDNSLookup(context.Background(), dns, "pool1.example", dnsmessage.TypeA, netStr)
	if err != nil || reused1 || len(addrs1) != 1 || addrs1[0] != netip.MustParseAddr("198.51.100.12") {
		t.Fatalf("first lookup = (%v, reused=%v, err=%v)", addrs1, reused1, err)
	}
	addrs2, _, reused2, err := d.ResolveDNSLookup(context.Background(), dns, "pool2.example", dnsmessage.TypeA, netStr)
	if err != nil || !reused2 || len(addrs2) != 1 {
		t.Fatalf("second lookup = (%v, reused=%v, err=%v)", addrs2, reused2, err)
	}
	if underlay.dials.Load() != 1 {
		t.Fatalf("dials before ResetTransport = %d, want 1", underlay.dials.Load())
	}

	d.ResetTransport()
	_, _, reused3, err := d.ResolveDNSLookup(context.Background(), dns, "pool3.example", dnsmessage.TypeA, netStr)
	if err != nil || reused3 {
		t.Fatalf("post-reset lookup reused=%v err=%v, want fresh redial", reused3, err)
	}
	if underlay.dials.Load() != 2 {
		t.Fatalf("dials after ResetTransport = %d, want 2", underlay.dials.Load())
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, _, err := d.ResolveDNSLookup(context.Background(), dns, "closed.example", dnsmessage.TypeA, netStr); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-close lookup err = %v, want net.ErrClosed", err)
	}
}

func TestDialerRetireClosesResolveDNSPoolsAndCircuitOpenResetsPool(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	underlay := &dialerTestPoolDialer{}
	d := NewDialerContext(
		context.Background(),
		underlay,
		&GlobalOption{Log: log, CheckInterval: time.Minute},
		InstanceOption{DisableCheck: true},
		&Property{Property: D.Property{Name: "retire-pool-test"}},
	)
	dns := netip.MustParseAddrPort("127.0.0.2:53")
	d.SetResolveDNS(dns)

	netStr := common.MagicNetwork("udp", 0, false)
	if _, _, _, err := d.ResolveDNSLookup(context.Background(), dns, "a.example", dnsmessage.TypeA, netStr); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if underlay.dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1", underlay.dials.Load())
	}

	// Opening the circuit breaker must reset pooled UDP sockets.
	now := time.Now()
	for range consts.ResolveDNSCircuitFailureThreshold {
		d.RecordResolveDNSFailure(netutils.ErrResolveTimeout, now)
	}
	if _, _, reused, err := d.ResolveDNSLookup(context.Background(), dns, "b.example", dnsmessage.TypeA, netStr); err != nil || reused {
		t.Fatalf("post-circuit-open lookup = (reused=%v, err=%v), want fresh dial", reused, err)
	}
	if underlay.dials.Load() != 2 {
		t.Fatalf("dials after circuit open = %d, want 2", underlay.dials.Load())
	}

	// Retiring for established flows must close resolve_dns pools immediately.
	d.RetireForEstablishedFlows()
	if _, _, _, err := d.ResolveDNSLookup(context.Background(), dns, "c.example", dnsmessage.TypeA, netStr); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-retire lookup err = %v, want net.ErrClosed", err)
	}
	_ = d.Close()
}
