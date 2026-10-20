//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

type liveCounters struct {
	up, down, finalUp, finalDown atomic.Int64
}

func (c *liveCounters) accounting() *tcpOffloadLiveAccounting {
	return &tcpOffloadLiveAccounting{
		Upload:   func(n int64) { c.up.Add(n) },
		Download: func(n int64) { c.down.Add(n) },
	}
}

func newLiveAccountingSession(t *testing.T, live *tcpOffloadLiveAccounting) (s *tcpRelayOffloadSession, leftPeer, rightPeer interface{ Write([]byte) (int, error) }) {
	t.Helper()
	left, lp := offloadTCPPair(t)
	right, rp := offloadTCPPair(t)
	lrx, _, err := tcpOffloadBaseline(left)
	if err != nil {
		t.Fatal(err)
	}
	rrx, _, err := tcpOffloadBaseline(right)
	if err != nil {
		t.Fatal(err)
	}
	return &tcpRelayOffloadSession{left: left, right: right, leftRxBase: lrx, rightRxBase: rrx, live: live}, lp, rp
}

// reportUntil polls reportLive until cond holds; tcp_info receive counters
// update asynchronously with respect to the peer's Write.
func reportUntil(t *testing.T, s *tcpRelayOffloadSession, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.reportLive()
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("live accounting did not converge")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTCPOffloadLiveAccountingReportsIncrementsOnce(t *testing.T) {
	var c liveCounters
	s, leftPeer, rightPeer := newLiveAccountingSession(t, c.accounting())

	if _, err := leftPeer.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	reportUntil(t, s, func() bool { return c.up.Load() == 100 })
	if _, err := leftPeer.Write(make([]byte, 50)); err != nil {
		t.Fatal(err)
	}
	reportUntil(t, s, func() bool { return c.up.Load() == 150 })
	if _, err := rightPeer.Write(make([]byte, 70)); err != nil {
		t.Fatal(err)
	}
	reportUntil(t, s, func() bool { return c.down.Load() == 70 })

	// No growth means no extra bytes, however often it is polled.
	for i := 0; i < 5; i++ {
		s.reportLive()
	}
	if c.up.Load() != 150 || c.down.Load() != 70 {
		t.Fatalf("idle reports changed totals: up=%d down=%d", c.up.Load(), c.down.Load())
	}
}

func TestTCPOffloadLiveAccountingFinalRecordsOnlyRemainder(t *testing.T) {
	var c liveCounters
	s := &tcpRelayOffloadSession{live: c.accounting(), reportedLeftRx: 150, reportedRightRx: 70}
	full := func(dst *atomic.Int64) func(int64) { return func(n int64) { dst.Add(n) } }

	// Everything already reported live: nothing is recorded again.
	s.recordFinal(150, 70, full(&c.finalDown), full(&c.finalUp))
	if c.up.Load() != 0 || c.down.Load() != 0 || c.finalUp.Load() != 0 || c.finalDown.Load() != 0 {
		t.Fatalf("double count: live up=%d down=%d final up=%d down=%d", c.up.Load(), c.down.Load(), c.finalUp.Load(), c.finalDown.Load())
	}

	// Growth after the last report is recorded once, as the remainder, through
	// the live recorders: the full recorders would measure TTFB at close.
	s.recordFinal(180, 100, full(&c.finalDown), full(&c.finalUp))
	if c.up.Load() != 30 || c.down.Load() != 30 {
		t.Fatalf("remainder wrong: up=%d down=%d", c.up.Load(), c.down.Load())
	}
	if c.finalUp.Load() != 0 || c.finalDown.Load() != 0 {
		t.Fatalf("remainder must not use the full recorders: up=%d down=%d", c.finalUp.Load(), c.finalDown.Load())
	}

	// A session without live reporting keeps the original behaviour.
	var up, down atomic.Int64
	plain := &tcpRelayOffloadSession{}
	plain.recordFinal(10, 20, full(&down), full(&up))
	if up.Load() != 10 || down.Load() != 20 {
		t.Fatalf("non-live session changed: up=%d down=%d", up.Load(), down.Load())
	}
}

// A sockmap-offloaded flow used to observe first-byte only at session end, as
// the whole flow lifetime. Against a millisecond baseline that is always
// "slow", which counts toward moving the site off a healthy dialer. The first
// non-zero live report must instead confirm the first byte right away.
func TestTCPOffloadFirstByteConfirmedByLiveReportNotAtClose(t *testing.T) {
	d := newTestEndpointDialer()
	other := newTestEndpointDialer()
	defer d.Close()
	defer other.Close()
	g := newTestOutboundGroup(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, d, other)
	defer g.Close()
	nt := dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	for range 3 {
		other.ObserveHandshake(&nt, time.Millisecond)
	}
	if !other.ObserveTTFB(&nt, 4*time.Second) {
		t.Fatal("fixture: a lifetime-sized TTFB must classify as slow")
	}

	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })
	flow, err := manager.adoptTCP(
		&memoryLayoutConn{id: 5}, nil,
		TcpFlowBinding{Egress: TcpEgressBinding{Dialer: other, Outbound: g, NetworkType: nt, SniffedDomain: "youtube.com"}},
		runtime, nil,
		netip.MustParseAddrPort("192.0.2.1:1"), netip.MustParseAddrPort("198.51.100.1:443"),
	)
	if err != nil {
		t.Fatal(err)
	}
	flow.startUnixNano = time.Now().Add(-4 * time.Second).UnixNano()

	selected := func() *dialer.Dialer {
		t.Helper()
		sel, _, _, err := g.SelectWithExclusionResultForSite(&nt, true, nil, "youtube.com")
		if err != nil {
			t.Fatal(err)
		}
		return sel
	}
	if selected() != d {
		t.Fatal("fixture: unpinned fallback group must select the first dialer")
	}

	s, _, rightPeer := newLiveAccountingSession(t, flow.offloadLiveAccounting())
	if _, err := rightPeer.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	reportUntil(t, s, func() bool { return flow.downloadBytes.Load() == 100 })
	// The flow is still open: its first byte must already be on record.
	if !flow.firstByte.Load() {
		t.Fatal("first live download report did not confirm the first byte")
	}
	if selected() != other {
		t.Fatal("confirmed first byte did not pin the site while the flow was open")
	}

	// Session end must not add a lifetime-sized observation or double count.
	s.recordFinal(0, 100, flow.recordDownload, flow.recordUpload)
	if got := flow.downloadBytes.Load(); got != 100 {
		t.Fatalf("download bytes after close = %d, want 100", got)
	}
}

// With a real sockmap redirect the payload never reaches userspace, so the
// flow's counters can only move through the periodic tcp_info reports. They
// must advance while the session is still running and the final totals must
// match the transferred bytes (no double count at close).
func TestTCPOffloadLiveAccountingRealRedirect(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("needs root for isolated BPF map")
	}
	coll := loadOffloadVerifyCollection(t)
	defer coll.Close()
	fast := coll.Maps["fast_sock"]
	lnk, err := link.AttachRawLink(link.RawLinkOptions{Target: fast.FD(), Program: coll.Programs["tcp_offload_redirect"], Attach: ebpf.AttachSkSKBStreamVerdict})
	if err != nil {
		t.Fatal(err)
	}
	defer lnk.Close()

	var up, down atomic.Int64
	add := func(dst *atomic.Int64) func(int64) { return func(n int64) { dst.Add(n) } }
	live := &tcpOffloadLiveAccounting{Upload: add(&up), Download: add(&down)}

	left, client := offloadTCPPair(t)
	server, right := offloadTCPPair(t) // production egress is dialed
	s, err := newTCPRelayOffloadSession(nil, fast, coll.Maps["tcp_offload_pause"], coll.Maps["tcp_offload_sent"], left, right, add(&down), add(&up))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.live = live

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type result struct{ l, r int64 }
	done := make(chan result, 1)
	go func() {
		l, r, _ := s.Run(ctx)
		s.recordFinal(l, r, add(&down), add(&up))
		done <- result{l, r}
	}()

	const upBytes, downBytes = 64 << 10, 32 << 10
	if _, err := client.Write(bytes.Repeat([]byte("u"), upBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(server, make([]byte, upBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write(bytes.Repeat([]byte("d"), downBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, downBytes)); err != nil {
		t.Fatal(err)
	}

	// Both sockets are still open: only live reports can have counted this.
	deadline := time.Now().Add(4 * time.Second)
	for up.Load() != upBytes || down.Load() != downBytes {
		select {
		case <-done:
			t.Fatalf("session ended before live reports caught up: up=%d down=%d", up.Load(), down.Load())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no live progress while flow is open: up=%d/%d down=%d/%d", up.Load(), upBytes, down.Load(), downBytes)
		}
		time.Sleep(20 * time.Millisecond)
	}

	_ = client.Close()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("session did not retire")
	}
	// tcp_info bytes_received also counts the FIN's sequence number, so the
	// closing side may add one byte per direction; this predates live
	// reporting (the final totals come from the same counters). Anything
	// beyond that would be a double count.
	if u, d := up.Load(), down.Load(); u < upBytes || u > upBytes+1 || d < downBytes || d > downBytes+1 {
		t.Fatalf("final totals double counted or lost: up=%d want %d(+1 FIN), down=%d want %d(+1 FIN)", u, upBytes, d, downBytes)
	}
}
