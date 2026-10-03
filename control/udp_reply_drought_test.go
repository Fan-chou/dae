// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
)

var droughtTestPeer = netip.MustParseAddrPort("192.0.2.1:27015")

func testDroughtObserver(t *testing.T, requestReply bool) *udpReplyDroughtObserver {
	t.Helper()
	p := config.UDPReplyDroughtPolicy{Observe: true, RequestReply: requestReply, Group: "game"}
	if requestReply {
		p.Peers = []netip.AddrPort{droughtTestPeer, netip.MustParseAddrPort("192.0.2.2:27015")}
	}
	o := newUDPReplyDroughtObserver(p)
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func fillDroughtWindow(f *udpReplyDroughtFlow, peer netip.AddrPort, base time.Time) {
	f.write(peer, 100, base.Add(-time.Second))
	for i := 0; i < 3; i++ {
		f.reply(peer, base.Add(-time.Second))
	}
	for bucket := 0; bucket < 6; bucket++ {
		for packet := 0; packet < 10; packet++ {
			f.write(peer, 100, base.Add(time.Duration(bucket)*5*time.Second+time.Second))
		}
	}
}

func TestUDPReplyDroughtQualificationAndIsolation(t *testing.T) {
	base := time.Now().Truncate(5 * time.Second)
	for _, tc := range []struct {
		name                 string
		contract, completion bool
		want                 string
	}{
		{"cs2_sdr_unknown", false, true, "unknown_reply_semantics"},
		{"queued_transport", true, false, "transport_completion_unknown"},
		{"declared_request_reply", true, true, "candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := testDroughtObserver(t, tc.contract)
			f := o.newFlow("client", "game", "node", tc.completion)
			fillDroughtWindow(f, droughtTestPeer, base)
			o.scan(base.Add(30 * time.Second))
			s := o.snapshot(base.Add(30 * time.Second))
			if len(s.Peers) != 1 || s.Peers[0].Eligibility != tc.want {
				t.Fatalf("qualification: %+v", s)
			}
			if (s.Stats.Candidates > 0) != (tc.want == "candidate") {
				t.Fatalf("candidate events: %+v", s.Stats)
			}
		})
	}
	o := testDroughtObserver(t, true)
	f := o.newFlow("client", "game", "node", true)
	other := netip.MustParseAddrPort("192.0.2.2:27015")
	fillDroughtWindow(f, droughtTestPeer, base)
	fillDroughtWindow(f, other, base)
	f.reply(droughtTestPeer, base.Add(29*time.Second))
	f.reply(netip.MustParseAddrPort("192.0.2.3:27015"), base.Add(29*time.Second))
	s := o.snapshot(base.Add(30 * time.Second))
	if len(s.Peers) != 2 || s.Peers[0].Eligibility != "recent_reply" || s.Peers[1].Eligibility != "candidate" || s.Stats.UnattributedReplies != 1 {
		t.Fatalf("peer isolation: %+v", s)
	}
}

func TestUDPReplyDroughtPauseKeepaliveAndIncompleteWindows(t *testing.T) {
	base := time.Now().Truncate(5 * time.Second)
	for _, kind := range []string{"pause", "zero_keepalive", "sparse_keepalive", "new_flow", "no_reply", "local_error", "current_error", "clock_backwards"} {
		t.Run(kind, func(t *testing.T) {
			o := testDroughtObserver(t, true)
			f := o.newFlow("client", "game", "node", true)
			switch kind {
			case "pause", "local_error", "current_error", "clock_backwards":
				fillDroughtWindow(f, droughtTestPeer, base)
				if kind == "local_error" {
					f.invalidate(base.Add(20 * time.Second))
				}
				if kind == "current_error" {
					f.invalidate(base.Add(30 * time.Second))
				}
				if kind == "clock_backwards" {
					f.reply(droughtTestPeer, base.Add(-time.Second))
				}
			default:
				f.write(droughtTestPeer, 100, base.Add(-time.Second))
				if kind != "no_reply" {
					for i := 0; i < 3; i++ {
						f.reply(droughtTestPeer, base.Add(-time.Second))
					}
				}
				for bucket := 0; bucket < 6; bucket++ {
					count, size := 10, 100
					if kind == "sparse_keepalive" {
						count = 1
					}
					if kind == "zero_keepalive" {
						size = 0
					}
					if kind == "new_flow" && bucket < 5 {
						continue
					}
					for i := 0; i < count; i++ {
						f.write(droughtTestPeer, size, base.Add(time.Duration(bucket)*5*time.Second+time.Second))
					}
				}
			}
			at := base.Add(30 * time.Second)
			if kind == "pause" {
				at = base.Add(45 * time.Second)
			}
			o.scan(at)
			s := o.snapshot(at)
			if len(s.Peers) != 1 || s.Peers[0].Eligibility == "candidate" || s.Stats.Candidates != 0 {
				t.Fatalf("unsafe %s: %+v", kind, s)
			}
		})
	}
}

func TestUDPReplyDroughtBatchCountsSuccessfulPrefix(t *testing.T) {
	o := testDroughtObserver(t, true)
	f := o.newFlow("client", "game", "node", true)
	ue := &UdpEndpoint{replyDrought: f}
	items := []netproxy.BatchItem{{Addr: droughtTestPeer.String(), Data: []byte{1}}, {Addr: "192.0.2.2:27015", Data: []byte{2}}}
	now := time.Now()
	ue.observeDroughtBatch(items, 1, errors.New("local backpressure"), now)
	s := o.snapshot(now)
	if len(s.Peers) != 1 || s.Stats.SuccessfulWrites != 1 || s.Stats.InvalidatedWindows != 1 {
		t.Fatalf("partial batch: %+v", s)
	}
	ue.observeDroughtBatch(items, 0, nil, now)
	if got := o.snapshot(now).Stats.SuccessfulWrites; got != 1 {
		t.Fatalf("zero flush counted %d", got)
	}
}

func TestUDPReplyDroughtOffBoundsEvictionAndReload(t *testing.T) {
	if o := newUDPReplyDroughtObserver(config.UDPReplyDroughtPolicy{}); o != nil {
		t.Fatal("off allocated observer")
	}
	o := testDroughtObserver(t, false)
	if f := o.newFlow("client", "other", "node", true); f != nil {
		t.Fatal("group scope ignored")
	}
	base := time.Now()
	flows := make([]*udpReplyDroughtFlow, 40)
	for i := range flows {
		f := o.newFlow("client", "game", "node", true)
		flows[i] = f
		for j := 0; j < 10; j++ {
			f.write(netip.AddrPortFrom(droughtTestPeer.Addr(), uint16(27000+j)), 100, base)
		}
	}
	s := o.snapshot(base)
	if len(s.Peers) != 256 || s.Stats.AdmissionDropped != 144 {
		t.Fatalf("bounds: peers=%d stats=%+v", len(s.Peers), s.Stats)
	}
	o.scan(base.Add(61 * time.Second))
	s = o.snapshot(base.Add(61 * time.Second))
	if len(s.Peers) != 0 || s.Stats.PeerEvicted != 256 {
		t.Fatalf("eviction: %+v", s)
	}
	flows[0].write(droughtTestPeer, 100, base.Add(62*time.Second))
	if got := o.snapshot(base.Add(62 * time.Second)); len(got.Peers) != 1 || got.Peers[0].Replies != 0 {
		t.Fatalf("evicted history reused: %+v", got)
	}
	plane := &ControlPlane{controlPlaneUDPRuntime: controlPlaneUDPRuntime{udpReplyDrought: o}}
	plane.MarkRetired()
	if len(flows[0].peers) != 0 {
		t.Fatal("retained endpoint kept old observation table")
	}
	flows[0].write(droughtTestPeer, 100, base.Add(63*time.Second))
	flows[0].reply(droughtTestPeer, base.Add(63*time.Second))
	if o.snapshot(base) != nil {
		t.Fatal("retired observer still published")
	}
	successor := testDroughtObserver(t, false)
	if successor.generation == o.generation || len(successor.snapshot(base).Peers) != 0 {
		t.Fatal("reload inherited old observations")
	}
	for _, f := range flows {
		f.Close()
	}
}

func TestUDPReplyDroughtConcurrentCallbacksAndSnapshots(t *testing.T) {
	o := testDroughtObserver(t, false)
	f := o.newFlow("client", "game", "node", true)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				now := time.Now()
				f.write(droughtTestPeer, 100, now)
				f.reply(droughtTestPeer, now)
				o.snapshot(now)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			o.scan(time.Now())
		}
		_ = o.Close()
		f.Close()
	}()
	wg.Wait()
}

func TestUDPReplyDroughtCountsFlushNotAppend(t *testing.T) {
	o := testDroughtObserver(t, true)
	conn := newBlockingBatchRecorder()
	ue := &UdpEndpoint{conn: conn, replyDrought: o.newFlow("client", "game", "node", true)}
	ue.writeBatch = newUDPWriteBatchAggregator(ue)
	defer func() { conn.release(); _ = ue.Close() }()
	if _, err := ue.WriteTo([]byte{1}, droughtTestPeer.String()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("flush did not start")
	}
	if got := o.snapshot(time.Now()).Stats.SuccessfulWrites; got != 0 {
		t.Fatalf("Append counted %d writes", got)
	}
	conn.release()
	ue.writeBatch.Close()
	if got := o.snapshot(time.Now()).Stats.SuccessfulWrites; got != 1 {
		t.Fatalf("completed flush counted %d writes", got)
	}
}

func TestUDPReplyDroughtReceiverRejectsDropAndForeignPeer(t *testing.T) {
	o := testDroughtObserver(t, false)
	f := o.newFlow("client", "game", "node", true)
	f.write(receiverTestFrom(), 100, time.Now())
	conn := &receiverConn{}
	ue := newReceiverTestEndpoint(t, conn, func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil })
	ue.replyDrought = f // test assigns before any receiver delivery
	defer ue.Close()
	ue.hasReply.Store(true)
	packets := []*netproxy.ReceivedPacket{
		netproxy.NewReceivedPacket([]byte{1}, receiverTestFrom(), netproxy.DatagramDropped(errors.New("truncated")), func() {}),
		netproxy.NewReceivedPacket([]byte{2}, droughtTestPeer, nil, func() {}),
		netproxy.NewReceivedPacket([]byte{3}, receiverTestFrom(), nil, func() {}),
	}
	for _, p := range packets {
		if !ue.handleReceivedPacket(p) {
			t.Fatal("observation changed receiver lifetime")
		}
	}
	s := o.snapshot(time.Now())
	if s.Stats.Replies != 1 || s.Stats.UnattributedReplies != 1 || s.Stats.InvalidatedWindows != 1 {
		t.Fatalf("drop or canonicalized foreign peer counted as reply: %+v", s.Stats)
	}
}

func TestUDPReplyDroughtCrossFamilyKeepsPeerAndAlias(t *testing.T) {
	store := openCrossFamilyTestStore(t, t.TempDir())
	peer := netip.MustParseAddrPort("[2001:db8::10]:27015")
	client := netip.MustParseAddrPort("192.0.2.10:30000")
	alias, err := store.reply(peer, client)
	if err != nil {
		t.Fatal(err)
	}
	o := testDroughtObserver(t, false)
	ue := &UdpEndpoint{conn: &receiverConn{}, crossFamily: store, poolKey: UdpEndpointKey{Dst: alias}, replyDrought: o.newFlow(client.String(), "game", "node", true), handler: func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil }}
	if !ue.startTransportReceiver() {
		t.Fatal("receiver registration failed")
	}
	defer ue.Close()
	if _, err := ue.WriteTo([]byte{1}, alias.String()); err != nil {
		t.Fatal(err)
	}
	if !ue.handleReceivedPacket(netproxy.NewReceivedPacket([]byte{2}, peer, nil, func() {})) {
		t.Fatal("observer changed receiver lifetime")
	}
	s := o.snapshot(time.Now())
	if len(s.Peers) != 1 || s.Peers[0].Peer != peer.String() || s.Peers[0].Replies != 1 || s.Peers[0].SuccessfulWrites != 1 {
		t.Fatalf("alias attribution: %+v", s)
	}
	if after, err := store.reply(peer, client); err != nil || after != alias || ue.poolKey.Dst != alias {
		t.Fatalf("observation changed alias %s to %s: %v", alias, after, err)
	}
}

func TestUDPReplyDroughtConcurrentAdmissionAndEventBounds(t *testing.T) {
	o := testDroughtObserver(t, false)
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		f := o.newFlow("client", "game", "node", true)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				f.write(netip.AddrPortFrom(droughtTestPeer.Addr(), uint16(27000+j)), 100, time.Now())
			}
		}()
	}
	wg.Wait()
	if s := o.snapshot(time.Now()); len(s.Peers) != 256 || s.Stats.AdmissionDropped != 384 {
		t.Fatalf("concurrent cap: peers=%d stats=%+v", len(s.Peers), s.Stats)
	}
	_ = o.Close()
	o = testDroughtObserver(t, true)
	base := time.Now().Truncate(5 * time.Second)
	for i := 0; i < 25; i++ {
		f := o.newFlow("client", "game", "node", true)
		fillDroughtWindow(f, droughtTestPeer, base)
	}
	o.scan(base.Add(30 * time.Second))
	s := o.snapshot(base.Add(30 * time.Second))
	if s.Stats.Candidates != 25 || len(s.Events) != 20 || s.Stats.EventRateLimited != 5 {
		t.Fatalf("event rate: %+v", s.Stats)
	}
	// Fresh associations in a later minute exercise retained-event eviction.
	base = base.Add(2 * time.Minute)
	for i := 0; i < 20; i++ {
		f := o.newFlow("client", "game", "node", true)
		fillDroughtWindow(f, droughtTestPeer, base)
	}
	o.scan(base.Add(30 * time.Second))
	s = o.snapshot(base.Add(30 * time.Second))
	if len(s.Events) != 32 || s.Stats.EventEvicted != 8 {
		t.Fatalf("event ring: events=%d stats=%+v", len(s.Events), s.Stats)
	}
}

func TestUDPReplyDroughtClientScope(t *testing.T) {
	p := config.UDPReplyDroughtPolicy{Observe: true, Client: netip.MustParseAddr("192.0.2.10")}
	o := newUDPReplyDroughtObserver(p)
	defer o.Close()
	if o.newFlow("192.0.2.11:30000", "game", "node", true) != nil {
		t.Fatal("other client observed")
	}
	if o.newFlow("[::ffff:192.0.2.10]:30000", "game", "node", true) == nil {
		t.Fatal("mapped client omitted")
	}
}
