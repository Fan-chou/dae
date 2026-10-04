// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestUDPReplyDroughtEarlyReplyAndFailedSend(t *testing.T) {
	for _, fail := range []bool{false, true} {
		o := testDroughtObserver(t, false)
		f := o.newFlow("client", "game", "node", true)
		conn := &mockPacketConn{writeToFn: func(p []byte, addr string) (int, error) {
			if s := o.snapshot(time.Now()); s.Stats.SuccessfulWrites != 0 {
				t.Fatalf("intent counted as completed send: %+v", s.Stats)
			}
			f.reply(droughtTestPeer, time.Now())
			if fail {
				return 0, netproxy.DatagramDropped(errors.New("queue timeout"))
			}
			return len(p), nil
		}}
		ue := &UdpEndpoint{conn: conn, replyDrought: f}
		_, _ = ue.WriteTo([]byte{1}, droughtTestPeer.String())
		defer ue.Close()
		s := o.snapshot(time.Now())
		wantWrites := uint64(1)
		if fail {
			wantWrites = 0
		}
		if len(s.Peers) != 1 || s.Stats.SuccessfulWrites != wantWrites || s.Stats.Replies != 1 || s.Stats.UnattributedReplies != 0 {
			t.Fatalf("fail=%v early reply: %+v", fail, s)
		}
		if fail && (s.Stats.InvalidatedWindows != 1 || s.Stats.Candidates != 0) {
			t.Fatalf("failed send evidence: %+v", s.Stats)
		}
	}
}

type earlyDroughtBatchConn struct {
	mockPacketConn
	f *udpReplyDroughtFlow
}

func (c *earlyDroughtBatchConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	for _, item := range items {
		peer, _ := netip.ParseAddrPort(item.Addr)
		c.f.reply(peer, time.Now())
	}
	return 1, netproxy.DatagramDropped(errors.New("partial batch"))
}

func TestUDPReplyDroughtEarlyBatchReplyKeepsPartialCompletion(t *testing.T) {
	o := testDroughtObserver(t, false)
	f := o.newFlow("client", "game", "node", true)
	ue := &UdpEndpoint{conn: &earlyDroughtBatchConn{f: f}, replyDrought: f}
	ue.writeBatch = newUDPWriteBatchAggregator(ue)
	defer ue.Close()
	// Prepare a single deterministic flush, before any timer can run.
	ue.writeBatch.items = []netproxy.BatchItem{{Addr: droughtTestPeer.String(), Data: []byte{1}}, {Addr: "192.0.2.2:27015", Data: []byte{2}}}
	ue.writeBatch.flush()
	s := o.snapshot(time.Now())
	if len(s.Peers) != 2 || s.Stats.Replies != 2 || s.Stats.SuccessfulWrites != 1 || s.Stats.UnattributedReplies != 0 || s.Stats.InvalidatedWindows != 1 {
		t.Fatalf("early batch replies: %+v", s)
	}
}

func TestUDPReplyDroughtNATReplyPeerIsolation(t *testing.T) {
	o := testDroughtObserver(t, false)
	conn := &receiverConn{}
	ue := newReceiverTestEndpoint(t, conn, func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil })
	ue.replyDrought = o.newFlow("client", "game", "node", true)
	defer ue.Close()
	ue.hasReply.Store(true)
	ue.replyDrought.write(droughtTestPeer, 1, time.Now())
	hint := netip.MustParseAddrPort("28.0.0.1:27015")
	for _, peer := range []netip.AddrPort{droughtTestPeer, netip.MustParseAddrPort("[::ffff:192.0.2.1]:27015"), netip.MustParseAddrPort("192.0.2.2:27015"), netip.MustParseAddrPort("192.0.2.1:27016"), {}} {
		p := netproxy.NewReceivedPacket([]byte{1}, hint, nil, nil)
		p.Peer = peer
		if !ue.handleReceivedPacket(p) {
			t.Fatal("observer changed receiver lifetime")
		}
	}
	s := o.snapshot(time.Now())
	if len(s.Peers) != 1 || s.Peers[0].Peer != droughtTestPeer.String() || s.Peers[0].Replies != 2 || s.Stats.UnattributedReplies != 3 {
		t.Fatalf("NAT identity merged different peers: %+v", s)
	}
	if len(s.Associations) != 1 || s.Associations[0].Association != ue.replyDrought.id || s.Associations[0].UnattributedReplies != 3 {
		t.Fatalf("missing per-association attribution: %+v", s.Associations)
	}
}

func TestUDPReplyDroughtIntentBoundsTTLAndClose(t *testing.T) {
	o := testDroughtObserver(t, false)
	f := o.newFlow("client", "game", "node", true)
	base := time.Now()
	for i := 0; i < 16; i++ {
		f.prepare(netip.AddrPortFrom(droughtTestPeer.Addr(), uint16(27000+i)), base)
	}
	o.scan(base.Add(time.Second))
	if s := o.snapshot(base); len(s.Peers) != 8 || s.Stats.SuccessfulWrites != 0 || s.Stats.Candidates != 0 {
		t.Fatalf("intent cap/expiry: %+v", s)
	}
	o.scan(base.Add(61 * time.Second))
	if s := o.snapshot(base.Add(61 * time.Second)); len(s.Peers) != 0 || s.Stats.PeerEvicted != 8 {
		t.Fatalf("intent TTL: %+v", s)
	}
	f.prepare(droughtTestPeer, base.Add(62*time.Second))
	f.Close()
	f.prepare(droughtTestPeer, base.Add(63*time.Second))
	if s := o.snapshot(base); len(s.Peers) != 0 {
		t.Fatalf("closed intent retained: %+v", s)
	}
}
