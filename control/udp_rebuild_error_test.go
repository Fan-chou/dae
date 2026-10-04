// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type rebuildErrorConn struct {
	mockPacketConn
	closed atomic.Int32
}

func (c *rebuildErrorConn) Close() error { c.closed.Add(1); return nil }

func TestUDPRebuildRedirectHardErrorKeepsSharedAncestor(t *testing.T) {
	for _, kind := range []string{"closed", "refused", "short"} {
		t.Run(kind, func(t *testing.T) {
			m := NewSessionManager(nil)
			defer m.Close()
			l := m.rebuildLedger()
			old, slot, key := testRebuildSlot(m, 1)
			old.conn = &mockPacketConn{}
			old.hasSent.Store(true)
			old.hasReply.Store(true)
			pc := &rebuildErrorConn{}
			pc.writeToFn = func(b []byte, _ string) (int, error) {
				switch kind {
				case "closed":
					return 0, net.ErrClosed
				case "refused":
					return 0, syscall.ECONNREFUSED
				default:
					return len(b) - 1, nil
				}
			}
			next := &UdpEndpoint{conn: pc, DialTarget: slot.peer.String(), poolKey: UdpEndpointKey{Dst: slot.peer}}
			next.hasSent.Store(true)
			next.hasReply.Store(true)
			ticket, _ := l.reserve(key, slot, old, time.Now())
			l.start(ticket, time.Now())
			l.commit(ticket, next, time.Now())
			l.finish(ticket, "")
			slot.owner.Store(&udpRebuildOwnership{endpoint: next, revision: 2})
			old.installRebuildPeer(slot.peer, slot)
			next.installRebuildPeer(slot.peer, slot)
			_, err := (UdpFlowDecision{}).writeTo(old, []byte("B/data"), slot.peer.String())
			if !isUdpEndpointWriteTolerated(err) {
				t.Fatalf("redirected error lets ingress close ancestor: %v", err)
			}
			waitRebuild(t, func() bool { return pc.closed.Load() == 1 })
			if old.dead.Load() || !next.dead.Load() {
				t.Fatal("hard error retired shared ancestor")
			}
			if _, err = old.WriteTo([]byte("A/healthy"), netip.MustParseAddrPort("192.0.2.2:1234").String()); err != nil {
				t.Fatal("healthy peer lost shared association")
			}
			if _, err = slot.claim(context.Background(), true); !isUdpEndpointWriteTolerated(err) {
				t.Fatal("closed successor fell back")
			}
			_ = old.Close()
		})
	}
}
