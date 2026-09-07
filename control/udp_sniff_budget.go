package control

import (
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

// armUDPSniffFlush is called under ps.Mu on the first incomplete Initial.
// Expiry schedules ordinary flow work; the timer never writes to the network.
func (c *ControlPlane) armUDPSniffFlush(ps *PacketSniffer, key PacketSnifferKey, first time.Time, lConn *net.UDPConn, src, dst netip.AddrPort, result *bpfRoutingResult, flow UdpFlowDecision) {
	if !ps.flushDeadline.IsZero() {
		return
	}
	// The ingress classifier creates the sniffer before joining the flow
	// queue. Include that queue wait instead of granting a fresh budget
	// when the first Initial finally reaches the worker.
	if !ps.createdAt.IsZero() {
		first = ps.createdAt
	}
	deadline := first.Add(c.sniffingTimeout)
	ps.flushDeadline = deadline
	ps.flushSampledAt = udpSniffWait.start()
	routing := *result
	snifferPool, taskPool := DefaultPacketSnifferSessionMgr, DefaultUdpTaskPool
	ps.flushTimer = time.AfterFunc(time.Until(deadline), func() {
		if c.ctx != nil && c.ctx.Err() != nil {
			return
		}
		if !taskPool.EmitTask(flow.Key, udpTaskFunc(func() {
			if c.ctx != nil && c.ctx.Err() != nil {
				return
			}
			ps.Mu.Lock()
			if ps.Sniffer == nil || ps.flushDeadline != deadline || snifferPool.Get(key) != ps {
				ps.Mu.Unlock()
				return
			}
			var packets []pool.PB
			udpSniffBudgetFlushes.Add(1)
			// Packet sniffers start with an empty sentinel; all remaining
			// entries are held datagrams, including the most recent one.
			for _, data := range ps.Data()[1:] {
				copyBuf := pool.Get(len(data))
				copy(copyBuf, data)
				packets = append(packets, copyBuf)
			}
			ps.GiveUpIncomplete()
			MarkQuicDcidFailed(key, quicDcidFailureReasonSoftBypass)
			ps.CompactPacketState()
			ps.Mu.Unlock()
			defer func() {
				for _, packet := range packets {
					packet.Put()
				}
			}()
			for _, packet := range packets {
				if err := c.handlePkt(lConn, packet, src, dst, &routing, flow, true); err != nil {
					if c.log != nil {
						c.log.WithError(err).Debug("UDP sniff budget replay stopped")
					}
					return
				}
			}
		})) {
			udpSniffBudgetRejected.Add(1)
		}
	})
}
