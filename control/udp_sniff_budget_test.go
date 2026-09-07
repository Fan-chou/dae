package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"testing"
	"time"
)

func TestQUICSniffBudgetReplaysWithoutAnotherPacket(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()
	first, _ := newSnifferNeedMorePayloads(t)
	conn := &udpReuseSimulationConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	d, _ := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	cp.sniffingTimeout = 20 * time.Millisecond
	src, dst, flow := newQuicInitialRegressionFlow(t, first)
	primeQuicRegressionAnyfrom(src, dst)
	route := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}
	if err := cp.handlePktWithPrefetch(nil, first, src, dst, route, flow, false, nil, UdpEndpointKey{}, false); err != nil {
		t.Fatal(err)
	}
	limit := time.Now().Add(time.Second)
	for conn.writeCalls.Load() == 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if got := conn.writeCalls.Load(); got != 1 {
		t.Fatalf("expiry writes=%d, want one held Initial", got)
	}
	ps := DefaultPacketSnifferSessionMgr.Get(NewPacketSnifferKey(src, dst, first))
	ps.Mu.Lock()
	defer ps.Mu.Unlock()
	if !ps.flushDeadline.IsZero() || ps.NeedMore() || len(ps.Data()) != 1 {
		t.Fatal("expiry did not finish and release sniff state")
	}
}

func TestQUICSniffBudgetPreservesBlockQuic(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()
	first, _ := newSnifferNeedMorePayloads(t)
	conn := &udpReuseSimulationConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	d, underlay := newCountingProxyEndpointDialer("anytls", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	cp.blockQuic = true
	cp.sniffingTimeout = 10 * time.Millisecond
	src, dst, flow := newQuicInitialRegressionFlow(t, first)
	primeQuicRegressionAnyfrom(src, dst)
	route := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}
	if err := cp.handlePktWithPrefetch(nil, first, src, dst, route, flow, false, nil, UdpEndpointKey{}, false); err != nil {
		t.Fatal(err)
	}
	limit := time.Now().Add(time.Second)
	ps := DefaultPacketSnifferSessionMgr.Get(NewPacketSnifferKey(src, dst, first))
	for {
		ps.Mu.Lock()
		finished := ps.flushDeadline.IsZero()
		ps.Mu.Unlock()
		if finished {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("sniff budget did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	// Drain the same ordered flow to wait for the expiry task's routing decision.
	barrier := make(chan struct{})
	if !DefaultUdpTaskPool.EmitTask(flow.Key, udpTaskFunc(func() { close(barrier) })) {
		t.Fatal("barrier rejected")
	}
	<-barrier
	if underlay.calls.Load() != 0 || conn.writeCalls.Load() != 0 {
		t.Fatal("expiry bypassed block_quic on a reliable carrier")
	}
}
