/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type phase0QuicAction string

const (
	phase0QuicActionDirect phase0QuicAction = "direct"
	phase0QuicActionProxy  phase0QuicAction = "proxy"
	phase0QuicActionBlock  phase0QuicAction = "block"
)

// QUIC SNI is a UDP data-plane fact, not a DnsController input. This corpus
// therefore pins the real handoff: a reassembled QUIC Initial supplies the
// domain to userspace routing and creates the resulting bound UDP endpoint.
type quicSniffingCorpusFixture struct {
	name             string
	expectedDomain   string
	expectedOutbound consts.OutboundIndex
	expectedMark     uint32
	expectedMust     bool
	expectedTarget   string
	expectedAction   phase0QuicAction
}

func phase0QuicSniffingCorpusFixtures() []quicSniffingCorpusFixture {
	return []quicSniffingCorpusFixture{{
		name:             "reassembled_initial_routes_by_sni",
		expectedDomain:   "i.ytimg.com",
		expectedOutbound: consts.OutboundUserDefinedMin + 1,
		expectedMark:     77,
		expectedMust:     true,
		expectedTarget:   "i.ytimg.com:443",
		expectedAction:   phase0QuicActionProxy,
	}}
}

// TestPhase0QuicSniffingCorpus_LegacyBaseline records the observable result
// of the QUIC sniffing pipeline. The captured Initial spans two datagrams; its
// first packet must wait for more crypto data, while the completed handshake
// must bind the SNI, select the SNI-matched outbound, pass domain:port
// (no resolve_dns on the test dialer), and reuse that bound flow for later packets.
func TestPhase0QuicSniffingCorpus_LegacyBaseline(t *testing.T) {
	for _, fixture := range phase0QuicSniffingCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			replayQuicSniffingCorpusFixture(t, fixture)
		})
	}
}

func replayQuicSniffingCorpusFixture(t *testing.T, fixture quicSniffingCorpusFixture) {
	t.Helper()
	defer setupQuicInitialRegressionTestState(t)()

	first, second := newSnifferNeedMorePayloads(t)
	fallbackConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	fallbackDialer, fallbackUnderlay := newCountingProxyEndpointDialer("hysteria2", "fallback.example:443", fallbackConn)
	sniffedConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	sniffedDialer, sniffedUnderlay := newCountingProxyEndpointDialer("hysteria2", "sniffed.example:443", sniffedConn)

	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(fallbackDialer))
	cp.outbounds = append(cp.outbounds, newTestFixedOutboundGroup(sniffedDialer))
	cp.routingMatcher = newQuicSniffingCorpusMatcher(t, fixture)

	src, dst, firstDecision := newQuicInitialRegressionFlow(t, first)
	primeQuicRegressionAnyfrom(src, dst)
	routingResult := &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}

	if err := cp.handlePkt(nil, first, src, dst, routingResult, firstDecision, false); err != nil {
		t.Fatalf("handlePkt(first): %v", err)
	}
	if got := fallbackUnderlay.calls.Load(); got != 0 {
		t.Fatalf("fallback DialContext calls after incomplete Initial = %d, want 0", got)
	}
	if got := sniffedUnderlay.calls.Load(); got != 0 {
		t.Fatalf("sniffed DialContext calls after incomplete Initial = %d, want 0", got)
	}

	secondDecision := ClassifyUdpFlow(src, dst, second).EnsureSnifferSession()
	if err := cp.handlePkt(nil, second, src, dst, routingResult, secondDecision, false); err != nil {
		t.Fatalf("handlePkt(second): %v", err)
	}

	key := firstDecision.SymmetricNatEndpointKey()
	endpoint, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || endpoint == nil {
		t.Fatal("expected SNI-bound symmetric UDP endpoint")
	}
	if got := endpoint.SniffedDomain; got != fixture.expectedDomain {
		t.Fatalf("SniffedDomain = %q, want %q", got, fixture.expectedDomain)
	}
	if got := endpoint.Outbound; got != cp.outbounds[fixture.expectedOutbound] {
		t.Fatalf("endpoint outbound = %p, want SNI-matched outbound %p", got, cp.outbounds[fixture.expectedOutbound])
	}
	if got := endpoint.DialTarget; got != fixture.expectedTarget {
		t.Fatalf("DialTarget = %q, want domain:port %q", got, fixture.expectedTarget)
	}
	binding := endpoint.FlowBinding()
	if binding.Route.Outbound != fixture.expectedOutbound || binding.Route.Mark != fixture.expectedMark || binding.Route.Must != fixture.expectedMust {
		t.Fatalf("QUIC route binding = %+v, want outbound=%v mark=%d must=%v", binding.Route, fixture.expectedOutbound, fixture.expectedMark, fixture.expectedMust)
	}
	if binding.Egress.Target != fixture.expectedTarget || binding.Egress.SniffedDomain != fixture.expectedDomain {
		t.Fatalf("QUIC egress binding = %+v, want target=%q domain=%q", binding.Egress, fixture.expectedTarget, fixture.expectedDomain)
	}
	if binding.Egress.NetworkType.L4Proto != consts.L4ProtoStr_UDP || binding.Egress.NetworkType.IpVersion != consts.IpVersionStr_4 {
		t.Fatalf("QUIC selected network family = %+v, want udp/ipv4", binding.Egress.NetworkType)
	}
	magicNetwork, err := netproxy.ParseMagicNetwork(binding.Egress.Network)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if magicNetwork.Network != "udp" || magicNetwork.Mark != fixture.expectedMark || magicNetwork.Mptcp {
		t.Fatalf("QUIC magic network = %+v, want udp with mark %d and mptcp disabled", magicNetwork, fixture.expectedMark)
	}
	if action := phase0QuicActionForOutbound(binding.Route.Outbound); action != fixture.expectedAction {
		t.Fatalf("QUIC action = %q, want %q", action, fixture.expectedAction)
	}
	if got := endpoint.natTimeout(); got != QuicNatTimeout {
		t.Fatalf("NAT timeout = %v, want %v", got, QuicNatTimeout)
	}
	if got := fallbackUnderlay.calls.Load(); got != 0 {
		t.Fatalf("fallback DialContext calls after SNI routing = %d, want 0", got)
	}
	if got := sniffedUnderlay.calls.Load(); got != 1 {
		t.Fatalf("sniffed DialContext calls after SNI routing = %d, want 1", got)
	}
	if got := sniffedConn.writeCalls.Load(); got != 2 {
		t.Fatalf("replayed packet writes = %d, want 2", got)
	}
	if addrs := sniffedConn.recordedWriteAddrs(); len(addrs) != 2 {
		t.Fatalf("WriteTo addrs after sniff = %v, want 2", addrs)
	} else {
		for i, addr := range addrs {
			if addr != fixture.expectedTarget {
				t.Fatalf("WriteTo[%d] = %q, want %q (must not send the packet IP)", i, addr, fixture.expectedTarget)
			}
		}
	}

	thirdDecision := ClassifyUdpFlow(src, dst, second)
	if err := cp.handlePkt(nil, second, src, dst, routingResult, thirdDecision, false); err != nil {
		t.Fatalf("handlePkt(third): %v", err)
	}
	if got := sniffedUnderlay.calls.Load(); got != 1 {
		t.Fatalf("sniffed DialContext calls after bound-flow reuse = %d, want 1", got)
	}
	if got := sniffedConn.writeCalls.Load(); got != 3 {
		t.Fatalf("packet writes after bound-flow reuse = %d, want 3", got)
	}
	if addrs := sniffedConn.recordedWriteAddrs(); len(addrs) != 3 {
		t.Fatalf("WriteTo addrs after reuse = %v, want 3", addrs)
	} else if addrs[2] != fixture.expectedTarget {
		t.Fatalf("WriteTo[2] = %q, want %q", addrs[2], fixture.expectedTarget)
	}
}

func TestHandlePkt_TransportShutdownKeepsSniffedDomain(t *testing.T) {
	rebuildAfterSniffedEndpointEviction(t, false, "transport")
}

func TestHandlePkt_TransportShutdownPinsResolveDNS(t *testing.T) {
	rebuildAfterSniffedEndpointEviction(t, true, "transport")
}

func TestHandlePkt_PoolResetKeepsSniffedDomain(t *testing.T) {
	rebuildAfterSniffedEndpointEviction(t, false, "reset")
}

func TestHandlePkt_PoolResetPinsResolveDNS(t *testing.T) {
	rebuildAfterSniffedEndpointEviction(t, true, "reset")
}

func rebuildAfterSniffedEndpointEviction(t *testing.T, withResolveDNS bool, evict string) {
	t.Helper()
	defer setupQuicInitialRegressionTestState(t)()
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	fixture := phase0QuicSniffingCorpusFixtures()[0]
	first, second := newSnifferNeedMorePayloads(t)
	fallbackConn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	fallbackDialer, _ := newCountingProxyEndpointDialer("hysteria2", "fallback.example:443", fallbackConn)
	conn1 := &udpReuseSimulationTransportConn{
		udpReuseSimulationConn: &udpReuseSimulationConn{
			reads:   make(chan scriptedPacketRead),
			closeCh: make(chan struct{}),
		},
		transportDone: make(chan struct{}),
	}
	conn2 := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	var factoryCalls atomic.Int32
	sniffedDialer, sniffedUnderlay := newFactoryProxyEndpointDialer("hysteria2", "sniffed.example:443", func() netproxy.Conn {
		if factoryCalls.Add(1) == 1 {
			return conn1
		}
		return conn2
	})
	wantTarget := fixture.expectedTarget
	var lookups atomic.Int32
	if withResolveDNS {
		sniffedDialer.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
		old := resolveIPViaDialer
		resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
			lookups.Add(1)
			return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, 0, nil
		}
		t.Cleanup(func() { resolveIPViaDialer = old })
		wantTarget = "203.0.113.9:443"
	}

	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(fallbackDialer))
	cp.outbounds = append(cp.outbounds, newTestFixedOutboundGroup(sniffedDialer))
	cp.routingMatcher = newQuicSniffingCorpusMatcher(t, fixture)

	src, dst, firstDecision := newQuicInitialRegressionFlow(t, first)
	primeQuicRegressionAnyfrom(src, dst)
	routingResult := &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}
	if err := cp.handlePkt(nil, first, src, dst, routingResult, firstDecision, false); err != nil {
		t.Fatalf("handlePkt(first): %v", err)
	}
	secondDecision := ClassifyUdpFlow(src, dst, second).EnsureSnifferSession()
	if err := cp.handlePkt(nil, second, src, dst, routingResult, secondDecision, false); err != nil {
		t.Fatalf("handlePkt(second): %v", err)
	}

	switch evict {
	case "transport":
		close(conn1.transportDone)
		waitForCloseSignal(t, conn1.closeCh, "transport lifecycle shutdown should retire the sniffed endpoint")
	case "reset":
		ResetGlobalUdpFlowState()
		waitForCloseSignal(t, conn1.closeCh, "fresh-datapath reset should close the sniffed endpoint")
		primeQuicRegressionAnyfrom(src, dst)
	default:
		t.Fatalf("unknown eviction mode %q", evict)
	}
	if _, ok := DefaultUdpEndpointPool.Get(firstDecision.SymmetricNatEndpointKey()); ok {
		t.Fatal("expected eviction to remove the sniffed endpoint")
	}

	shortHeader := []byte{0x41, 0x00, 0x01, 0x02, 0x03, 0x04}
	shortDecision := ClassifyUdpFlow(src, dst, shortHeader)
	if shortDecision.IsQuicInitial {
		t.Fatal("1-RTT short header must not be classified as QUIC Initial")
	}
	if err := cp.handlePkt(nil, shortHeader, src, dst, routingResult, shortDecision, false); err != nil {
		t.Fatalf("handlePkt(short): %v", err)
	}
	if got := sniffedUnderlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls after rebuild = %d, want 2", got)
	}
	addrs := conn2.recordedWriteAddrs()
	if len(addrs) != 1 || addrs[0] != wantTarget {
		t.Fatalf("WriteTo after rebuild = %v, want [%s] (must not fall back to packet IP)", addrs, wantTarget)
	}
	if withResolveDNS && lookups.Load() == 0 {
		t.Fatal("resolve_dns must be queried when rebuilding after endpoint eviction")
	}
}

func newQuicSniffingCorpusMatcher(t *testing.T, fixture quicSniffingCorpusFixture) *RoutingMatcher {
	t.Helper()
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		[]*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Full),
					Val: fixture.expectedDomain,
				}},
			}},
			Outbound: config_parser.Function{
				Name: "sniffed",
				Params: []*config_parser.Param{
					{Key: "mark", Val: "77"},
					{Val: "must"},
				},
			},
		}},
		map[string]uint8{
			"fallback": uint8(consts.OutboundUserDefinedMin),
			"sniffed":  uint8(fixture.expectedOutbound),
		},
		nil,
		config.FunctionOrString("fallback"),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace() error = %v", err)
	}
	return matcher
}

func phase0QuicActionForOutbound(outbound consts.OutboundIndex) phase0QuicAction {
	switch outbound {
	case consts.OutboundDirect:
		return phase0QuicActionDirect
	case consts.OutboundBlock:
		return phase0QuicActionBlock
	default:
		return phase0QuicActionProxy
	}
}
