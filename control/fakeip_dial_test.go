/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func seedDnsCacheA(t *testing.T, cp *ControlPlane, domain string, ip netip.Addr) {
	t.Helper()
	ctrl := newTestDnsController()
	rr := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   dnsmessage.CanonicalName(domain),
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: ip.AsSlice(),
	}
	ctrl.dnsCache.Store(ctrl.cacheKey(domain, dnsmessage.TypeA), &DnsCache{Answer: []dnsmessage.RR{rr}})
	cp.controlPlaneDNSRuntime = controlPlaneDNSRuntime{dnsController: ctrl}
}

func TestRealIPForFakeIPRouteUsesCachedAnswer(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "codexradar.com")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	real := netip.MustParseAddr("104.26.14.186")
	seedDnsCacheA(t, cp, "codexradar.com", real)
	got, err := cp.realIPForFakeIPRoute(context.Background(), "codexradar.com", fake)
	if err != nil {
		t.Fatal(err)
	}
	if got != real {
		t.Fatalf("real IP = %v, want %v", got, real)
	}
}

func TestRealIPForFakeIPRouteSkipsPoolAddress(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "codexradar.com")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	seedDnsCacheA(t, cp, "codexradar.com", fake)
	_, err := cp.realIPForFakeIPRoute(context.Background(), "codexradar.com", fake)
	if err == nil {
		t.Fatal("expected error when cache only has FakeIP")
	}
}

func TestRealIPForFakeIPRouteMissingCacheFails(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "codexradar.com")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	_, err := cp.realIPForFakeIPRoute(context.Background(), "codexradar.com", fake)
	if err == nil {
		t.Fatal("expected error when DnsCache has no real IP")
	}
}

func TestChooseProxyDialerFakeIPRoutesOnRealIP(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "codexradar.com")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	cp.dialMode = consts.DialMode_DomainPlus
	cp.routingMatcher = testFakeIPMatcher(t, `
ip(0.0.0.0/8) -> direct
ip(203.0.113.0/24) -> proxy
fallback: direct
`, []string{"proxy"})
	real := netip.MustParseAddr("203.0.113.10")
	seedDnsCacheA(t, cp, "codexradar.com", real)

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.AddrPortFrom(fake, 443),
		Network:  "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "codexradar.com:443" || res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want domain dial", res.DialTarget, res.IsDialIp)
	}
}

func TestChooseProxyDialerFakeIPRefusesWhenRealIPIsDirect(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "cn.example")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	cp.routingMatcher = testFakeIPMatcher(t, `
ip(203.0.113.0/24) -> direct
fallback: proxy
`, []string{"proxy"})
	seedDnsCacheA(t, cp, "cn.example", netip.MustParseAddr("203.0.113.10"))

	_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.AddrPortFrom(fake, 443),
		Network:  "tcp",
	})
	if err == nil {
		t.Fatal("expected refuse FakeIP via direct")
	}
}

func TestRouteNilRoutingResultDoesNotPanic(t *testing.T) {
	cp := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			routingMatcher: testFakeIPMatcher(t, `fallback: direct`, nil),
		},
	}
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	outbound, _, _, err := cp.Route(src, dst, "dns.google", consts.L4ProtoType_UDP, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outbound != consts.OutboundDirect {
		t.Fatalf("outbound = %v, want direct", outbound)
	}
}

func newTestFakeIPStore(t *testing.T, names ...string) (*FakeIPStore, netip.Addr) {
	t.Helper()
	store := NewFakeIPStore(t.TempDir(), 8)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	v6 := netip.MustParsePrefix("fd00:daee::/112")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var first netip.Addr
	for _, name := range names {
		a4, _, _, err := store.Assign(name)
		if err != nil {
			t.Fatal(err)
		}
		if !first.IsValid() {
			first = a4
		}
	}
	return store, first
}

func attachFakeIPStore(cp *ControlPlane, store *FakeIPStore) {
	cp.fakeIPPolicy = NewFakeIPPolicy(config.FakeIP{Enable: true}, store, nil, nil, 1)
}

func testDialControlPlane(outbound *ob.DialerGroup) *ControlPlane {
	cp := newTestDialControlPlane(outbound)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	cp.log = logger
	return cp
}

func TestRewriteFakeIPDialTargetPassesDomain(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "chatgpt.com")
	cp := &ControlPlane{}
	attachFakeIPStore(cp, store)
	dst := netip.AddrPortFrom(fake, 443)
	got, dialIP, err := cp.rewriteFakeIPDialTarget("chatgpt.com", dst, dst.String(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "chatgpt.com:443" || dialIP {
		t.Fatalf("rewrite = (%q, %v), want (chatgpt.com:443, false)", got, dialIP)
	}
}

func TestRewriteFakeIPDialTargetUnnamedRejected(t *testing.T) {
	store, _ := newTestFakeIPStore(t)
	cp := &ControlPlane{}
	attachFakeIPStore(cp, store)
	hole := netip.MustParseAddr("198.18.0.1")
	if !store.Contains(hole) {
		t.Fatal("prefix trap must contain unassigned FakeIP")
	}
	_, _, err := cp.rewriteFakeIPDialTarget("", netip.AddrPortFrom(hole, 443), hole.String(), true)
	if err == nil {
		t.Fatal("expected unnamed FakeIP error")
	}
}

func TestUdpDialTargetPrefersSelected(t *testing.T) {
	if got := udpDialTarget("chatgpt.com:443", "198.51.100.10:443"); got != "chatgpt.com:443" {
		t.Fatalf("got %q", got)
	}
	if got := udpDialTarget("", "198.51.100.10:443"); got != "198.51.100.10:443" {
		t.Fatalf("got %q", got)
	}
}

func TestChooseProxyDialerUDPPinsDestIP(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.dialMode = consts.DialMode_DomainPlus
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      src,
		Dest:     dst,
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "chatgpt.com:443" || res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want domain:port", res.DialTarget, res.IsDialIp)
	}
	if res.SniffedDomain != "chatgpt.com" {
		t.Fatalf("SniffedDomain = %q, want chatgpt.com", res.SniffedDomain)
	}
}

func TestEnsureUdpDialTargetIPPassesDomainWithoutResolveDNS(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.dialMode = consts.DialMode_DomainPlus
	seedDnsCacheA(t, cp, "chatgpt.com", netip.MustParseAddr("1.1.1.1"))
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     dst,
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "chatgpt.com:443" || res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want domain not cache/packet IP", res.DialTarget, res.IsDialIp)
	}
}

func TestEnsureUdpDialTargetIPPassesDomainInIPMode(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.dialMode = consts.DialMode_Ip
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     dst,
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "chatgpt.com:443" || res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want domain:port", res.DialTarget, res.IsDialIp)
	}
}

func TestEnsureUdpDialTargetIPResolveDNSWinsOverDnsCache(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus
	seedDnsCacheA(t, cp, "chatgpt.com", netip.MustParseAddr("1.1.1.1"))
	old := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "104.18.32.1:443" {
		t.Fatalf("DialTarget = %q, want resolve_dns pin not cache 1.1.1.1", res.DialTarget)
	}
}

func TestEnsureUdpDialTargetIPLeavesTCPDomain(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.dialMode = consts.DialMode_DomainPlus
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "chatgpt.com:443" || res.IsDialIp {
		t.Fatalf("TCP DialTarget = (%q, %v), want domain", res.DialTarget, res.IsDialIp)
	}
}

func TestChooseProxyDialerUDPWithoutDomainPinsDest(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.dialMode = consts.DialMode_DomainPlus
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     dst,
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != dst.String() {
		t.Fatalf("DialTarget = %q, want %s", res.DialTarget, dst)
	}
	if !res.IsDialIp {
		t.Fatal("expected IP dial")
	}
}

func TestChooseProxyDialerFakeIPUDPPinsCachedRealIP(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "chatgpt.com")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	cp.routingMatcher = testFakeIPMatcher(t, `fallback: proxy`, []string{"proxy"})
	real := netip.MustParseAddr("203.0.113.20")
	seedDnsCacheA(t, cp, "chatgpt.com", real)
	dst := netip.AddrPortFrom(fake, 443)
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     dst,
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "chatgpt.com:443" || res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want domain:port not cached IP", res.DialTarget, res.IsDialIp)
	}
}

func TestApplyProxyResolveDNSPinsIPViaSelectedDialer(t *testing.T) {
	d := newTestEndpointDialer()
	dns := netip.MustParseAddrPort("8.8.8.8:53")
	d.SetResolveDNS(dns)
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	var gotDialer netproxy.Dialer
	var gotDNS netip.AddrPort
	var gotHost string
	var gotType uint16
	var gotNetwork string
	old := resolveIPViaDialer
	resolveIPViaDialer = func(ctx context.Context, dialer netproxy.Dialer, resolver netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, error) {
		gotDialer = dialer
		gotDNS = resolver
		gotHost = host
		gotType = typ
		gotNetwork = network
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotDialer != d || gotDNS != dns || gotHost != "chatgpt.com" || gotType != dnsmessage.TypeA {
		t.Fatalf("resolve args dialer=%v dns=%v host=%q type=%d", gotDialer == d, gotDNS, gotHost, gotType)
	}
	if res.DialTarget != "104.18.32.1:443" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want pinned 104.18.32.1:443", res.DialTarget, res.IsDialIp)
	}
	assertMagicIPVersion(t, gotNetwork, "")
	assertMagicIPVersion(t, res.Network, "4")
}

func TestApplyProxyResolveDNSFailureDoesNotFallBackToDomain(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("1.1.1.1:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus
	old := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, error) {
		return nil, fmt.Errorf("resolver down")
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err == nil {
		t.Fatal("expected resolve failure")
	}
}

func TestChooseProxyDialerRejectsIdentifiedQuicBeforeResolveDNS(t *testing.T) {
	conn := &udpReuseSimulationConn{closeCh: make(chan struct{})}
	d, _ := newCountingProxyEndpointDialer("anytls", "anytls.example:443", conn)
	d.SetResolveDNS(netip.MustParseAddrPort("1.1.1.1:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.blockQuic = true
	cp.dialMode = consts.DialMode_DomainPlus
	var lookups atomic.Int32
	old := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, fmt.Errorf("resolver down")
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound:       consts.OutboundUserDefinedMin,
		Domain:         "chatgpt.com",
		Src:            netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:           netip.MustParseAddrPort("198.51.100.20:443"),
		Network:        "udp",
		IdentifiedQuic: true,
	})
	if !errors.Is(err, ErrQuicAdministrativelyProhibited) {
		t.Fatalf("err = %v, want ErrQuicAdministrativelyProhibited", err)
	}
	if got := lookups.Load(); got != 0 {
		t.Fatalf("resolve_dns lookups = %d, want 0 before QUIC reject", got)
	}
}

func TestPickResolvedDialIPSkipsFakeIPPool(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "chatgpt.com")
	_, err := pickResolvedDialIP([]netip.Addr{fake}, false, store)
	if err == nil {
		t.Fatal("expected skip of FakeIP pool address")
	}
	got, err := pickResolvedDialIP([]netip.Addr{fake, netip.MustParseAddr("203.0.113.9")}, false, store)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "203.0.113.9" {
		t.Fatalf("got %v", got)
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	got, err = pickResolvedDialIP([]netip.Addr{fake, v6}, false, store)
	if err != nil {
		t.Fatal(err)
	}
	if got != v6 {
		t.Fatalf("prefer v4 with only AAAA = %v, want %v", got, v6)
	}
	got, err = pickResolvedDialIP([]netip.Addr{v6, netip.MustParseAddr("203.0.113.9")}, false, store)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "203.0.113.9" {
		t.Fatalf("prefer v4 = %v, want 203.0.113.9", got)
	}
}

func TestApplyProxyResolveDNSFallsBackToOtherFamily(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	var types []uint16
	old := resolveIPViaDialer
	resolveIPViaDialer = func(ctx context.Context, dialer netproxy.Dialer, resolver netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, error) {
		types = append(types, typ)
		if typ == dnsmessage.TypeA {
			return nil, nil
		}
		return []netip.Addr{netip.MustParseAddr("2001:db8::9")}, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "ipv6only.example",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 2 || types[0] != dnsmessage.TypeA || types[1] != dnsmessage.TypeAAAA {
		t.Fatalf("qtypes = %v, want A then AAAA", types)
	}
	if res.DialTarget != "[2001:db8::9]:443" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want pinned AAAA", res.DialTarget, res.IsDialIp)
	}
	assertMagicIPVersion(t, res.Network, "4")
	if res.SelectionNetworkTypeObj == nil || res.SelectionNetworkTypeObj.IpVersion != consts.IpVersionStr_4 {
		t.Fatalf("selection IP version = %v, want 4", res.SelectionNetworkTypeObj)
	}
}

func TestApplyProxyResolveDNSIPv6DestFallsBackToA(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	var types []uint16
	var gotNetwork string
	old := resolveIPViaDialer
	resolveIPViaDialer = func(ctx context.Context, dialer netproxy.Dialer, resolver netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, error) {
		types = append(types, typ)
		gotNetwork = network
		if typ == dnsmessage.TypeAAAA {
			return nil, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "v4only.example",
		Src:      netip.MustParseAddrPort("[2001:db8::2]:40000"),
		Dest:     netip.MustParseAddrPort("[2001:db8::1]:443"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 2 || types[0] != dnsmessage.TypeAAAA || types[1] != dnsmessage.TypeA {
		t.Fatalf("qtypes = %v, want AAAA then A", types)
	}
	if res.DialTarget != "203.0.113.9:443" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want pinned A", res.DialTarget, res.IsDialIp)
	}
	assertMagicIPVersion(t, gotNetwork, "")
	assertMagicIPVersion(t, res.Network, "6")
	if res.SelectionNetworkTypeObj == nil || res.SelectionNetworkTypeObj.IpVersion != consts.IpVersionStr_6 {
		t.Fatalf("selection IP version = %v, want 6", res.SelectionNetworkTypeObj)
	}
}

func TestApplyProxyResolveDNSLookupOmitsIPVersion(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("[2001:db8::53]:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	var gotNetwork string
	old := resolveIPViaDialer
	resolveIPViaDialer = func(ctx context.Context, dialer netproxy.Dialer, resolver netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, error) {
		gotNetwork = network
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMagicIPVersion(t, gotNetwork, "")
	assertMagicIPVersion(t, res.Network, "4")
	if res.DialTarget != "104.18.32.1:443" {
		t.Fatalf("DialTarget = %q", res.DialTarget)
	}
}

func TestApplyProxyResolveDNSCacheHit(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	var calls int
	old := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	param := &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	}
	first, err := cp.chooseProxyDialer(context.Background(), param)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cp.chooseProxyDialer(context.Background(), param)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("resolve calls = %d, want 1", calls)
	}
	if first.DialTarget != second.DialTarget || second.DialTarget != "104.18.32.1:443" {
		t.Fatalf("cached target = %q / %q", first.DialTarget, second.DialTarget)
	}
}

func assertMagicIPVersion(t *testing.T, network, want string) {
	t.Helper()
	magic, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		t.Fatalf("ParseMagicNetwork(%q) error = %v", network, err)
	}
	if magic.IPVersion != want {
		t.Fatalf("network %q IP version = %q, want %q", network, magic.IPVersion, want)
	}
}
