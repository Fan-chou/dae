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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func seedDnsCacheA(t *testing.T, cp *ControlPlane, domain string, ip netip.Addr) {
	t.Helper()
	seedDnsCacheIP(t, cp, domain, ip)
}

func seedDnsCacheIP(t *testing.T, cp *ControlPlane, domain string, ip netip.Addr) {
	t.Helper()
	ctrl := newTestDnsController()
	if ip.Is6() && !ip.Is4In6() {
		rr := &dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(domain),
				Rrtype: dnsmessage.TypeAAAA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			AAAA: ip.AsSlice(),
		}
		ctrl.dnsCache.Store(ctrl.cacheKey(domain, dnsmessage.TypeAAAA), &DnsCache{Answer: []dnsmessage.RR{rr}})
	} else {
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
	}
	cp.controlPlaneDNSRuntime = controlPlaneDNSRuntime{dnsController: ctrl}
}

func attachTestDirectOutbound(cp *ControlPlane) {
	g := newTestFixedOutboundGroup(newTestEndpointDialer())
	g.Name = consts.OutboundDirect.String()
	cp.outbounds[consts.OutboundDirect] = g
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

func TestChooseProxyDialerFakeIPDirectPinsRealIP(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "cn.example")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	attachTestDirectOutbound(cp)
	cp.routingMatcher = testFakeIPMatcher(t, `
ip(203.0.113.0/24) -> direct
fallback: proxy
`, []string{"proxy"})
	real := netip.MustParseAddr("203.0.113.10")
	seedDnsCacheA(t, cp, "cn.example", real)

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.AddrPortFrom(fake, 443),
		Network:  "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OutboundIndex != consts.OutboundDirect {
		t.Fatalf("outbound = %v, want direct", res.OutboundIndex)
	}
	if res.DialTarget != "203.0.113.10:443" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want real IP dial", res.DialTarget, res.IsDialIp)
	}
}

func TestChooseProxyDialerFakeIPDirectUsesRealIPFamily(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "v6only.example")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	attachTestDirectOutbound(cp)
	cp.routingMatcher = testFakeIPMatcher(t, `
ipversion(4) -> proxy
fallback: direct
`, []string{"proxy"})
	real := netip.MustParseAddr("2001:db8::9")
	seedDnsCacheIP(t, cp, "v6only.example", real)

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.AddrPortFrom(fake, 443),
		Domain:   "v6only.example",
		Network:  "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OutboundIndex != consts.OutboundDirect {
		t.Fatalf("outbound = %v, want direct (real dest is v6)", res.OutboundIndex)
	}
	if res.DialTarget != "[2001:db8::9]:443" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want real AAAA", res.DialTarget, res.IsDialIp)
	}
	if res.SelectionNetworkTypeObj == nil || res.SelectionNetworkTypeObj.IpVersion != consts.IpVersionStr_6 {
		t.Fatalf("selection IP version = %v, want 6", res.SelectionNetworkTypeObj)
	}
}

func TestChooseProxyDialerFakeIPDirectUsesRealIPFamilyUDP(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "v6only.example")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	attachTestDirectOutbound(cp)
	cp.routingMatcher = testFakeIPMatcher(t, `
ipversion(4) -> proxy
fallback: direct
`, []string{"proxy"})
	real := netip.MustParseAddr("2001:db8::9")
	seedDnsCacheIP(t, cp, "v6only.example", real)

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.AddrPortFrom(fake, 443),
		Domain:   "v6only.example",
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OutboundIndex != consts.OutboundDirect {
		t.Fatalf("outbound = %v, want direct (real dest is v6)", res.OutboundIndex)
	}
	if res.DialTarget != "[2001:db8::9]:443" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want real AAAA", res.DialTarget, res.IsDialIp)
	}
	if res.SelectionNetworkTypeObj == nil || res.SelectionNetworkTypeObj.IpVersion != consts.IpVersionStr_6 {
		t.Fatalf("selection IP version = %v, want 6", res.SelectionNetworkTypeObj)
	}
}

func TestChooseProxyDialerUDPIPDialAlignsClientFamily(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("[2001:db8::80]:443"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "[2001:db8::80]:443" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want dest IP", res.DialTarget, res.IsDialIp)
	}
	if res.SelectionNetworkTypeObj == nil || res.SelectionNetworkTypeObj.IpVersion != consts.IpVersionStr_4 {
		t.Fatalf("selection IP version = %v, want 4 (client family)", res.SelectionNetworkTypeObj)
	}
}

func TestFakeIPDialSkipResolve(t *testing.T) {
	if !fakeIPDialSkipResolve(nil, consts.OutboundBlock) {
		t.Fatal("block skips resolve")
	}
	if fakeIPDialSkipResolve(nil, consts.OutboundDirect) {
		t.Fatal("builtin direct must resolve")
	}
	if !fakeIPDialSkipResolve(nil, consts.OutboundUserDefinedMin) {
		t.Fatal("nil matcher treats user groups as proxy")
	}
	directLeaf := &RoutingMatcher{fakeIPLeafIsProxy: func(consts.OutboundIndex) bool { return false }}
	if fakeIPDialSkipResolve(directLeaf, consts.OutboundUserDefinedMin) {
		t.Fatal("direct leaf must resolve")
	}
	proxyLeaf := &RoutingMatcher{fakeIPLeafIsProxy: func(consts.OutboundIndex) bool { return true }}
	if !fakeIPDialSkipResolve(proxyLeaf, consts.OutboundUserDefinedMin) {
		t.Fatal("proxy leaf may skip")
	}
}

func TestChooseProxyDialerFakeIPGroupLeafDirectNeedsRealIP(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "x.ss2.us")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	cp.dialMode = consts.DialMode_DomainPlus
	cp.routingMatcher = testFakeIPMatcher(t, `
domain(suffix: ss2.us) -> proxy
fallback: direct
`, []string{"proxy"})
	cp.routingMatcher.fakeIPLeafIsProxy = func(consts.OutboundIndex) bool { return false }

	_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.AddrPortFrom(fake, 80),
		Domain:   "x.ss2.us",
		Network:  "tcp",
	})
	if err == nil {
		t.Fatal("expected real-IP lookup when the matched group leaf is direct")
	}
}

func TestChooseProxyDialerFakeIPDomainProxySkipsDNS(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "x.ss2.us")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	cp.dialMode = consts.DialMode_DomainPlus
	cp.routingMatcher = testFakeIPMatcher(t, `
domain(suffix: ss2.us) -> proxy
ip(203.0.113.0/24) -> direct
fallback: direct
`, []string{"proxy"})

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.AddrPortFrom(fake, 80),
		Domain:   "x.ss2.us",
		Network:  "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "x.ss2.us:80" || res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want domain dial without DNS", res.DialTarget, res.IsDialIp)
	}
}

func TestChooseProxyDialerFakeIPIpRuleStillNeedsRealIP(t *testing.T) {
	store, fake := newTestFakeIPStore(t, "only-ip.example")
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachFakeIPStore(cp, store)
	cp.routingMatcher = testFakeIPMatcher(t, `
ip(203.0.113.0/24) -> proxy
fallback: direct
`, []string{"proxy"})

	_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.AddrPortFrom(fake, 443),
		Domain:   "only-ip.example",
		Network:  "tcp",
	})
	if err == nil {
		t.Fatal("expected real-IP lookup when the first hit needs dest ip()")
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
	if !errors.Is(err, ErrUnnamedFakeIP) {
		t.Fatalf("err = %v, want ErrUnnamedFakeIP", err)
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
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, 0, nil
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
	resolveIPViaDialer = func(ctx context.Context, dialer netproxy.Dialer, resolver netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, time.Duration, error) {
		gotDialer = dialer
		gotDNS = resolver
		gotHost = host
		gotType = typ
		gotNetwork = network
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, 0, nil
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
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		return nil, 0, fmt.Errorf("resolver down")
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
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		lookups.Add(1)
		return nil, 0, fmt.Errorf("resolver down")
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
	resolveIPViaDialer = func(ctx context.Context, dialer netproxy.Dialer, resolver netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, time.Duration, error) {
		types = append(types, typ)
		if typ == dnsmessage.TypeA {
			return nil, 0, nil
		}
		return []netip.Addr{netip.MustParseAddr("2001:db8::9")}, 0, nil
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
	resolveIPViaDialer = func(ctx context.Context, dialer netproxy.Dialer, resolver netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, time.Duration, error) {
		types = append(types, typ)
		gotNetwork = network
		if typ == dnsmessage.TypeAAAA {
			return nil, 0, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, 0, nil
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
	resolveIPViaDialer = func(ctx context.Context, dialer netproxy.Dialer, resolver netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, time.Duration, error) {
		gotNetwork = network
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, 0, nil
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
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, 0, nil
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

func TestProxyResolveDNSPinKeyLowercasesDomain(t *testing.T) {
	d := newTestEndpointDialer()
	dns := netip.MustParseAddrPort("8.8.8.8:53")
	a := proxyResolveDNSPinKey(d, dns, "ChatGPT.COM.", false)
	b := proxyResolveDNSPinKey(d, dns, "chatgpt.com", false)
	if a != b {
		t.Fatal("pin key must ignore case and trailing dot")
	}
}

func TestPrefetchProxyResolveDNSSkipsWithoutResolveDNSNode(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.routingMatcher = testFakeIPMatcher(t, `fallback: proxy`, []string{"proxy"})
	cp.prefetchProxyResolveDNS("chatgpt.com", false, netip.MustParseAddrPort("192.0.2.10:40000"), [6]uint8{}, 0, [16]uint8{})
	n := 0
	cp.resolveDNSPins.prefetch.Range(func(_, _ any) bool {
		n++
		return true
	})
	if n != 0 {
		t.Fatalf("scheduled %d prefetch(es), want 0 without resolve_dns", n)
	}
}

func TestClampResolveDNSPinTTL(t *testing.T) {
	if got := clampResolveDNSPinTTL(0); got != consts.ResolveDNSCacheTTLMin {
		t.Fatalf("zero = %v, want min", got)
	}
	if got := clampResolveDNSPinTTL(10 * time.Second); got != consts.ResolveDNSCacheTTLMin {
		t.Fatalf("below min = %v", got)
	}
	if got := clampResolveDNSPinTTL(2 * time.Minute); got != 2*time.Minute {
		t.Fatalf("mid = %v", got)
	}
	if got := clampResolveDNSPinTTL(time.Hour); got != consts.ResolveDNSCacheTTLMax {
		t.Fatalf("above max = %v", got)
	}
}

func TestApplyProxyResolveDNSStoresAnswerTTL(t *testing.T) {
	d := newTestEndpointDialer()
	dns := netip.MustParseAddrPort("8.8.8.8:53")
	d.SetResolveDNS(dns)
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	old := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, 2 * time.Minute, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	key := proxyResolveDNSPinKey(d, dns, "chatgpt.com", false)
	cp.resolveDNSPins.mu.Lock()
	ent := cp.resolveDNSPins.entries[key]
	cp.resolveDNSPins.mu.Unlock()
	remain := time.Until(ent.expires)
	if remain < time.Minute || remain > 2*time.Minute+time.Second {
		t.Fatalf("pin remain = %v, want ~2m", remain)
	}
	staleRemain := time.Until(ent.staleUntil)
	wantStale := remain + consts.ResolveDNSStaleTTL
	if staleRemain < wantStale-time.Second || staleRemain > wantStale+time.Second {
		t.Fatalf("stale remain = %v, want ~%v", staleRemain, wantStale)
	}
}

func TestApplyProxyResolveDNSSingleflight(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	old := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, 0, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	param := &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	}
	errCh := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := cp.chooseProxyDialer(context.Background(), param)
			errCh <- err
		}()
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("lookup did not start")
	}
	close(release)
	for range 8 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolve calls = %d, want 1", got)
	}
}

func TestApplyProxyResolveDNSPrefetchJoinsInFlight(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.routingMatcher = testFakeIPMatcher(t, `fallback: proxy`, []string{"proxy"})
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	old := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, 0, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	src := netip.MustParseAddrPort("192.0.2.10:40000")
	cp.prefetchProxyResolveDNS("ChatGPT.COM", false, src, [6]uint8{}, 0, [16]uint8{})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("prefetch did not start lookup")
	}
	done := make(chan error, 1)
	go func() {
		_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "chatgpt.com",
			Src:      src,
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		done <- err
	}()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolve calls = %d, want 1 (prefetch joined)", got)
	}
}

func TestChooseProxyDialerTCPPrefetchesUDPResolveDNS(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.routingMatcher = testFakeIPMatcher(t, `fallback: proxy`, []string{"proxy"})
	var calls atomic.Int32
	old := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, 0, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = old })

	_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, 2*time.Second, "tcp prefetch lookup", func() bool { return calls.Load() >= 1 })
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
		t.Fatalf("DialTarget = %q", res.DialTarget)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolve calls = %d, want 1 after TCP prefetch", got)
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

func TestResolveDNSPinLookupServesStale(t *testing.T) {
	var c proxyResolveDNSPinCache
	key := "k"
	now := time.Now()
	c.entries = map[string]proxyResolveDNSPin{
		key: {
			ip:         netip.MustParseAddr("1.1.1.1"),
			expires:    now.Add(-time.Second),
			staleUntil: now.Add(time.Minute),
		},
	}
	ip, stale, ok := c.lookupFreshOrStale(key, now)
	if !ok || !stale || ip.String() != "1.1.1.1" {
		t.Fatalf("got ip=%v stale=%v ok=%v", ip, stale, ok)
	}
}

func TestResolveDNSPinLookupDropsAfterStaleWindow(t *testing.T) {
	var c proxyResolveDNSPinCache
	key := "k"
	now := time.Now()
	c.entries = map[string]proxyResolveDNSPin{
		key: {
			ip:         netip.MustParseAddr("1.1.1.1"),
			expires:    now.Add(-time.Minute),
			staleUntil: now.Add(-time.Millisecond),
		},
	}
	if ip, stale, ok := c.lookupFreshOrStale(key, now); ok {
		t.Fatalf("got ip=%v stale=%v, want miss", ip, stale)
	}
	if _, ok := c.entries[key]; ok {
		t.Fatal("expired stale entry should be deleted")
	}
}

func TestApplyProxyResolveDNSServeStaleWhileRefresh(t *testing.T) {
	d := newTestEndpointDialer()
	dns := netip.MustParseAddrPort("8.8.8.8:53")
	d.SetResolveDNS(dns)
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	key := proxyResolveDNSPinKey(d, dns, "chatgpt.com", false)
	now := time.Now()
	old := netip.MustParseAddr("1.1.1.1")
	cp.resolveDNSPins.mu.Lock()
	cp.resolveDNSPins.entries = map[string]proxyResolveDNSPin{
		key: {
			ip:         old,
			expires:    now.Add(-time.Second),
			staleUntil: now.Add(time.Minute),
		},
	}
	cp.resolveDNSPins.mu.Unlock()

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	prev := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		return []netip.Addr{netip.MustParseAddr("104.18.32.1")}, time.Minute, nil
	}
	t.Cleanup(func() { resolveIPViaDialer = prev })

	done := make(chan struct{})
	var res *proxyDialResult
	var err error
	go func() {
		res, err = cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "chatgpt.com",
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("serve-stale blocked on refresh")
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "1.1.1.1:443" {
		t.Fatalf("DialTarget = %q, want stale 1.1.1.1:443", res.DialTarget)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("stale refresh did not start")
	}
	close(release)
	waitForCondition(t, 2*time.Second, "stale pin refresh", func() bool {
		cp.resolveDNSPins.mu.Lock()
		ent := cp.resolveDNSPins.entries[key]
		cp.resolveDNSPins.mu.Unlock()
		return ent.ip.String() == "104.18.32.1" && !time.Now().After(ent.expires)
	})
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolve calls = %d, want 1", got)
	}
}

func TestApplyProxyResolveDNSServeStaleRefreshFailureKeepsPin(t *testing.T) {
	d := newTestEndpointDialer()
	dns := netip.MustParseAddrPort("8.8.8.8:53")
	d.SetResolveDNS(dns)
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	key := proxyResolveDNSPinKey(d, dns, "chatgpt.com", false)
	now := time.Now()
	old := netip.MustParseAddr("1.1.1.1")
	staleUntil := now.Add(time.Minute)
	cp.resolveDNSPins.mu.Lock()
	cp.resolveDNSPins.entries = map[string]proxyResolveDNSPin{
		key: {
			ip:         old,
			expires:    now.Add(-time.Second),
			staleUntil: staleUntil,
		},
	}
	cp.resolveDNSPins.mu.Unlock()

	var calls atomic.Int32
	prev := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		calls.Add(1)
		return nil, 0, netutils.ErrResolveTimeout
	}
	t.Cleanup(func() { resolveIPViaDialer = prev })

	param := &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "chatgpt.com",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	}
	res, err := cp.chooseProxyDialer(context.Background(), param)
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "1.1.1.1:443" {
		t.Fatalf("DialTarget = %q, want stale 1.1.1.1:443", res.DialTarget)
	}

	waitForCondition(t, 2*time.Second, "failed refresh clears refreshing", func() bool {
		if calls.Load() < 1 {
			return false
		}
		cp.resolveDNSPins.mu.Lock()
		ent := cp.resolveDNSPins.entries[key]
		cp.resolveDNSPins.mu.Unlock()
		return ent.ip == old && !ent.refreshing && ent.staleUntil.Equal(staleUntil)
	})

	firstCalls := calls.Load()
	res, err = cp.chooseProxyDialer(context.Background(), param)
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "1.1.1.1:443" {
		t.Fatalf("after failed refresh DialTarget = %q", res.DialTarget)
	}
	waitForCondition(t, 2*time.Second, "stale hit retries refresh", func() bool {
		return calls.Load() > firstCalls
	})
}

func TestUdpEndpointCreateFailureTTL(t *testing.T) {
	if got := udpEndpointCreateFailureTTL(netutils.ErrResolveTimeout); got != consts.UdpEndpointFailureCacheTimeoutTTL {
		t.Fatalf("timeout sentinel = %v", got)
	}
	wrapped := fmt.Errorf("resolve chatgpt.com via 8.8.8.8:53: %w", netutils.ErrResolveTimeout)
	if got := udpEndpointCreateFailureTTL(wrapped); got != consts.UdpEndpointFailureCacheTimeoutTTL {
		t.Fatalf("wrapped timeout = %v", got)
	}
	if got := udpEndpointCreateFailureTTL(context.DeadlineExceeded); got != consts.UdpEndpointFailureCacheTTL {
		t.Fatalf("handshake deadline = %v, want 2s", got)
	}
	if got := udpEndpointCreateFailureTTL(fmt.Errorf("connection refused")); got != consts.UdpEndpointFailureCacheTTL {
		t.Fatalf("other failure = %v", got)
	}
}
