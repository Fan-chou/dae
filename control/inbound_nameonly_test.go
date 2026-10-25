/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// These tests deliberately attach no FakeIP store and no DNS runtime: a
// name-only flow must not depend on either, and any lookup it attempts fails.

func nameOnlyTestParam(domain string, port uint16, network string) *proxyDialParam {
	return &proxyDialParam{
		Outbound: consts.OutboundControlPlaneRouting,
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     nameOnlyDest(port),
		Domain:   domain,
		Network:  network,
		NameOnly: true,
	}
}

func TestNameOnlyProxyDialsByNameWithoutLookup(t *testing.T) {
	for _, mode := range []consts.DialMode{consts.DialMode_Ip, consts.DialMode_Domain, consts.DialMode_DomainPlus} {
		cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
		cp.dialMode = mode
		cp.routingMatcher = testFakeIPMatcher(t, `
domain(suffix: ss2.us) -> proxy
ip(203.0.113.0/24) -> direct
fallback: direct
`, []string{"proxy"})

		res, err := cp.chooseProxyDialer(context.Background(), nameOnlyTestParam("x.ss2.us", 80, "tcp"))
		if err != nil {
			t.Fatalf("dial_mode %v: %v", mode, err)
		}
		if res.DialTarget != "x.ss2.us:80" || res.IsDialIp {
			t.Fatalf("dial_mode %v: DialTarget = (%q, %v), want a name dial", mode, res.DialTarget, res.IsDialIp)
		}
	}
}

func TestNameOnlyUDPProxyDialsByName(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.dialMode = consts.DialMode_Ip
	cp.routingMatcher = testFakeIPMatcher(t, "domain(suffix: ss2.us) -> proxy\nfallback: direct", []string{"proxy"})

	res, err := cp.chooseProxyDialer(context.Background(), nameOnlyTestParam("x.ss2.us", 53, "udp"))
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "x.ss2.us:53" {
		t.Fatalf("DialTarget = %q, want x.ss2.us:53", res.DialTarget)
	}
}

func TestNameOnlyBlockNeedsNoLookup(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	cp.outbounds[consts.OutboundBlock] = newTestFixedOutboundGroup(newTestEndpointDialer())
	cp.routingMatcher = testFakeIPMatcher(t, "domain(suffix: bad.example) -> block\nfallback: direct", []string{"proxy"})

	res, err := cp.chooseProxyDialer(context.Background(), nameOnlyTestParam("a.bad.example", 443, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if res.OutboundIndex != consts.OutboundBlock {
		t.Fatalf("outbound = %v, want block", res.OutboundIndex)
	}
}

func TestNameOnlyDirectPinsResolvedIP(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachTestDirectOutbound(cp)
	cp.routingMatcher = testFakeIPMatcher(t, "domain(suffix: cn.example) -> direct\nfallback: proxy", []string{"proxy"})
	real := netip.MustParseAddr("203.0.113.7")
	seedDnsCacheA(t, cp, "a.cn.example", real)

	res, err := cp.chooseProxyDialer(context.Background(), nameOnlyTestParam("a.cn.example", 80, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "203.0.113.7:80" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want the resolved address", res.DialTarget, res.IsDialIp)
	}
}

func TestNameOnlyDirectWithoutAnswerFailsInsteadOfDialingPlaceholder(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachTestDirectOutbound(cp)
	cp.routingMatcher = testFakeIPMatcher(t, "domain(suffix: cn.example) -> direct\nfallback: proxy", []string{"proxy"})

	res, err := cp.chooseProxyDialer(context.Background(), nameOnlyTestParam("a.cn.example", 80, "tcp"))
	if err == nil {
		t.Fatalf("expected a resolution error, got DialTarget %q", res.DialTarget)
	}
	if !strings.Contains(err.Error(), "resolve a.cn.example") {
		t.Fatalf("error %q does not name the failed lookup", err)
	}
}

func TestNameOnlyIPRuleResolvesBeforeDeciding(t *testing.T) {
	cp := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachTestDirectOutbound(cp)
	cp.routingMatcher = testFakeIPMatcher(t, "ip(203.0.113.0/24) -> proxy\nfallback: direct", []string{"proxy"})
	seedDnsCacheA(t, cp, "only-ip.example", netip.MustParseAddr("203.0.113.10"))

	res, err := cp.chooseProxyDialer(context.Background(), nameOnlyTestParam("only-ip.example", 443, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if res.OutboundIndex != consts.OutboundUserDefinedMin {
		t.Fatalf("outbound = %v, want the proxy group chosen by the resolved address", res.OutboundIndex)
	}

	// Without an answer the rule cannot be evaluated; the flow must fail, not
	// fall through to a verdict that ignored the address.
	cp2 := testDialControlPlane(newTestFixedOutboundGroup(newTestEndpointDialer()))
	attachTestDirectOutbound(cp2)
	cp2.routingMatcher = testFakeIPMatcher(t, "ip(203.0.113.0/24) -> proxy\nfallback: direct", []string{"proxy"})
	if _, err := cp2.chooseProxyDialer(context.Background(), nameOnlyTestParam("only-ip.example", 443, "tcp")); err == nil {
		t.Fatal("expected an error when the rule needs an address that cannot be resolved")
	}
}

// A group that looks like a proxy to the matcher may still select a direct
// dialer; the flow must then resolve and dial the real address.
func TestNameOnlyDirectLeafInsideProxyGroupResolves(t *testing.T) {
	build := func() *ControlPlane {
		// The group's selected member is the direct dialer.
		cp := testDialControlPlane(newTestFixedOutboundGroup(newNamedTestEndpointDialer(consts.OutboundDirect.String())))
		cp.routingMatcher = testFakeIPMatcher(t, "domain(suffix: leaf.example) -> proxy\nfallback: direct", []string{"proxy"})
		return cp
	}

	cp := build()
	seedDnsCacheA(t, cp, "a.leaf.example", netip.MustParseAddr("203.0.113.9"))
	res, err := cp.chooseProxyDialer(context.Background(), nameOnlyTestParam("a.leaf.example", 80, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget != "203.0.113.9:80" || !res.IsDialIp {
		t.Fatalf("DialTarget = (%q, %v), want the resolved address", res.DialTarget, res.IsDialIp)
	}

	if res, err := build().chooseProxyDialer(context.Background(), nameOnlyTestParam("a.leaf.example", 80, "tcp")); err == nil {
		t.Fatalf("expected an error, got DialTarget %q", res.DialTarget)
	}
}

func TestGuardNameOnlyDialTarget(t *testing.T) {
	named := &proxyDialParam{NameOnly: true, Domain: "x.example"}
	for _, target := range []string{"0.0.0.0:80", "[::]:80", "0.0.0.0"} {
		if err := guardNameOnlyDialTarget(named, &proxyDialResult{DialTarget: target}); err == nil {
			t.Errorf("%q must be refused", target)
		}
	}
	for _, target := range []string{"x.example:80", "203.0.113.1:80", "[2001:db8::1]:80"} {
		if err := guardNameOnlyDialTarget(named, &proxyDialResult{DialTarget: target}); err != nil {
			t.Errorf("%q must be allowed: %v", target, err)
		}
	}
	// Other flows are never touched.
	if err := guardNameOnlyDialTarget(&proxyDialParam{}, &proxyDialResult{DialTarget: "0.0.0.0:80"}); err != nil {
		t.Errorf("the guard must only apply to name-only flows: %v", err)
	}
}

func TestResolveInboundTargetDeferred(t *testing.T) {
	cp := &ControlPlane{}

	dst, domain, nameOnly, err := cp.resolveInboundTarget(context.Background(), InboundTarget{Domain: "Example.com.", Port: 443}, true)
	if err != nil || !nameOnly || domain != "Example.com" || dst != nameOnlyDest(443) {
		t.Fatalf("deferred domain = (%v, %q, %v, %v)", dst, domain, nameOnly, err)
	}

	// Literals never defer: there is nothing to resolve.
	ip := netip.MustParseAddr("203.0.113.5")
	dst, domain, nameOnly, err = cp.resolveInboundTarget(context.Background(), InboundTarget{IP: ip, Port: 80}, true)
	if err != nil || nameOnly || domain != "" || dst != netip.AddrPortFrom(ip, 80) {
		t.Fatalf("IP target = (%v, %q, %v, %v)", dst, domain, nameOnly, err)
	}
	dst, _, nameOnly, err = cp.resolveInboundTarget(context.Background(), InboundTarget{Domain: "203.0.113.5", Port: 80}, true)
	if err != nil || nameOnly || dst != netip.AddrPortFrom(ip, 80) {
		t.Fatalf("IP literal sent as a domain = (%v, %v, %v)", dst, nameOnly, err)
	}

	// Local mode resolves immediately and fails when it cannot.
	if _, _, _, err := cp.resolveInboundTarget(context.Background(), InboundTarget{Domain: "nx.example", Port: 80}, false); err == nil || !strings.HasPrefix(err.Error(), "resolve nx.example") {
		t.Fatalf("local resolution error = %v", err)
	}
}
