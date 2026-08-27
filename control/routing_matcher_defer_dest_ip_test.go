/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func deferDestIP(t *testing.T, m *RoutingMatcher, domain string, l4 consts.L4ProtoType, dport uint16) (consts.OutboundIndex, bool) {
	t.Helper()
	src := netip.MustParseAddr("192.0.2.10").As16()
	dst := netip.MustParseAddr("198.18.0.1").As16()
	var mac [16]uint8
	var pname [16]uint8
	outbound, _, _, needsIP, err := m.MatchDeferringDestIP(
		src, dst, 40000, dport, consts.IpVersion_4, l4, domain, pname, 0, mac,
	)
	if err != nil {
		t.Fatal(err)
	}
	return outbound, needsIP
}

func TestMatchDeferringDestIP_DomainProxySkipsDestIP(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: ss2.us) -> proxy
ip(203.0.113.0/24) -> direct
fallback: direct
`, []string{"proxy"})
	outbound, needsIP := deferDestIP(t, m, "x.ss2.us", consts.L4ProtoType_TCP, 80)
	if needsIP {
		t.Fatal("domain -> proxy must not require dest IP")
	}
	if outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("outbound = %v, want proxy", outbound)
	}
}

func TestMatchDeferringDestIP_IpVersionNeedsDestIP(t *testing.T) {
	m := testFakeIPMatcher(t, `
ipversion(6) -> proxy
domain(suffix: ss2.us) -> proxy
fallback: direct
`, []string{"proxy"})
	_, needsIP := deferDestIP(t, m, "x.ss2.us", consts.L4ProtoType_TCP, 80)
	if !needsIP {
		t.Fatal("ipversion() must require dest IP, not FakeIP family")
	}
}

func TestMatchDeferringDestIP_IpRuleNeedsDestIP(t *testing.T) {
	m := testFakeIPMatcher(t, `
ip(203.0.113.0/24) -> proxy
fallback: direct
`, []string{"proxy"})
	_, needsIP := deferDestIP(t, m, "only-ip.example", consts.L4ProtoType_TCP, 443)
	if !needsIP {
		t.Fatal("ip() first-match must require dest IP")
	}
}

func TestMatchDeferringDestIP_DomainAndIPNeedsDestIP(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: example.com) && ip(203.0.113.0/24) -> proxy
fallback: direct
`, []string{"proxy"})
	_, needsIP := deferDestIP(t, m, "www.example.com", consts.L4ProtoType_TCP, 443)
	if !needsIP {
		t.Fatal("domain && ip must require dest IP")
	}
}

func TestMatchDeferringDestIP_DomainMissAndIPSkipsDestIP(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: example.com) && ip(203.0.113.0/24) -> proxy
fallback: proxy
`, []string{"proxy"})
	outbound, needsIP := deferDestIP(t, m, "x.ss2.us", consts.L4ProtoType_TCP, 443)
	if needsIP {
		t.Fatal("domain miss && ip() must not require dest IP")
	}
	if outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("outbound = %v, want fallback proxy", outbound)
	}
}

func TestMatchDeferringDestIP_IPAndDomainMissSkipsDestIP(t *testing.T) {
	m := testFakeIPMatcher(t, `
ip(203.0.113.0/24) && domain(suffix: example.com) -> proxy
fallback: proxy
`, []string{"proxy"})
	outbound, needsIP := deferDestIP(t, m, "x.ss2.us", consts.L4ProtoType_TCP, 443)
	if needsIP {
		t.Fatal("ip() && domain miss must not require dest IP")
	}
	if outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("outbound = %v, want fallback proxy", outbound)
	}
}

func TestMatchDeferringDestIP_IPThenDomainStillNeedsDestIP(t *testing.T) {
	m := testFakeIPMatcher(t, `
ip(203.0.113.0/24) -> direct
domain(suffix: ss2.us) -> proxy
fallback: direct
`, []string{"proxy"})
	_, needsIP := deferDestIP(t, m, "x.ss2.us", consts.L4ProtoType_TCP, 80)
	if !needsIP {
		t.Fatal("leading ip() first-match must require dest IP even if a later domain rule would hit")
	}
}

func TestMatchDeferringDestIP_UDP443BlockThenDomainProxy(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: openai.com) && l4proto(udp) && dport(443) -> block
domain(suffix: openai.com) -> AI
fallback: direct
`, []string{"AI"})
	tcpOut, tcpNeeds := deferDestIP(t, m, "api.openai.com", consts.L4ProtoType_TCP, 443)
	if tcpNeeds || tcpOut != consts.OutboundUserDefinedMin {
		t.Fatalf("tcp = (%v, needs=%v), want AI without dest IP", tcpOut, tcpNeeds)
	}
	udpOut, udpNeeds := deferDestIP(t, m, "api.openai.com", consts.L4ProtoType_UDP, 443)
	if udpNeeds || udpOut != consts.OutboundBlock {
		t.Fatalf("udp/443 = (%v, needs=%v), want block without dest IP", udpOut, udpNeeds)
	}
}
