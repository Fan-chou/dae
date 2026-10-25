/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func inboundTestBuilder(t testing.TB, routingBody string, groups []string) *RoutingMatcherBuilder {
	t.Helper()
	src := "global {\n}\n" +
		"inbound {\n" +
		"  s1 {\n    listen: '127.0.0.1:1080'\n  }\n" +
		"  s2 {\n    listen: '127.0.0.1:1081'\n  }\n" +
		"  s3 {\n    listen: '127.0.0.1:1082'\n  }\n" +
		"}\n" +
		"routing {\n" + routingBody + "\n}\n"
	sections, err := config_parser.Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	program, err := routing.NewNormalizedProgram(conf.Routing.Rules, conf.Routing.Fallback, &routing.AliasOptimizer{})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	names := map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"block":  uint8(consts.OutboundBlock),
	}
	next := uint8(consts.OutboundUserDefinedMin)
	for _, g := range groups {
		names[g] = next
		next++
	}
	builder, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), program, names, nil)
	if err != nil {
		t.Fatalf("builder: %v", err)
	}
	return builder
}

func inboundTestMatcher(t testing.TB, routingBody string, groups []string) *RoutingMatcher {
	t.Helper()
	matcher, err := inboundTestBuilder(t, routingBody, groups).BuildUserspace()
	if err != nil {
		t.Fatalf("userspace: %v", err)
	}
	return matcher
}

func inboundTestMatch(t testing.TB, m *RoutingMatcher, inbound uint32, domain string, dport uint16) consts.OutboundIndex {
	t.Helper()
	src := netip.MustParseAddr("192.0.2.10").As16()
	dst := netip.MustParseAddr("203.0.113.5").As16()
	var mac, pname [16]uint8
	out, _, _, err := m.MatchInbound(inbound, src, dst, 40000, dport, consts.IpVersion_4, consts.L4ProtoType_TCP, domain, pname, 0, mac)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var (
	inboundTestS1 = consts.InboundID("s1")
	inboundTestS2 = consts.InboundID("s2")
	inboundTestS3 = consts.InboundID("s3")
)

// inboundTestProxy is the first user-defined group handed to the test builder.
const inboundTestProxy = consts.OutboundUserDefinedMin

func TestInboundRouting_MatchesOnlyNamedInbound(t *testing.T) {
	m := inboundTestMatcher(t, "inbound(s1) -> proxy\nfallback: direct", []string{"proxy"})
	if got := inboundTestMatch(t, m, inboundTestS1, "", 80); got != inboundTestProxy {
		t.Fatalf("s1 -> %v, want proxy", got)
	}
	if got := inboundTestMatch(t, m, inboundTestS2, "", 80); got != consts.OutboundDirect {
		t.Fatalf("s2 -> %v, want direct", got)
	}
	if got := inboundTestMatch(t, m, 0, "", 80); got != consts.OutboundDirect {
		t.Fatalf("transparent -> %v, want direct", got)
	}
}

func TestInboundRouting_PlainMatchIsTransparent(t *testing.T) {
	m := inboundTestMatcher(t, "inbound(s1) -> proxy\nfallback: direct", []string{"proxy"})
	src := netip.MustParseAddr("192.0.2.10").As16()
	dst := netip.MustParseAddr("203.0.113.5").As16()
	var mac, pname [16]uint8
	out, _, _, err := m.Match(src, dst, 40000, 80, consts.IpVersion_4, consts.L4ProtoType_TCP, "", pname, 0, mac)
	if err != nil {
		t.Fatal(err)
	}
	if out != consts.OutboundDirect {
		t.Fatalf("Match() without an inbound hit inbound(s1): %v", out)
	}
}

func TestInboundRouting_Negation(t *testing.T) {
	m := inboundTestMatcher(t, "!inbound(s1) -> proxy\nfallback: direct", []string{"proxy"})
	if got := inboundTestMatch(t, m, inboundTestS1, "", 80); got != consts.OutboundDirect {
		t.Fatalf("s1 -> %v, want direct", got)
	}
	if got := inboundTestMatch(t, m, inboundTestS2, "", 80); got != inboundTestProxy {
		t.Fatalf("s2 -> %v, want proxy", got)
	}
	if got := inboundTestMatch(t, m, 0, "", 80); got != inboundTestProxy {
		t.Fatalf("transparent -> %v, want proxy", got)
	}
}

func TestInboundRouting_SeveralNamesAreOr(t *testing.T) {
	m := inboundTestMatcher(t, "inbound(s1, s2) -> proxy\nfallback: direct", []string{"proxy"})
	for name, id := range map[string]uint32{"s1": inboundTestS1, "s2": inboundTestS2} {
		if got := inboundTestMatch(t, m, id, "", 80); got != inboundTestProxy {
			t.Fatalf("%s -> %v, want proxy", name, got)
		}
	}
	if got := inboundTestMatch(t, m, inboundTestS3, "", 80); got != consts.OutboundDirect {
		t.Fatalf("s3 -> %v, want direct", got)
	}
}

func TestInboundRouting_SeparateRulesPickTheirOwnGroup(t *testing.T) {
	m := inboundTestMatcher(t, "inbound(s1) -> a\ninbound(s2) -> b\nfallback: direct", []string{"a", "b"})
	if got := inboundTestMatch(t, m, inboundTestS1, "", 80); got != inboundTestProxy {
		t.Fatalf("s1 -> %v, want a", got)
	}
	if got := inboundTestMatch(t, m, inboundTestS2, "", 80); got != inboundTestProxy+1 {
		t.Fatalf("s2 -> %v, want b", got)
	}
}

func TestInboundRouting_AndWithOtherPredicates(t *testing.T) {
	m := inboundTestMatcher(t, "inbound(s1) && dport(443) -> proxy\nfallback: direct", []string{"proxy"})
	if got := inboundTestMatch(t, m, inboundTestS1, "", 443); got != inboundTestProxy {
		t.Fatalf("s1:443 -> %v, want proxy", got)
	}
	if got := inboundTestMatch(t, m, inboundTestS1, "", 80); got != consts.OutboundDirect {
		t.Fatalf("s1:80 -> %v, want direct", got)
	}
	if got := inboundTestMatch(t, m, inboundTestS2, "", 443); got != consts.OutboundDirect {
		t.Fatalf("s2:443 -> %v, want direct", got)
	}
	if got := inboundTestMatch(t, m, 0, "", 443); got != consts.OutboundDirect {
		t.Fatalf("transparent:443 -> %v, want direct", got)
	}
}

func TestInboundRouting_AndWithDomain(t *testing.T) {
	m := inboundTestMatcher(t, "inbound(s1) && domain(suffix: example.com) -> proxy\nfallback: direct", []string{"proxy"})
	if got := inboundTestMatch(t, m, inboundTestS1, "www.example.com", 443); got != inboundTestProxy {
		t.Fatalf("s1 example.com -> %v, want proxy", got)
	}
	if got := inboundTestMatch(t, m, inboundTestS1, "other.org", 443); got != consts.OutboundDirect {
		t.Fatalf("s1 other.org -> %v, want direct", got)
	}
	if got := inboundTestMatch(t, m, 0, "www.example.com", 443); got != consts.OutboundDirect {
		t.Fatalf("transparent example.com -> %v, want direct", got)
	}
}

func TestInboundRouting_DeferringDestIPCarriesInbound(t *testing.T) {
	m := inboundTestMatcher(t, "inbound(s1) && domain(suffix: example.com) -> proxy\nfallback: direct", []string{"proxy"})
	src := netip.MustParseAddr("192.0.2.10").As16()
	dst := netip.MustParseAddr("198.18.0.1").As16()
	var mac, pname [16]uint8
	for _, tc := range []struct {
		inbound uint32
		want    consts.OutboundIndex
	}{
		{inboundTestS1, inboundTestProxy},
		{inboundTestS2, consts.OutboundDirect},
		{0, consts.OutboundDirect},
	} {
		out, _, _, needsIP, err := m.MatchDeferringDestIPInbound(tc.inbound, src, dst, 40000, 443, consts.IpVersion_4, consts.L4ProtoType_TCP, "www.example.com", pname, 0, mac)
		if err != nil {
			t.Fatal(err)
		}
		if needsIP || out != tc.want {
			t.Fatalf("inbound %d: got %v needsIP=%v, want %v", tc.inbound, out, needsIP, tc.want)
		}
	}
}

// The kernel only sees transparent traffic, so an inbound() match must reach it
// as a constant FALSE that keeps its negation and outbound.
func TestInboundRouting_KernelProjectionIsConstantFalse(t *testing.T) {
	b := inboundTestBuilder(t, "inbound(s1, s2) -> proxy\n!inbound(s3) && dport(443) -> proxy\nfallback: direct", []string{"proxy"})
	snapshot := b.KernspaceSnapshot()
	var userInbound int
	for _, r := range snapshot.rules {
		if consts.MatchType(r.Type) == consts.MatchType_Inbound {
			userInbound++
		}
	}
	if userInbound != 3 {
		t.Fatalf("compiled %d inbound matches, want 3", userInbound)
	}
	kern, err := rewriteKernRulesWithRingLpmIndex(snapshot.rules, 0, uint32(len(snapshot.simulatedLpmTries)))
	if err != nil {
		t.Fatal(err)
	}
	if len(kern) != len(snapshot.rules) {
		t.Fatalf("kernel rule count %d != %d", len(kern), len(snapshot.rules))
	}
	for i, r := range snapshot.rules {
		if consts.MatchType(r.Type) != consts.MatchType_Inbound {
			if kern[i] != r {
				t.Fatalf("rule %d changed by the kernel projection", i)
			}
			continue
		}
		k := kern[i]
		if k.Type != uint8(consts.MatchType_L4Proto) {
			t.Fatalf("rule %d kernel type = %d, want l4proto", i, k.Type)
		}
		if k.Value != ([16]byte{}) {
			t.Fatalf("rule %d kernel value = %v, want zero mask", i, k.Value)
		}
		if k.Not != r.Not || k.Outbound != r.Outbound || k.Mark != r.Mark || k.Must != r.Must {
			t.Fatalf("rule %d lost not/outbound/mark/must: %+v vs %+v", i, k, r)
		}
	}
	// The user-space copy keeps the real type.
	for _, r := range snapshot.rules {
		if consts.MatchType(r.Type) == consts.MatchType_L4Proto && r.Value[0] == 0 {
			t.Fatal("projection must not modify the source rules")
		}
	}
}
