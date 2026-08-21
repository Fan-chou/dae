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

func testFakeIPMatcher(t *testing.T, routingBody string, groups []string) *RoutingMatcher {
	t.Helper()
	src := "global {}\nrouting {\n" + routingBody + "\n}\n"
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
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("userspace: %v", err)
	}
	return matcher
}

func ipv4Ver() *consts.IpVersionType {
	v := consts.IpVersion_4
	return &v
}

func TestFakeIPEligibility_DomainAndIPCidrIsUnknown(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: example.com) && ip(203.0.113.0/24) -> AI
fallback: direct
`, []string{"AI"})
	if got := m.FakeIPEligibility("www.example.com", ipv4Ver()); got != FakeIPEligibilityUnknown {
		t.Fatalf("got %v, want UNKNOWN", got)
	}
}

func TestFakeIPEligibility_DomainAndUDPThenDomainIsProxy(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: openai.com) && l4proto(udp) && dport(443) -> block
domain(suffix: openai.com) -> AI
fallback: direct
`, []string{"AI"})
	if got := m.FakeIPEligibility("api.openai.com", ipv4Ver()); got != FakeIPEligibilityProxy {
		t.Fatalf("got %v, want PROXY (udp/dport are FALSE so the domain-only rule hits)", got)
	}
}

func TestFakeIPEligibility_DomainAndSipIsUnknown(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: openai.com) && sip(192.0.2.1) -> AI
domain(suffix: openai.com) -> direct
fallback: Apple_Proxy
`, []string{"AI", "Apple_Proxy"})
	if got := m.FakeIPEligibility("api.openai.com", ipv4Ver()); got != FakeIPEligibilityUnknown {
		t.Fatalf("got %v, want UNKNOWN (sip must not be skipped)", got)
	}
}

func TestFakeIPEligibility_DomainAndSipFromClientIsProxy(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: openai.com) && sip(192.0.2.1) -> AI
domain(suffix: openai.com) -> direct
fallback: Apple_Proxy
`, []string{"AI", "Apple_Proxy"})
	src := netip.MustParseAddr("192.0.2.1")
	if got := m.FakeIPEligibilityFor("api.openai.com", ipv4Ver(), src, [6]byte{}); got != FakeIPEligibilityProxy {
		t.Fatalf("got %v, want PROXY (DNS sip proves the rule)", got)
	}
	other := netip.MustParseAddr("192.0.2.8")
	if got := m.FakeIPEligibilityFor("api.openai.com", ipv4Ver(), other, [6]byte{}); got != FakeIPEligibilityDirect {
		t.Fatalf("got %v, want DIRECT (other sip misses, domain-only is direct)", got)
	}
}

func TestFakeIPEligibility_DomainAndMatchMacSipIsProxy(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: apple.com) && sip(match_mac: '192.168.124.202/32') -> Cherry_Apple
domain(suffix: apple.com) -> Apple_Apple
fallback: direct
`, []string{"Cherry_Apple", "Apple_Apple"})
	from202 := netip.MustParseAddr("192.168.124.202")
	if got := m.FakeIPEligibilityFor("init.itunes.apple.com", ipv4Ver(), from202, [6]byte{}); got != FakeIPEligibilityProxy {
		t.Fatalf("got %v, want PROXY (match_mac CIDR still matches DNS sip)", got)
	}
	from220 := netip.MustParseAddr("192.168.124.220")
	if got := m.FakeIPEligibilityFor("init.itunes.apple.com", ipv4Ver(), from220, [6]byte{}); got != FakeIPEligibilityProxy {
		t.Fatalf("got %v, want PROXY (miss 202, later domain-only Apple_Apple is still a node)", got)
	}
}

func TestFakeIPEligibility_GroupLeafDirectIsDirect(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: baidu.com) -> CN_CN
fallback: Apple_Proxy
`, []string{"CN_CN", "Apple_Proxy"})
	m.fakeIPLeafIsProxy = func(idx consts.OutboundIndex) bool {
		return idx != consts.OutboundUserDefinedMin
	}
	if got := m.FakeIPEligibility("www.baidu.com", ipv4Ver()); got != FakeIPEligibilityDirect {
		t.Fatalf("got %v, want DIRECT (CN_CN leaf is direct)", got)
	}
	if got := m.FakeIPEligibility("chatgpt.com", ipv4Ver()); got != FakeIPEligibilityProxy {
		t.Fatalf("got %v, want PROXY (fallback Apple_Proxy leaf is a node)", got)
	}
}

func TestFakeIPEligibility_MulticastPrefixThenDomainIsProxy(t *testing.T) {
	m := testFakeIPMatcher(t, `
dip(224.0.0.0/3) -> must_direct
domain(suffix: chatgpt.com) -> AI
fallback: Apple_Proxy
`, []string{"AI", "Apple_Proxy"})
	if got := m.FakeIPEligibility("chatgpt.com", ipv4Ver()); got != FakeIPEligibilityProxy {
		t.Fatalf("got %v, want PROXY (no-domain prefix must be skipped)", got)
	}
}

func TestFakeIPEligibility_FallbackProxyIsProxy(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: lan) -> direct
fallback: Apple_Proxy
`, []string{"Apple_Proxy"})
	if got := m.FakeIPEligibility("chatgpt.com", ipv4Ver()); got != FakeIPEligibilityProxy {
		t.Fatalf("got %v, want PROXY (non-direct fallback is a proxy group)", got)
	}
}

func TestFakeIPEligibility_FallbackDirectIsDirect(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: lan) -> direct
fallback: direct
`, nil)
	if got := m.FakeIPEligibility("chatgpt.com", ipv4Ver()); got != FakeIPEligibilityDirect {
		t.Fatalf("got %v, want DIRECT", got)
	}
}

func TestFakeIPEligibility_IpVersionPrefixDoesNotBlockDomain(t *testing.T) {
	m := testFakeIPMatcher(t, `
ipversion(6) -> direct
domain(suffix: chatgpt.com) -> AI
fallback: direct
`, []string{"AI"})
	if got := m.FakeIPEligibility("chatgpt.com", ipv4Ver()); got != FakeIPEligibilityProxy {
		t.Fatalf("got %v, want PROXY", got)
	}
}

func TestFakeIPEligibility_DomainToDirectIsDirect(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: example.com) -> direct
fallback: AI
`, []string{"AI"})
	if got := m.FakeIPEligibility("www.example.com", ipv4Ver()); got != FakeIPEligibilityDirect {
		t.Fatalf("got %v, want DIRECT", got)
	}
}

func TestFakeIPStoreAssignLookBackAndTombstone(t *testing.T) {
	dir := t.TempDir()
	store := NewFakeIPStore(dir, 2)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	v6 := netip.MustParsePrefix("fd00:daee::/112")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	a4, _, _, err := store.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	name, ok := store.LookBack(a4)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("lookback = %q %v", name, ok)
	}
	a4b, _, _, err := store.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if a4b != a4 {
		t.Fatal("same name must keep the same address")
	}

	if _, _, _, err := store.Assign("api.openai.com"); err != nil {
		t.Fatal(err)
	}
	c4, _, _, err := store.Assign("ios.chat.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	if c4 == a4 {
		t.Fatal("evicted address must not be reused")
	}
	if _, ok := store.LookBack(a4); !ok {
		t.Fatal("evicted ACTIVE must remain LookBack-able (retired reverse)")
	}

	store.RetireActive(netip.MustParsePrefix("198.19.0.0/16"), v6)
	if !store.Contains(a4) {
		t.Fatal("retired prefix must still trap")
	}
	name, ok = store.LookBack(a4)
	if !ok || name != "chatgpt.com." {
		t.Fatalf("retired lookback = %q %v", name, ok)
	}
}

func TestFakeIPStoreEvictsIdleNotPopular(t *testing.T) {
	dir := t.TempDir()
	store := NewFakeIPStore(dir, 2)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	v6 := netip.MustParsePrefix("fd00:daee::/112")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, _, err := store.Assign("chatgpt.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Assign("api.openai.com"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	for i, rec := range store.records {
		switch rec.qname {
		case "chatgpt.com.":
			store.records[i].updatedUnix = 2000
		case "api.openai.com.":
			store.records[i].updatedUnix = 1000
		}
	}
	store.mu.Unlock()
	if _, _, _, err := store.Assign("oneshot.cdn.example"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := store.Lookup("chatgpt.com"); !ok {
		t.Fatal("recently resolved chatgpt.com must stay ACTIVE")
	}
	if _, _, ok := store.Lookup("api.openai.com"); ok {
		t.Fatal("idle name should be evicted first")
	}
}

func TestFakeIPStoreReloadReusesSnapshot(t *testing.T) {
	dir := t.TempDir()
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	s1 := NewFakeIPStore(dir, 8)
	if err := s1.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	a4, _, _, err := s1.Assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := NewFakeIPStore(dir, 8)
	if err := s2.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, _, ok := s2.Lookup("chatgpt.com")
	if !ok || got != a4 {
		t.Fatalf("reload lookup = %v %v, want %v", got, ok, a4)
	}
}

func BenchmarkFakeIPStoreLookBack(b *testing.B) {
	dir := b.TempDir()
	store := NewFakeIPStore(dir, 1024)
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	if err := store.Open(v4, v6); err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	addr, _, _, err := store.Assign("chatgpt.com")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if name, ok := store.LookBack(addr); !ok || name == "" {
			b.Fatal("lookback miss")
		}
	}
}
