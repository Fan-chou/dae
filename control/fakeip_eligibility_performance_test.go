package control

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// Exercise the former evaluator against the same compiled rules, including
// mixed real addresses, missing facts and live group selection changes.
func TestFakeIPEligibilityOptimizedMatchesReference(t *testing.T) {
	policies := []string{
		`sip(match_mac: 192.168.124.129, match_mac: 192.168.124.220) -> direct
   domain(suffix: example.com) -> proxy
   fallback: direct`,
		`domain(suffix: example.com) && sip(match_mac: 192.168.124.129) && ip(203.0.113.0/24) -> proxy
   domain(suffix: example.com) && !ip(198.51.100.0/24) -> direct
   fallback: proxy`,
		`!domain(suffix: other.example) && !sip(192.168.124.0/24) -> proxy
   domain(suffix: example.com) && l4proto(udp) -> block
   domain(suffix: example.com) && ip_no_resolve(203.0.113.0/24) -> proxy
   fallback: direct`,
		`domain(suffix: example.com) && mac('aa:bb:cc:dd:ee:ff') -> proxy
   fallback: direct`,
	}
	for i, policy := range policies {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			m := testFakeIPMatcher(t, policy, []string{"proxy"})
			m.lookupMacAssoc = func([6]byte) []string { return []string{fakeIPAddrBin(netip.MustParseAddr("192.168.124.129"))} }
			for _, proxy := range []bool{true, false} {
				m.fakeIPLeafIsProxy = func(consts.OutboundIndex) bool { return proxy }
				for _, domain := range []string{"www.example.com", "other.example", "unmatched.test", ""} {
					for _, src := range []netip.Addr{{}, netip.MustParseAddr("192.168.124.220"), netip.MustParseAddr("10.0.0.8")} {
						for _, mac := range [][6]byte{{}, {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}} {
							for _, version := range []*consts.IpVersionType{nil, ipv4Ver()} {
								a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("198.51.100.1")
								for _, dests := range [][]netip.Addr{nil, {{}}, {a}, {b}, {a, b}, {b, a}, {a, {}, b}} {
									want := m.FakeIPEligibilityForReference(domain, version, src, mac, dests)
									got := m.FakeIPEligibilityFor(domain, version, src, mac, dests)
									if got != want {
										t.Fatalf("domain=%s src=%s mac=%x dests=%v proxy=%v got=%v want=%v", domain, src, mac, dests, proxy, got, want)
									}
								}
							}
						}
					}
				}
			}
		})
	}
}

func TestFakeIPEligibilitySkipsUnrelatedSourceRules(t *testing.T) {
	m := testFakeIPMatcher(t, `sip(match_mac: 192.168.124.129) -> direct
 domain(suffix: example.com) -> proxy
 fallback: direct`, []string{"proxy"})
	m.lookupMacAssoc = func([6]byte) []string { t.Fatal("source-only rule must not look up MAC associations"); return nil }
	got := m.FakeIPEligibilityFor("www.example.com", ipv4Ver(), netip.MustParseAddr("192.168.124.220"), [6]byte{1}, []netip.Addr{netip.MustParseAddr("203.0.113.1")})
	if got != FakeIPEligibilityProxy {
		t.Fatal(got)
	}
}

func TestFakeIPEligibilityReusesQueryFacts(t *testing.T) {
	m := testFakeIPMatcher(t, `domain(suffix: example.com) && sip(match_mac: 192.168.124.129) && ip(203.0.113.0/24) -> proxy
 fallback: direct`, []string{"proxy"})
	calls := 0
	m.lookupMacAssoc = func([6]byte) []string {
		calls++
		return []string{fakeIPAddrBin(netip.MustParseAddr("192.168.124.129"))}
	}
	dests := []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("203.0.113.1")}
	for i := 0; i < 2; i++ {
		got := m.FakeIPEligibilityFor("www.example.com", ipv4Ver(), netip.MustParseAddr("192.168.124.220"), [6]byte{1}, dests)
		if got != FakeIPEligibilityProxy || calls != i+1 {
			t.Fatalf("got=%v MAC lookups=%d", got, calls)
		}
	}
}

func TestFakeIPEligibilitySpecialActions(t *testing.T) {
	for _, action := range []consts.OutboundIndex{consts.OutboundMustRules, consts.OutboundDirect, consts.OutboundUserDefinedMin} {
		m := &RoutingMatcher{compiledMatches: []compiledRoutingMatch{{matchType: consts.MatchType_SourceIpSetMatchMac, outbound: consts.OutboundLogicalAnd}, {matchType: consts.MatchType_Fallback, outbound: action}}}
		got := m.FakeIPEligibilityFor("example.com", nil, netip.Addr{}, [6]byte{}, nil)
		want := m.FakeIPEligibilityForReference("example.com", nil, netip.Addr{}, [6]byte{}, nil)
		if got != want {
			t.Fatalf("action=%v got=%v want=%v", action, got, want)
		}
	}
}

func BenchmarkFakeIPEligibilityLANMultiA(b *testing.B) {
	var entries []string
	for i := 129; i <= 150; i++ {
		entries = append(entries, fmt.Sprintf("match_mac: '192.168.124.%d/32'", i))
	}
	for _, i := range []int{201, 202, 203, 205, 215, 216, 220, 221, 224} {
		entries = append(entries, fmt.Sprintf("match_mac: '192.168.124.%d/32'", i))
	}
	m := testFakeIPMatcher(b, "!sip("+strings.Join(entries, ",")+") -> direct\ndomain(suffix: codexradar.com) -> proxy\nfallback: direct", []string{"proxy"})
	src := netip.MustParseAddr("192.168.124.220")
	mac := [6]byte{1, 2, 3, 4, 5, 6}
	m.lookupMacAssoc = func([6]byte) []string { return []string{fakeIPAddrBin(src)} }
	dests := []netip.Addr{netip.MustParseAddr("104.26.15.186"), netip.MustParseAddr("172.67.70.76"), netip.MustParseAddr("104.26.14.186")}
	for _, optimized := range []bool{false, true} {
		b.Run(fmt.Sprintf("optimized=%v", optimized), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var got FakeIPEligibility
				if optimized {
					got = m.FakeIPEligibilityFor("codexradar.com", ipv4Ver(), src, mac, dests)
				} else {
					got = m.FakeIPEligibilityForReference("codexradar.com", ipv4Ver(), src, mac, dests)
				}
				if got != FakeIPEligibilityProxy {
					b.Fatal(got)
				}
			}
		})
	}
}
