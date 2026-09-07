package control

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func orderedTestRoute(t *testing.T, body string, resolveIP string, network consts.L4ProtoType) (consts.OutboundIndex, int) {
	t.Helper()
	m := testFakeIPMatcher(t, body, []string{"A", "B", "C"})
	facts, err := m.newFacts(netip.MustParseAddr("192.0.2.10").As16(), netip.MustParseAddr("28.0.0.1").As16(), 40000, 443, consts.IpVersion_4, network, "test.example", [16]byte{}, 0, [16]byte{})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	out, _, _, _, err := m.matchOrderedFakeIP(facts, func() (netip.Addr, error) {
		calls++
		if resolveIP == "" {
			return netip.Addr{}, fmt.Errorf("DNS unavailable")
		}
		return netip.MustParseAddr(resolveIP), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, calls
}
func TestNoResolveOrderedRouting(t *testing.T) {
	tests := []struct {
		name, body, ip string
		out            consts.OutboundIndex
		calls          int
	}{
		{"domain without lookup", `ip_no_resolve(0.0.0.0/0) -> A
domain(suffix: example) -> C
fallback: direct`, "", consts.OutboundUserDefinedMin + 2, 0},
		{"no retroactive hit", `ip_no_resolve(203.0.113.0/24) -> A
ip(198.51.100.0/24) -> B
domain(suffix: example) -> C
fallback: direct`, "203.0.113.9", consts.OutboundUserDefinedMin + 2, 1},
		{"use earlier resolution", `ip(198.51.100.0/24) -> B
ip_no_resolve(203.0.113.0/24) -> A
fallback: direct`, "203.0.113.9", consts.OutboundUserDefinedMin, 1},
		{"not missing IP", `!ip_no_resolve(203.0.113.0/24) -> A
fallback: direct`, "", consts.OutboundUserDefinedMin, 0},
		{"failed resolution continues once", `ip(198.51.100.0/24) -> B
ip(203.0.113.0/24) -> B
ip_no_resolve(0.0.0.0/0) -> A
domain(suffix: example) -> C
fallback: direct`, "", consts.OutboundUserDefinedMin + 2, 1},
	}
	for _, tt := range tests {
		for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
			t.Run(fmt.Sprintf("%s/%d", tt.name, proto), func(t *testing.T) {
				out, n := orderedTestRoute(t, tt.body, tt.ip, proto)
				if out != tt.out || n != tt.calls {
					t.Fatalf("out=%d calls=%d, want %d/%d", out, n, tt.out, tt.calls)
				}
			})
		}
	}
}

func TestNoResolveSubRuleEntryDecision(t *testing.T) {
	atom := func(name, value string) *routing.OrderedExpr {
		return &routing.OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: name, Params: []*config_parser.Param{{Val: value}}}}
	}
	guard := &routing.OrderedExpr{MemoID: 1, Op: "not", Children: []*routing.OrderedExpr{atom("ip_no_resolve", "203.0.113.0/24")}}
	render := func(e *routing.OrderedExpr) string {
		f, err := routing.EncodeOrderedExpr(e)
		if err != nil {
			t.Fatal(err)
		}
		return f.String(false, true, false)
	}
	first := &routing.OrderedExpr{Op: "and", Children: []*routing.OrderedExpr{guard, atom("ip", "198.51.100.0/24")}}
	second := &routing.OrderedExpr{Op: "and", Children: []*routing.OrderedExpr{guard, atom("domain", "test.example")}}
	body := render(first) + " -> A\n" + render(second) + " -> B\nfallback: direct"
	for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
		out, calls := orderedTestRoute(t, body, "203.0.113.9", proto)
		if out != consts.OutboundUserDefinedMin+1 || calls != 1 {
			t.Fatalf("entry re-evaluated: out=%d calls=%d", out, calls)
		}
	}
}
func TestNoResolveNestedExpressionOrder(t *testing.T) {
	atom := func(name, value string) *routing.OrderedExpr {
		return &routing.OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: name, Params: []*config_parser.Param{{Val: value}}}}
	}

	// NOT A(no-resolve) is true before B resolves to A and misses. The OR
	// then hits a domain. DNF would repeat NOT A after resolution and fail.
	expr := &routing.OrderedExpr{Op: "and", Children: []*routing.OrderedExpr{
		{Op: "not", Children: []*routing.OrderedExpr{atom("ip_no_resolve", "203.0.113.0/24")}},
		{Op: "or", Children: []*routing.OrderedExpr{atom("ip", "198.51.100.0/24"), atom("domain", "example")}},
	}}

	f, err := routing.EncodeOrderedExpr(expr)
	if err != nil {
		t.Fatal(err)
	}
	body := f.String(false, true, false) + " -> A\ndomain(suffix: example) -> C\nfallback: direct"
	out, n := orderedTestRoute(t, body, "203.0.113.9", consts.L4ProtoType_TCP)
	if out != consts.OutboundUserDefinedMin || n != 1 {
		t.Fatalf("out=%d calls=%d", out, n)
	}
}

func TestNoResolveFakeIPRouteWithoutDNS(t *testing.T) {
	m := testFakeIPMatcher(t, `ip_no_resolve(0.0.0.0/0) -> direct
domain(suffix: example) -> A
fallback: direct`, []string{"A"})
	cp := &ControlPlane{}
	cp.routingMatcher = m
	for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
		out, _, _, real, err := cp.routeFakeIP(context.Background(), netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("28.0.0.1:443"), "test.example", proto, nil)
		if err != nil || real.IsValid() || out != consts.OutboundUserDefinedMin {
			t.Fatalf("out=%d real=%v err=%v", out, real, err)
		}
	}
	// The same rule still matches an actual IP in the ordinary kernel-equivalent matcher.
	out, _, _, err := m.Match(netip.MustParseAddr("192.0.2.10").As16(), netip.MustParseAddr("203.0.113.9").As16(), 40000, 443, consts.IpVersion_4, consts.L4ProtoType_TCP, "test.example", [16]byte{}, 0, [16]byte{})
	if err != nil || out != consts.OutboundDirect {
		t.Fatalf("known IP out=%d err=%v", out, err)
	}
}
