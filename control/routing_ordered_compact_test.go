package control

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestNoResolveLargeAdjacentSets(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 1100; i++ {
		fmt.Fprintf(&body, "domain(full: host%d.example) -> A\n", i)
	}
	body.WriteString("ip_no_resolve(203.0.113.0/24) -> direct\nfallback: direct")
	m := testFakeIPMatcher(t, body.String(), []string{"A"})
	if len(m.compiledMatches) != 3 {
		t.Fatalf("adjacent domains not compacted: %d matches", len(m.compiledMatches))
	}
	for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
		facts, err := m.newFacts(netip.MustParseAddr("192.0.2.10").As16(), netip.MustParseAddr("28.0.0.1").As16(), 40000, 443, consts.IpVersion_4, proto, "host1099.example", [16]byte{}, 0, [16]byte{})
		if err != nil {
			t.Fatal(err)
		}
		out, _, _, _, err := m.matchOrderedFakeIP(facts, func() (netip.Addr, error) {
			t.Fatal("domain match unexpectedly resolved destination")
			return netip.Addr{}, nil
		})
		if err != nil || out != consts.OutboundUserDefinedMin {
			t.Fatalf("out=%d err=%v", out, err)
		}
	}
}

func TestNoResolveLargeProviderSet(t *testing.T) {
	e := &routing.OrderedExpr{Op: "or", MemoID: 17}
	for i := 0; i < 1100; i++ {
		e.Children = append(e.Children, &routing.OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: "ip_no_resolve", Params: []*config_parser.Param{{Val: fmt.Sprintf("10.%d.%d.1/32", i/256, i%256)}}}})
	}
	f, err := routing.EncodeOrderedExpr(e)
	if err != nil {
		t.Fatal(err)
	}
	body := f.String(false, true, false) + " -> A\nfallback: direct"
	m := testFakeIPMatcher(t, body, []string{"A"})
	if len(m.compiledMatches) != 2 || len(m.lpmMatcher) != 1 {
		t.Fatalf("provider fragmented: matches=%d sets=%d", len(m.compiledMatches), len(m.lpmMatcher))
	}
	// A known IP must still match the last entry of the combined LPM set.
	out, _, _, err := m.Match(netip.MustParseAddr("192.0.2.10").As16(), netip.MustParseAddr("10.4.75.1").As16(), 40000, 443, consts.IpVersion_4, consts.L4ProtoType_TCP, "", [16]byte{}, 0, [16]byte{})
	if err != nil || out != consts.OutboundUserDefinedMin {
		t.Fatalf("known IP out=%d err=%v", out, err)
	}
}

func TestNoResolveNativeProviderRepeatedPredicate(t *testing.T) {
	dir := t.TempDir()
	data := "IP-CIDR,203.0.113.0/24,no-resolve\nIP-CIDR,198.51.100.0/24\nIP-CIDR,203.0.113.0/24,no-resolve\n"
	if err := os.WriteFile(filepath.Join(dir, "rules.txt"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := ruleprovider.Load(context.Background(), []config.RuleProvider{{Name: "p", Type: "file", Path: "rules.txt", Behavior: "classical", Format: "text", MaxSize: 1024}}, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ruleprovider.ExpandRoutingRules([]*config_parser.RoutingRule{{AndFunctions: []*config_parser.Function{{Name: "ruleset", Params: []*config_parser.Param{{Val: "p"}}}}, Outbound: config_parser.Function{Name: "A"}}}, registry)
	if err != nil {
		t.Fatal(err)
	}
	body := rules[0].String(false, true, false) + "\nfallback: direct"
	for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
		out, calls := orderedTestRoute(t, body, "203.0.113.9", proto)
		if out != consts.OutboundUserDefinedMin || calls != 1 {
			t.Fatalf("later no-resolve lost: out=%d lookups=%d", out, calls)
		}
	}
}
