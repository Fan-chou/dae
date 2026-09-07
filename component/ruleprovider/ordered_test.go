package ruleprovider

import (
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"testing"
)

func TestNoResolveProviderExpansion(t *testing.T) {
	ip, err := parseItem("IP-CIDR,203.0.113.0/24,no-resolve", "classical")
	if err != nil {
		t.Fatal(err)
	}
	if ip.Name != "ip_no_resolve" {
		t.Fatal("entry option discarded")
	}
	regular, _ := parseItem("IP-CIDR,198.51.100.0/24", "classical")
	rule := &config_parser.RoutingRule{AndFunctions: []*config_parser.Function{{Name: "ruleset_no_resolve", Params: []*config_parser.Param{{Val: "p"}}}}, Outbound: config_parser.Function{Name: "direct"}}
	out, err := ExpandRoutingRules([]*config_parser.RoutingRule{rule}, Registry{"p": {Functions: []*config_parser.Function{ip, regular}}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := routing.DecodeOrderedExpr(out[0].AndFunctions[0])
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	err = e.Walk(func(f *config_parser.Function) error {
		if f.Name != "ip_no_resolve" {
			t.Fatalf("scope lost: %s", f.Name)
		}
		n++
		return nil
	})
	if err != nil || n != 2 {
		t.Fatalf("expansion: n=%d err=%v", n, err)
	}
	if regular.Name != "dip" {
		t.Fatal("provider mutated")
	}
}
