package main

import (
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestNoResolveImportRoundTrip(t *testing.T) {
	atom := func(kind, value string, options ...string) MihomoExpr {
		return makeMihomoAtomExpression(kind, append([]string{value}, options...), "")
	}
	rule := MihomoRuleIRRule{Expr: MihomoExpr{Kind: MihomoExprAnd, Children: []MihomoExpr{
		{Kind: MihomoExprOr, Children: []MihomoExpr{atom("IP-CIDR", "203.0.113.0/24", "no-resolve"), atom("IP-CIDR", "198.51.100.0/24")}},
		atom("DOMAIN", "test.example"),
	}}, Action: MihomoAction{Target: "proxy"}}
	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{OutboundNameMap: map[string]string{"proxy": "proxy"}})
	if err != nil {
		t.Fatal(err)
	}
	text, _, err := renderMihomoLoweredRoutes(lowered)
	if err != nil {
		t.Fatal(err)
	}
	sections, err := config_parser.Parse("global {}\nrouting {\n" + text + "\nfallback: direct\n}")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	p, err := routing.NewNormalizedProgram(cfg.Routing.Rules, cfg.Routing.Fallback, &routing.AliasOptimizer{}, &routing.MergeAndSortRulesOptimizer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Ordered) != 1 || p.Ordered[0].Expr.Children[0].Op != "and" {
		t.Fatal("ordered expression lost")
	}
	e := p.Ordered[0].Expr.Children[0]
	if e.Children[0].Children[0].Atom.Name != "ip_no_resolve" {
		t.Fatal("no-resolve lost")
	}
}
func TestNoResolveRuleSetCallScope(t *testing.T) {
	rule := MihomoRuleIRRule{Expr: MihomoExpr{Kind: MihomoExprRuleSet, ProviderRef: &MihomoRuleSetRef{Provider: "mixed"}}, Action: MihomoAction{Target: "DIRECT", NoResolve: true}}
	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{ProviderNameMap: map[string]string{"mixed": "mixed"}, ProviderBehaviors: map[string]string{"mixed": "classical"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := routing.ExprFromFunction(lowered[0].Rule.AndFunctions[0])
	if err != nil {
		t.Fatal(err)
	}
	if e.Atom.Name != "ruleset_no_resolve" {
		t.Fatal("call-level option lost")
	}
}

func TestNoResolveSubRuleChildScope(t *testing.T) {
	child := mihomoCompilerRule(0, 2, "RULE-SET,mixed,DIRECT,no-resolve", "DIRECT", MihomoExpr{
		Kind: MihomoExprRuleSet, ProviderRef: &MihomoRuleSetRef{Provider: "mixed"},
	})
	child.Action.NoResolve = true
	ir, err := CompileMihomoSubRules(MihomoRuleIR{
		Rules:    []MihomoRuleIRRule{mihomoCompilerCall(0, 1, "SUB-RULE,(NETWORK,tcp),sub", "sub", mihomoCompilerAtom("NETWORK", "tcp"))},
		SubRules: []MihomoSubRuleIR{{Name: "sub", Rules: []MihomoRuleIRRule{child}}},
	}, MihomoSubRuleCompilerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lowered, err := LowerMihomoRule(ir.Rules[0], MihomoRuleLowererOptions{ProviderNameMap: map[string]string{"mixed": "mixed"}, ProviderBehaviors: map[string]string{"mixed": "classical"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := routing.ExprFromFunction(lowered[0].Rule.AndFunctions[0])
	if err != nil {
		t.Fatal(err)
	}
	if e.Op != "and" || e.Children[0].Atom.Name == "ruleset_no_resolve" || e.Children[1].Atom.Name != "ruleset_no_resolve" {
		t.Fatalf("child option scope lost: %#v", e)
	}
}

func TestNoResolveSubRuleGuardCallIdentity(t *testing.T) {
	guard := makeMihomoAtomExpression("IP-CIDR", []string{"203.0.113.0/24", "no-resolve"}, "")
	call := mihomoCompilerCall(0, 1, "", "sub", guard)
	ir, err := CompileMihomoSubRules(MihomoRuleIR{
		Rules: []MihomoRuleIRRule{call, call},
		SubRules: []MihomoSubRuleIR{{Name: "sub", Rules: []MihomoRuleIRRule{
			mihomoCompilerRule(0, 2, "", "DIRECT", mihomoCompilerAtom("DOMAIN", "one.example")),
			mihomoCompilerRule(1, 3, "", "DIRECT", mihomoCompilerAtom("MATCH", "")),
		}}},
	}, MihomoSubRuleCompilerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int
	for _, rule := range ir.Rules {
		lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{})
		if err != nil {
			t.Fatal(err)
		}
		e, err := routing.ExprFromFunction(lowered[0].Rule.AndFunctions[0])
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.Children[0].MemoID)
	}
	if len(ids) != 4 || ids[0] == 0 || ids[0] != ids[1] || ids[2] != ids[3] || ids[0] == ids[2] {
		t.Fatalf("SUB-RULE call identities lost: %v", ids)
	}
}
func TestNoResolveProviderEntriesPreserveOrder(t *testing.T) {
	p, err := ParseProvider([]byte("IP-CIDR,203.0.113.0/24,no-resolve\nDOMAIN,test.example\nIP-CIDR,198.51.100.0/24\n"), ProviderSpec{Format: "text", Behavior: "classical"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Ordered) != 3 || !hasMihomoNoResolve(p.Ordered[0]) || p.Ordered[1].Atom.Type != "DOMAIN" {
		t.Fatal("provider order/options lost")
	}
}

func TestNoResolveDATReference(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip.dat")
	if _, err := writeGeoIPDAT(path, "p", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}); err != nil {
		t.Fatal(err)
	}
	f, err := routing.EncodeOrderedExpr(&routing.OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: "ip_no_resolve", Params: []*config_parser.Param{{Key: "ext", Val: "ip.dat:p"}}}})
	if err != nil {
		t.Fatal(err)
	}
	rules := []*config_parser.RoutingRule{{AndFunctions: []*config_parser.Function{f}, Outbound: config_parser.Function{Name: "direct"}}}
	refs, err := generationDATReferences(rules)
	if err != nil || len(refs) != 1 {
		t.Fatalf("refs=%v err=%v", refs, err)
	}
	p, err := routing.NewNormalizedProgram(rules, config.FunctionOrString("direct"), &routing.AliasOptimizer{}, &routing.DatReaderOptimizer{Logger: logrus.New(), LocationFinder: assets.NewLocationFinder([]string{dir})})
	if err != nil {
		t.Fatal(err)
	}
	if p.Rules[0].AndFunctions[0].Name != "ip_no_resolve" || p.Rules[0].AndFunctions[0].Params[0].Key != "" {
		t.Fatal("DAT predicate not compiled")
	}
}
