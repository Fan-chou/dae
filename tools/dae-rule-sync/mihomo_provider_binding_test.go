package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBindMihomoProviderDataPreservesLogicAndBindsDAT(t *testing.T) {
	providers := MihomoProviderNormalization{
		Providers: []ProviderSpec{
			{Name: "ads-safe", Behavior: "domain"},
			{Name: "mixed-safe", Behavior: "classical"},
		},
		NameMap:        map[string]string{"ads": "ads-safe", "mixed": "mixed-safe"},
		ReverseNameMap: map[string]string{"ads-safe": "ads", "mixed-safe": "mixed"},
	}
	original := MihomoRuleIR{Rules: []MihomoRuleIRRule{{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 4, SourceLine: 9, Raw: "AND"},
		Expr: MihomoExpr{Kind: MihomoExprAnd, Children: []MihomoExpr{
			{Kind: MihomoExprRuleSet, ProviderRef: &MihomoRuleSetRef{Provider: "ads"}},
			{Kind: MihomoExprNot, Children: []MihomoExpr{{Kind: MihomoExprRuleSet, ProviderRef: &MihomoRuleSetRef{Provider: "mixed"}}}},
		}},
		Action: MihomoAction{Target: "proxy", Options: []string{"keep"}, NoResolve: true},
	}}}
	sets := map[string]ParsedRuleSet{
		"ads-safe": {Domains: []DomainRule{{Kind: DomainSuffix, Value: "ads.example"}}},
		"mixed": {
			Domains:  []DomainRule{{Kind: DomainSuffix, Value: "one.example"}, {Kind: DomainFull, Value: "two.example"}},
			Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		},
	}

	got, err := BindMihomoProviderData(original, providers, sets, MihomoProviderBindingOptions{
		UseDAT:                     true,
		GenerationDATRuleThreshold: 1,
		MaxExpandedRules:           8,
	})
	if err != nil {
		t.Fatalf("BindMihomoProviderData() error = %v", err)
	}
	if got.IR.Rules[0].Action.Target != "proxy" || len(got.IR.Rules[0].Action.Options) != 1 || !got.IR.Rules[0].Action.NoResolve {
		t.Fatalf("action changed during binding: %#v", got.IR.Rules[0].Action)
	}
	bound := got.IR.Rules[0].Expr
	if bound.Kind != MihomoExprAnd || len(bound.Children) != 2 || bound.Children[0].Kind != MihomoExprProviderData {
		t.Fatalf("bound outer expression = %#v", bound)
	}
	if bound.Children[0].ProviderDataRef.ProviderCode != "ads-safe" || bound.Children[0].ProviderDataRef.Kind != MihomoProviderDataDomain {
		t.Fatalf("domain provider data = %#v", bound.Children[0].ProviderDataRef)
	}
	not := bound.Children[1]
	if not.Kind != MihomoExprNot || len(not.Children) != 1 || not.Children[0].Kind != MihomoExprOr || len(not.Children[0].Children) != 2 {
		t.Fatalf("classical replacement = %#v", not)
	}
	if not.Children[0].Children[0].ProviderDataRef.Kind != MihomoProviderDataDomain || !not.Children[0].Children[0].ProviderDataRef.UseDAT {
		t.Fatalf("classical domain leaf = %#v", not.Children[0].Children[0].ProviderDataRef)
	}
	ipLeaf := not.Children[0].Children[1].ProviderDataRef
	if ipLeaf.Kind != MihomoProviderDataIPCIDR || ipLeaf.UseDAT || len(ipLeaf.Prefixes) != 1 {
		t.Fatalf("classical ip leaf = %#v", ipLeaf)
	}
	if len(got.GenerationDATSpecs) != 1 || got.GenerationDATSpecs[0].Provider != "mixed-safe" || got.GenerationDATSpecs[0].Kind != "domain" || got.GenerationDATSpecs[0].RelativePath != "generated/geosite/mixed-safe.dat" {
		t.Fatalf("DAT specs = %#v", got.GenerationDATSpecs)
	}
	if len(got.GenerationDATSpecs[0].Domains) != 2 || len(got.UsedProviders) != 2 || got.UsedProviders[0] != "ads-safe" || got.UsedProviders[1] != "mixed-safe" {
		t.Fatalf("bound metadata = specs %#v, providers %#v", got.GenerationDATSpecs, got.UsedProviders)
	}
	if original.Rules[0].Expr.Children[1].Children[0].Kind != MihomoExprRuleSet {
		t.Fatal("binding mutated the input IR")
	}
}

func TestBindMihomoProviderDataRejectsIncompleteProviderData(t *testing.T) {
	providers := MihomoProviderNormalization{
		Providers: []ProviderSpec{{Name: "p", Behavior: "domain"}},
		NameMap:   map[string]string{"p": "p"},
	}
	base := MihomoRuleIR{Rules: []MihomoRuleIRRule{{Expr: MihomoExpr{Kind: MihomoExprRuleSet, ProviderRef: &MihomoRuleSetRef{Provider: "p"}}}}}
	for _, test := range []struct {
		name string
		sets map[string]ParsedRuleSet
		want string
	}{
		{name: "missing collection", sets: map[string]ParsedRuleSet{}, want: "missing rule-set data"},
		{name: "empty", sets: map[string]ParsedRuleSet{"p": {}}, want: "no domain rules"},
		{name: "unsupported", sets: map[string]ParsedRuleSet{"p": {Unsupported: []UnsupportedRule{{Raw: "x", Reason: "bad"}}}}, want: "unsupported rules"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := BindMihomoProviderData(base, providers, test.sets, MihomoProviderBindingOptions{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}
