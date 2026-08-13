package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParseMihomoRuleIRPreservesOrderedRulesAndTypedExpressions(t *testing.T) {
	document := MihomoRoutingDocument{
		Rules: []MihomoRule{
			{Raw: "DOMAIN-SUFFIX,example.com,proxy,custom-option", SourceIndex: 4, SourceLine: 21},
			{Raw: "AND,((DOMAIN,api.example.com),(NETWORK,TCP)),DIRECT", SourceIndex: 5, SourceLine: 22},
			{Raw: `OR,((DOMAIN-REGEX,"^a,b$"),(UNKNOWN,value,with,commas)),REJECT,no-resolve,keep-me`, SourceIndex: 6, SourceLine: 23},
			{Raw: "RULE-SET,ads,block", SourceIndex: 7, SourceLine: 24},
			{Raw: "MATCH,proxy", SourceIndex: 8, SourceLine: 25},
		},
	}

	got, err := ParseMihomoRuleIR(document)
	if err != nil {
		t.Fatalf("ParseMihomoRuleIR() error = %v", err)
	}
	if len(got.Rules) != len(document.Rules) {
		t.Fatalf("len(Rules) = %d, want %d", len(got.Rules), len(document.Rules))
	}
	if got.Rules[0].SourceIndex != 4 || got.Rules[0].SourceLine != 21 || got.Rules[0].Raw != document.Rules[0].Raw {
		t.Fatalf("first source = %#v, want index/line/raw from input", got.Rules[0].MihomoRuleSource)
	}
	if got.Rules[0].Expr.Kind != MihomoExprAtom || got.Rules[0].Expr.Atom.Type != "DOMAIN-SUFFIX" {
		t.Fatalf("first expression = %#v", got.Rules[0].Expr)
	}
	if got.Rules[0].Action.Target != "proxy" || len(got.Rules[0].Action.Options) != 1 || got.Rules[0].Action.Options[0] != "custom-option" {
		t.Fatalf("first action = %#v", got.Rules[0].Action)
	}

	and := got.Rules[1].Expr
	if and.Kind != MihomoExprAnd || len(and.Children) != 2 || and.Children[0].Atom.Value != "api.example.com" || and.Children[1].Atom.Value != "TCP" {
		t.Fatalf("AND expression = %#v", and)
	}

	or := got.Rules[2].Expr
	if or.Kind != MihomoExprOr || len(or.Children) != 2 {
		t.Fatalf("OR expression = %#v", or)
	}
	if or.Children[0].Atom.Value != "^a,b$" || or.Children[1].Atom.Type != "UNKNOWN" || len(or.Children[1].Atom.Arguments) != 3 {
		t.Fatalf("quoted/unknown expression = %#v", or)
	}
	if !got.Rules[2].Action.NoResolve || len(got.Rules[2].Action.Options) != 2 || got.Rules[2].Action.Options[1] != "keep-me" {
		t.Fatalf("options/no-resolve = %#v", got.Rules[2].Action)
	}

	if got.Rules[3].Expr.Kind != MihomoExprRuleSet || got.Rules[3].Expr.ProviderRef.Provider != "ads" {
		t.Fatalf("RULE-SET expression = %#v", got.Rules[3].Expr)
	}
	if got.Rules[4].Expr.Kind != MihomoExprAtom || got.Rules[4].Expr.Atom.Type != "MATCH" || got.Rules[4].Action.Target != "proxy" {
		t.Fatalf("MATCH rule = %#v", got.Rules[4])
	}
}

func TestParseMihomoRuleIRPreservesSubRuleOrderAndReferences(t *testing.T) {
	document := MihomoRoutingDocument{
		Rules: []MihomoRule{{Raw: "SUB-RULE,(NETWORK,tcp),first", SourceIndex: 0, SourceLine: 3}},
		SubRuleValues: []MihomoSubRule{
			{Name: "first", SourceIndex: 0, SourceLine: 8, Rules: []MihomoRule{{Raw: "DOMAIN,one.example,DIRECT", SourceIndex: 0, SourceLine: 9}}},
			{Name: "second", SourceIndex: 1, SourceLine: 11, Rules: []MihomoRule{{Raw: "MATCH,REJECT", SourceIndex: 0, SourceLine: 12}}},
		},
	}

	got, err := ParseMihomoRuleIR(document)
	if err != nil {
		t.Fatalf("ParseMihomoRuleIR() error = %v", err)
	}
	if len(got.SubRules) != 2 || got.SubRules[0].Name != "first" || got.SubRules[1].Name != "second" {
		t.Fatalf("sub-rule order = %#v", got.SubRules)
	}
	ref := got.Rules[0].Expr
	if ref.Kind != MihomoExprSubRule || ref.SubRuleRef.Name != "first" || ref.SubRuleRef.Guard.Atom.Value != "tcp" {
		t.Fatalf("SUB-RULE reference = %#v", ref)
	}
	if got.SubRules[0].Rules[0].Action.Target != "DIRECT" || got.SubRules[1].Rules[0].Action.Target != "REJECT" {
		t.Fatalf("sub-rule actions = %#v", got.SubRules)
	}
}

func TestParseMihomoRuleIRRejectsMalformedRules(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "unclosed parentheses", raw: "AND,((DOMAIN,example.com),(NETWORK,tcp),proxy", want: "unclosed parentheses"},
		{name: "empty condition", raw: "DOMAIN,,proxy", want: "empty"},
		{name: "missing action", raw: "DOMAIN,example.com", want: "action"},
		{name: "missing sub-rule name", raw: "SUB-RULE,(DOMAIN,example.com),", want: "empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseMihomoRuleIR(MihomoRoutingDocument{Rules: []MihomoRule{{Raw: test.raw, SourceIndex: 2, SourceLine: 17}}})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseMihomoRuleIRRejectsActiveScript(t *testing.T) {
	_, err := ParseMihomoRuleIR(MihomoRoutingDocument{Rules: []MihomoRule{{Raw: "SCRIPT,shortcut,proxy", SourceIndex: 9, SourceLine: 31}}})
	if !errors.Is(err, ErrMihomoRuleScriptUnsupported) {
		t.Fatalf("error = %v, want ErrMihomoRuleScriptUnsupported", err)
	}
	if !strings.Contains(err.Error(), "line 31") || !strings.Contains(err.Error(), "shortcut") {
		t.Fatalf("error = %v, want source and shortcut", err)
	}
}
