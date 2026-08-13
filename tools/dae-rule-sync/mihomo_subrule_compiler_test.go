package main

import (
	"errors"
	"strings"
	"testing"
)

func TestCompileMihomoSubRulesExpandsReachableCallsInPlace(t *testing.T) {
	ir := MihomoRuleIR{
		Rules: []MihomoRuleIRRule{
			mihomoCompilerRule(0, 10, "DOMAIN,before.example,DIRECT", "before", mihomoCompilerAtom("DOMAIN", "before.example")),
			mihomoCompilerCall(1, 11, "SUB-RULE,(NETWORK,tcp),outer", "outer", mihomoCompilerAtom("NETWORK", "tcp")),
			mihomoCompilerRule(2, 12, "MATCH,after.example,DIRECT", "after", mihomoCompilerAtom("MATCH", "")),
		},
		SubRules: []MihomoSubRuleIR{
			{
				Name: "outer", SourceIndex: 4, SourceLine: 20,
				Rules: []MihomoRuleIRRule{
					mihomoCompilerRule(7, 21, "DOMAIN,child.example,child-proxy", "child-proxy", mihomoCompilerAtom("DOMAIN", "child.example")),
				},
			},
			// An unreachable cycle is intentionally malformed but must not block.
			{Name: "unused-a", Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 30, "SUB-RULE,(MATCH),unused-b", "unused-b", mihomoCompilerAtom("MATCH", ""))}},
			{Name: "unused-b", Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 31, "SUB-RULE,(MATCH),unused-a", "unused-a", mihomoCompilerAtom("MATCH", ""))}},
		},
	}

	got, err := CompileMihomoSubRules(ir, MihomoSubRuleCompilerOptions{})
	if err != nil {
		t.Fatalf("CompileMihomoSubRules() error = %v", err)
	}
	if len(got.Rules) != 3 || len(got.SubRules) != 0 {
		t.Fatalf("compiled shape = %#v, want three top-level rules and no definitions", got)
	}
	if got.Rules[0].SourceIndex != 0 || got.Rules[1].SourceIndex != 7 || got.Rules[2].SourceIndex != 2 {
		t.Fatalf("source order/metadata = %#v", got.Rules)
	}
	if got.Rules[1].Action.Target != "child-proxy" || got.Rules[1].Raw != "DOMAIN,child.example,child-proxy" {
		t.Fatalf("child source/action = %#v", got.Rules[1])
	}
	if got.Rules[1].Expr.Kind != MihomoExprAnd || len(got.Rules[1].Expr.Children) != 2 {
		t.Fatalf("merged guard expression = %#v", got.Rules[1].Expr)
	}
	if got.Rules[1].CallTrace == nil || len(got.Rules[1].CallTrace) != 1 || got.Rules[1].CallTrace[0].Name != "outer" {
		t.Fatalf("call trace = %#v", got.Rules[1].CallTrace)
	}
}

func TestCompileMihomoSubRulesRecursivelyInheritsGuards(t *testing.T) {
	ir := MihomoRuleIR{
		Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 1, "SUB-RULE,(NETWORK,tcp),outer", "outer", mihomoCompilerAtom("NETWORK", "tcp"))},
		SubRules: []MihomoSubRuleIR{
			{Name: "outer", Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 2, "SUB-RULE,(DOMAIN,outer.example),inner", "inner", mihomoCompilerAtom("DOMAIN", "outer.example"))}},
			{Name: "inner", Rules: []MihomoRuleIRRule{mihomoCompilerRule(0, 3, "PROCESS-NAME,app,proxy", "proxy", mihomoCompilerAtom("PROCESS-NAME", "app"))}},
		},
	}

	got, err := CompileMihomoSubRules(ir, MihomoSubRuleCompilerOptions{})
	if err != nil {
		t.Fatalf("CompileMihomoSubRules() error = %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Expr.Kind != MihomoExprAnd || len(got.Rules[0].Expr.Children) != 2 {
		t.Fatalf("inherited guard = %#v", got.Rules)
	}
	outerGuard := got.Rules[0].Expr.Children[0]
	if outerGuard.Kind != MihomoExprAnd || len(outerGuard.Children) != 2 {
		t.Fatalf("nested inherited guard = %#v", outerGuard)
	}
	if len(got.Rules[0].CallTrace) != 2 || got.Rules[0].CallTrace[0].Name != "outer" || got.Rules[0].CallTrace[1].Name != "inner" {
		t.Fatalf("nested call trace = %#v", got.Rules[0].CallTrace)
	}
}

func TestCompileMihomoSubRulesRejectsReachableGraphFailures(t *testing.T) {
	tests := []struct {
		name    string
		ir      MihomoRuleIR
		options MihomoSubRuleCompilerOptions
		wantErr error
		wantMsg string
	}{
		{
			name:    "undefined",
			ir:      MihomoRuleIR{Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 1, "SUB-RULE,(MATCH),missing", "missing", mihomoCompilerAtom("MATCH", ""))}},
			wantErr: ErrMihomoSubRuleUndefined,
			wantMsg: "missing",
		},
		{
			name: "duplicate",
			ir: MihomoRuleIR{
				Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 1, "SUB-RULE,(MATCH),same", "same", mihomoCompilerAtom("MATCH", ""))},
				SubRules: []MihomoSubRuleIR{
					{Name: "same", Rules: []MihomoRuleIRRule{mihomoCompilerRule(0, 2, "MATCH,a", "a", mihomoCompilerAtom("MATCH", ""))}},
					{Name: "same", Rules: []MihomoRuleIRRule{mihomoCompilerRule(0, 3, "MATCH,b", "b", mihomoCompilerAtom("MATCH", ""))}},
				},
			},
			wantErr: ErrMihomoSubRuleDuplicate,
			wantMsg: "same",
		},
		{
			name: "cycle",
			ir: MihomoRuleIR{
				Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 1, "SUB-RULE,(MATCH),a", "a", mihomoCompilerAtom("MATCH", ""))},
				SubRules: []MihomoSubRuleIR{
					{Name: "a", Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 2, "SUB-RULE,(MATCH),b", "b", mihomoCompilerAtom("MATCH", ""))}},
					{Name: "b", Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 3, "SUB-RULE,(MATCH),a", "a", mihomoCompilerAtom("MATCH", ""))}},
				},
			},
			wantErr: ErrMihomoSubRuleCycle,
			wantMsg: "a -> b -> a",
		},
		{
			name: "empty",
			ir: MihomoRuleIR{
				Rules:    []MihomoRuleIRRule{mihomoCompilerCall(0, 1, "SUB-RULE,(MATCH),empty", "empty", mihomoCompilerAtom("MATCH", ""))},
				SubRules: []MihomoSubRuleIR{{Name: "empty"}},
			},
			wantErr: ErrMihomoSubRuleEmpty,
			wantMsg: "empty",
		},
		{
			name: "depth",
			ir: MihomoRuleIR{
				Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 1, "SUB-RULE,(MATCH),a", "a", mihomoCompilerAtom("MATCH", ""))},
				SubRules: []MihomoSubRuleIR{
					{Name: "a", Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 2, "SUB-RULE,(MATCH),b", "b", mihomoCompilerAtom("MATCH", ""))}},
					{Name: "b", Rules: []MihomoRuleIRRule{mihomoCompilerRule(0, 3, "MATCH,proxy", "proxy", mihomoCompilerAtom("MATCH", ""))}},
				},
			},
			options: MihomoSubRuleCompilerOptions{MaxDepth: 1},
			wantErr: ErrMihomoSubRuleDepth,
			wantMsg: "maximum depth 1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileMihomoSubRules(test.ir, test.options)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) || !strings.Contains(err.Error(), test.wantMsg) {
				t.Fatalf("error = %v, want %v containing %q", err, test.wantErr, test.wantMsg)
			}
		})
	}
}

func TestCompileMihomoSubRulesRejectsEmbeddedCallsAndExpansionLimit(t *testing.T) {
	embedded := MihomoRuleIR{
		Rules: []MihomoRuleIRRule{{
			MihomoRuleSource: MihomoRuleSource{SourceIndex: 4, SourceLine: 9, Raw: "AND,((SUB-RULE,(MATCH),child),(DOMAIN,example)),proxy"},
			Expr: MihomoExpr{Kind: MihomoExprAnd, Children: []MihomoExpr{
				{Kind: MihomoExprSubRule, SubRuleRef: &MihomoSubRuleRef{Name: "child", Guard: mihomoCompilerAtom("MATCH", "")}},
				mihomoCompilerAtom("DOMAIN", "example"),
			}},
			Action: MihomoAction{Target: "proxy"},
		}},
	}
	_, err := CompileMihomoSubRules(embedded, MihomoSubRuleCompilerOptions{})
	if !errors.Is(err, ErrMihomoSubRuleEmbedded) || !strings.Contains(err.Error(), "line 9") {
		t.Fatalf("embedded call error = %v", err)
	}

	limited := MihomoRuleIR{
		Rules: []MihomoRuleIRRule{mihomoCompilerCall(0, 1, "SUB-RULE,(MATCH),many", "many", mihomoCompilerAtom("MATCH", ""))},
		SubRules: []MihomoSubRuleIR{{Name: "many", Rules: []MihomoRuleIRRule{
			mihomoCompilerRule(0, 2, "MATCH,a", "a", mihomoCompilerAtom("MATCH", "")),
			mihomoCompilerRule(1, 3, "MATCH,b", "b", mihomoCompilerAtom("MATCH", "")),
		}}},
	}
	_, err = CompileMihomoSubRules(limited, MihomoSubRuleCompilerOptions{MaxExpandedRules: 1})
	if !errors.Is(err, ErrMihomoSubRuleExpansionLimit) {
		t.Fatalf("expansion limit error = %v", err)
	}
}

func mihomoCompilerAtom(kind, value string) MihomoExpr {
	return MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: kind, Value: value, Arguments: []string{value}, Raw: kind + "," + value}}
}

func mihomoCompilerRule(index, line int, raw, action string, expr MihomoExpr) MihomoRuleIRRule {
	return MihomoRuleIRRule{MihomoRuleSource: MihomoRuleSource{SourceIndex: index, SourceLine: line, Raw: raw}, Expr: expr, Action: MihomoAction{Target: action}}
}

func mihomoCompilerCall(index, line int, raw, name string, guard MihomoExpr) MihomoRuleIRRule {
	return MihomoRuleIRRule{MihomoRuleSource: MihomoRuleSource{SourceIndex: index, SourceLine: line, Raw: raw}, Expr: MihomoExpr{Kind: MihomoExprSubRule, Raw: raw, SubRuleRef: &MihomoSubRuleRef{Name: name, Guard: guard}}}
}
