package main

import (
	"strings"
	"testing"
)

func TestLowerMihomoRuleSkipsINPortCondition(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 1, SourceLine: 12, Raw: "IN-PORT,7893,proxy"},
		Expr: MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{
			Type: "IN-PORT", Value: "7893", Arguments: []string{"7893"},
		}},
		Action: MihomoAction{Target: "proxy"},
	}

	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{OutboundNameMap: map[string]string{"proxy": "proxy"}})
	if err != nil {
		t.Fatalf("LowerMihomoRule() error = %v", err)
	}
	if len(lowered) != 0 {
		t.Fatalf("lowered = %#v, want IN-PORT rule skipped", lowered)
	}
}

func TestLowerMihomoRuleDropsIgnoredINPortORBranch(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 2, SourceLine: 13, Raw: "OR"},
		Expr: MihomoExpr{Kind: MihomoExprOr, Children: []MihomoExpr{
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "IN-PORT", Value: "7894", Arguments: []string{"7894"}}},
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "DOMAIN", Value: "example.com", Arguments: []string{"example.com"}}},
		}},
		Action: MihomoAction{Target: "proxy"},
	}

	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{OutboundNameMap: map[string]string{"proxy": "proxy"}})
	if err != nil {
		t.Fatalf("LowerMihomoRule() error = %v", err)
	}
	if len(lowered) != 1 || len(lowered[0].Rule.AndFunctions) != 1 || lowered[0].Rule.AndFunctions[0].Name != "domain" {
		t.Fatalf("lowered = %#v, want only the representable OR branch", lowered)
	}
}

func TestLowerMihomoRuleIgnoresMatchMacOption(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 3, SourceLine: 14, Raw: "SRC-IP-CIDR"},
		Expr: MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{
			Type: "SRC-IP-CIDR", Value: "192.0.2.0/24", Arguments: []string{"192.0.2.0/24", "match-mac"},
		}},
		Action: MihomoAction{Target: "DIRECT"},
	}

	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{})
	if err != nil {
		t.Fatalf("LowerMihomoRule() error = %v", err)
	}
	if len(lowered) != 1 || len(lowered[0].Rule.AndFunctions) != 1 || lowered[0].Rule.AndFunctions[0].Name != "sip" {
		t.Fatalf("lowered = %#v, want source-IP condition without match-mac", lowered)
	}
	if strings.Contains(lowered[0].Rule.String(false, false, false), "match-mac") {
		t.Fatalf("lowered rule retained ignored match-mac option: %s", lowered[0].Rule.String(false, false, false))
	}
}
