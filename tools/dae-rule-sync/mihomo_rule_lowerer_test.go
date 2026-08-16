package main

import (
	"fmt"
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

func TestLowerMihomoRuleEmitsSipMatchMac(t *testing.T) {
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
		t.Fatalf("lowered = %#v, want sip(match_mac: ...)", lowered)
	}
	got := lowered[0].Rule.AndFunctions[0]
	if len(got.Params) != 1 || got.Params[0].Key != "match_mac" || got.Params[0].Val != "192.0.2.0/24" {
		t.Fatalf("sip params = %#v, want match_mac:192.0.2.0/24", got.Params)
	}
}

func TestLowerMihomoRuleEmitsSipMatchMacFromActionOption(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 7, SourceLine: 18, Raw: "SRC-IP-CIDR,192.0.2.0/24,REJECT-DROP,match-mac"},
		Expr: MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{
			Type: "SRC-IP-CIDR", Value: "192.0.2.0/24", Arguments: []string{"192.0.2.0/24"},
		}},
		Action: MihomoAction{Target: "REJECT-DROP", Options: []string{"match-mac"}},
	}

	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{})
	if err != nil {
		t.Fatalf("LowerMihomoRule() error = %v", err)
	}
	if len(lowered) != 1 || lowered[0].Rule.Outbound.Name != "block" {
		t.Fatalf("lowered = %#v, want REJECT-DROP mapped to block", lowered)
	}
	got := lowered[0].Rule.AndFunctions[0]
	if got.Name != "sip" || len(got.Params) != 1 || got.Params[0].Key != "match_mac" || got.Params[0].Val != "192.0.2.0/24" {
		t.Fatalf("sip params = %#v, want match_mac:192.0.2.0/24", got.Params)
	}
}

func TestLowerMihomoRuleEmitsSipMatchMacFromANDActionOption(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{
			SourceIndex: 0,
			SourceLine:  1425,
			Raw:         "SRC-IP-CIDR,192.168.124.142/32,REJECT-DROP,match-mac",
		},
		Expr: MihomoExpr{Kind: MihomoExprAnd, Children: []MihomoExpr{
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "NETWORK", Value: "UDP", Arguments: []string{"UDP"}}},
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "DST-PORT", Value: "3478", Arguments: []string{"3478"}}},
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "SRC-IP-CIDR", Value: "192.168.124.142/32", Arguments: []string{"192.168.124.142/32"}}},
		}},
		Action: MihomoAction{Target: "REJECT-DROP", Options: []string{"match-mac"}},
	}

	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{})
	if err != nil {
		t.Fatalf("LowerMihomoRule() error = %v", err)
	}
	if len(lowered) != 1 || lowered[0].Rule.Outbound.Name != "block" {
		t.Fatalf("lowered = %#v, want one block rule", lowered)
	}

	got := lowered[0].Rule.AndFunctions
	if len(got) != 3 || got[0].Name != "l4proto" || got[1].Name != "dport" {
		t.Fatalf("functions = %#v, want l4proto && dport && sip(match_mac:)", got)
	}
	if len(got[0].Params) != 1 || got[0].Params[0].Val != "udp" {
		t.Fatalf("l4proto params = %#v, want lowercase udp (dae only matches tcp/udp)", got[0].Params)
	}
	sip := got[2]
	if sip.Name != "sip" || len(sip.Params) != 1 || sip.Params[0].Key != "match_mac" || sip.Params[0].Val != "192.168.124.142/32" {
		t.Fatalf("sip params = %#v, want match_mac:192.168.124.142/32", sip.Params)
	}
}

func TestLowerMihomoRuleEmitsSipMatchMacFromIPCIDRSrcAndAction(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 10, SourceLine: 21, Raw: "AND"},
		Expr: MihomoExpr{Kind: MihomoExprAnd, Children: []MihomoExpr{
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "NETWORK", Value: "TCP", Arguments: []string{"TCP"}}},
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "IP-CIDR", Value: "192.0.2.1/32", Arguments: []string{"192.0.2.1/32", "src"}}},
		}},
		Action: MihomoAction{Target: "DIRECT", Options: []string{"match-mac"}},
	}

	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{})
	if err != nil {
		t.Fatalf("LowerMihomoRule() error = %v", err)
	}
	if len(lowered) != 1 || len(lowered[0].Rule.AndFunctions) != 2 {
		t.Fatalf("lowered = %#v, want l4proto && sip(match_mac:)", lowered)
	}
	if proto := lowered[0].Rule.AndFunctions[0]; proto.Name != "l4proto" || len(proto.Params) != 1 || proto.Params[0].Val != "tcp" {
		t.Fatalf("l4proto params = %#v, want lowercase tcp", lowered[0].Rule.AndFunctions[0].Params)
	}
	sip := lowered[0].Rule.AndFunctions[1]
	if sip.Name != "sip" || len(sip.Params) != 1 || sip.Params[0].Key != "match_mac" || sip.Params[0].Val != "192.0.2.1/32" {
		t.Fatalf("sip params = %#v, want match_mac:192.0.2.1/32", sip.Params)
	}
}

func TestLowerMihomoRuleRejectsMatchMacWithoutSourceIP(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 9, SourceLine: 20, Raw: "AND"},
		Expr: MihomoExpr{Kind: MihomoExprAnd, Children: []MihomoExpr{
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "DOMAIN", Value: "example.com", Arguments: []string{"example.com"}}},
			{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "DST-PORT", Value: "443", Arguments: []string{"443"}}},
		}},
		Action: MihomoAction{Target: "REJECT-DROP", Options: []string{"match-mac"}},
	}

	if _, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{}); err == nil {
		t.Fatal("LowerMihomoRule() error = nil, want match-mac rejected without a source IP matcher")
	}
}

func TestLowerMihomoRuleLowercasesDomainKeyword(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 8, SourceLine: 19, Raw: "DOMAIN-KEYWORD,Torrent,DIRECT"},
		Expr: MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{
			Type: "DOMAIN-KEYWORD", Value: "Torrent", Arguments: []string{"Torrent"},
		}},
		Action: MihomoAction{Target: "DIRECT"},
	}

	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{})
	if err != nil {
		t.Fatalf("LowerMihomoRule() error = %v", err)
	}
	if len(lowered) != 1 || len(lowered[0].Rule.AndFunctions) != 1 {
		t.Fatalf("lowered = %#v, want one domain keyword rule", lowered)
	}
	got := lowered[0].Rule.AndFunctions[0]
	if got.Name != "domain" || len(got.Params) != 1 || got.Params[0].Key != "keyword" || got.Params[0].Val != "torrent" {
		t.Fatalf("condition = %#v, want domain(keyword: \"torrent\")", got)
	}
}

func TestLowerMihomoRuleLowercasesDomainSuffixAndFull(t *testing.T) {
	tests := []struct {
		atomType string
		value    string
		key      string
		want     string
	}{
		{atomType: "DOMAIN-SUFFIX", value: "Example.COM", key: "suffix", want: "example.com"},
		{atomType: "DOMAIN", value: "Full.Example.COM", key: "full", want: "full.example.com"},
	}
	for _, test := range tests {
		rule := MihomoRuleIRRule{
			MihomoRuleSource: MihomoRuleSource{SourceIndex: 9, SourceLine: 20, Raw: test.atomType + "," + test.value + ",DIRECT"},
			Expr: MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{
				Type: test.atomType, Value: test.value, Arguments: []string{test.value},
			}},
			Action: MihomoAction{Target: "DIRECT"},
		}
		lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{})
		if err != nil {
			t.Fatalf("LowerMihomoRule(%s) error = %v", test.atomType, err)
		}
		if len(lowered) != 1 || len(lowered[0].Rule.AndFunctions) != 1 {
			t.Fatalf("LowerMihomoRule(%s) = %#v, want one domain rule", test.atomType, lowered)
		}
		got := lowered[0].Rule.AndFunctions[0]
		if got.Name != "domain" || len(got.Params) != 1 || got.Params[0].Key != test.key || got.Params[0].Val != test.want {
			t.Fatalf("condition = %#v, want domain(%s: %q)", got, test.key, test.want)
		}
	}
}

func TestLowerMihomoRuleFallsBackRejectDropToBlock(t *testing.T) {
	rule := MihomoRuleIRRule{
		MihomoRuleSource: MihomoRuleSource{SourceIndex: 4, SourceLine: 15, Raw: "DOMAIN,example.com,REJECT-DROP"},
		Expr: MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{
			Type: "DOMAIN", Value: "example.com", Arguments: []string{"example.com"},
		}},
		Action: MihomoAction{Target: "REJECT-DROP"},
	}

	lowered, err := LowerMihomoRule(rule, MihomoRuleLowererOptions{})
	if err != nil {
		t.Fatalf("LowerMihomoRule() error = %v", err)
	}
	if len(lowered) != 1 || lowered[0].Rule.Outbound.Name != "block" {
		t.Fatalf("lowered = %#v, want REJECT-DROP mapped to block", lowered)
	}
}

func TestLowerMihomoRuleIRSkipsUnsupportedRulesAndLogsDetails(t *testing.T) {
	var logs []string
	ir := MihomoRuleIR{Rules: []MihomoRuleIRRule{
		{
			MihomoRuleSource: MihomoRuleSource{SourceIndex: 5, SourceLine: 16, Raw: "IP-ASN,38365,REJECT"},
			Expr:             MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "IP-ASN", Value: "38365", Arguments: []string{"38365"}}},
			Action:           MihomoAction{Target: "REJECT"},
		},
		{
			MihomoRuleSource: MihomoRuleSource{SourceIndex: 6, SourceLine: 17, Raw: "UNKNOWN,value,REJECT"},
			Expr:             MihomoExpr{Kind: MihomoExprAtom, Atom: &MihomoAtom{Type: "UNKNOWN", Value: "value", Arguments: []string{"value"}}},
			Action:           MihomoAction{Target: "REJECT"},
		},
	}}

	lowered, err := NewMihomoRuleLowerer(MihomoRuleLowererOptions{
		SkipUnsupported: true,
		Logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	}).LowerIR(ir)
	if err != nil {
		t.Fatalf("LowerIR() error = %v", err)
	}
	if len(lowered) != 0 {
		t.Fatalf("lowered = %#v, want unsupported rules skipped", lowered)
	}
	if len(logs) != 2 || !strings.Contains(logs[0], "line 16") || !strings.Contains(logs[0], "IP-ASN") || !strings.Contains(logs[1], "line 17") || !strings.Contains(logs[1], "UNKNOWN") {
		t.Fatalf("logs = %#v, want source locations and reasons for skipped rules", logs)
	}
}
