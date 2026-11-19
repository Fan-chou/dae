/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestNormalizedProgramPreservesRuleMetaAndPolicyHashInvariant(t *testing.T) {
	makeRules := func() []*config_parser.RoutingRule {
		return []*config_parser.RoutingRule{
			{
				AndFunctions: []*config_parser.Function{{
					Name:   "domain",
					Params: []*config_parser.Param{{Key: "suffix", Val: "example.com"}},
				}},
				Outbound: config_parser.Function{Name: "proxy"},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name:   "domain",
					Params: []*config_parser.Param{{Key: "suffix", Val: "example.org"}},
				}},
				Outbound: config_parser.Function{Name: "proxy"},
			},
			{
				AndFunctions: []*config_parser.Function{{
					Name: "ip",
					Params: []*config_parser.Param{
						{Val: "10.0.0.0/8"},
						{Val: "172.16.0.0/12"},
						{Val: "192.168.0.0/16"},
						{Val: "100.64.0.0/10"},
					},
				}},
				Outbound: config_parser.Function{Name: "direct"},
			},
		}
	}

	rulesA := makeRules()
	progA, err := NewNormalizedProgram(rulesA, "proxy", &AliasOptimizer{}, &MergeAndSortRulesOptimizer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(progA.Rules) != 2 {
		t.Fatalf("expected 2 merged rules, got %d", len(progA.Rules))
	}
	if progA.Rules[0].SourceIndex != 1 || progA.Rules[0].SourceOrigin != "config" {
		t.Fatalf("unexpected rule 0 meta: index=%d origin=%q summary=%q", progA.Rules[0].SourceIndex, progA.Rules[0].SourceOrigin, progA.Rules[0].SourceSummary)
	}
	if progA.Rules[1].SourceIndex != 3 || progA.Rules[1].SourceSummary != "ip(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, +1) -> direct" {
		t.Fatalf("unexpected rule 1 summary: index=%d summary=%q", progA.Rules[1].SourceIndex, progA.Rules[1].SourceSummary)
	}

	// Mutating only metadata on rulesB must produce identical PolicyHash.
	rulesB := makeRules()
	rulesB[0].SourceIndex = 99
	rulesB[0].SourceSummary = "custom provider label"
	rulesB[0].SourceOrigin = "rule_provider"
	rulesB[1].SourceIndex = 99
	rulesB[1].SourceSummary = "custom provider label"
	rulesB[1].SourceOrigin = "rule_provider"
	progB, err := NewNormalizedProgram(rulesB, "proxy", &AliasOptimizer{}, &MergeAndSortRulesOptimizer{})
	if err != nil {
		t.Fatal(err)
	}
	if progB.Rules[0].SourceOrigin != "rule_provider" || progB.Rules[0].SourceSummary != "custom provider label" {
		t.Fatalf("expected identical rule_provider metadata to survive merge, got origin=%q summary=%q", progB.Rules[0].SourceOrigin, progB.Rules[0].SourceSummary)
	}

	hashA, err := hashNormalizedProgram(progA)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := hashNormalizedProgram(progB)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatalf("PolicyHash changed when only rule metadata changed: %x != %x", hashA, hashB)
	}
}

func TestSummarizeRoutingRuleRedactsURIAndBoundsLength(t *testing.T) {
	rule := &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{
			Name: "domain",
			Params: []*config_parser.Param{{
				Key: "suffix",
				Val: "vless://secret@example.com:443",
			}},
		}},
		Outbound: config_parser.Function{Name: "proxy"},
	}
	summary := SummarizeRoutingRule(rule)
	if summary != "domain(suffix:[redacted]) -> proxy" {
		t.Fatalf("unexpected sanitized summary: %q", summary)
	}
}
