package main

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRenderMihomoLoweredRoutesUsesFallbackForMatch(t *testing.T) {
	rules := []MihomoLoweredRoutingRule{
		{
			Source: MihomoRuleSource{SourceIndex: 0, SourceLine: 10, Raw: "MATCH,DIRECT"},
			Rule:   &config_parser.RoutingRule{Outbound: config_parser.Function{Name: "direct"}},
		},
	}

	routes, report, err := renderMihomoLoweredRoutes(rules)
	if err != nil {
		t.Fatalf("renderMihomoLoweredRoutes() error = %v", err)
	}
	if report.Generated != 1 {
		t.Fatalf("report.Generated = %d, want 1 fallback", report.Generated)
	}
	if routes != "    fallback: direct\n" {
		t.Fatalf("routes = %q, want fallback only", routes)
	}
	if _, err := config_parser.Parse("global {}\nrouting {\n" + routes + "}\n"); err != nil {
		t.Fatalf("rendered fallback does not parse as kdae routing: %v", err)
	}
}

func TestRenderMihomoLoweredRoutesStopsAfterMatchFallback(t *testing.T) {
	rules := []MihomoLoweredRoutingRule{
		{
			Source: MihomoRuleSource{SourceIndex: 0, SourceLine: 10, Raw: "DOMAIN,example.com,DIRECT"},
			Rule: &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{
					Name:   "domain",
					Params: []*config_parser.Param{{Key: "full", Val: "example.com"}},
				}},
				Outbound: config_parser.Function{Name: "direct"},
			},
		},
		{
			Source: MihomoRuleSource{SourceIndex: 1, SourceLine: 11, Raw: "MATCH,block"},
			Rule:   &config_parser.RoutingRule{Outbound: config_parser.Function{Name: "block"}},
		},
		{
			Source: MihomoRuleSource{SourceIndex: 2, SourceLine: 12, Raw: "DST-PORT,443,DIRECT"},
			Rule: &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{
					Name:   "dport",
					Params: []*config_parser.Param{{Val: "443"}},
				}},
				Outbound: config_parser.Function{Name: "direct"},
			},
		},
	}

	routes, report, err := renderMihomoLoweredRoutes(rules)
	if err != nil {
		t.Fatalf("renderMihomoLoweredRoutes() error = %v", err)
	}
	if report.Generated != 2 {
		t.Fatalf("report.Generated = %d, want one route plus fallback", report.Generated)
	}
	if !strings.Contains(routes, "domain(full: \"example.com\") -> direct") {
		t.Fatalf("routes = %q, missing preceding route", routes)
	}
	if !strings.Contains(routes, "fallback: block") {
		t.Fatalf("routes = %q, missing MATCH fallback", routes)
	}
	if strings.Contains(routes, "dport(443)") {
		t.Fatalf("routes = %q, emitted a route after an unconditional MATCH", routes)
	}
}
