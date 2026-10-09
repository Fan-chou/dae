package mihomo

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type ruleGolden struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error"`
	RoutesDae string `json:"routes_dae"`
	Events    []struct {
		Kind  string `json:"kind"`
		Index int    `json:"index"`
	} `json:"events"`
}

type ruleCases struct {
	Cases map[string]struct {
		Rules    []string            `yaml:"rules"`
		SubRules map[string][]string `yaml:"sub_rules"`
		NoMatch  bool                `yaml:"no_match"`
	} `yaml:"cases"`
}

// ruleDeviations lists the only cases where the new lowering may differ from
// the archived sidecar; a stale entry fails the test.
var ruleDeviations = map[string]string{
	"expand_1025_skipped":            devMergeCap,
	"expand_1024_exact":              devMergeCap,
	"expand_1331_skipped":            devMergeCap,
	"expand_accumulate_exact":        devMergeCap,
	"expand_accumulate_break":        devMergeCap,
	"fatal_sub_expansion_limit":      devMergeCap,
	"fatal_sub_expansion_with_match": devMergeCap,
	"domain_regex_keeps_case":        devRegexEscape,
	"domain_wildcard_star":           devRegexEscape,
	"domain_wildcard_q":              devRegexEscape,
	"domain_wildcard_upper_special":  devRegexEscape,
}

// devMergeCap: the sidecar counts rules before adjacent ones are merged, so a
// long run of same-outbound rules overflows its 1024 cap (a sub-rule makes
// the whole conversion fail, top-level rules silently drop everything after
// the cap, MATCH included). Counting after merging keeps them. The result is
// checked against the same rules lowered without merging and without a cap.
const devMergeCap = "rule cap applied after adjacent rules are merged"

// devRegexEscape: the sidecar writes routes.dae with every backslash doubled,
// but dae's parser does not unescape double-quoted values, so the regex dae
// ends up with has doubled backslashes: "\\." matches a literal backslash
// plus any character instead of a literal dot, and no real domain matches.
// The in-memory conversion keeps the intended regex. The expected value is
// the sidecar's with the doubling undone.
const devRegexEscape = "sidecar text round trip doubles regex backslashes"

func loadRuleFixtures(t *testing.T) (ruleCases, map[string]ruleGolden) {
	t.Helper()
	var cases ruleCases
	raw, err := os.ReadFile("testdata/rules/cases.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &cases))
	golden := map[string]ruleGolden{}
	body, err := os.ReadFile("testdata/rules/golden.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &golden))
	require.Equal(t, len(golden), len(cases.Cases), "golden and cases out of sync; regenerate")
	return cases, golden
}

func parseOracleRoutes(t *testing.T, routes string) ([]*config_parser.RoutingRule, string) {
	t.Helper()
	sections, err := config_parser.Parse("global {}\nrouting {\n" + routes + "\n}\n")
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)
	fallback, err := config.ParseFunctionOrString(conf.Routing.Fallback)
	require.NoError(t, err)
	return conf.Routing.Rules, fallback.Name
}

func eventKeys(events []string) []string {
	sort.Strings(events)
	return events
}

// TestRuleLoweringMatchesArchivedSidecar lowers every fixture and compares
// the canonical routing program, the fatal/non-fatal split, and the exact
// set of skipped or ignored rules with the archived sidecar.
func TestRuleLoweringMatchesArchivedSidecar(t *testing.T) {
	cases, golden := loadRuleFixtures(t)
	env := RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY", "OTHER": "OTHER"}}
	for name, c := range cases.Cases {
		want := golden[name]
		t.Run(name, func(t *testing.T) {
			raw := append([]string(nil), c.Rules...)
			if !c.NoMatch {
				raw = append(raw, "MATCH,PROXY")
			}
			rules := make([]Rule, len(raw))
			for i, r := range raw {
				rules[i] = Rule{Raw: r, Index: i, Line: i + 1}
			}
			var subs []SubRule
			for _, name := range sortedKeys(c.SubRules) {
				sr := SubRule{Name: name, Line: 1}
				for i, r := range c.SubRules[name] {
					sr.Rules = append(sr.Rules, Rule{Raw: r, Index: i, Line: i + 1})
				}
				subs = append(subs, sr)
			}
			got, err := LowerRules(rules, subs, RuleEnv{Outbounds: env.Outbounds})

			deviation := ruleDeviations[name]
			if deviation == devMergeCap {
				// The sidecar must really have hit its cap, or this entry is stale.
				hitCap := !want.OK
				for _, e := range want.Events {
					hitCap = hitCap || e.Kind == "skip"
				}
				require.True(t, hitCap, "stale deviation: the sidecar no longer hits its cap")
				require.NoError(t, err)
				for _, e := range got.Events {
					require.NotEqual(t, EventSkip, e.Kind, "merged rules must fit the cap: %+v", e)
				}
				if !c.NoMatch {
					require.Equal(t, "PROXY", got.Fallback, "MATCH must survive")
				}
				return
			}
			if !want.OK {
				if strings.Contains(want.Error, "produced no routes") {
					// An empty result is rejected when the whole configuration
					// is assembled, not while lowering rules.
					require.NoError(t, err)
					require.Empty(t, got.Rules)
					require.Empty(t, got.Fallback)
					return
				}
				require.Error(t, err, "oracle rejected: %s", want.Error)
				if strings.Contains(want.Error, "SCRIPT") || strings.Contains(want.Error, "script") {
					require.ErrorIs(t, err, ErrScriptUnsupported)
				}
				// Sub-rule failures must be rejected for the same reason, not
				// merely rejected.
				for text, kind := range map[string]error{
					"cycle detected":        ErrSubRuleCycle,
					"maximum depth":         ErrSubRuleDepth,
					"is not defined":        ErrSubRuleUndefined,
					"has no rules":          ErrSubRuleEmpty,
					"nested inside":         ErrSubRuleEmbedded,
					"cannot carry":          ErrSubRuleCall,
					"expanded rules exceed": ErrSubRuleLimit,
				} {
					if strings.Contains(want.Error, text) && strings.Contains(want.Error, "compile Mihomo sub-rule") {
						require.ErrorIs(t, err, kind, "oracle: %s", want.Error)
					}
				}
				return
			}
			require.NoError(t, err)

			wantRules, wantFallback := parseOracleRoutes(t, want.RoutesDae)
			if deviation == devRegexEscape {
				changed := false
				for _, r := range wantRules {
					for _, f := range r.AndFunctions {
						for _, p := range f.Params {
							if p.Key == "regex" && strings.Contains(p.Val, `\\`) {
								p.Val = strings.ReplaceAll(p.Val, `\\`, `\`)
								changed = true
							}
						}
					}
				}
				require.True(t, changed, "stale deviation: the sidecar no longer doubles backslashes")
			}
			wantProg, err := canonProgram(wantRules, wantFallback)
			require.NoError(t, err)
			gotProg, err := canonProgram(got.Rules, got.Fallback)
			require.NoError(t, err)
			require.Equal(t, wantProg, gotProg)

			var wantEvents, gotEvents []string
			for _, e := range want.Events {
				wantEvents = append(wantEvents, e.Kind+":"+itoa(e.Index))
			}
			for _, e := range got.Events {
				gotEvents = append(gotEvents, string(e.Kind)+":"+itoa(e.Index))
			}
			require.Equal(t, eventKeys(wantEvents), eventKeys(gotEvents))
		})
	}
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// TestMergingDoesNotChangeWhatRulesMatch lowers every fixture twice, once as
// shipped and once with merging off and no rule cap, and requires the same
// routing program. A merge that reordered or widened anything would show up
// here for any fixture, not just the ones with long runs.
func TestMergingDoesNotChangeWhatRulesMatch(t *testing.T) {
	cases, _ := loadRuleFixtures(t)
	env := RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY", "OTHER": "OTHER"}}
	unlimited := RuleEnv{Outbounds: env.Outbounds, MaxExpandedRules: 5_000_000}
	for name, c := range cases.Cases {
		t.Run(name, func(t *testing.T) {
			raw := append([]string(nil), c.Rules...)
			if !c.NoMatch {
				raw = append(raw, "MATCH,PROXY")
			}
			rules := make([]Rule, len(raw))
			for i, r := range raw {
				rules[i] = Rule{Raw: r, Index: i, Line: i + 1}
			}
			var subs []SubRule
			for _, sub := range sortedKeys(c.SubRules) {
				sr := SubRule{Name: sub, Line: 1}
				for i, r := range c.SubRules[sub] {
					sr.Rules = append(sr.Rules, Rule{Raw: r, Index: i, Line: i + 1})
				}
				subs = append(subs, sr)
			}
			merged, err := lowerRules(rules, subs, env, false)
			plain, plainErr := lowerRules(rules, subs, unlimited, true)
			if err != nil || plainErr != nil {
				require.Equal(t, err != nil, plainErr != nil)
				return
			}
			for _, e := range merged.Events {
				if e.Kind == EventSkip && strings.Contains(e.Reason, "exceed") {
					return // merged output itself hit the cap; nothing to compare
				}
			}
			a, err := canonProgram(merged.Rules, merged.Fallback)
			require.NoError(t, err)
			b, err := canonProgram(plain.Rules, plain.Fallback)
			require.NoError(t, err)
			require.Equal(t, b, a)
			require.LessOrEqual(t, len(merged.Rules), len(plain.Rules), "merging must never add rules")
		})
	}
}

// TestSubRuleLeavesCollapseIntoOneDomainSet measures the point of merging: a
// sub-rule that lists many domains for one outbound becomes one rule, and
// dae's own normalization turns it into a single term holding one domain set,
// instead of one rule (and kernel match set) per line.
func TestSubRuleLeavesCollapseIntoOneDomainSet(t *testing.T) {
	const n = 800
	var leaves []Rule
	for i := 0; i < n; i++ {
		leaves = append(leaves, Rule{Raw: fmt.Sprintf("DOMAIN-SUFFIX,site%d.example.com,PROXY", i), Index: i, Line: i + 1})
	}
	got, err := LowerRules(
		[]Rule{{Raw: "SUB-RULE,(NETWORK,tcp),big", Index: 0, Line: 1}, {Raw: "MATCH,DIRECT", Index: 1, Line: 2}},
		[]SubRule{{Name: "big", Rules: leaves}},
		RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY"}},
	)
	require.NoError(t, err)
	require.Len(t, got.Rules, 1, "%d leaves must become one rule", n)
	require.Empty(t, got.Events)

	program, err := routing.NewNormalizedProgram(got.Rules, got.Fallback)
	require.NoError(t, err)
	require.Len(t, program.Rules, 1, "normalized program must hold one term, not %d", n)
	var sets int
	for _, f := range program.Rules[0].AndFunctions {
		if f.Name == "domain" {
			sets++
			require.Len(t, f.Params, n)
		}
	}
	require.Equal(t, 1, sets)
}

// Runs of same-outbound top-level rules are merged before the cap is applied,
// so a long plain list does not silently push MATCH out of the budget.
func TestLongPlainRuleRunKeepsMatch(t *testing.T) {
	var rules []Rule
	for i := 0; i < 3000; i++ {
		rules = append(rules, Rule{Raw: fmt.Sprintf("DOMAIN-SUFFIX,site%d.example.com,PROXY", i), Index: i, Line: i + 1})
	}
	rules = append(rules, Rule{Raw: "MATCH,DIRECT", Index: 3000, Line: 3001})
	got, err := LowerRules(rules, nil, RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY"}})
	require.NoError(t, err)
	require.Len(t, got.Rules, 1)
	require.Len(t, got.Rules[0].AndFunctions[0].Params, 3000)
	require.Equal(t, "direct", got.Fallback, "MATCH must not be dropped")
	require.Empty(t, got.Events)
}

// A different outbound in between must split the runs: order decides who wins.
func TestMergingNeverCrossesADifferentOutbound(t *testing.T) {
	rules := []Rule{
		{Raw: "DOMAIN-SUFFIX,a.com,PROXY", Index: 0}, {Raw: "DOMAIN-SUFFIX,b.com,OTHER", Index: 1},
		{Raw: "DOMAIN-SUFFIX,c.com,PROXY", Index: 2}, {Raw: "DOMAIN-SUFFIX,d.com,PROXY", Index: 3},
	}
	got, err := LowerRules(rules, nil, RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY", "OTHER": "OTHER"}})
	require.NoError(t, err)
	require.Len(t, got.Rules, 3)
	require.Len(t, got.Rules[2].AndFunctions[0].Params, 2)
}
