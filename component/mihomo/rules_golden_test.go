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

// mihomoAligned lists cases where Mihomo itself loads the rules and the
// sidecar did not (it failed the whole conversion, or mis-split the line). The
// converter follows Mihomo here; each check states the expected result.
// A case is stale when the sidecar now agrees (it converted the rule and
// skipped nothing), so the list cannot outlive the gap it documents.
var mihomoAligned = map[string]func(t *testing.T, got *LoweredRules){
	// Empty option fields (a trailing comma, ",,") are ignored.
	"fatal_trailing_comma":    programIs("DOMAIN,a.com,PROXY"),
	"fatal_empty_option":      programIs("DOMAIN,a.com,PROXY,no-resolve"),
	"trailing_comma_on_logic": programIs("AND,((DOMAIN-SUFFIX,a.com),(DST-PORT,443)),PROXY"),
	// An empty value loads in Mihomo but cannot be lowered: the rule is
	// skipped with a reason instead of failing the whole conversion.
	"fatal_empty_field": func(t *testing.T, got *LoweredRules) {
		require.Empty(t, got.Rules)
		require.Len(t, got.Events, 1)
		require.Equal(t, EventSkip, got.Events[0].Kind)
	},
	// Quotes are not special to Mihomo: an unclosed one is an ordinary character.
	"fatal_unclosed_quote":    programHas("[domain(full='a.com)] -> PROXY"),
	"process_name_apostrophe": programHas("[pname(Foo's App)] -> PROXY"),
	// Regex rules take the last field as the outbound and keep every comma,
	// parenthesis and quote before it in the pattern.
	"domain_regex_with_comma":           programHas(`[domain(regex=^a{1,3}\.example\.com$)] -> PROXY`),
	"domain_regex_with_paren_and_quote": programHas(`[domain(regex=^[(]x[^"']+\.com$)] -> PROXY`),
	// Upstream Mihomo reads only no-resolve and src, only for IP rules, and
	// ignores every other option; the rule stays active and the ignored option
	// is reported. (match-mac is deliberately absent: it belongs to the
	// deployed fork, so it keeps its conservative skip.)
	"domain_src_option":                        programHasIgnoring(`[domain(full=a.com)] -> PROXY`, 1),
	"opt_unknown":                              programHasIgnoring(`[domain(full=a.com)] -> PROXY`, 1),
	"no_resolve_on_domain_atom":                programHasIgnoring(`[domain(full=a.com) & port(443)] -> PROXY`, 1),
	"opt_src_on_rule_set_like_domain_in_logic": programHasIgnoring(`[domain(full=a.com) & port(443)] -> PROXY`, 1),
	"ip_unknown_option":                        programHasIgnoring(`[ip(1.2.3.0/24)] -> PROXY`, 1),
	"ip_unknown_option_with_no_resolve":        programHasIgnoring(`[ip_no_resolve(1.2.3.0/24)] -> PROXY`, 1),
	// DSCP is the 6-bit DSCP of the IP header on both sides.
	"dscp":            programHas(`[dscp(46)] -> PROXY`),
	"dscp_slash_list": programHas(`[dscp(10)] -> PROXY`, `[dscp(20)] -> PROXY`),
	"dscp_range":      programHas(`[dscp(0)] -> PROXY`, `[dscp(1)] -> PROXY`, `[dscp(2)] -> PROXY`, `[dscp(46)] -> PROXY`),
	"dscp_in_and":     programHas(`[dscp(46) & l4proto(udp)] -> PROXY`),
	"dscp_negated":    programHas(`[!dscp(46)] -> PROXY`),
	// Sub-rule definitions nobody calls are not examined beyond syntax.
	"fatal_sub_unused_syntax_error": func(t *testing.T, got *LoweredRules) { require.Empty(t, got.Events) },
	// An empty sub-rule matches nothing and matching goes on.
	"fatal_sub_empty_referenced": func(t *testing.T, got *LoweredRules) {
		require.Empty(t, got.Rules)
		require.Empty(t, got.Events)
		require.Equal(t, "PROXY", got.Fallback)
	},
	// Mihomo sets no depth limit besides rejecting cycles.
	"fatal_sub_depth_exceeded": programHas("[dport(443) & l4proto(tcp)] -> PROXY"),
	"fatal_sub_depth_33":       programHas("[dport(443) & l4proto(tcp)] -> PROXY"),
	// A stray extra field makes the last field the sub-rule name. It is a
	// proxy, not a sub-rule, so Mihomo loads the rule and it never matches.
	"fatal_sub_call_with_action": func(t *testing.T, got *LoweredRules) {
		require.Empty(t, got.Rules)
		require.Len(t, got.Events, 1)
		require.Equal(t, EventSkip, got.Events[0].Kind)
		require.Contains(t, got.Events[0].Reason, "never matches")
	},
	// ... unless a sub-rule really has that name, which is then the one called.
	"sub_call_name_is_defined_sub_rule": programHas("[dport(22) & l4proto(tcp)] -> OTHER"),
}

func lowerStrings(t *testing.T, raw ...string) *LoweredRules {
	t.Helper()
	rules := make([]Rule, len(raw))
	for i, r := range raw {
		rules[i] = Rule{Raw: r, Index: i, Line: i + 1}
	}
	got, err := LowerRules(rules, nil, RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY", "OTHER": "OTHER"}})
	require.NoError(t, err)
	return got
}

// programIs: the result equals that of the given, well-formed rule plus MATCH.
func programIs(rule string) func(*testing.T, *LoweredRules) {
	return func(t *testing.T, got *LoweredRules) {
		want := lowerStrings(t, rule, "MATCH,PROXY")
		a, err := canonProgram(got.Rules, got.Fallback)
		require.NoError(t, err)
		b, err := canonProgram(want.Rules, want.Fallback)
		require.NoError(t, err)
		require.Equal(t, b, a)
		require.Empty(t, got.Events)
	}
}

// programHas: the canonical program contains the given term.
func programHas(terms ...string) func(*testing.T, *LoweredRules) {
	return func(t *testing.T, got *LoweredRules) {
		prog, err := canonProgram(got.Rules, got.Fallback)
		require.NoError(t, err)
		for _, term := range terms {
			require.Contains(t, prog, term)
		}
		require.Empty(t, got.Events)
	}
}

// programHasIgnoring: like programHas, and exactly n options were ignored.
func programHasIgnoring(term string, n int) func(*testing.T, *LoweredRules) {
	return func(t *testing.T, got *LoweredRules) {
		prog, err := canonProgram(got.Rules, got.Fallback)
		require.NoError(t, err)
		require.Contains(t, prog, term)
		require.Len(t, got.Events, n)
		for _, e := range got.Events {
			require.Equal(t, EventIgnore, e.Kind)
		}
	}
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
			if check, ok := mihomoAligned[name]; ok {
				differs := !want.OK
				for _, e := range want.Events {
					differs = differs || e.Kind == "skip"
				}
				require.True(t, differs, "stale entry: the sidecar already handles this the Mihomo way")
				require.NoError(t, err)
				check(t, got)
				return
			}
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
					"nested inside":         ErrSubRuleEmbedded,
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

// TestDumpAcceptance writes, for every rule fixture, whether this converter
// accepts it (and how many rules it skipped), for hack/mihomo-oracle's
// crosscheck_mihomo.py. It does nothing unless DUMP_ACCEPTANCE names a file.
func TestDumpAcceptance(t *testing.T) {
	path := os.Getenv("DUMP_ACCEPTANCE")
	if path == "" {
		t.Skip("DUMP_ACCEPTANCE not set")
	}
	cases, _ := loadRuleFixtures(t)
	out := map[string]map[string]any{}
	for name, c := range cases.Cases {
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
		got, err := LowerRules(rules, subs, RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY", "OTHER": "OTHER"}})
		entry := map[string]any{"ok": err == nil}
		if err != nil {
			entry["error"] = err.Error()
		} else {
			skips := 0
			for _, e := range got.Events {
				if e.Kind == EventSkip {
					skips++
				}
			}
			entry["skipped"] = skips
			entry["rules"] = len(got.Rules)
		}
		out[name] = entry
	}
	body, err := json.MarshalIndent(out, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, body, 0o600))
}
