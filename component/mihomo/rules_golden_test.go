package mihomo

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

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
		Rules   []string `yaml:"rules"`
		NoMatch bool     `yaml:"no_match"`
	} `yaml:"cases"`
}

// ruleDeviations lists the only cases where the new lowering may differ from
// the archived sidecar; a stale entry fails the test.
var ruleDeviations = map[string]string{
	"domain_regex_keeps_case":       devRegexEscape,
	"domain_wildcard_star":          devRegexEscape,
	"domain_wildcard_q":             devRegexEscape,
	"domain_wildcard_upper_special": devRegexEscape,
}

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
			got, err := LowerRules(rules, RuleEnv{Outbounds: env.Outbounds})

			deviation := ruleDeviations[name]
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

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
