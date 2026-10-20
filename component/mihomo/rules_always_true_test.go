package mihomo

import (
	"testing"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func hasPortRange(t *testing.T, rules []*config_parser.RoutingRule, text string) bool {
	t.Helper()
	found := false
	for _, r := range rules {
		for _, f := range r.AndFunctions {
			e, err := routing.ExprFromFunction(f)
			require.NoError(t, err)
			require.NoError(t, e.Walk(func(a *config_parser.Function) error {
				if a.Name == "port" && len(a.Params) == 1 && a.Params[0].Val == text {
					found = true
				}
				return nil
			}))
		}
	}
	return found
}

// `SUB-RULE,(RULE-SET,x),sub` whose body is `MATCH,G` used to lower to
// `ruleset && port(0-65535)`: an extra match entry in the kernel and
// userspace walks for a predicate that is always true.
func TestSubRuleMatchBodyDropsTheAlwaysTrueConjunct(t *testing.T) {
	env := RuleEnv{
		Providers: map[string]string{"rules-cn": "rules-cn"},
		Outbounds: map[string]string{"CN": "CN"},
	}
	got, err := LowerRules(
		[]Rule{{Raw: "SUB-RULE,(RULE-SET,rules-cn),cn", Index: 0, Line: 1}, {Raw: "MATCH,DIRECT", Index: 1, Line: 2}},
		[]SubRule{{Name: "cn", Rules: []Rule{{Raw: "MATCH,CN", Index: 0, Line: 1}}}},
		env,
	)
	require.NoError(t, err)
	require.Len(t, got.Rules, 1)
	require.False(t, hasPortRange(t, got.Rules, "0-65535"), "MATCH must not become a port predicate")

	canon, err := canonProgram(got.Rules, got.Fallback)
	require.NoError(t, err)
	require.Equal(t, []string{"[ruleset(rules-cn)] -> CN", "FALLBACK direct"}, canon)

	// The guard keeps its memo id: the rule is a lone, memo-tagged atom, and
	// that shape must survive the route_expr round trip.
	e, err := routing.ExprFromFunction(got.Rules[0].AndFunctions[0])
	require.NoError(t, err)
	require.Equal(t, "atom", e.Op)
	require.NotZero(t, e.MemoID)
	require.Equal(t, "ruleset", e.Atom.Name)
	terms, err := e.DNF(false, 100)
	require.NoError(t, err)
	require.Len(t, terms, 1)
	require.Len(t, terms[0], 1)
}

// A body that is more than MATCH keeps every real conjunct, and a MATCH that
// follows another line keeps its own rule.
func TestSubRuleKeepsRealConjunctsNextToMatch(t *testing.T) {
	env := RuleEnv{
		Providers: map[string]string{"rules-cn": "rules-cn"},
		Outbounds: map[string]string{"CN": "CN", "BLOCK": "BLOCK"},
	}
	got, err := LowerRules(
		[]Rule{{Raw: "SUB-RULE,(RULE-SET,rules-cn),cn", Index: 0, Line: 1}, {Raw: "MATCH,DIRECT", Index: 1, Line: 2}},
		[]SubRule{{Name: "cn", Rules: []Rule{
			{Raw: "AND,((NETWORK,UDP),(DST-PORT,443)),BLOCK", Index: 0, Line: 1},
			{Raw: "MATCH,CN", Index: 1, Line: 2},
		}}},
		env,
	)
	require.NoError(t, err)
	require.Len(t, got.Rules, 2)
	require.False(t, hasPortRange(t, got.Rules, "0-65535"))
	canon, err := canonProgram(got.Rules, got.Fallback)
	require.NoError(t, err)
	require.Len(t, canon, 3)
	require.Contains(t, canon[0], "port(443)")
	require.Equal(t, "[ruleset(rules-cn)] -> CN", canon[1])
}

// Nested SUB-RULE guards each carry their own memo id. Dropping the MATCH
// must leave both guards tagged and ANDed.
func TestNestedSubRuleGuardsKeepTheirMemoIds(t *testing.T) {
	env := RuleEnv{
		Providers: map[string]string{"a": "rules-a", "b": "rules-b"},
		Outbounds: map[string]string{"G": "G"},
	}
	got, err := LowerRules(
		[]Rule{{Raw: "SUB-RULE,(RULE-SET,a),outer", Index: 0, Line: 1}, {Raw: "MATCH,DIRECT", Index: 1, Line: 2}},
		[]SubRule{
			{Name: "outer", Rules: []Rule{{Raw: "SUB-RULE,(RULE-SET,b),inner", Index: 0, Line: 1}}},
			{Name: "inner", Rules: []Rule{{Raw: "MATCH,G", Index: 0, Line: 1}}},
		},
		env,
	)
	require.NoError(t, err)
	require.Len(t, got.Rules, 1)
	require.False(t, hasPortRange(t, got.Rules, "0-65535"))
	canon, err := canonProgram(got.Rules, got.Fallback)
	require.NoError(t, err)
	require.Equal(t, []string{"[ruleset(rules-a) & ruleset(rules-b)] -> G", "FALLBACK direct"}, canon)

	e, err := routing.ExprFromFunction(got.Rules[0].AndFunctions[0])
	require.NoError(t, err)
	ids := map[int]bool{}
	var collect func(*routing.OrderedExpr)
	collect = func(n *routing.OrderedExpr) {
		if n.MemoID != 0 {
			ids[n.MemoID] = true
		}
		for _, c := range n.Children {
			collect(c)
		}
	}
	collect(e)
	require.Len(t, ids, 2, "both guards keep a distinct memo id")
}
