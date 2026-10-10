package mihomo

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/stretchr/testify/require"
)

// TestRealWorldMatchesArchivedSidecar compares one real Mihomo configuration
// with what the archived sidecar generated from it. It reads private data and
// the network, so it only runs when pointed at them:
//
//	REAL_YAML=/path/mihomo.yaml REAL_GENERATION=/path/generation-dir go test -run RealWorld ./component/mihomo
//
// REAL_GENERATION is the -generation-dir the sidecar was run with.
func TestRealWorldMatchesArchivedSidecar(t *testing.T) {
	yamlPath, genDir := os.Getenv("REAL_YAML"), os.Getenv("REAL_GENERATION")
	if yamlPath == "" || genDir == "" {
		t.Skip("REAL_YAML and REAL_GENERATION are not set")
	}
	body, err := os.ReadFile(yamlPath)
	require.NoError(t, err)
	baseDir := t.TempDir()
	got, err := runConvert(t, string(body), nil, "", baseDir)
	require.NoError(t, err)
	registry, err := ruleprovider.Load(context.Background(), got.Providers, baseDir, http.DefaultClient)
	require.NoError(t, err)
	expanded, err := ruleprovider.ExpandRoutingRules(got.Rules, registry)
	require.NoError(t, err)
	gotProg, err := canonProgram(expanded, got.Fallback)
	require.NoError(t, err)

	routes, err := os.ReadFile(filepath.Join(genDir, "current", "routes.dae"))
	require.NoError(t, err)
	wantRules, wantFallback := parseOracleRoutes(t, string(routes))
	wantRules = expandExt(t, wantRules, filepath.Join(genDir, "current"))
	wantProg, err := canonProgram(wantRules, wantFallback)
	require.NoError(t, err)

	t.Logf("new: %d nodes, %d groups, %d rules -> %d terms; sidecar: %d terms", len(got.Nodes), len(got.Groups), len(got.Rules), len(gotProg), len(wantProg))
	// Rules match first-come, so what must agree is the sequence of outcomes
	// and, within each stretch of one outcome, the set of terms. The order
	// inside such a stretch cannot change which outcome a flow gets; the
	// sidecar and this code just sort provider entries differently.
	gotRuns, wantRuns := outcomeRuns(gotProg), outcomeRuns(wantProg)
	require.Equal(t, len(wantRuns), len(gotRuns), "number of outcome stretches")
	n := 0
	for i := range wantRuns {
		if wantRuns[i].outcome != gotRuns[i].outcome || !equalTermSets(wantRuns[i].terms, gotRuns[i].terms) {
			n++
			if n <= 5 {
				t.Errorf("stretch %d differs: sidecar %q (%d terms), new %q (%d terms)", i, wantRuns[i].outcome, len(wantRuns[i].terms), gotRuns[i].outcome, len(gotRuns[i].terms))
			}
		}
	}
	require.Zero(t, n, "differing stretches")
}

type outcomeRun struct {
	outcome string
	terms   map[string]int
}

// outcomeRuns splits a canonical program into stretches of the same outcome.
// The sidecar writes a regexp's backslash doubled; that is only its encoding.
func outcomeRuns(program []string) []outcomeRun {
	var runs []outcomeRun
	for _, term := range program {
		term = strings.ReplaceAll(term, `\\`, `\`)
		outcome := term[strings.LastIndex(term, "-> ")+3:]
		if len(runs) == 0 || runs[len(runs)-1].outcome != outcome {
			runs = append(runs, outcomeRun{outcome: outcome, terms: map[string]int{}})
		}
		runs[len(runs)-1].terms[term]++
	}
	return runs
}

func equalTermSets(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, n := range a {
		if b[k] != n {
			return false
		}
	}
	return true
}
