package mihomo

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
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
	require.Equal(t, len(wantProg), len(gotProg))
	n := 0
	for i := range wantProg {
		if wantProg[i] != gotProg[i] && n < 10 {
			n++
			t.Errorf("term %d differs:\n  sidecar: %.300s\n  new:     %.300s", i, wantProg[i], gotProg[i])
		}
	}
}
