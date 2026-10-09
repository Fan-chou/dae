package mihomo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type convertCases struct {
	Cases map[string]struct {
		Config     string            `yaml:"config"`
		ResolveDNS map[string]string `yaml:"resolve_dns"`
		Isolate    string            `yaml:"isolate"`
	} `yaml:"cases"`
}

type convertGolden struct {
	OK           bool              `json:"ok"`
	Error        string            `json:"error"`
	Nodes        [][2]string       `json:"nodes"`
	GroupsDae    string            `json:"groups_dae"`
	RoutesDae    string            `json:"routes_dae"`
	DAT          map[string]string `json:"dat"`
	NodeNameMap  map[string]string `json:"node_name_map"`
	GroupNameMap map[string]string `json:"group_name_map"`
	Events       []struct {
		Kind  string `json:"kind"`
		Index int    `json:"index"`
	} `json:"events"`
}

// convertDeviations lists the only cases where the whole conversion may differ
// from the archived sidecar; a stale entry fails the test.
var convertDeviations = map[string]string{}

func runConvert(t *testing.T, config string, resolveDNS map[string]string, isolate, baseDir string) (*Result, error) {
	t.Helper()
	doc, err := Parse([]byte(config))
	if err != nil {
		return nil, err
	}
	opts := Options{BaseDir: baseDir, Validate: daeLinkValidator, ResolveDNS: resolveDNS}
	if isolate != "" {
		opts.IsolateTransportGroups = strings.Split(isolate, ",")
	}
	return Convert(doc, opts)
}

// TestConvertMatchesArchivedSidecar converts whole configurations and
// compares nodes, groups, the routing program after native provider
// expansion, name maps, and the skipped rules with the archived sidecar.
func TestConvertMatchesArchivedSidecar(t *testing.T) {
	var file convertCases
	raw, err := os.ReadFile("testdata/convert/cases.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &file))
	golden := map[string]convertGolden{}
	body, err := os.ReadFile("testdata/convert/golden.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &golden))
	require.Equal(t, len(golden), len(file.Cases), "golden and cases out of sync; regenerate")

	for name, c := range file.Cases {
		want := golden[name]
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			copyTree(t, "testdata/providers/files", baseDir)
			got, err := runConvert(t, c.Config, c.ResolveDNS, c.Isolate, baseDir)
			// Fetching and parsing the rule sets is the native loader's job;
			// whether it fails is part of whether the configuration loads.
			var expanded []*config_parser.RoutingRule
			if err == nil {
				var registry ruleprovider.Registry
				if registry, err = ruleprovider.Load(context.Background(), got.Providers, baseDir, nil); err == nil {
					expanded, err = ruleprovider.ExpandRoutingRules(got.Rules, registry)
				}
			}

			if reason, ok := convertDeviations[name]; ok {
				_ = reason
				return
			}
			if !want.OK {
				require.Error(t, err, "oracle rejected: %s", want.Error)
				return
			}
			require.NoError(t, err)

			// Nodes: internal name and link, in order.
			require.Len(t, got.Nodes, len(want.Nodes))
			gotNodeMap := map[string]string{}
			for i, n := range got.Nodes {
				require.Equal(t, want.Nodes[i][0], n.Safe)
				require.Equal(t, want.Nodes[i][1], n.Link, "link of %s", n.Safe)
				gotNodeMap[n.Name] = n.Safe
			}
			require.Equal(t, want.NodeNameMap, gotNodeMap)

			// Groups, wrappers included, in order.
			sections, err := config_parser.Parse(want.GroupsDae)
			require.NoError(t, err)
			wantGroups, err := config.DecodeGroups(sections[0])
			require.NoError(t, err)
			require.Len(t, got.Groups, len(wantGroups))
			gotGroupMap := map[string]string{}
			for i, g := range got.Groups {
				require.Equal(t, wantGroups[i], g.Config, "group %s", g.Safe)
				if !g.Wrapper {
					gotGroupMap[g.Name] = g.Safe
				}
			}
			wantDeclared := map[string]string{}
			for orig, safe := range want.GroupNameMap {
				wantDeclared[orig] = safe
			}
			for _, g := range got.Groups {
				if g.Wrapper {
					delete(wantDeclared, g.Safe) // wrappers are reported under their own name
				}
			}
			require.Equal(t, wantDeclared, gotGroupMap)

			// Routes, after the native loader expanded the rule sets.
			assetDir := t.TempDir()
			for rel, b64 := range want.DAT {
				data, err := base64.StdEncoding.DecodeString(b64)
				require.NoError(t, err)
				dest := filepath.Join(assetDir, rel)
				require.NoError(t, os.MkdirAll(filepath.Dir(dest), 0o755))
				require.NoError(t, os.WriteFile(dest, data, 0o600))
			}
			wantRules, wantFallback := parseOracleRoutes(t, want.RoutesDae)
			wantRules = expandExt(t, wantRules, assetDir)
			wantProg, err := canonProgram(wantRules, wantFallback)
			require.NoError(t, err)
			gotProg, err := canonProgram(expanded, got.Fallback)
			require.NoError(t, err)
			if len(want.DAT) > 0 {
				sort.Strings(wantProg)
				sort.Strings(gotProg)
			}
			require.Equal(t, wantProg, gotProg)

			var wantEvents, gotEvents []string
			for _, e := range want.Events {
				wantEvents = append(wantEvents, e.Kind+":"+itoa(e.Index))
			}
			for _, e := range got.Report.Events {
				gotEvents = append(gotEvents, string(e.Kind)+":"+itoa(e.Index))
			}
			require.Equal(t, eventKeys(wantEvents), eventKeys(gotEvents))
		})
	}
}
