package mihomo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type providerCaseFile struct {
	Cases map[string]struct {
		Providers map[string]struct {
			File     string `yaml:"file"`
			Type     string `yaml:"type"`
			URL      string `yaml:"url"`
			Path     string `yaml:"path"`
			Behavior string `yaml:"behavior"`
			Format   string `yaml:"format"`
			Interval int64  `yaml:"interval"`
		} `yaml:"providers"`
		Rules    []string            `yaml:"rules"`
		SubRules map[string][]string `yaml:"sub_rules"`
		NoMatch  bool                `yaml:"no_match"`
	} `yaml:"cases"`
}

type providerGolden struct {
	OK        bool              `json:"ok"`
	Error     string            `json:"error"`
	RoutesDae string            `json:"routes_dae"`
	DAT       map[string]string `json:"dat"`
	Events    []struct {
		Kind  string `json:"kind"`
		Index int    `json:"index"`
	} `json:"events"`
}

// providerDeviations lists the only cases where the new pipeline may differ
// from the archived sidecar; a stale entry fails the test.
var providerDeviations = map[string]string{
	// The sidecar treats CIDR text in a domain provider as domain suffixes
	// that can never match a host; the native provider parser rejects it
	// (fail closed) rather than keep dead entries.
	"rs_fatal_behavior_mismatch_cidr_in_domain": "native providers reject CIDR entries in a domain provider",
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		dest := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, body, 0o600)
	}))
}

// expandExt replaces ext: parameters (the sidecar's DAT references) with the
// entries they stand for, using dae's own DAT reader, in plain rules and
// inside route_expr trees.
func expandExt(t *testing.T, rules []*config_parser.RoutingRule, assetDir string) []*config_parser.RoutingRule {
	t.Helper()
	log := logrus.New()
	log.SetOutput(os.Stderr)
	opt := &routing.DatReaderOptimizer{LocationFinder: assets.NewLocationFinder([]string{assetDir}), Logger: log}
	expandAtom := func(f *config_parser.Function) *config_parser.Function {
		has := false
		for _, p := range f.Params {
			has = has || p.Key == "ext"
		}
		if !has {
			return f
		}
		out, err := opt.Optimize([]*config_parser.RoutingRule{{AndFunctions: []*config_parser.Function{f}, Outbound: config_parser.Function{Name: "x"}}})
		require.NoError(t, err)
		require.Len(t, out, 1)
		return out[0].AndFunctions[0]
	}
	var walk func(e *routing.OrderedExpr)
	walk = func(e *routing.OrderedExpr) {
		if e.Op == "atom" {
			e.Atom = expandAtom(e.Atom)
			return
		}
		for _, c := range e.Children {
			walk(c)
		}
	}
	out := make([]*config_parser.RoutingRule, 0, len(rules))
	for _, r := range routing.DeepCloneRules(rules) {
		for i, f := range r.AndFunctions {
			if f.Name == "route_expr" {
				e, err := routing.DecodeOrderedExpr(f)
				require.NoError(t, err)
				walk(e)
				enc, err := routing.EncodeOrderedExpr(e)
				require.NoError(t, err)
				r.AndFunctions[i] = enc
				continue
			}
			r.AndFunctions[i] = expandAtom(f)
		}
		out = append(out, r)
	}
	return out
}

// convertWithProviders runs the whole path: declarations, rules, then the
// native provider loader and expansion. A returned error is a fatal one.
func convertWithProviders(t *testing.T, c struct {
	Providers map[string]struct {
		File     string `yaml:"file"`
		Type     string `yaml:"type"`
		URL      string `yaml:"url"`
		Path     string `yaml:"path"`
		Behavior string `yaml:"behavior"`
		Format   string `yaml:"format"`
		Interval int64  `yaml:"interval"`
	} `yaml:"providers"`
	Rules    []string            `yaml:"rules"`
	SubRules map[string][]string `yaml:"sub_rules"`
	NoMatch  bool                `yaml:"no_match"`
}, baseDir string) (*LoweredRules, []*config_parser.RoutingRule, error) {
	names := make([]string, 0, len(c.Providers))
	for n := range c.Providers {
		names = append(names, n)
	}
	sort.Strings(names)
	var declared []Provider
	for _, n := range names {
		p := c.Providers[n]
		typ := p.Type
		if typ == "" && p.URL == "" {
			typ = "file"
		}
		path := p.Path
		if path == "" {
			path = p.File
		}
		declared = append(declared, Provider{Name: n, Type: typ, URL: p.URL, Path: path, Behavior: p.Behavior, Format: p.Format,
			Interval: time.Duration(p.Interval) * time.Second})
	}
	table, err := NewProviderTable(declared, baseDir)
	if err != nil {
		return nil, nil, err
	}

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
	got, err := LowerRules(rules, subs, RuleEnv{
		Providers: table.Names(),
		Outbounds: map[string]string{"PROXY": "PROXY", "OTHER": "OTHER"},
	})
	if err != nil {
		return nil, nil, err
	}
	selected, err := table.Select(got.UsedProviders)
	if err != nil {
		return nil, nil, err
	}
	registry, err := ruleprovider.Load(context.Background(), selected, baseDir, nil)
	if err != nil {
		return nil, nil, err
	}
	expanded, err := ruleprovider.ExpandRoutingRules(got.Rules, registry)
	if err != nil {
		return nil, nil, err
	}
	return got, expanded, nil
}

// TestProviderPipelineMatchesArchivedSidecar converts every provider fixture
// and compares the routing program, after native provider expansion, with the
// sidecar's (whose large providers are DAT references that are expanded with
// dae's DAT reader first). Fatal-versus-not and the skipped rules must agree.
func TestProviderPipelineMatchesArchivedSidecar(t *testing.T) {
	var file providerCaseFile
	raw, err := os.ReadFile("testdata/providers/cases.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &file))
	golden := map[string]providerGolden{}
	body, err := os.ReadFile("testdata/providers/golden.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &golden))
	require.Equal(t, len(golden), len(file.Cases), "golden and cases out of sync; regenerate")

	for name, c := range file.Cases {
		want := golden[name]
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			copyTree(t, "testdata/providers/files", baseDir)
			got, expanded, err := convertWithProviders(t, c, baseDir)

			if reason, ok := providerDeviations[name]; ok {
				require.True(t, want.OK, "stale deviation: the sidecar now rejects it")
				require.Error(t, err, reason)
				return
			}
			if !want.OK {
				require.Error(t, err, "oracle rejected: %s", want.Error)
				return
			}
			require.NoError(t, err)

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
			if name == "rs_classical_wildcard_unquoted" {
				// devRegexEscape: undo the sidecar's doubled backslashes.
				for _, r := range wantRules {
					for _, f := range r.AndFunctions {
						for _, p := range f.Params {
							if p.Key == "regex" {
								p.Val = strings.ReplaceAll(p.Val, `\\`, `\`)
							}
						}
					}
				}
			}

			wantProg, err := canonProgram(wantRules, wantFallback)
			require.NoError(t, err)
			gotProg, err := canonProgram(expanded, got.Fallback)
			require.NoError(t, err)
			if len(want.DAT) > 0 {
				// One provider rule: its entries are alternatives, and the
				// DAT stores them in its own order.
				sort.Strings(wantProg)
				sort.Strings(gotProg)
			}
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
