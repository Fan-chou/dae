package mihomo

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type groupGolden struct {
	OK           bool              `json:"ok"`
	GroupsDae    string            `json:"groups_dae"`
	GroupNameMap map[string]string `json:"group_name_map"`
	Error        string            `json:"error"`
}

// groupDeviations lists the only cases where the new conversion may differ
// from the archived sidecar. Stale entries (new behavior equals the golden)
// fail the test.
var groupDeviations = map[string]struct {
	accept bool
	reason string
}{
	"unknown_field_include_all":    {false, "unsupported group fields change membership and are rejected, not dropped"},
	"unknown_field_filter":         {false, "unsupported group fields change membership and are rejected, not dropped"},
	"unknown_field_interface_name": {false, "unsupported group fields change the transport and are rejected, not dropped"},
	"unknown_field_disable_udp":    {false, "unsupported group fields change behavior and are rejected, not dropped"},
	"group_collision_sanitized":    {true, "colliding internal names are disambiguated instead of failing"},
	"group_collision_cjk":          {true, "colliding internal names are disambiguated instead of failing"},
}

type groupCaseFile struct {
	Proxies []yaml.Node `yaml:"proxies"`
	Cases   map[string]struct {
		Groups  []yaml.Node `yaml:"groups"`
		Proxies []yaml.Node `yaml:"proxies"`
		Isolate string      `yaml:"isolate"`
	} `yaml:"cases"`
}

func entriesFrom(t *testing.T, nodes []yaml.Node) []Entry {
	t.Helper()
	out := make([]Entry, 0, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		var head struct {
			Name string `yaml:"name"`
			Type string `yaml:"type"`
		}
		require.NoError(t, n.Decode(&head))
		out = append(out, Entry{Name: head.Name, Type: head.Type, Node: n})
	}
	return out
}

func parseGoldenGroups(t *testing.T, text string) []config.Group {
	t.Helper()
	sections, err := config_parser.Parse(text)
	require.NoError(t, err)
	require.Len(t, sections, 1)
	groups, err := config.DecodeGroups(sections[0])
	require.NoError(t, err)
	return groups
}

// TestGroupConversionMatchesArchivedSidecar converts every fixture through
// ConvertGroups and compares the resulting config.Group values with what dae's
// own parser makes of the sidecar's groups.dae.
func TestGroupConversionMatchesArchivedSidecar(t *testing.T) {
	raw, err := os.ReadFile("testdata/groups/cases.yaml")
	require.NoError(t, err)
	var file groupCaseFile
	require.NoError(t, yaml.Unmarshal(raw, &file))

	golden := map[string]groupGolden{}
	body, err := os.ReadFile("testdata/groups/golden.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &golden))
	require.Equal(t, len(golden), len(file.Cases), "golden and cases out of sync; regenerate")

	for name, c := range file.Cases {
		want, ok := golden[name]
		require.True(t, ok, "no golden for %s", name)
		t.Run(name, func(t *testing.T) {
			proxyNodes := file.Proxies
			if c.Proxies != nil {
				proxyNodes = c.Proxies
			}
			nodes, err := ConvertProxies(entriesFrom(t, proxyNodes), nil)
			require.NoError(t, err)
			var opts GroupOptions
			if c.Isolate != "" {
				opts.IsolateTransportGroups = strings.Split(c.Isolate, ",")
			}
			groups, err := ConvertGroups(entriesFrom(t, c.Groups), nodes, opts)

			if dev, deviates := groupDeviations[name]; deviates {
				require.NotEqual(t, want.OK, dev.accept, "stale deviation (%s)", dev.reason)
				if !dev.accept {
					require.Error(t, err, dev.reason)
					return
				}
				require.NoError(t, err, dev.reason)
				seen := map[string]bool{}
				for _, g := range groups {
					require.False(t, seen[g.Safe], "duplicate internal name %s", g.Safe)
					seen[g.Safe] = true
					require.Equal(t, g.Safe, g.Config.Name)
				}
				return
			}
			if !want.OK {
				require.Error(t, err, "oracle rejected: %s", want.Error)
				return
			}
			require.NoError(t, err)
			wantGroups := parseGoldenGroups(t, want.GroupsDae)
			require.Len(t, groups, len(wantGroups))
			gotMap := map[string]string{}
			for i, g := range groups {
				gotMap[g.Name] = g.Safe
				require.Equal(t, wantGroups[i], g.Config, "group %q", g.Name)
			}
			require.Equal(t, want.GroupNameMap, gotMap)
		})
	}
}

func TestConvertGroupsDisplayNameSurvivesDisambiguation(t *testing.T) {
	var file groupCaseFile
	raw, err := os.ReadFile("testdata/groups/cases.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &file))
	nodes, err := ConvertProxies(entriesFrom(t, file.Proxies), nil)
	require.NoError(t, err)
	c := file.Cases["group_collision_cjk"]
	groups, err := ConvertGroups(entriesFrom(t, c.Groups), nodes, GroupOptions{})
	require.NoError(t, err)
	require.Equal(t, "香港 01", groups[0].Name)
	require.Equal(t, "日本 01", groups[1].Name)
	require.NotEqual(t, groups[0].Safe, groups[1].Safe)
	require.Regexp(t, `^n_01_[0-9a-f]{6}$`, groups[0].Safe)
}

func TestConvertGroupsYieldsToNodeNameOnSanitizedClash(t *testing.T) {
	// The group "n 1" sanitizes to n_1, which is node "n_1"'s tag: the group
	// is the one that gets a suffix.
	doc, err := Parse([]byte(`
proxies:
  - {name: n_1, type: ss, server: x.com, port: 1, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: "n 1", type: select, proxies: [n_1]}
`))
	require.NoError(t, err)
	nodes, err := ConvertProxies(doc.Proxies, nil)
	require.NoError(t, err)
	groups, err := ConvertGroups(doc.Groups, nodes, GroupOptions{})
	require.NoError(t, err)
	require.Equal(t, "n_1", nodes[0].Safe)
	require.Regexp(t, `^n_1_[0-9a-f]{6}$`, groups[0].Safe)
}

func TestConvertGroupsRejectsDeepNestingAndErrorsHideValues(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n  - {name: p, type: ss, server: x.com, port: 1, cipher: aes-128-gcm, password: TOPSECRET}\nproxy-groups:\n")
	const depth = maxNestedGroupDepth + 2
	for i := 0; i < depth; i++ {
		member := "p"
		if i+1 < depth {
			member = "g" + string(rune('a'+(i+1)/26)) + string(rune('a'+(i+1)%26))
		}
		b.WriteString("  - {name: g" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ", type: select, proxies: [" + member + "]}\n")
	}
	doc, err := Parse([]byte(b.String()))
	require.NoError(t, err)
	nodes, err := ConvertProxies(doc.Proxies, nil)
	require.NoError(t, err)
	_, err = ConvertGroups(doc.Groups, nodes, GroupOptions{})
	require.ErrorContains(t, err, "depth")
	require.NotContains(t, err.Error(), "TOPSECRET")
}
