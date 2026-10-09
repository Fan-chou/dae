package mihomo

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type nodeGolden struct {
	OK       bool   `json:"ok"`
	Name     string `json:"name"`
	Safe     string `json:"safe"`
	Protocol string `json:"type"`
	Link     string `json:"link"`
	Error    string `json:"error"`
}

// intentionalDeviations lists the only cases where the new conversion is
// allowed to differ from the archived sidecar, with the reason. A deviation
// that no longer differs from the golden is stale and fails the test.
var intentionalDeviations = map[string]struct {
	accept bool // new behavior
	reason string
}{
	"unknown_field_dialer_proxy": {false, "unsupported proxy fields are rejected; the sidecar silently dropped dialer-proxy, which changes the egress path"},
	"unknown_field_tfo":          {false, "unsupported proxy fields are rejected rather than silently dropped"},
	"bad_name_maps_to_direct":    {true, "a name that sanitizes to a reserved outbound gets a derived internal name instead of failing"},
	"bad_name_maps_to_block":     {true, "a name that sanitizes to a reserved outbound gets a derived internal name instead of failing"},
}

// TestProxyConversionMatchesArchivedSidecar replays every fixture proxy
// through ConvertProxies and compares it with testdata/nodes/golden.json,
// which hack/mihomo-oracle/gen_node_goldens.py produced from the archived
// dae-rule-sync. Accept/reject and the generated name and link must agree.
func TestProxyConversionMatchesArchivedSidecar(t *testing.T) {
	raw, err := os.ReadFile("testdata/nodes/cases.yaml")
	require.NoError(t, err)
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(raw, &root))
	mapping := root.Content[0]

	golden := map[string]nodeGolden{}
	body, err := os.ReadFile("testdata/nodes/golden.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &golden))

	seen := 0
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		caseName, node := mapping.Content[i].Value, mapping.Content[i+1]
		want, ok := golden[caseName]
		require.True(t, ok, "no golden for %s; regenerate", caseName)
		seen++
		t.Run(caseName, func(t *testing.T) {
			var head struct {
				Name string `yaml:"name"`
				Type string `yaml:"type"`
			}
			require.NoError(t, node.Decode(&head))
			nodes, err := ConvertProxies([]Entry{{Name: head.Name, Type: head.Type, Node: node}}, daeLinkValidator)
			if dev, ok := intentionalDeviations[caseName]; ok {
				require.NotEqual(t, want.OK, dev.accept, "stale deviation (%s): new behavior equals the golden", dev.reason)
				if !dev.accept {
					require.Error(t, err, dev.reason)
					return
				}
				require.NoError(t, err, dev.reason)
				require.Len(t, nodes, 1)
				require.Regexp(t, `^mihomo_[0-9a-f]{6}$`, nodes[0].Safe)
				require.Equal(t, head.Name, nodes[0].Name, "display name must stay the original")
				return
			}
			if !want.OK {
				require.Error(t, err, "oracle rejected: %s", want.Error)
				return
			}
			require.NoError(t, err)
			require.Len(t, nodes, 1)
			require.Equal(t, want.Safe, nodes[0].Safe, "safe name")
			require.Equal(t, want.Protocol, nodes[0].Protocol, "protocol")
			require.Equal(t, want.Link, nodes[0].Link, "link")
		})
	}
	require.Equal(t, len(golden), seen, "golden has cases missing from cases.yaml")
}

func ssEntry(t *testing.T, name string, extra string) Entry {
	t.Helper()
	var n yaml.Node
	body := "{server: x.com, port: 1, cipher: aes-128-gcm, password: p" + extra + "}"
	require.NoError(t, yaml.Unmarshal([]byte(body), &n))
	return Entry{Name: name, Type: "ss", Node: n.Content[0]}
}

func safeNames(nodes []Node) map[string]string {
	out := make(map[string]string, len(nodes))
	for _, n := range nodes {
		out[n.Name] = n.Safe
	}
	return out
}

func TestConvertProxiesDisambiguatesCollidingNamesAndKeepsDisplayNames(t *testing.T) {
	a, b := "香港 01", "日本 01" // both sanitize to n_01
	nodes, err := ConvertProxies([]Entry{ssEntry(t, a, ""), ssEntry(t, b, ""), ssEntry(t, "Tokyo-1", "")}, nil)
	require.NoError(t, err)
	got := safeNames(nodes)
	require.NotEqual(t, got[a], got[b])
	require.Regexp(t, `^n_01_[0-9a-f]{6}$`, got[a])
	require.Regexp(t, `^n_01_[0-9a-f]{6}$`, got[b])
	require.Equal(t, "Tokyo-1", got["Tokyo-1"], "non-colliding names stay as they were")
	for _, n := range nodes {
		require.Contains(t, []string{a, b, "Tokyo-1"}, n.Name, "Name must stay the original text")
	}

	// Order must not matter.
	reversed, err := ConvertProxies([]Entry{ssEntry(t, "Tokyo-1", ""), ssEntry(t, b, ""), ssEntry(t, a, "")}, nil)
	require.NoError(t, err)
	require.Equal(t, got, safeNames(reversed))

	// A lone name is not suffixed; its sibling appearing renames it once.
	alone, err := ConvertProxies([]Entry{ssEntry(t, a, "")}, nil)
	require.NoError(t, err)
	require.Equal(t, "n_01", safeNames(alone)[a])
}

func TestConvertProxiesDerivedNamesAvoidExistingNames(t *testing.T) {
	a, b := "香港 01", "日本 01"
	probe, err := ConvertProxies([]Entry{ssEntry(t, a, ""), ssEntry(t, b, "")}, nil)
	require.NoError(t, err)
	// A proxy literally named like a derived name must not be clobbered.
	squatter := safeNames(probe)[a]
	nodes, err := ConvertProxies([]Entry{ssEntry(t, a, ""), ssEntry(t, b, ""), ssEntry(t, squatter, "")}, nil)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, n := range nodes {
		require.False(t, seen[n.Safe], "duplicate safe name %s", n.Safe)
		seen[n.Safe] = true
	}
	require.Equal(t, squatter, safeNames(nodes)[squatter])
}

func TestConvertProxiesRejectsDuplicateAndReservedOriginals(t *testing.T) {
	_, err := ConvertProxies([]Entry{ssEntry(t, "dup", ""), ssEntry(t, "dup", "")}, nil)
	require.ErrorContains(t, err, "duplicate proxy")
	_, err = ConvertProxies([]Entry{ssEntry(t, "DIRECT", "")}, nil)
	require.ErrorContains(t, err, "reserved")
}

func TestConvertProxiesRejectsUnsupportedFieldsIncludingViaMerge(t *testing.T) {
	_, err := ConvertProxies([]Entry{ssEntry(t, "a", ", dialer-proxy: other")}, nil)
	require.ErrorContains(t, err, `unsupported field "dialer-proxy"`)
	require.NotContains(t, err.Error(), "other", "field values must not be echoed")

	// A field smuggled in through a YAML merge key is still caught.
	doc, err := Parse([]byte(`
proxies:
  - &base {name: base, type: ss, server: x.com, port: 1, cipher: aes-128-gcm, password: p, smux: {enabled: true}}
  - <<: *base
    name: derived
proxy-groups: []
`))
	require.NoError(t, err)
	_, err = ConvertProxies(doc.Proxies, nil)
	require.ErrorContains(t, err, `unsupported field "smux"`)

	doc, err = Parse([]byte(`
proxies:
  - &base {name: base, type: ss, server: x.com, port: 1, cipher: aes-128-gcm, password: p}
  - <<: *base
    name: derived
`))
	require.NoError(t, err)
	nodes, err := ConvertProxies(doc.Proxies, nil)
	require.NoError(t, err)
	require.Len(t, nodes, 2)
}

func TestConvertProxiesErrorsNeverContainCredentials(t *testing.T) {
	var n yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("{server: x.com, port: 1, cipher: aes-128-gcm, password: TOPSECRET, udp: false}"), &n))
	_, err := ConvertProxies([]Entry{{Name: "a", Type: "ss", Node: n.Content[0]}}, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "TOPSECRET")

	reject := func(string) error { return os.ErrInvalid }
	require.NoError(t, yaml.Unmarshal([]byte("{server: x.com, port: 1, cipher: aes-128-gcm, password: TOPSECRET}"), &n))
	_, err = ConvertProxies([]Entry{{Name: "a", Type: "ss", Node: n.Content[0]}}, reject)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "TOPSECRET")
}
