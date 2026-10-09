package mihomo

import (
	"encoding/json"
	"os"
	"sort"
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

func TestConvertProxiesRejectsNameCollisions(t *testing.T) {
	mk := func(name string) Entry {
		var n yaml.Node
		require.NoError(t, yaml.Unmarshal([]byte("{server: x.com, port: 1, cipher: aes-128-gcm, password: p}"), &n))
		return Entry{Name: name, Type: "ss", Node: n.Content[0]}
	}
	// Both CJK names sanitize to n_01.
	_, err := ConvertProxies([]Entry{mk("香港 01"), mk("日本 01")}, nil)
	require.ErrorContains(t, err, "same dae node name")
	_, err = ConvertProxies([]Entry{mk("dup"), mk("dup")}, nil)
	require.ErrorContains(t, err, "duplicate proxy")

	nodes, err := ConvertProxies([]Entry{mk("a"), mk("b")}, nil)
	require.NoError(t, err)
	names := []string{nodes[0].Safe, nodes[1].Safe}
	sort.Strings(names)
	require.Equal(t, []string{"a", "b"}, names)
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
