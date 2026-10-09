package mihomo

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const fullDoc = `
mixed-port: 7890
proxies:
  - {name: a, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: SECRET}
  - name: b
    type: socks5
    server: 1.2.3.4
    port: 1080
proxy-groups:
  - {name: PROXY, type: select, proxies: [a, b, DIRECT]}
rule-providers:
  ads:
    type: http
    url: "https://example.com/ads.yaml"
    behavior: domain
    interval: 3600
rules:
  - DOMAIN-SUFFIX,example.com,PROXY
  - RULE-SET,ads,REJECT
  - MATCH,PROXY
sub-rules:
  extra:
    - DOMAIN,x.example.com,DIRECT
script:
  shortcuts:
    q: "x"
`

func TestParseExtractsSectionsInSourceOrder(t *testing.T) {
	doc, err := Parse([]byte(fullDoc))
	require.NoError(t, err)
	require.Len(t, doc.Proxies, 2)
	require.Equal(t, "a", doc.Proxies[0].Name)
	require.Equal(t, "ss", doc.Proxies[0].Type)
	require.Equal(t, "socks5", doc.Proxies[1].Type)
	require.Len(t, doc.Groups, 1)
	require.Equal(t, "PROXY", doc.Groups[0].Name)
	require.Len(t, doc.Providers, 1)
	require.Equal(t, time.Hour, doc.Providers[0].Interval)
	require.Equal(t, []string{"DOMAIN-SUFFIX,example.com,PROXY", "RULE-SET,ads,REJECT", "MATCH,PROXY"},
		[]string{doc.Rules[0].Raw, doc.Rules[1].Raw, doc.Rules[2].Raw})
	require.Equal(t, 2, doc.Rules[2].Index)
	require.Len(t, doc.SubRules, 1)
	require.Equal(t, "extra", doc.SubRules[0].Name)
	require.True(t, doc.ScriptPresent)
	require.Equal(t, []string{"mixed-port"}, doc.Ignored)
}

func TestParseAllowsAnchorsAndMerge(t *testing.T) {
	doc, err := Parse([]byte(`
proxies:
  - &base {name: a, type: ss, server: example.com, port: 1, cipher: aes-128-gcm, password: p}
  - <<: *base
    name: b
`))
	require.NoError(t, err)
	require.Len(t, doc.Proxies, 2)
	require.Equal(t, "b", doc.Proxies[1].Name)
	require.Equal(t, "ss", doc.Proxies[1].Type)
}

func TestParseRejectsAliasBomb(t *testing.T) {
	var b strings.Builder
	b.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 12; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [%s]\n", i, i, strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*a%d, ", i-1), 10), ", "))
	}
	_, err := Parse([]byte(b.String()))
	require.Error(t, err)
	require.Contains(t, err.Error(), "expanded YAML nodes")
}

func TestParseRejectsDeepNesting(t *testing.T) {
	_, err := Parse([]byte("k: " + strings.Repeat("[", MaxYAMLDepth+5) + strings.Repeat("]", MaxYAMLDepth+5)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "nesting")
}

func TestParseRejectsMalformedStructure(t *testing.T) {
	for name, body := range map[string]string{
		"empty":              ``,
		"multi doc":          "a: 1\n---\nb: 2\n",
		"top level sequence": "- a\n",
		"duplicate key":      "rules: []\nrules: []\n",
		"proxies not list":   "proxies: {a: b}\n",
		"proxy not mapping":  "proxies: [x]\n",
		"proxy without name": "proxies: [{type: ss}]\n",
		"rule not string":    "rules: [{a: b}]\n",
		"rule numeric":       "rules: [1]\n",
		"sub-rule not list":  "sub-rules: {a: b}\n",
		"provider not map":   "rule-providers: {a: b}\n",
		"negative interval":  "rule-providers: {a: {type: http, interval: -1}}\n",
		"duplicate provider": "rule-providers: {a: {type: http}, a: {type: http}}\n",
		"duplicate sub-rule": "sub-rules: {a: [], a: []}\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(body))
			require.Error(t, err)
		})
	}
}

// Values (passwords, URLs, rule text) must never appear in errors; names of
// proxies, groups and providers are identifiers and may.
func TestParseErrorsNeverEchoDocumentContent(t *testing.T) {
	for _, body := range []string{
		"proxies:\n  - {name: a, type: ss, password: TOPSECRET\n",
		"rules: [{TOPSECRET: b}]\n",
		"proxies: [TOPSECRET]\n",
		"rule-providers: {p: {type: http, url: TOPSECRET, interval: -1}}\n",
		"rule-providers: {p: {interval: TOPSECRET}}\n",
	} {
		_, err := Parse([]byte(body))
		require.Error(t, err)
		require.NotContains(t, err.Error(), "TOPSECRET", body)
	}
}

func TestParseNullSectionsAreEmpty(t *testing.T) {
	doc, err := Parse([]byte("proxies:\nproxy-groups:\nrules:\nsub-rules:\nrule-providers:\n"))
	require.NoError(t, err)
	require.Empty(t, doc.Proxies)
	require.Empty(t, doc.Rules)
}
