package mihomo

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestDescribeShowsConvertedRulesWithoutCredentials(t *testing.T) {
	doc, err := Parse([]byte(`
proxies:
  - {name: "🇭🇰 HK 01", type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: TOPSECRET}
  - {name: sock, type: socks5, server: 1.2.3.4, port: 1080, username: user, password: TOPSECRET2}
proxy-groups:
  - {name: "🚀 Proxy", type: select, proxies: ["🇭🇰 HK 01", sock, DIRECT]}
rule-providers:
  ads: {type: file, path: dom_basic.yaml, behavior: domain, interval: 3600}
sub-rules:
  child:
    - DST-PORT,443,🚀 Proxy
    - DOMAIN-SUFFIX,a.com,sock
rules:
  - RULE-SET,ads,REJECT
  - NOT,((RULE-SET,ads)),sock
  - SUB-RULE,(IP-CIDR,10.0.0.0/8,no-resolve),child
  - GEOIP,CN,DIRECT
  - DOMAIN-SUFFIX,example.com,🚀 Proxy
  - MATCH,🚀 Proxy
`))
	require.NoError(t, err)
	res, err := Convert(doc, Options{BaseDir: t.TempDir()})
	require.NoError(t, err)
	text := res.Describe()
	t.Log("\n" + text)

	require.NotContains(t, text, "TOPSECRET")
	require.NotContains(t, text, "user")
	require.Contains(t, text, `HK_HK_01 ("🇭🇰 HK 01")  ss hk.example.com:8388`)
	require.Contains(t, text, "sock  socks5 1.2.3.4:1080")
	require.Contains(t, text, `Rocket_Proxy ("🚀 Proxy")  fixed(0)`)
	require.Contains(t, text, "node_sock")
	require.Contains(t, text, "wraps a single node")
	require.Contains(t, text, "ruleset(ads) -> block")
	require.Contains(t, text, "!ruleset(ads) -> node_sock")
	require.Contains(t, text, "ip_no_resolve(10.0.0.0/8)")
	require.Contains(t, text, "fallback (from MATCH): Rocket_Proxy")
	require.Contains(t, text, "[skip] rule 3")
	require.Contains(t, text, "GEOIP,CN,DIRECT")
}

func TestDescribeCapsLongValueLists(t *testing.T) {
	var parts []string
	for i := 0; i < 50; i++ {
		parts = append(parts, "DOMAIN-SUFFIX,s"+string(rune('a'+i%26))+string(rune('a'+i/26))+".com,PROXY")
	}
	_ = parts
	got := DescribeRule(mustSingleRule(t, "DOMAIN-SUFFIX,a.com,PROXY"))
	require.Equal(t, "domain(suffix: a.com) -> PROXY", got)
	// Merged run of many same-outbound rules collapses to one capped line.
	var rules []Rule
	for i := 0; i < 40; i++ {
		rules = append(rules, Rule{Raw: "DOMAIN-SUFFIX,site" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + ".com,PROXY", Index: i})
	}
	lowered, err := LowerRules(rules, nil, RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY"}})
	require.NoError(t, err)
	require.Len(t, lowered.Rules, 1)
	line := DescribeRule(lowered.Rules[0])
	require.Contains(t, line, "… +34 more")
	require.Less(t, len(line), 200)
}

func mustSingleRule(t *testing.T, raw string) *config_parser.RoutingRule {
	t.Helper()
	lowered, err := LowerRules([]Rule{{Raw: raw}}, nil, RuleEnv{Outbounds: map[string]string{"PROXY": "PROXY"}})
	require.NoError(t, err)
	require.Len(t, lowered.Rules, 1)
	return lowered.Rules[0]
}
