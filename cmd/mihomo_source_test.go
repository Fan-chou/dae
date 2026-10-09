package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/stretchr/testify/require"
)

const testMihomoYAML = `
proxies:
  - {name: "🇭🇰 HK 01", type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: pw}
  - {name: sock, type: socks5, server: 1.2.3.4, port: 1080}
proxy-groups:
  - {name: "🚀 Proxy", type: select, proxies: ["🇭🇰 HK 01", sock, DIRECT]}
rule-providers:
  ads: {type: file, path: ads.yaml, behavior: domain}
rules:
  - RULE-SET,ads,REJECT
  - DOMAIN-SUFFIX,example.com,🚀 Proxy
  - DOMAIN,direct.example.org,sock
  - MATCH,🚀 Proxy
`

func writeMihomoFixture(t *testing.T, mihomoBody string) (dir, configPath string) {
	t.Helper()
	dir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ads.yaml"), []byte("payload:\n  - ads.example.net\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mihomo.yaml"), []byte(mihomoBody), 0o600))
	configPath = filepath.Join(dir, "config.dae")
	require.NoError(t, os.WriteFile(configPath, []byte(`global {}
node {
  mine: 'socks5://9.9.9.9:1080'
}
group {
  hand {
    filter: name(mine)
    policy: min_moving_avg
  }
}
mihomo {
  routing_file: 'mihomo.yaml'
}
routing {
  dip(224.0.0.0/3) -> must_direct
  fallback: direct
}
`), 0o600))
	return dir, configPath
}

func TestReadConfigMergesMihomoSourceAfterHandWrittenConfig(t *testing.T) {
	_, configPath := writeMihomoFixture(t, testMihomoYAML)
	conf, _, err := readConfig(configPath)
	require.NoError(t, err)

	// Nodes: the hand-written one first, then the converted ones as tag:link.
	require.Len(t, conf.Node, 3)
	require.Equal(t, config.KeyableString("mine:socks5://9.9.9.9:1080"), conf.Node[0])
	require.True(t, strings.HasPrefix(string(conf.Node[1]), "HK_HK_01:ss://"))
	require.Equal(t, config.KeyableString("sock:socks5://1.2.3.4:1080"), conf.Node[2])

	// Groups: hand-written first; the converted group, then a wrapper for the
	// proxy a rule names directly.
	names := make([]string, len(conf.Group))
	for i, g := range conf.Group {
		names[i] = g.Name
	}
	require.Equal(t, []string{"hand", "Rocket_Proxy", "node_sock"}, names)

	// Routing: the hand-written rule keeps priority, the rule set is expanded,
	// and the Mihomo MATCH decides the fallback.
	require.GreaterOrEqual(t, len(conf.Routing.Rules), 4)
	require.Equal(t, "dip", conf.Routing.Rules[0].AndFunctions[0].Name)
	last := conf.Routing.Rules[len(conf.Routing.Rules)-1]
	require.Equal(t, "node_sock", last.Outbound.Name)
	fallback, err := config.ParseFunctionOrString(conf.Routing.Fallback)
	require.NoError(t, err)
	require.Equal(t, "Rocket_Proxy", fallback.Name)

	status := CurrentMihomoStatus()
	require.True(t, status.Enabled)
	require.Empty(t, status.Error)
	require.False(t, status.UsedLastGood)
	require.Equal(t, 2, status.Nodes)
	require.Equal(t, 2, status.Groups)
	require.Equal(t, "mihomo.yaml", status.Source)
}

func TestReadConfigUsesLastGoodMihomoSource(t *testing.T) {
	dir, configPath := writeMihomoFixture(t, testMihomoYAML)
	first, _, err := readConfig(configPath)
	require.NoError(t, err)

	// A source that does not convert must not replace the one in use.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mihomo.yaml"), []byte("proxies: [{name: a, type: vmess, server: x, port: 1}]\nproxy-groups: []\nrules: []\n"), 0o600))
	second, _, err := readConfig(configPath)
	require.NoError(t, err)
	require.Equal(t, first.Node, second.Node)
	require.Equal(t, len(first.Group), len(second.Group))
	require.True(t, CurrentMihomoStatus().UsedLastGood)

	// So does a source that disappeared.
	require.NoError(t, os.Remove(filepath.Join(dir, "mihomo.yaml")))
	third, _, err := readConfig(configPath)
	require.NoError(t, err)
	require.Equal(t, first.Node, third.Node)
	require.True(t, CurrentMihomoStatus().UsedLastGood)

	// A valid change is picked up.
	changed := strings.Replace(testMihomoYAML, "sock, type: socks5, server: 1.2.3.4", "sock, type: socks5, server: 5.6.7.8", 1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mihomo.yaml"), []byte(changed), 0o600))
	fourth, _, err := readConfig(configPath)
	require.NoError(t, err)
	require.Contains(t, string(fourth.Node[2]), "5.6.7.8")
	require.False(t, CurrentMihomoStatus().UsedLastGood)
}

func TestReadConfigFailsWithoutAnyUsableMihomoSource(t *testing.T) {
	_, configPath := writeMihomoFixture(t, "proxies: []\n")
	_, _, err := readConfig(configPath)
	require.Error(t, err)
	status := CurrentMihomoStatus()
	require.NotEmpty(t, status.Error)
	require.True(t, status.Enabled)
}

func TestReadConfigRejectsClashesWithHandWrittenNames(t *testing.T) {
	for name, body := range map[string]string{
		"group": strings.Replace(testMihomoYAML, `"🚀 Proxy"`, "hand", -1),
		"node":  strings.NewReplacer("{name: sock,", "{name: mine,", "HK 01\", sock,", "HK 01\", mine,", ",DIRECT]", ",DIRECT]", "sock, DIRECT", "mine, DIRECT", "direct.example.org,sock", "direct.example.org,mine").Replace(testMihomoYAML),
	} {
		t.Run(name, func(t *testing.T) {
			_, configPath := writeMihomoFixture(t, body)
			_, _, err := readConfig(configPath)
			require.Error(t, err)
			require.Contains(t, err.Error(), "clashes")
		})
	}
}

func TestReadConfigReservesTheMihomoDocumentName(t *testing.T) {
	dir, _ := writeMihomoFixture(t, testMihomoYAML)
	configPath := filepath.Join(dir, "reserved.dae")
	require.NoError(t, os.WriteFile(configPath, []byte(`global {}
rule_provider {
  mihomo-routing {
    type: file
    path: ads.yaml
    behavior: domain
  }
}
mihomo { routing_file: 'mihomo.yaml' }
routing { fallback: direct }
`), 0o600))
	_, _, err := readConfig(configPath)
	require.ErrorContains(t, err, "reserved")
}

func TestMihomoSubscriptionTokenNeverReachesErrorsOrStatus(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	require.NoError(t, os.WriteFile(configPath, []byte(`global {}
mihomo { routing_subscription: 'https://mihomo-source.invalid/sub?token=TOPSECRET' }
routing { fallback: direct }
`), 0o600))
	start := time.Now()
	_, _, err := readConfig(configPath)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "TOPSECRET")
	status := CurrentMihomoStatus()
	require.NotContains(t, status.Error, "TOPSECRET")
	require.NotContains(t, status.Source, "TOPSECRET")
	require.Equal(t, "https://mihomo-source.invalid/…", status.Source)
	require.Less(t, time.Since(start), time.Minute)
}

func TestMihomoDisabledLeavesConfigUntouched(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	require.NoError(t, os.WriteFile(configPath, []byte("global {}\nrouting { fallback: direct }\n"), 0o600))
	conf, _, err := readConfig(configPath)
	require.NoError(t, err)
	require.Empty(t, conf.Node)
	require.Empty(t, conf.Group)
	require.False(t, CurrentMihomoStatus().Enabled)
}

func TestRuleProviderRefreshIntervalIncludesMihomoSource(t *testing.T) {
	conf := &config.Config{Mihomo: config.Mihomo{RoutingFile: "m.yaml", Interval: 30 * time.Minute}}
	require.Equal(t, 30*time.Minute, ruleProviderRefreshInterval(conf))
	conf.RuleProvider = []config.RuleProvider{{Name: "a", Interval: 10 * time.Minute}}
	require.Equal(t, 10*time.Minute, ruleProviderRefreshInterval(conf))
	conf.Mihomo.Interval = 0
	conf.RuleProvider = nil
	require.Zero(t, ruleProviderRefreshInterval(conf))
}

func TestPreviewShowsMergeWithoutCredentials(t *testing.T) {
	_, configPath := writeMihomoFixture(t, testMihomoYAML)
	var out strings.Builder
	require.NoError(t, previewMihomo(context.Background(), configPath, &out))
	text := out.String()
	t.Log("\n" + text)

	require.NotContains(t, text, "pw", "node passwords must not be printed")
	require.NotContains(t, text, "socks5://")
	require.NotContains(t, text, "ss://")
	// Hand-written first, Mihomo's after, in that order.
	handRule := strings.Index(text, "dip(224.0.0.0/3) -> direct(must)")
	mihomoRule := strings.Index(text, "ruleset(ads) -> block")
	require.True(t, handRule >= 0 && mihomoRule > handRule, "hand-written rule must precede Mihomo rules")
	require.Contains(t, text, "== added from the Mihomo source")
	require.Contains(t, text, "fallback: Rocket_Proxy (from the Mihomo MATCH, replacing the configured one)")
	require.Contains(t, text, "3 nodes, 3 groups")
}

func TestPreviewReportsAClash(t *testing.T) {
	_, configPath := writeMihomoFixture(t, strings.ReplaceAll(testMihomoYAML, `"🚀 Proxy"`, "hand"))
	var out strings.Builder
	err := previewMihomo(context.Background(), configPath, &out)
	require.Error(t, err)
	require.Contains(t, out.String(), "cannot merge")
}

func TestPreviewWithoutMihomoSource(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	require.NoError(t, os.WriteFile(configPath, []byte("global {}\nrouting { fallback: direct }\n"), 0o600))
	var out strings.Builder
	require.NoError(t, previewMihomo(context.Background(), configPath, &out))
	require.Contains(t, out.String(), "No mihomo routing source")
}

func writeSubscriptionConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.dae")
	require.NoError(t, os.WriteFile(path, []byte(`global {}
node {
  mine: 'socks5://9.9.9.9:1080'
}
mihomo {
  routing_subscription: 'https://sub.invalid/token-abc123'
  interval: 1h
}
routing {
  fallback: direct
}
`), 0o600))
	return path
}

func TestStartupToleratesUnreachableSourceWithoutACopy(t *testing.T) {
	path := writeSubscriptionConfig(t)

	// A reload must not: a mistyped URL cannot replace working routing.
	_, _, err := readConfig(path)
	require.Error(t, err)

	conf, _, err := readConfigAtStartup(path)
	require.NoError(t, err)
	require.Len(t, conf.Node, 1)
	require.Equal(t, "direct", conf.Routing.Fallback)

	status := CurrentMihomoStatus()
	require.True(t, status.Degraded)
	require.NotEmpty(t, status.Error)
	require.Contains(t, mihomoWarning(status), "running without it")
	require.NotContains(t, status.Error+status.Source, "token-abc123")

	// It keeps trying soon, even though the configured interval is an hour.
	require.Equal(t, time.Hour, ruleProviderRefreshInterval(conf))
}

func TestStartupStillRejectsABrokenLocalSource(t *testing.T) {
	_, path := writeMihomoFixture(t, "proxies: [")
	_, _, err := readConfigAtStartup(path)
	require.Error(t, err)
}

func TestPreviewErrorKeepsSubscriptionTokenOut(t *testing.T) {
	path := writeSubscriptionConfig(t)
	var out strings.Builder
	err := previewMihomo(context.Background(), path, &out)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "token-abc123")
}
