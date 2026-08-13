package config

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestNewParsesRuleProviderSectionAndRulesetRoute(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
rule_provider {
  openai {
    type: http
    url: "https://example.com/openai.yaml"
    behavior: domain
    format: yaml
    path: "persist.d/openai.yaml"
    interval: 2h
    max_size: 8388608
  }
}
routing {
  ruleset(openai) -> proxy
  fallback: proxy
}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	require.Len(t, conf.RuleProvider, 1)
	require.Equal(t, "openai", conf.RuleProvider[0].Name)
	require.Equal(t, "http", conf.RuleProvider[0].Type)
	require.Equal(t, 2*time.Hour, conf.RuleProvider[0].Interval)
	require.EqualValues(t, 8388608, conf.RuleProvider[0].MaxSize)
	require.Len(t, conf.Routing.Rules, 1)
	require.Equal(t, "ruleset", conf.Routing.Rules[0].AndFunctions[0].Name)
}

func TestValidateRuleProvidersRejectsDuplicateNamesAndUnsafePaths(t *testing.T) {
	providers := []RuleProvider{
		{Name: "same", Type: "http", URL: "https://example.com/a", Behavior: "domain", Format: "yaml"},
		{Name: "same", Type: "file", Path: "../outside.yaml", Behavior: "domain", Format: "yaml"},
	}
	err := ValidateRuleProviders(providers, "/etc/dae")
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")
}

func TestValidateRuleProvidersRejectsUnsupportedBehavior(t *testing.T) {
	providers := []RuleProvider{{
		Name:     "p",
		Type:     "http",
		URL:      "https://example.com/p",
		Behavior: "script",
		Format:   "yaml",
	}}
	err := ValidateRuleProviders(providers, "/etc/dae")
	require.Error(t, err)
	require.Contains(t, err.Error(), "behavior")
}

func TestValidateRuleProvidersRejectsSpecialBlockedAddressRanges(t *testing.T) {
	for _, rawURL := range []string{
		"http://0.0.0.1/rules.yaml", "http://100.64.0.1/rules.yaml",
		"http://192.0.2.1/rules.yaml", "http://198.18.0.1/rules.yaml",
		"http://198.51.100.1/rules.yaml", "http://203.0.113.1/rules.yaml",
		"http://100.100.100.200/rules.yaml", "http://168.63.129.16/rules.yaml",
		"http://169.254.169.254/rules.yaml", "http://192.88.99.1/rules.yaml", "http://240.0.0.1/rules.yaml",
		"http://255.255.255.255/rules.yaml", "http://[2001:db8::1]/rules.yaml",
	} {
		err := ValidateRuleProviders([]RuleProvider{{
			Name: "blocked", Type: "http", URL: rawURL,
			Behavior: "domain", Format: "yaml",
		}}, "/etc/dae")
		require.Error(t, err, "url %s", rawURL)
	}
}

func TestBlockedRuleProviderIPRejectsSixToFourRelayRange(t *testing.T) {
	if !blockedRuleProviderIP(net.ParseIP("192.88.99.1")) {
		t.Fatal("blockedRuleProviderIP(192.88.99.1) = false, want true")
	}
}

func TestValidateRuleProvidersRejectsReservedIPv6Ranges(t *testing.T) {
	for _, rawURL := range []string{
		"http://[2001:0::1]/rules.yaml",
		"http://[2001:2::1]/rules.yaml",
		"http://[2001:10::1]/rules.yaml",
		"http://[2001:20::1]/rules.yaml",
		"http://[fec0::1]/rules.yaml",
		"http://[64:ff9b::a00:1]/rules.yaml",
		"http://[64:ff9b::a9fe:a9fe]/rules.yaml",
		"http://[64:ff9b:1::a00:1]/rules.yaml",
		"http://[2002:7f00:1::1]/rules.yaml",
		"http://[100:0:0:1::1]/rules.yaml",
		"http://[5f00::1]/rules.yaml",
		"http://[3fff::1]/rules.yaml",
		"http://[100::1]/rules.yaml",
	} {
		err := ValidateRuleProviders([]RuleProvider{{
			Name: "blocked", Type: "http", URL: rawURL,
			Behavior: "domain", Format: "yaml",
		}}, "/etc/dae")
		require.Error(t, err, "url %s", rawURL)
	}
}

func TestValidateRuleProvidersRedactsCredentialsFromMalformedURL(t *testing.T) {
	rawURL := "http://user:stage1-secret%zz@example.com/rules"
	err := ValidateRuleProviders([]RuleProvider{{
		Name: "credentialed", Type: "http", URL: rawURL,
		Behavior: "domain", Format: "yaml",
	}}, "/etc/dae")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "user")
	require.NotContains(t, err.Error(), "stage1-secret")
}
