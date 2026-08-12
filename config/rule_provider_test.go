package config

import (
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
