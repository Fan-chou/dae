package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfigExpandsHardenedNativeRuleProvider(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte("payload:\n  - example.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	configPath := filepath.Join(dir, "config.dae")
	configBody := `global {}
rule_provider {
  local {
    type: file
    path: rules.yaml
    behavior: domain
    format: yaml
  }
}
routing {
  ruleset(local) -> proxy
  fallback: direct
}
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	conf, _, err := readConfig(configPath)
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
	}
	if len(conf.Routing.Rules) != 1 || conf.Routing.Rules[0].AndFunctions[0].Name != "domain" {
		t.Fatalf("routing rules = %#v", conf.Routing.Rules)
	}
	if got := conf.Routing.Rules[0].AndFunctions[0].Params[0].Val; got != "example.com" {
		t.Fatalf("domain = %q", got)
	}
}

func TestReadConfigUsesFileProviderLastGoodAfterSourceDisappears(t *testing.T) {
	dir := t.TempDir()
	providerPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(providerPath, []byte("payload:\n  - first.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(provider) error = %v", err)
	}
	configPath := filepath.Join(dir, "config.dae")
	configBody := `global {}
rule_provider {
  local {
    type: file
    path: rules.yaml
    behavior: domain
    format: yaml
  }
}
routing {
  ruleset(local) -> proxy
  fallback: direct
}
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	first, _, err := readConfig(configPath)
	if err != nil {
		t.Fatalf("initial readConfig() error = %v", err)
	}
	if len(first.Routing.Rules) != 1 || first.Routing.Rules[0].AndFunctions[0].Params[0].Val != "first.example" {
		t.Fatalf("initial routing rules = %#v", first.Routing.Rules)
	}
	if err := os.Remove(providerPath); err != nil {
		t.Fatalf("Remove(provider) error = %v", err)
	}

	second, _, err := readConfig(configPath)
	if err != nil {
		t.Fatalf("readConfig() after provider disappearance error = %v, want last-good snapshot", err)
	}
	if len(second.Routing.Rules) != 1 || second.Routing.Rules[0].AndFunctions[0].Params[0].Val != "first.example" {
		t.Fatalf("last-good routing rules = %#v", second.Routing.Rules)
	}
}
