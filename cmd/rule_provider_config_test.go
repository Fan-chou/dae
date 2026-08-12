package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfigExpandsNativeRuleProvider(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte("payload:\n  - example.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	configPath := filepath.Join(dir, "dae.conf")
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
