package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/ruleprovider"
)

func TestReadConfigRejectsNativeRuleProviderBeforeSecurityHardening(t *testing.T) {
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
	if _, _, err := readConfig(configPath); !errors.Is(err, ruleprovider.ErrProductionRuntimeDisabled) {
		t.Fatalf("readConfig() error = %v, want %v", err, ruleprovider.ErrProductionRuntimeDisabled)
	}
}
