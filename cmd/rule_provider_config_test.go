package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/sirupsen/logrus"
)

func seedCachedHTTPProvider(t *testing.T, baseDir, name, rawURL, behavior, format string, maxSize int64, body []byte, updatedAt time.Time, batchID string) {
	t.Helper()
	if maxSize == 0 {
		maxSize = 8 << 20
	}
	sumBytes := sha256.Sum256(body)
	bodySHA := hex.EncodeToString(sumBytes[:])
	keySum := sha256.Sum256([]byte(strings.Join([]string{
		name,
		"http",
		rawURL,
		behavior,
		format,
		strconv.FormatInt(maxSize, 10),
		"2",
	}, "\x00")))
	sourceKey := hex.EncodeToString(keySum[:])

	persistRoot := filepath.Join(baseDir, "persist.d")
	providersRoot := filepath.Join(persistRoot, "rule-providers")
	root := filepath.Join(providersRoot, name)
	verDir := filepath.Join(root, "versions", "v1")
	for _, d := range []string{persistRoot, providersRoot, root, filepath.Join(root, "versions"), verDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", d, err)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatalf("Chmod(%q) error = %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(verDir, "body"), body, 0o600); err != nil {
		t.Fatalf("WriteFile(body) error = %v", err)
	}
	meta := map[string]any{
		"schema_version": 2,
		"provider_name":  name,
		"source_type":    "http",
		"source":         rawURL,
		"source_key":     sourceKey,
		"behavior":       behavior,
		"format":         format,
		"max_size":       maxSize,
		"sha256":         bodySHA,
		"updated_at":     updatedAt.UTC().Format(time.RFC3339Nano),
		"batch_identity": batchID,
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("Marshal(metadata) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(verDir, "metadata.json"), metaJSON, 0o600); err != nil {
		t.Fatalf("WriteFile(metadata) error = %v", err)
	}
	if err := os.Symlink(filepath.Join("versions", "v1"), filepath.Join(root, "current")); err != nil {
		t.Fatalf("Symlink(current) error = %v", err)
	}
}

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

func TestReadConfigAtStartupReusesExpiredConsistentHTTPRuleProviders(t *testing.T) {
	t.Cleanup(func() {
		setRuleProviderStatus(RuleProviderStatus{})
		setMihomoStatus(MihomoStatus{})
	})
	dir := t.TempDir()
	const batchID = "0123456789abcdef0123456789abcdef"
	expired := time.Now().Add(-3 * time.Hour)
	seedCachedHTTPProvider(t, dir, "a", "https://a.invalid/rules.yaml", "domain", "yaml", 0, []byte("payload:\n  - a.example\n"), expired, batchID)
	seedCachedHTTPProvider(t, dir, "b", "https://b.invalid/rules.yaml", "domain", "yaml", 0, []byte("payload:\n  - b.example\n"), expired, batchID)

	configPath := filepath.Join(dir, "config.dae")
	configBody := `global {}
rule_provider {
  a {
    type: http
    url: 'https://a.invalid/rules.yaml'
    behavior: domain
    format: yaml
    interval: 1h
  }
  b {
    type: http
    url: 'https://b.invalid/rules.yaml'
    behavior: domain
    format: yaml
    interval: 1h
  }
}
routing {
  ruleset(a) -> proxy
  ruleset(b) -> direct
  fallback: direct
}
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	// Strict reload hits the network and falls back to the shared batch with UsedLastGood=true,
	// whereas cold start reuses the expired consistent disk batch directly without touching network.
	if _, _, err := readConfig(configPath); err != nil {
		t.Fatalf("readConfig() with consistent fallback cache failed: %v", err)
	}
	if !CurrentRuleProviderStatus().UsedLastGood || CurrentRuleProviderStatus().Error == "" {
		t.Fatalf("expected strict reload fallback to record UsedLastGood and Warning, got %#v", CurrentRuleProviderStatus())
	}

	setRuleProviderStatus(RuleProviderStatus{})
	start := time.Now()
	conf, _, err := readConfigAtStartup(configPath)
	if err != nil {
		t.Fatalf("readConfigAtStartup() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("readConfigAtStartup() took %v reusing disk cache, want fast startup", elapsed)
	}
	if len(conf.Routing.Rules) != 2 {
		t.Fatalf("routing rules count = %d, want 2 expanded rules", len(conf.Routing.Rules))
	}
	if st := CurrentRuleProviderStatus(); st.Degraded || st.UsedLastGood || st.Error != "" {
		t.Fatalf("expected clean cache-reuse status without network fallback, got %#v", st)
	}
	oldest, ok := ruleprovider.OldestCheck(conf.RuleProvider, nil, dir)
	if !ok || time.Since(oldest) < 2*time.Hour {
		t.Fatalf("OldestCheck = %v ok=%v, want expired age retained for background refresh", oldest, ok)
	}

	rm := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), nil)
	holder, _, err := newRuleProviderLifecycleHolder(conf, dir, ruleProviderRefreshInterval(conf), rm, logrus.New())
	if err != nil {
		t.Fatalf("newRuleProviderLifecycleHolder() error = %v", err)
	}
	if wait := holder.initialWait(time.Hour)(); wait != initialRefreshFloor {
		t.Fatalf("initialWait() = %v, want %v so expired reused cache refreshes promptly", wait, initialRefreshFloor)
	}
}

func TestReadConfigAtStartupSurvivesUnreachableHTTPRuleProviderWithoutCache(t *testing.T) {
	t.Cleanup(func() {
		setRuleProviderStatus(RuleProviderStatus{})
		setMihomoStatus(MihomoStatus{})
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "local.yaml"), []byte("payload:\n  - local.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(local) error = %v", err)
	}
	configPath := filepath.Join(dir, "config.dae")
	configBody := `global {}
rule_provider {
  local {
    type: file
    path: local.yaml
    behavior: domain
    format: yaml
  }
  remote_a {
    type: http
    url: 'https://a.invalid/rules.yaml'
    behavior: domain
    format: yaml
  }
  remote_b {
    type: http
    url: 'https://b.invalid/rules.yaml'
    behavior: domain
    format: yaml
  }
}
routing {
  ruleset(local) -> direct
  ruleset(remote_a) -> proxy
  ruleset(remote_b) -> proxy
  fallback: direct
}
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	conf, _, err := readConfigAtStartup(configPath)
	if err != nil {
		t.Fatalf("readConfigAtStartup() failed instead of degrading: %v", err)
	}
	if len(conf.Routing.Rules) != 1 || conf.Routing.Rules[0].AndFunctions[0].Params[0].Val != "local.example" {
		t.Fatalf("routing rules = %#v, want local.example preserved and degraded rules skipped", conf.Routing.Rules)
	}
	status := CurrentRuleProviderStatus()
	if !status.Degraded || !status.UsedLastGood {
		t.Fatalf("RuleProviderStatus = %#v, want Degraded=true UsedLastGood=true", status)
	}
	if !strings.Contains(status.Error, `"remote_a"`) || !strings.Contains(status.Error, `"remote_b"`) {
		t.Fatalf("status error %q should identify all failing providers", status.Error)
	}
	interval := ruleProviderRefreshInterval(conf)
	if interval != time.Hour {
		t.Fatalf("ruleProviderRefreshInterval() = %v, want 1h fallback retry when degraded", interval)
	}

	rm := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), nil)
	holder, _, err := newRuleProviderLifecycleHolder(conf, dir, interval, rm, logrus.New())
	if err != nil {
		t.Fatalf("newRuleProviderLifecycleHolder() error = %v", err)
	}
	if wait := holder.initialWait(interval)(); wait != initialRefreshFloor {
		t.Fatalf("initialWait() = %v, want %v when degraded", wait, initialRefreshFloor)
	}
}

func TestCoalesceReloadRequestPreservesFromRefreshOnlyWhenAllFromRefresh(t *testing.T) {
	reqs := make(chan reloadRequest, 4)
	rm := newReloadManager(reqs, make(chan struct{}, 1), nil)

	reqs <- reloadRequest{fromRefresh: true, requestedAt: time.Now()}
	got := rm.coalesceReloadRequest(reloadRequest{fromRefresh: true, requestedAt: time.Now()})
	if !got.fromRefresh {
		t.Fatal("coalescing two fromRefresh requests dropped fromRefresh")
	}

	reqs <- reloadRequest{fromRefresh: false, requestedAt: time.Now()}
	got = rm.coalesceReloadRequest(reloadRequest{fromRefresh: true, requestedAt: time.Now()})
	if got.fromRefresh {
		t.Fatal("coalescing a manual reload with a fromRefresh request kept fromRefresh=true")
	}
}
