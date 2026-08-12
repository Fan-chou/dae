package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSyncFetchesProviderAndWritesRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
	}))
	defer server.Close()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := fmt.Sprintf("providers:\n  - name: example\n    type: http\n    url: %s\n    behavior: domain\n    format: yaml\nroutes:\n  - provider: example\n    outbound: proxy\n    kind: domain\n", server.URL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	outputPath := filepath.Join(dir, "generated", "routes.dae")

	report, err := RunSync(context.Background(), SyncOptions{
		ManifestPath: manifestPath,
		CacheDir:     filepath.Join(dir, "cache"),
		RoutesOutput: outputPath,
		Client:       http.DefaultClient,
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(body) != "domain(suffix: 'example.com') -> proxy\n" {
		t.Fatalf("routes = %q", body)
	}
	if report.Providers[0].Updated != true || report.Routes.Generated != 1 {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunSyncWritesFlatGroupsAndReportsUnsupportedMembers(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	if err := os.WriteFile(manifestPath, []byte("providers: []\nroutes: []\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	mihomoPath := filepath.Join(dir, "mihomo.yaml")
	mihomo := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1, DIRECT]
`
	if err := os.WriteFile(mihomoPath, []byte(mihomo), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	groupsPath := filepath.Join(dir, "generated", "groups.dae")

	report, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: mihomoPath,
		GroupsOutput:    groupsPath,
	})
	if err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	body, err := os.ReadFile(groupsPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(body), "filter: name('hk-1')") {
		t.Fatalf("groups = %q", body)
	}
	if len(report.Groups.Unsupported) != 1 {
		t.Fatalf("groups report = %#v", report.Groups)
	}
}

func TestRunSyncKeepsLastGoodCacheWhenNewProviderBodyCannotBeParsed(t *testing.T) {
	valid := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if valid {
			_, _ = fmt.Fprint(w, "payload:\n  - good.example\n")
			return
		}
		_, _ = fmt.Fprint(w, "payload: [this is not valid yaml")
	}))
	defer server.Close()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := fmt.Sprintf("providers:\n  - name: p\n    type: http\n    url: %s\n    behavior: domain\n    format: yaml\nroutes:\n  - provider: p\n    outbound: proxy\n    kind: domain\n", server.URL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	outputPath := filepath.Join(dir, "routes.dae")
	options := SyncOptions{ManifestPath: manifestPath, CacheDir: filepath.Join(dir, "cache"), RoutesOutput: outputPath, Client: http.DefaultClient, AllowPrivate: true}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	valid = false
	report, err := RunSync(context.Background(), options)
	if err != nil {
		t.Fatalf("stale-cache RunSync() error = %v", err)
	}
	if report.Providers[0].Warning == "" || !report.Providers[0].UsedCache {
		t.Fatalf("report = %#v, want stale-cache warning", report)
	}
	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(body) != "domain(suffix: 'good.example') -> proxy\n" {
		t.Fatalf("routes after bad update = %q", body)
	}
}

func TestRunSyncRejectsFileProviderSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("payload:\n  - outside.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	link := filepath.Join(dir, "rules.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := `providers:
  - name: p
    type: file
    path: rules.yaml
    behavior: domain
    format: yaml
routes:
  - provider: p
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := RunSync(context.Background(), SyncOptions{ManifestPath: manifestPath, RoutesOutput: filepath.Join(dir, "routes.dae")}); err == nil {
		t.Fatal("RunSync() error = nil for symlink escape")
	}
}

func TestRunSyncDoesNotOverwriteRoutesWithEmptyProviderResult(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := `providers:
  - name: empty
    type: inline
    behavior: domain
    format: yaml
    data: "payload: []"
routes:
  - provider: empty
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	outputPath := filepath.Join(dir, "routes.dae")
	if err := os.WriteFile(outputPath, []byte("domain(suffix: 'old.example') -> proxy\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := RunSync(context.Background(), SyncOptions{ManifestPath: manifestPath, RoutesOutput: outputPath})
	if err == nil {
		t.Fatal("RunSync() error = nil for empty route result")
	}
	body, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if string(body) != "domain(suffix: 'old.example') -> proxy\n" {
		t.Fatalf("routes after empty result = %q", body)
	}
}

func TestAtomicWriteReplacesFileWithoutTemporarySibling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "output.dae")
	if err := writeAtomic(path, []byte("first")); err != nil {
		t.Fatalf("first writeAtomic() error = %v", err)
	}
	if err := writeAtomic(path, []byte("second")); err != nil {
		t.Fatalf("second writeAtomic() error = %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(body) != "second" {
		t.Fatalf("body = %q", body)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temporary sibling remains: %s", entry.Name())
		}
	}
}
