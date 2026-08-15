package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCLIArgsAcceptsRoutingURL(t *testing.T) {
	t.Parallel()
	options, err := ParseCLIArgs([]string{"-mihomo-routing-url", "https://example.com/clash", "-generation-dir", "/tmp/gen"})
	if err != nil {
		t.Fatal(err)
	}
	if options.MihomoRoutingURL != "https://example.com/clash" {
		t.Fatalf("url = %q", options.MihomoRoutingURL)
	}
}

func TestParseCLIArgsRejectsCombinedRoutingSources(t *testing.T) {
	t.Parallel()
	_, err := ParseCLIArgs([]string{
		"-mihomo-routing-config", "a.yaml",
		"-mihomo-routing-url", "https://example.com/clash",
		"-generation-dir", "/tmp/gen",
	})
	if err == nil {
		t.Fatal("expected combined-source error")
	}
}

func TestNormalizeMihomoRoutingFetchURL(t *testing.T) {
	t.Parallel()
	got := normalizeMihomoRoutingFetchURL("https-file://example.com/clash")
	if got != "https://example.com/clash" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadMihomoRoutingSourceFetchesAndPersists(t *testing.T) {
	t.Parallel()
	body := []byte("proxies: []\nproxy-groups: []\nrules: [MATCH,DIRECT]\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "dae-rule-sync" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	got, baseDir, err := loadMihomoRoutingSource(context.Background(), SyncOptions{
		MihomoRoutingURL: server.URL,
		GenerationDir:    dir,
		Client:           server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch")
	}
	cached, err := os.ReadFile(filepath.Join(baseDir, "mihomo-routing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cached) != string(body) {
		t.Fatal("cached body mismatch")
	}
}

func TestLoadMihomoRoutingSourceURLFile(t *testing.T) {
	t.Parallel()
	body := []byte("proxies: []\nrules: [MATCH,DIRECT]\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	urlFile := filepath.Join(t.TempDir(), "routing.url")
	if err := os.WriteFile(urlFile, []byte(server.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err := loadMihomoRoutingSource(context.Background(), SyncOptions{
		MihomoRoutingURLFile: urlFile,
		GenerationDir:        t.TempDir(),
		Client:               server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatal("body mismatch")
	}
}

func TestValidateMihomoRoutingSubscriptionURLDoesNotEchoInput(t *testing.T) {
	t.Parallel()
	err := validateMihomoRoutingSubscriptionURL("not a url")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "not a url") {
		t.Fatalf("error leaked input: %v", err)
	}
}

func TestFetchMihomoRoutingSubscriptionHTTPErrorHasNoURL(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	_, err := fetchMihomoRoutingSubscription(context.Background(), server.Client(), server.URL+"/secret-token")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("error leaked URL: %v", err)
	}
}
