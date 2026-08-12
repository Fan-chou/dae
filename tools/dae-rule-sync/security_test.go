package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateProviderURLRejectsCanonicalAndNumericLoopbackForms(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1./rules",
		"http://127.1./rules",
		"http://[::1]/rules",
		"http://localhost./rules",
	} {
		if err := validateProviderURL(raw); err == nil {
			t.Fatalf("validateProviderURL(%q) error = nil", raw)
		}
	}
}
func TestParseProviderRejectsYAMLAliases(t *testing.T) {
	_, err := ParseProvider([]byte("payload: &rules\n  - example.com\ncopy: *rules\n"), ProviderSpec{Name: "p", Behavior: "domain", Format: "yaml"})
	if err == nil {
		t.Fatal("ParseProvider() error = nil for YAML alias")
	}
}
func TestSafeDialRejectsLoopbackResolution(t *testing.T) {
	called := false
	dial := safeDialContext(func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, nil
	})
	_, err := dial(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("safeDialContext() error = nil")
	}
	if called {
		t.Fatal("safeDialContext() called original dialer for blocked IP")
	}
}

func TestProviderFetcherUsesTimeoutAndContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	fetcher := newTestProviderFetcher(http.DefaultClient, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := fetcher.Fetch(ctx, ProviderSpec{Name: "p", Type: "http", URL: server.URL, MaxSize: 1024})
	if err == nil {
		t.Fatal("Fetch() error = nil after context deadline")
	}
}
