package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestSafeTransportDisablesProxy(t *testing.T) {
	transport, err := safeTransport(http.DefaultTransport)
	if err != nil {
		t.Fatalf("safeTransport() error = %v", err)
	}
	if got := transport.(*http.Transport).Proxy; got != nil {
		t.Fatal("safeTransport() retained proxy configuration")
	}
}

func TestBlockedProviderIPIncludesSpecialInternalRanges(t *testing.T) {
	for _, raw := range []string{"100.100.100.200", "100.64.0.1", "198.18.0.1", "168.63.129.16"} {
		if !blockedProviderIP(net.ParseIP(raw)) {
			t.Fatalf("blockedProviderIP(%s) = false", raw)
		}
	}
}

func TestProviderFetcherRedactsQueryTokensFromErrors(t *testing.T) {
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("dial failed")
	}}
	fetcher := NewProviderFetcher(&http.Client{Transport: transport}, t.TempDir())
	fetcher.ValidateURL = func(string) error { return nil }
	_, err := fetcher.Fetch(context.Background(), ProviderSpec{Name: "p", Type: "http", URL: "https://example.com/rules?token=secret", MaxSize: 1024})
	if err == nil {
		t.Fatal("Fetch() error = nil")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("Fetch() leaked query token: %v", err)
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
