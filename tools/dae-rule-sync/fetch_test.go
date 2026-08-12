package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProviderFetcherCachesAndRevalidatesWithETag(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.Header.Get("If-None-Match"); got == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = fmt.Fprint(w, "payload-v1")
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	fetcher := newTestProviderFetcher(http.DefaultClient, cacheDir)
	spec := ProviderSpec{Name: "p", Type: "http", URL: server.URL, MaxSize: 1024}

	first, err := fetcher.Fetch(context.Background(), spec)
	if err != nil {
		t.Fatalf("first Fetch() error = %v", err)
	}
	if first.UsedCache || !first.Updated || string(first.Snapshot.Body) != "payload-v1" {
		t.Fatalf("first result = %#v", first)
	}

	second, err := fetcher.Fetch(context.Background(), spec)
	if err != nil {
		t.Fatalf("second Fetch() error = %v", err)
	}
	if !second.UsedCache || second.Updated || string(second.Snapshot.Body) != "payload-v1" {
		t.Fatalf("second result = %#v", second)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want 2", requests.Load())
	}
}

func TestProviderFetcherRetainsLastGoodCacheOnHTTPFailure(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "temporarily unavailable", http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, "good")
	}))
	defer server.Close()

	fetcher := newTestProviderFetcher(http.DefaultClient, t.TempDir())
	spec := ProviderSpec{Name: "p", Type: "http", URL: server.URL, MaxSize: 1024}
	if _, err := fetcher.Fetch(context.Background(), spec); err != nil {
		t.Fatalf("initial Fetch() error = %v", err)
	}
	fail.Store(true)

	result, err := fetcher.Fetch(context.Background(), spec)
	if err != nil {
		t.Fatalf("Fetch() with stale cache error = %v", err)
	}
	if !result.UsedCache || result.Warning == nil || string(result.Snapshot.Body) != "good" {
		t.Fatalf("stale result = %#v", result)
	}
}

func TestProviderFetcherRejectsOversizedResponseWithoutReplacingCache(t *testing.T) {
	var payload atomic.Value
	payload.Store("good")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, payload.Load().(string))
	}))
	defer server.Close()

	fetcher := newTestProviderFetcher(http.DefaultClient, t.TempDir())
	spec := ProviderSpec{Name: "p", Type: "http", URL: server.URL, MaxSize: 4}
	payload.Store("ok")
	if _, err := fetcher.Fetch(context.Background(), spec); err != nil {
		t.Fatalf("initial Fetch() error = %v", err)
	}
	payload.Store("too-large")

	result, err := fetcher.Fetch(context.Background(), spec)
	if err != nil {
		t.Fatalf("Fetch() with oversized response error = %v", err)
	}
	if !result.UsedCache || result.Warning == nil || string(result.Snapshot.Body) != "ok" {
		t.Fatalf("oversized result = %#v", result)
	}
}

func TestProviderFetcherLeavesNoTemporaryCacheAfterCommit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "payload")
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	fetcher := newTestProviderFetcher(http.DefaultClient, cacheDir)
	spec := ProviderSpec{Name: "p", Type: "http", URL: server.URL, MaxSize: 1024}
	if _, err := fetcher.Fetch(context.Background(), spec); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(cacheDir, "p"))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temporary cache entry remains: %s", entry.Name())
		}
	}
}

func newTestProviderFetcher(client *http.Client, cacheDir string) *ProviderFetcher {
	fetcher := NewProviderFetcher(client, cacheDir)
	fetcher.ValidateURL = func(string) error { return nil }
	fetcher.AllowPrivate = true
	return fetcher
}

func TestProviderFetcherSingleFlightsConcurrentRefreshes(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, "payload")
	}))
	defer server.Close()

	fetcher := newTestProviderFetcher(http.DefaultClient, t.TempDir())
	spec := ProviderSpec{Name: "p", Type: "http", URL: server.URL, MaxSize: 1024}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := fetcher.Fetch(context.Background(), spec)
			results <- err
		}()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Fetch() error = %v", err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestProviderFetcherDoesNotReuseCacheWhenURLChanges(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "first")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			t.Fatal("sent conditional header for a different source URL")
		}
		_, _ = fmt.Fprint(w, "second")
	}))
	defer second.Close()

	fetcher := newTestProviderFetcher(http.DefaultClient, t.TempDir())
	if _, err := fetcher.Fetch(context.Background(), ProviderSpec{Name: "p", Type: "http", URL: first.URL, MaxSize: 1024}); err != nil {
		t.Fatalf("first Fetch() error = %v", err)
	}
	result, err := fetcher.Fetch(context.Background(), ProviderSpec{Name: "p", Type: "http", URL: second.URL, MaxSize: 1024})
	if err != nil {
		t.Fatalf("second Fetch() error = %v", err)
	}
	if string(result.Snapshot.Body) != "second" {
		t.Fatalf("body = %q, want second", result.Snapshot.Body)
	}
}
