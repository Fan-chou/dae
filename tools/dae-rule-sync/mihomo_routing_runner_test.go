package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRenderMihomoLoweredRoutesUsesFallbackForMatch(t *testing.T) {
	rules := []MihomoLoweredRoutingRule{
		{
			Source: MihomoRuleSource{SourceIndex: 0, SourceLine: 10, Raw: "MATCH,DIRECT"},
			Rule:   &config_parser.RoutingRule{Outbound: config_parser.Function{Name: "direct"}},
		},
	}

	routes, report, err := renderMihomoLoweredRoutes(rules)
	if err != nil {
		t.Fatalf("renderMihomoLoweredRoutes() error = %v", err)
	}
	if report.Generated != 1 {
		t.Fatalf("report.Generated = %d, want 1 fallback", report.Generated)
	}
	if routes != "    fallback: direct\n" {
		t.Fatalf("routes = %q, want fallback only", routes)
	}
	if _, err := config_parser.Parse("global {}\nrouting {\n" + routes + "}\n"); err != nil {
		t.Fatalf("rendered fallback does not parse as kdae routing: %v", err)
	}
}

func TestRenderMihomoLoweredRoutesStopsAfterMatchFallback(t *testing.T) {
	rules := []MihomoLoweredRoutingRule{
		{
			Source: MihomoRuleSource{SourceIndex: 0, SourceLine: 10, Raw: "DOMAIN,example.com,DIRECT"},
			Rule: &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{
					Name:   "domain",
					Params: []*config_parser.Param{{Key: "full", Val: "example.com"}},
				}},
				Outbound: config_parser.Function{Name: "direct"},
			},
		},
		{
			Source: MihomoRuleSource{SourceIndex: 1, SourceLine: 11, Raw: "MATCH,block"},
			Rule:   &config_parser.RoutingRule{Outbound: config_parser.Function{Name: "block"}},
		},
		{
			Source: MihomoRuleSource{SourceIndex: 2, SourceLine: 12, Raw: "DST-PORT,443,DIRECT"},
			Rule: &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{
					Name:   "dport",
					Params: []*config_parser.Param{{Val: "443"}},
				}},
				Outbound: config_parser.Function{Name: "direct"},
			},
		},
	}

	routes, report, err := renderMihomoLoweredRoutes(rules)
	if err != nil {
		t.Fatalf("renderMihomoLoweredRoutes() error = %v", err)
	}
	if report.Generated != 2 {
		t.Fatalf("report.Generated = %d, want one route plus fallback", report.Generated)
	}
	if !strings.Contains(routes, "domain(full: \"example.com\") -> direct") {
		t.Fatalf("routes = %q, missing preceding route", routes)
	}
	if !strings.Contains(routes, "fallback: block") {
		t.Fatalf("routes = %q, missing MATCH fallback", routes)
	}
	if strings.Contains(routes, "dport(443)") {
		t.Fatalf("routes = %q, emitted a route after an unconditional MATCH", routes)
	}
}

func TestLoadMihomoGenerationProvidersFetchesInParallel(t *testing.T) {
	const n = providerFetchConcurrency
	var current atomic.Int32
	var max atomic.Int32
	started := make(chan struct{}, n)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := current.Add(1)
		for {
			old := max.Load()
			if c <= old || max.CompareAndSwap(old, c) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			http.Error(w, "timed out waiting for barrier", http.StatusGatewayTimeout)
			return
		}
		current.Add(-1)
		_, _ = fmt.Fprint(w, "payload: [example.com]\n")
	}))
	t.Cleanup(server.Close)

	go func() {
		for range n {
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				return
			}
		}
		close(release)
	}()

	jobs := make([]mihomoProviderFetchJob, n)
	for i := range n {
		jobs[i] = mihomoProviderFetchJob{
			spec:         testMihomoHTTPProviderSpec(fmt.Sprintf("p%d", i), server.URL+"/"+fmt.Sprintf("%d", i)),
			originalName: fmt.Sprintf("p%d", i),
		}
	}
	loaded, err := loadMihomoGenerationProviders(context.Background(), newTestProviderFetcher(server.Client(), t.TempDir()), t.TempDir(), jobs)
	if err != nil {
		t.Fatalf("loadMihomoGenerationProviders() error = %v", err)
	}
	if len(loaded) != n {
		t.Fatalf("loaded = %d, want %d", len(loaded), n)
	}
	if got := max.Load(); got != int32(n) {
		t.Fatalf("peak concurrent fetches = %d, want %d", got, n)
	}
	for i, item := range loaded {
		if item.originalName != jobs[i].originalName || len(item.parsed.Domains) == 0 {
			t.Fatalf("outcome[%d] = %#v", i, item)
		}
	}
}

func TestLoadMihomoGenerationProvidersFailsClosedOnFirstProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/p1") {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, "payload: [example.com]\n")
	}))
	t.Cleanup(server.Close)

	jobs := []mihomoProviderFetchJob{
		{spec: testMihomoHTTPProviderSpec("p0", server.URL+"/p0"), originalName: "p0"},
		{spec: testMihomoHTTPProviderSpec("p1", server.URL+"/p1"), originalName: "p1"},
		{spec: testMihomoHTTPProviderSpec("p2", server.URL+"/p2"), originalName: "p2"},
	}
	_, err := loadMihomoGenerationProviders(context.Background(), newTestProviderFetcher(server.Client(), t.TempDir()), t.TempDir(), jobs)
	if err == nil {
		t.Fatal("loadMihomoGenerationProviders() error = nil, want fail-closed")
	}
	if !strings.Contains(err.Error(), `provider "p1"`) {
		t.Fatalf("error = %v, want provider p1", err)
	}
}

func TestLoadMihomoGenerationProvidersHonorsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	jobs := []mihomoProviderFetchJob{{
		spec:         testMihomoHTTPProviderSpec("p0", "http://127.0.0.1:1/p0"),
		originalName: "p0",
	}}
	_, err := loadMihomoGenerationProviders(ctx, newTestProviderFetcher(http.DefaultClient, t.TempDir()), t.TempDir(), jobs)
	if err == nil {
		t.Fatal("loadMihomoGenerationProviders() error = nil, want cancellation")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("error = %v, want cancellation", err)
	}
}

func testMihomoHTTPProviderSpec(name, rawURL string) ProviderSpec {
	return ProviderSpec{
		Name:     name,
		Type:     "http",
		URL:      rawURL,
		Behavior: "domain",
		Format:   "yaml",
		MaxSize:  1024,
	}
}
