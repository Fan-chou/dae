/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package ruleprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/component/routing"
)

type countingProvider struct {
	server *httptest.Server
	hits   atomic.Int64
}

func newCountingProvider(t *testing.T, body string) *countingProvider {
	t.Helper()
	p := &countingProvider{}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(p.server.Close)
	return p
}

func cacheModeOptions(mode CacheMode) loadOptions {
	opts := mode.options()
	opts.allowPrivate = true // the test servers are on loopback
	return opts
}

func cacheModeConfig(t *testing.T, interval time.Duration, a, b *countingProvider) *config.Config {
	t.Helper()
	sections, err := config_parser.Parse("routing {\n  ruleset(a) && ruleset(b) -> proxy\n  fallback: direct\n}\n")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var routing config.Routing
	if err := config.SectionParser(reflect.ValueOf(&routing), sections[0]); err != nil {
		t.Fatalf("SectionParser() error = %v", err)
	}
	return &config.Config{
		RuleProvider: []config.RuleProvider{
			{Name: "a", Type: "http", URL: a.server.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20, Interval: interval},
			{Name: "b", Type: "http", URL: b.server.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20, Interval: interval},
		},
		Routing: routing,
	}
}

func primeCache(t *testing.T, dir string, a, b *countingProvider) {
	t.Helper()
	conf := cacheModeConfig(t, time.Hour, a, b)
	if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheNever)); err != nil {
		t.Fatalf("priming load: %v", err)
	}
	if a.hits.Load() == 0 || b.hits.Load() == 0 {
		t.Fatalf("priming load asked a=%d b=%d times, want both asked", a.hits.Load(), b.hits.Load())
	}
}

func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		tree[rel] = fmt.Sprintf("%v|%d|%d", info.Mode(), info.Size(), info.ModTime().UnixNano())
		return nil
	})
	return tree
}

func TestCacheOnlyNeverAsksTheNetworkNorWrites(t *testing.T) {
	a, b := newCountingProvider(t, "a.example\n"), newCountingProvider(t, "b.example\n")
	dir := t.TempDir()
	primeCache(t, dir, a, b)
	before := snapshotTree(t, dir)
	a.hits.Store(0)
	b.hits.Store(0)

	conf := cacheModeConfig(t, time.Hour, a, b)
	if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheOnly)); err != nil {
		t.Fatalf("CacheOnly load: %v", err)
	}
	if a.hits.Load()+b.hits.Load() != 0 {
		t.Fatalf("CacheOnly asked the network: a=%d b=%d", a.hits.Load(), b.hits.Load())
	}
	if after := snapshotTree(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("CacheOnly changed the cache directory:\nbefore=%v\nafter=%v", before, after)
	}
}

func TestCacheOnlyWithNothingCachedPassesAndWritesNothing(t *testing.T) {
	a, b := newCountingProvider(t, "a.example\n"), newCountingProvider(t, "b.example\n")
	dir := t.TempDir()
	conf := cacheModeConfig(t, time.Hour, a, b)
	if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheOnly)); err != nil {
		t.Fatalf("CacheOnly load with an empty cache: %v", err)
	}
	if a.hits.Load()+b.hits.Load() != 0 {
		t.Fatalf("CacheOnly asked the network: a=%d b=%d", a.hits.Load(), b.hits.Load())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("CacheOnly created %d entries in the cache directory", len(entries))
	}
}

func TestReuseFreshSkipsTheNetworkOnlyWhileEveryCopyIsFresh(t *testing.T) {
	a, b := newCountingProvider(t, "a.example\n"), newCountingProvider(t, "b.example\n")
	dir := t.TempDir()
	primeCache(t, dir, a, b)

	run := func(interval time.Duration, x, y *countingProvider) {
		t.Helper()
		x.hits.Store(0)
		y.hits.Store(0)
		conf := cacheModeConfig(t, interval, x, y)
		if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheReuseFresh)); err != nil {
			t.Fatalf("CacheReuseFresh load: %v", err)
		}
		if len(conf.Routing.Rules) == 0 {
			t.Fatal("no routing rules after the load")
		}
	}

	run(time.Hour, a, b)
	if a.hits.Load()+b.hits.Load() != 0 {
		t.Fatalf("fresh copies were still fetched: a=%d b=%d", a.hits.Load(), b.hits.Load())
	}

	run(time.Nanosecond, a, b)
	if a.hits.Load() == 0 || b.hits.Load() == 0 {
		t.Fatalf("stale copies were not refreshed: a=%d b=%d", a.hits.Load(), b.hits.Load())
	}

	// A different source is a different cache: the old copy must not answer.
	c, d := newCountingProvider(t, "c.example\n"), newCountingProvider(t, "d.example\n")
	run(time.Hour, c, d)
	if c.hits.Load() == 0 || d.hits.Load() == 0 {
		t.Fatalf("a changed source was answered from the cache of the old one: c=%d d=%d", c.hits.Load(), d.hits.Load())
	}
}

func TestFetchDocumentCacheModes(t *testing.T) {
	doc := newCountingProvider(t, "ok: from-http\n")
	dir := t.TempDir()
	spec := config.RuleProvider{Name: "doc", Type: "http", URL: doc.server.URL, MaxSize: 1024, Interval: time.Hour}

	if _, err := fetchDocument(context.Background(), spec, dir, http.DefaultClient, requireMarker, cacheModeOptions(CacheOnly)); err == nil {
		t.Fatal("CacheOnly returned a document with nothing cached")
	}
	if doc.hits.Load() != 0 {
		t.Fatalf("CacheOnly asked the network %d times", doc.hits.Load())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("CacheOnly wrote %d entries", len(entries))
	}

	if _, err := fetchDocument(context.Background(), spec, dir, http.DefaultClient, requireMarker, cacheModeOptions(CacheNever)); err != nil {
		t.Fatalf("priming fetch: %v", err)
	}
	doc.hits.Store(0)

	got, err := fetchDocument(context.Background(), spec, dir, http.DefaultClient, requireMarker, cacheModeOptions(CacheOnly))
	if err != nil || string(got.Body) != "ok: from-http\n" || doc.hits.Load() != 0 {
		t.Fatalf("CacheOnly = %q err=%v hits=%d, want the cached body with no request", got.Body, err, doc.hits.Load())
	}
	got, err = fetchDocument(context.Background(), spec, dir, http.DefaultClient, requireMarker, cacheModeOptions(CacheReuseFresh))
	if err != nil || string(got.Body) != "ok: from-http\n" || doc.hits.Load() != 0 {
		t.Fatalf("fresh reuse = %q err=%v hits=%d, want the cached body with no request", got.Body, err, doc.hits.Load())
	}
	spec.Interval = time.Nanosecond
	if _, err = fetchDocument(context.Background(), spec, dir, http.DefaultClient, requireMarker, cacheModeOptions(CacheReuseFresh)); err != nil || doc.hits.Load() == 0 {
		t.Fatalf("a stale document was not refreshed: err=%v hits=%d", err, doc.hits.Load())
	}
}

// ageContent makes every cached copy's content look old, as a source that has
// not changed for hours does; only the content's updated_at is touched.
func ageContent(t *testing.T, dir string, by time.Duration) {
	t.Helper()
	var files []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Name() == "metadata.json" {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		t.Fatal("no cache metadata found")
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatal(err)
		}
		meta["updated_at"] = time.Now().Add(-by).UTC().Format(time.RFC3339Nano)
		out, _ := json.Marshal(meta)
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReuseFreshCountsASuccessfulCheckEvenWhenNothingChanged(t *testing.T) {
	a, b := newCountingProvider(t, "a.example\n"), newCountingProvider(t, "b.example\n")
	dir := t.TempDir()
	primeCache(t, dir, a, b)
	ageContent(t, dir, 3*time.Hour) // unchanged for hours, longer than the 1h interval

	load := func() {
		t.Helper()
		conf := cacheModeConfig(t, time.Hour, a, b)
		if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheReuseFresh)); err != nil {
			t.Fatalf("CacheReuseFresh load: %v", err)
		}
	}

	a.hits.Store(0)
	b.hits.Store(0)
	load() // the content is old and nothing says it was checked: ask
	if a.hits.Load() == 0 || b.hits.Load() == 0 {
		t.Fatalf("a copy with no recent check was not asked: a=%d b=%d", a.hits.Load(), b.hits.Load())
	}

	a.hits.Store(0)
	b.hits.Store(0)
	load() // the answer was "unchanged" a moment ago: that counts as a check
	if a.hits.Load()+b.hits.Load() != 0 {
		t.Fatalf("an unchanged source that was just checked was asked again: a=%d b=%d", a.hits.Load(), b.hits.Load())
	}
}

func TestOldestCheckFollowsChecksNotContentAge(t *testing.T) {
	a, b := newCountingProvider(t, "a.example\n"), newCountingProvider(t, "b.example\n")
	dir := t.TempDir()
	conf := cacheModeConfig(t, time.Hour, a, b)
	if _, ok := OldestCheck(conf.RuleProvider, nil, dir); ok {
		t.Fatal("OldestCheck reported a check with nothing cached")
	}
	primeCache(t, dir, a, b)
	ageContent(t, dir, 5*time.Hour)

	old, ok := OldestCheck(conf.RuleProvider, nil, dir)
	if !ok || time.Since(old) < 4*time.Hour {
		t.Fatalf("OldestCheck = %v ok=%v, want about the aged content time", old, ok)
	}
	// Nothing has re-checked them since: the first fetch publishes and needs no
	// marker, so the aged content time is the last known check.
	if time.Since(old) > 6*time.Hour || time.Since(old) < 0 {
		t.Fatalf("OldestCheck = %v is out of range", old)
	}
	// A later successful check, even an "unchanged" one, moves it to now.
	_ = loadAndExpandWithOptions(context.Background(), cacheModeConfig(t, time.Hour, a, b), dir, http.DefaultClient, cacheModeOptions(CacheNever))
	if fresh, ok := OldestCheck(conf.RuleProvider, nil, dir); !ok || time.Since(fresh) > time.Minute {
		t.Fatalf("OldestCheck after a successful check = %v ok=%v, want about now", fresh, ok)
	}
}

func TestColdStartReusesConsistentStaleCacheWithoutNetwork(t *testing.T) {
	a, b := newCountingProvider(t, "a.example\n"), newCountingProvider(t, "b.example\n")
	dir := t.TempDir()
	primeCache(t, dir, a, b)
	ageContent(t, dir, 3*time.Hour)

	a.hits.Store(0)
	b.hits.Store(0)
	conf := cacheModeConfig(t, time.Hour, a, b)
	report, err := loadAndExpandWithOptionsAndReport(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheColdStart))
	if err != nil {
		t.Fatalf("CacheColdStart load = %v", err)
	}
	if a.hits.Load()+b.hits.Load() != 0 {
		t.Fatalf("CacheColdStart asked network for consistent cached batch: a=%d b=%d", a.hits.Load(), b.hits.Load())
	}
	if !report.ReusedCache || report.Degraded || report.UsedLastGood || report.Warning != nil {
		t.Fatalf("CacheColdStart report = %#v, want ReusedCache=true only", report)
	}
	if len(conf.Routing.Rules) == 0 {
		t.Fatal("expected expanded routing rules from cached batch")
	}
	oldest, ok := OldestCheck(conf.RuleProvider, nil, dir)
	if !ok || time.Since(oldest) < 2*time.Hour {
		t.Fatalf("OldestCheck = %v ok=%v, want stale check preserved so background refresh runs promptly", oldest, ok)
	}
}

func TestReuseFreshUpdatesHealthyAndRetriesOnlyFailedProvider(t *testing.T) {
	var mu sync.Mutex
	aBody := "a1.example\n"
	bBody := "b1.example\n"
	bDown := false
	a := newCountingProvider(t, "")
	b := newCountingProvider(t, "")
	a.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		mu.Lock()
		body := aBody
		mu.Unlock()
		_, _ = fmt.Fprint(w, body)
	})
	b.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		mu.Lock()
		down, body := bDown, bBody
		mu.Unlock()
		if down {
			http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
			return
		}
		_, _ = fmt.Fprint(w, body)
	})

	dir := t.TempDir()
	primeCache(t, dir, a, b)
	descA := testCacheDescriptor(t, config.RuleProvider{Name: "a", Type: "http", URL: a.server.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20}, dir)
	descB := testCacheDescriptor(t, config.RuleProvider{Name: "b", Type: "http", URL: b.server.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20}, dir)

	ageContent(t, dir, 3*time.Hour)
	mu.Lock()
	aBody = "a2.example\n"
	bDown = true
	mu.Unlock()
	a.hits.Store(0)
	b.hits.Store(0)

	conf := cacheModeConfig(t, time.Hour, a, b)
	report, err := loadAndExpandWithOptionsAndReport(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheReuseFresh))
	if err != nil {
		t.Fatalf("CacheReuseFresh load with failing sibling b = %v", err)
	}
	if !report.UsedLastGood || report.ReusedCache || report.Warning == nil {
		t.Fatalf("CacheReuseFresh report = %#v, want UsedLastGood=true ReusedCache=false Warning!=nil", report)
	}
	if !strings.Contains(report.Warning.Error(), `"b"`) {
		t.Fatalf("warning %q does not identify failing provider b", report.Warning)
	}
	if a.hits.Load() != 1 || b.hits.Load() != 1 {
		t.Fatalf("fetch counts = a:%d b:%d, want single fetch per provider", a.hits.Load(), b.hits.Load())
	}
	snapAAfter, _ := readCacheSnapshot(descA)
	snapBAfter, _ := readCacheSnapshot(descB)
	if string(snapAAfter.body) != "a2.example\n" || string(snapBAfter.body) != "b1.example\n" {
		t.Fatalf("disk cache after mixed round = a:%q b:%q, want a2.example and b1.example", snapAAfter.body, snapBAfter.body)
	}

	// Fast retry while a's 1h interval is fresh and b recovered: skips a, fetches only b.
	a.hits.Store(0)
	b.hits.Store(0)
	mu.Lock()
	bBody = "b2.example\n"
	bDown = false
	mu.Unlock()
	retryConf := cacheModeConfig(t, time.Hour, a, b)
	refreshReport, retryLoadReport, err := refreshWithOptions(context.Background(), retryConf, dir, http.DefaultClient, loadOptions{allowPrivate: true, reuseFresh: true, refreshGrace: true})
	if err != nil {
		t.Fatalf("subsequent refreshWithOptions error = %v", err)
	}
	if a.hits.Load() != 0 || b.hits.Load() != 1 {
		t.Fatalf("retry fetch counts = a:%d b:%d, want a=0 (fresh skipped) and b=1 (failed provider retried)", a.hits.Load(), b.hits.Load())
	}
	if !refreshReport.Changed || refreshReport.UsedLastGood || retryLoadReport.UsedLastGood || retryLoadReport.Warning != nil {
		t.Fatalf("retry reports = %#v / %#v, want Changed=true UsedLastGood=false", refreshReport, retryLoadReport)
	}
	snapARetry, _ := readCacheSnapshot(descA)
	snapBRetry, _ := readCacheSnapshot(descB)
	if string(snapARetry.body) != "a2.example\n" || string(snapBRetry.body) != "b2.example\n" {
		t.Fatalf("disk cache after retry = a:%q b:%q, want a2.example and b2.example", snapARetry.body, snapBRetry.body)
	}
}

func TestColdStartSurvivesUncachedTimeoutAndMixedBatchesInDegradedMode(t *testing.T) {
	t.Run("uncached-timeout-skips-only-degraded-rules", func(t *testing.T) {
		a := newCountingProvider(t, "a1.example\n")
		b := newCountingProvider(t, "b1.example\n")
		b.server.Close()

		sections, err := config_parser.Parse(`routing {
  ruleset(a) -> proxy
  ruleset(b) -> proxy
  ruleset_no_resolve(b) -> proxy
  ruleset(a) && ruleset_no_resolve(b) -> proxy
  !ruleset_no_resolve(b) -> direct
  fallback: direct
}`)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		var r config.Routing
		if err := config.SectionParser(reflect.ValueOf(&r), sections[0]); err != nil {
			t.Fatalf("SectionParser() error = %v", err)
		}
		conf := &config.Config{
			RuleProvider: []config.RuleProvider{
				{Name: "a", Type: "http", URL: a.server.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20, Interval: time.Hour},
				{Name: "b", Type: "http", URL: b.server.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20, Interval: time.Hour},
			},
			Routing: r,
		}
		dir := t.TempDir()
		report, err := loadAndExpandWithOptionsAndReport(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheColdStart))
		if err != nil {
			t.Fatalf("CacheColdStart degraded load error = %v", err)
		}
		if !report.Degraded || !report.UsedLastGood || report.Warning == nil {
			t.Fatalf("degraded report = %#v, want Degraded=true UsedLastGood=true Warning!=nil", report)
		}
		if !strings.Contains(report.Warning.Error(), `"b"`) {
			t.Fatalf("degraded warning %q should name failing provider b", report.Warning)
		}
		if len(conf.Routing.Rules) != 1 || conf.Routing.Rules[0].AndFunctions[0].Params[0].Val != "a1.example" {
			t.Fatalf("expanded routing rules = %#v, want only a1.example rule", conf.Routing.Rules)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "persist.d", "rule-providers", "a", "current")); !os.IsNotExist(statErr) {
			t.Fatalf("partial batch persisted cache for a: %v", statErr)
		}

		// Also verify direct OrderedExpr negation & or/and behavior on degraded provider.
		reg := Registry{
			"a": {Functions: []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "a1.example"}}}}},
			"b": {Degraded: true},
		}
		negExpr, _ := routing.EncodeOrderedExpr(&routing.OrderedExpr{
			Op:   "not",
			Children: []*routing.OrderedExpr{{Op: "atom", Atom: &config_parser.Function{Name: "ruleset_no_resolve", Params: []*config_parser.Param{{Val: "b"}}}}},
		})
		out, err := ExpandRoutingRules([]*config_parser.RoutingRule{
			{AndFunctions: []*config_parser.Function{negExpr}, Outbound: config_parser.Function{Name: "direct"}},
		}, reg)
		if err != nil || len(out) != 0 {
			t.Fatalf("negated degraded OrderedExpr = out=%#v err=%v, want skipped without error", out, err)
		}
	})

	t.Run("mismatched-disk-batches-tolerate-mixed-cold-start", func(t *testing.T) {
		aBody := "a1.example\n"
		bDown := atomic.Bool{}
		var aMu sync.Mutex
		a := newCountingProvider(t, "")
		a.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a.hits.Add(1)
			aMu.Lock()
			body := aBody
			aMu.Unlock()
			_, _ = fmt.Fprint(w, body)
		})
		b := newCountingProvider(t, "")
		b.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b.hits.Add(1)
			if bDown.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = fmt.Fprint(w, "b1.example\n")
		})
		dir := t.TempDir()
		// Prime A and B separately so their on-disk caches have different batch identities.
		if _, err := loadWithOptions(context.Background(), []config.RuleProvider{{Name: "a", Type: "http", URL: a.server.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20}}, dir, http.DefaultClient, cacheModeOptions(CacheNever)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadWithOptions(context.Background(), []config.RuleProvider{{Name: "b", Type: "http", URL: b.server.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20}}, dir, http.DefaultClient, cacheModeOptions(CacheNever)); err != nil {
			t.Fatal(err)
		}

		// Cold start reuses independent valid unversioned caches directly without network requests.
		a.hits.Store(0)
		b.hits.Store(0)
		bDown.Store(true)
		conf := cacheModeConfig(t, time.Hour, a, b)
		report, err := loadAndExpandWithOptionsAndReport(context.Background(), conf, dir, http.DefaultClient, cacheModeOptions(CacheColdStart))
		if err != nil {
			t.Fatalf("CacheColdStart with independent disk batches = %v", err)
		}
		if a.hits.Load()+b.hits.Load() != 0 {
			t.Fatalf("CacheColdStart asked network: a=%d b=%d", a.hits.Load(), b.hits.Load())
		}
		if !report.ReusedCache || report.Degraded || report.UsedLastGood || report.Warning != nil {
			t.Fatalf("cold-start report = %#v, want ReusedCache=true only", report)
		}
		if len(conf.Routing.Rules) == 0 {
			t.Fatal("expected cached rules to expand on cold start")
		}

		// Strict load while b is down still updates a and keeps b's last-good cache.
		aMu.Lock()
		aBody = "a2.example\n"
		aMu.Unlock()
		conf2 := cacheModeConfig(t, time.Hour, a, b)
		report2, err := loadAndExpandWithOptionsAndReport(context.Background(), conf2, dir, http.DefaultClient, cacheModeOptions(CacheNever))
		if err != nil {
			t.Fatalf("CacheNever mixed load with mismatched disk batches = %v", err)
		}
		if !report2.UsedLastGood || report2.Warning == nil || !strings.Contains(report2.Warning.Error(), `"b"`) {
			t.Fatalf("report2 = %#v, want UsedLastGood=true and Warning naming b", report2)
		}
		snapA, _ := readCacheSnapshot(testCacheDescriptor(t, conf2.RuleProvider[0], dir))
		snapB, _ := readCacheSnapshot(testCacheDescriptor(t, conf2.RuleProvider[1], dir))
		if string(snapA.body) != "a2.example\n" || string(snapB.body) != "b1.example\n" {
			t.Fatalf("caches after CacheNever mixed load = a:%q b:%q, want a2.example and b1.example", snapA.body, snapB.body)
		}
	})
}
