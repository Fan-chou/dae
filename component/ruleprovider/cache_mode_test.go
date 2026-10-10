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
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
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
