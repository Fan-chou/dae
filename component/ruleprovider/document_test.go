/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package ruleprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
)

func requireMarker(body []byte) error {
	if !strings.HasPrefix(string(body), "ok:") {
		return errors.New("missing ok marker")
	}
	return nil
}

func TestFetchDocumentFileUsesLastGoodWhenSourceBreaks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doc.yaml")
	if err := os.WriteFile(path, []byte("ok: first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := config.RuleProvider{Name: "doc", Type: "file", Path: "doc.yaml", MaxSize: 1024}
	opts := loadOptions{}

	first, err := fetchDocument(context.Background(), spec, dir, nil, requireMarker, opts)
	if err != nil {
		t.Fatalf("first fetch error = %v", err)
	}
	if string(first.Body) != "ok: first\n" || first.UsedLastGood {
		t.Fatalf("first = %#v", first)
	}

	// An invalid update must neither be returned nor replace the cache.
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := fetchDocument(context.Background(), spec, dir, nil, requireMarker, opts)
	if err != nil {
		t.Fatalf("fetch after bad update error = %v, want last-good", err)
	}
	if string(second.Body) != "ok: first\n" || !second.UsedLastGood {
		t.Fatalf("second = %#v, want last-good first body", second)
	}

	// A vanished source also falls back.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	third, err := fetchDocument(context.Background(), spec, dir, nil, requireMarker, opts)
	if err != nil || string(third.Body) != "ok: first\n" || !third.UsedLastGood {
		t.Fatalf("third = %#v err = %v", third, err)
	}

	// A valid update replaces the snapshot.
	if err := os.WriteFile(path, []byte("ok: second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fourth, err := fetchDocument(context.Background(), spec, dir, nil, requireMarker, opts)
	if err != nil || string(fourth.Body) != "ok: second\n" || fourth.UsedLastGood || !fourth.Changed {
		t.Fatalf("fourth = %#v err = %v", fourth, err)
	}
}

func TestFetchDocumentRejectsInvalidBodyWithoutCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "doc.yaml"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := config.RuleProvider{Name: "doc", Type: "file", Path: "doc.yaml", MaxSize: 1024}
	if doc, err := fetchDocument(context.Background(), spec, dir, nil, requireMarker, loadOptions{}); err == nil {
		t.Fatalf("fetch error = nil, doc = %#v; want rejection with no last-good", doc)
	}
}

func TestFetchDocumentHTTPFallsBackAndEnforcesMaxSize(t *testing.T) {
	available := true
	body := "ok: from-http\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{Name: "doc", Type: "http", URL: server.URL, MaxSize: 1024}
	opts := loadOptions{allowPrivate: true}
	first, err := fetchDocument(context.Background(), spec, dir, http.DefaultClient, requireMarker, opts)
	if err != nil || string(first.Body) != body {
		t.Fatalf("first = %#v err = %v", first, err)
	}
	available = false
	second, err := fetchDocument(context.Background(), spec, dir, http.DefaultClient, requireMarker, opts)
	if err != nil || string(second.Body) != body || !second.UsedLastGood {
		t.Fatalf("second = %#v err = %v", second, err)
	}

	available = true
	body = "ok: " + strings.Repeat("x", 4096)
	third, err := fetchDocument(context.Background(), spec, dir, http.DefaultClient, requireMarker, opts)
	if err != nil || !third.UsedLastGood || string(third.Body) != "ok: from-http\n" {
		t.Fatalf("oversized body must fall back to last-good: %#v err = %v", third, err)
	}
}

func TestFetchDocumentRejectsPrivateURLByDefault(t *testing.T) {
	spec := config.RuleProvider{Name: "doc", Type: "http", URL: "http://127.0.0.1:1/x", MaxSize: 1024}
	if _, err := FetchDocument(context.Background(), spec, t.TempDir(), nil, requireMarker); err == nil {
		t.Fatal("FetchDocument accepted a loopback URL")
	}
}

func TestDocumentBehaviorIsNotAvailableToRuleProviders(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "doc.yaml"), []byte("payload:\n  - a.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := config.RuleProvider{Name: "doc", Type: "file", Path: "doc.yaml", Behavior: documentBehavior, Format: "yaml", MaxSize: 1024}
	if _, err := Load(context.Background(), []config.RuleProvider{spec}, dir, nil); err == nil {
		t.Fatal("Load accepted the internal document behavior")
	}
}

func TestClassicalProviderLowersDomainWildcardToAnchoredRegex(t *testing.T) {
	dir := t.TempDir()
	body := "payload:\n  - DOMAIN-WILDCARD,*.Example.com\n  - DOMAIN-SUFFIX,plain.example.com\n"
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := config.RuleProvider{Name: "p", Type: "file", Path: "p.yaml", Behavior: "classical", Format: "yaml", MaxSize: 1024}
	registry, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, nil, loadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	functions := registry["p"].Functions
	if len(functions) != 2 || functions[0].Name != "domain" || functions[0].Params[0].Key != "regex" ||
		functions[0].Params[0].Val != `^.*\.example\.com$` {
		t.Fatalf("functions = %#v", functions)
	}

	// An ipcidr provider cannot hold domain rules.
	ipSpec := config.RuleProvider{Name: "q", Type: "file", Path: "p.yaml", Behavior: "ipcidr", Format: "yaml", MaxSize: 1024}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{ipSpec}, dir, nil, loadOptions{}); err == nil {
		t.Fatal("ipcidr provider accepted DOMAIN-WILDCARD")
	}
}

func TestPlainScalarsWithStarAfterCommaAreNotAliases(t *testing.T) {
	for _, body := range []string{
		"payload:\n  - DOMAIN-WILDCARD,*.example.com\n",
		"payload:\n  - DOMAIN-SUFFIX,a&b.example.com\n",
	} {
		if err := preflightProviderYAML([]byte(body)); err != nil {
			t.Fatalf("preflight(%q) = %v, want accepted", body, err)
		}
	}
	for _, body := range []string{
		"payload:\n  - *anchor\n",
		"payload:\n  - &anchor a.example.com\n",
		"payload: [*anchor, b.example.com]\n",
		"payload: [a.example.com, *anchor]\n",
		"payload: {x: *anchor}\n",
	} {
		if err := preflightProviderYAML([]byte(body)); err == nil {
			t.Fatalf("preflight(%q) accepted an alias or anchor", body)
		}
	}
}
