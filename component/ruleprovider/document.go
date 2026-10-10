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

	"github.com/daeuniverse/dae/config"
)

// Document is an opaque remote or local document obtained through the same
// SSRF-guarded fetch, verified cache and last-good machinery as rule providers.
type Document struct {
	Body []byte
	// UsedLastGood reports that the source could not be read or failed
	// validation and the previously published valid body was returned.
	UsedLastGood bool
	// Changed reports that a new body was published to the cache.
	Changed bool
}

// FetchDocument fetches provider.URL (or provider.Path) and returns the body
// once validate accepts it. A failing source falls back to the last body that
// passed validate; with no valid cached body it returns an error. It never
// returns an unvalidated body and never overwrites a valid cache with one.
//
// provider.Behavior and provider.Format are ignored. The cache lives beside
// rule providers, so provider.Name must not collide with a rule provider.
func FetchDocument(ctx context.Context, provider config.RuleProvider, baseDir string, client *http.Client, validate func([]byte) error) (Document, error) {
	return fetchDocument(ctx, provider, baseDir, client, validate, loadOptions{})
}

// FetchDocumentCached is FetchDocument with a cache mode. The provider's
// Interval says how long a cached copy counts as fresh.
func FetchDocumentCached(ctx context.Context, provider config.RuleProvider, baseDir string, client *http.Client, validate func([]byte) error, mode CacheMode) (Document, error) {
	return fetchDocument(ctx, provider, baseDir, client, validate, mode.options())
}

func fetchDocument(ctx context.Context, provider config.RuleProvider, baseDir string, client *http.Client, validate func([]byte) error, options loadOptions) (Document, error) {
	if validate == nil {
		return Document{}, errors.New("document validator is required")
	}
	if baseDir == "" {
		return Document{}, errors.New("document base directory is empty")
	}
	provider.Behavior = documentBehavior
	provider.Format = "yaml"
	options.document = true
	options.parse = func(body []byte, p config.RuleProvider) (ProviderRules, error) {
		if int64(len(body)) > normalizeProvider(p).MaxSize {
			return ProviderRules{}, fmt.Errorf("document body exceeds max_size %d", normalizeProvider(p).MaxSize)
		}
		if err := validate(body); err != nil {
			return ProviderRules{}, err
		}
		return ProviderRules{}, nil
	}

	if !options.validateOnly {
		if err := recoverPendingPublish(baseDir); err != nil {
			return Document{}, err
		}
	}
	_, prepared, err := prepareProviders(ctx, []config.RuleProvider{provider}, baseDir, client, options)
	if err != nil {
		return Document{}, err
	}
	published := false
	if !options.validateOnly {
		if published, err = publishPreparedWithContext(ctx, prepared); err != nil {
			return Document{}, err
		}
	}
	snapshot, err := readCacheSnapshot(prepared[0].descriptor)
	if err != nil {
		return Document{}, fmt.Errorf("read published document %q: %w", provider.Name, err)
	}
	return Document{Body: snapshot.body, UsedLastGood: prepared[0].usedLastGood, Changed: published}, nil
}
