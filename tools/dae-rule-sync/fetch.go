package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type ProviderSnapshot struct {
	Name         string
	Body         []byte
	ETag         string
	LastModified string
	SourceURL    string
	SourceKey    string
	SHA256       string
	UpdatedAt    time.Time
	Behavior     string
	Format       string
}

type FetchResult struct {
	Snapshot  ProviderSnapshot
	UsedCache bool
	Updated   bool
	Warning   error
}

type ProviderFetcher struct {
	Client       *http.Client
	CacheDir     string
	Now          func() time.Time
	ValidateURL  func(string) error
	ValidateBody func(ProviderSpec, []byte) error
	AllowPrivate bool
	// DeferCacheCommit lets a caller validate and publish a complete output
	// generation before making a fetched snapshot the provider's last-good.
	DeferCacheCommit bool
	flightMu         sync.Mutex
	flights          map[string]*providerFlight
	cacheMu          sync.Mutex
}

type providerFlight struct {
	done   chan struct{}
	result FetchResult
	err    error
}

type providerCacheMetadata struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	SHA256       string    `json:"sha256"`
	SourceURL    string    `json:"source_url,omitempty"`
	SourceKey    string    `json:"source_key"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func NewProviderFetcher(client *http.Client, cacheDir string) *ProviderFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &ProviderFetcher{Client: client, CacheDir: cacheDir, Now: time.Now, ValidateURL: validateProviderURL}
}

func (f *ProviderFetcher) Fetch(ctx context.Context, spec ProviderSpec) (FetchResult, error) {
	if f == nil {
		return FetchResult{}, errors.New("nil provider fetcher")
	}
	return f.fetchFlight(ctx, "cache\x00"+spec.Name+"\x00"+spec.URL, func() (FetchResult, error) {
		return f.fetch(ctx, spec)
	})
}

func (f *ProviderFetcher) fetchFlight(ctx context.Context, key string, fetch func() (FetchResult, error)) (FetchResult, error) {
	f.flightMu.Lock()
	if f.flights == nil {
		f.flights = make(map[string]*providerFlight)
	}
	if existing, ok := f.flights[key]; ok {
		f.flightMu.Unlock()
		return waitProviderFlight(ctx, existing)
	}
	flight := &providerFlight{done: make(chan struct{})}
	f.flights[key] = flight
	f.flightMu.Unlock()

	go func() {
		result, err := fetch()
		f.flightMu.Lock()
		flight.result = cloneFetchResult(result)
		flight.err = err
		close(flight.done)
		delete(f.flights, key)
		f.flightMu.Unlock()
	}()
	return waitProviderFlight(ctx, flight)
}

func waitProviderFlight(ctx context.Context, flight *providerFlight) (FetchResult, error) {
	if err := ctx.Err(); err != nil {
		return FetchResult{}, err
	}
	select {
	case <-flight.done:
	case <-ctx.Done():
		return FetchResult{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return FetchResult{}, err
	}
	return cloneFetchResult(flight.result), flight.err
}

func (f *ProviderFetcher) fetch(ctx context.Context, spec ProviderSpec) (FetchResult, error) {
	if err := f.validateHTTPSpec(spec); err != nil {
		return FetchResult{}, err
	}
	if f.CacheDir == "" {
		return FetchResult{}, errors.New("cache directory is empty")
	}
	cached, cacheErr := f.readCache(spec.Name, spec.EffectiveMaxSize(), spec.URL)
	return f.fetchRemote(ctx, spec, cached, cacheErr, true, f.ValidateBody, func(warning error) (FetchResult, error) {
		return f.staleResult(cached, cacheErr, warning)
	})
}

// FetchWithFallback fetches a provider without consulting or publishing the
// standalone provider cache. The supplied snapshot is the caller's pinned
// last-good value (the generation-local snapshot in generation mode).
func (f *ProviderFetcher) FetchWithFallback(ctx context.Context, spec ProviderSpec, fallback ProviderSnapshot) (FetchResult, error) {
	return f.fetchWithFallback(ctx, spec, fallback, f.ValidateBody)
}

// FetchWithFallbackValidated is FetchWithFallback with a caller-supplied
// acceptance check for both a fresh response and its generation-local
// fallback. Concurrent callers share only the HTTP response; each caller
// applies its own acceptance check and fallback afterwards.
func (f *ProviderFetcher) FetchWithFallbackValidated(ctx context.Context, spec ProviderSpec, fallback ProviderSnapshot, validateBody func(ProviderSpec, []byte) error) (FetchResult, error) {
	if f == nil {
		return FetchResult{}, errors.New("nil provider fetcher")
	}
	if f.ValidateBody != nil && validateBody != nil {
		baseValidate := f.ValidateBody
		semanticValidate := validateBody
		validateBody = func(spec ProviderSpec, body []byte) error {
			if err := baseValidate(spec, body); err != nil {
				return err
			}
			return semanticValidate(spec, body)
		}
	} else if validateBody == nil {
		validateBody = f.ValidateBody
	}
	return f.fetchWithFallback(ctx, spec, fallback, validateBody)
}

func (f *ProviderFetcher) fetchWithFallback(ctx context.Context, spec ProviderSpec, fallback ProviderSnapshot, validateBody func(ProviderSpec, []byte) error) (FetchResult, error) {
	if err := ctx.Err(); err != nil {
		return FetchResult{}, err
	}
	if err := f.validateHTTPSpec(spec); err != nil {
		return FetchResult{}, err
	}
	maxSize := spec.EffectiveMaxSize()
	fallbackErr := error(os.ErrNotExist)
	if fallback.Name != "" {
		if fallback.Name != spec.Name || fallback.SourceKey != digest([]byte(spec.URL)) {
			fallbackErr = errors.New("generation provider snapshot source mismatch")
		} else if int64(len(fallback.Body)) > maxSize {
			fallbackErr = fmt.Errorf("generation provider snapshot exceeds max_size %d", maxSize)
		} else if fallback.SHA256 != digest(fallback.Body) {
			fallbackErr = errors.New("generation provider snapshot checksum mismatch")
		} else if fallback.Behavior != normalizedProviderBehavior(spec) || normalizedSnapshotFormat(fallback.Format) != normalizedProviderFormat(spec) {
			fallbackErr = errors.New("generation provider snapshot behavior or format mismatch")
		} else if validateBody != nil {
			fallbackErr = validateBody(spec, fallback.Body)
		} else {
			fallbackErr = nil
		}
		if fallbackErr == nil && strings.TrimSpace(fallback.Format) == "" {
			// Pre-default-format snapshots are semantically YAML. Persist the
			// canonical value if this snapshot is selected again.
			fallback.Format = normalizedProviderFormat(spec)
		}
	}
	key := "generation\x00" + spec.Name + "\x00" + spec.URL
	result, err := f.fetchFlight(ctx, key, func() (FetchResult, error) {
		// The generation flight carries raw bytes that may be consumed by
		// callers other than its leader. HTTP client timeouts still bound the
		// shared request, while each caller keeps its own cancellation below.
		flightCtx := context.WithoutCancel(ctx)
		// A generation flight shares raw bytes, not a caller's max_size
		// decision. Manifest validation caps every individual max_size at this
		// global limit; each caller applies its own lower limit below.
		sharedSpec := spec
		sharedSpec.MaxSize = maxProviderMaxSize
		return f.fetchRemote(flightCtx, sharedSpec, ProviderSnapshot{}, os.ErrNotExist, false, nil, func(warning error) (FetchResult, error) {
			return FetchResult{}, redactProviderError(warning)
		})
	})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return FetchResult{}, ctxErr
	}
	if err == nil && int64(len(result.Snapshot.Body)) > maxSize {
		err = fmt.Errorf("provider response exceeds max_size %d", maxSize)
	}
	if err == nil && validateBody != nil {
		if validationErr := validateBody(spec, result.Snapshot.Body); validationErr != nil {
			err = fmt.Errorf("validate provider body: %w", validationErr)
		}
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return FetchResult{}, ctxErr
		}
		return f.staleResult(fallback, fallbackErr, err)
	}
	result.Snapshot.Behavior = normalizedProviderBehavior(spec)
	result.Snapshot.Format = normalizedProviderFormat(spec)
	if fallbackErr == nil && fallback.SHA256 == result.Snapshot.SHA256 {
		result.UsedCache = true
		result.Updated = false
	}
	return result, nil
}

func normalizedProviderBehavior(spec ProviderSpec) string {
	return strings.ToLower(strings.TrimSpace(spec.Behavior))
}

func normalizedProviderFormat(spec ProviderSpec) string {
	return normalizedSnapshotFormat(spec.Format)
}

func normalizedSnapshotFormat(format string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		return "yaml"
	}
	return format
}

func (f *ProviderFetcher) validateHTTPSpec(spec ProviderSpec) error {
	if f == nil {
		return errors.New("nil provider fetcher")
	}
	if spec.Name == "" {
		return errors.New("provider name is empty")
	}
	if !providerNamePattern.MatchString(spec.Name) {
		return fmt.Errorf("provider name %q is not a safe identifier", spec.Name)
	}
	if spec.Type == "" {
		spec.Type = "http"
	}
	if spec.Type != "http" {
		return fmt.Errorf("provider %q: fetcher only supports http, got %q", spec.Name, spec.Type)
	}
	validateURL := f.ValidateURL
	if validateURL == nil {
		validateURL = validateProviderURL
	}
	if err := validateURL(spec.URL); err != nil {
		return fmt.Errorf("provider %q: %w", spec.Name, redactProviderError(err))
	}
	return nil
}

func (f *ProviderFetcher) fetchRemote(ctx context.Context, spec ProviderSpec, cached ProviderSnapshot, cacheErr error, allowCacheCommit bool, validateBody func(ProviderSpec, []byte) error, stale func(error) (FetchResult, error)) (FetchResult, error) {
	validateURL := f.ValidateURL
	if validateURL == nil {
		validateURL = validateProviderURL
	}
	baseClient := f.Client
	if baseClient == nil {
		baseClient = http.DefaultClient
	}
	client := *baseClient
	if client.Timeout == 0 {
		client.Timeout = 45 * time.Second
	}
	if !f.AllowPrivate {
		transport, err := safeTransport(client.Transport)
		if err != nil {
			return FetchResult{}, err
		}
		client.Transport = transport
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return validateURL(req.URL.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		return FetchResult{}, fmt.Errorf("create request: %w", redactProviderError(err))
	}
	if cacheErr == nil {
		req.Header.Set("If-None-Match", cached.ETag)
		req.Header.Set("If-Modified-Since", cached.LastModified)
	}
	resp, err := client.Do(req)
	if err != nil {
		return stale(fmt.Errorf("fetch provider: %w", err))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if cacheErr != nil {
			return stale(fmt.Errorf("provider returned 304 without usable cache: %w", cacheErr))
		}
		return FetchResult{Snapshot: cloneSnapshot(cached), UsedCache: true}, nil
	case http.StatusOK:
		// Continue below.
	default:
		return stale(fmt.Errorf("provider returned HTTP %s", resp.Status))
	}

	maxSize := spec.EffectiveMaxSize()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return stale(fmt.Errorf("read provider: %w", err))
	}
	if int64(len(body)) > maxSize {
		return stale(fmt.Errorf("provider response exceeds max_size %d", maxSize))
	}
	if validateBody != nil {
		if err := validateBody(spec, body); err != nil {
			return stale(fmt.Errorf("validate provider body: %w", err))
		}
	}
	now := f.Now
	if now == nil {
		now = time.Now
	}
	snapshot := ProviderSnapshot{
		Name:         spec.Name,
		Body:         append([]byte(nil), body...),
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		SourceURL:    redactProviderURL(spec.URL),
		SourceKey:    digest([]byte(spec.URL)),
		SHA256:       digest(body),
		UpdatedAt:    now().UTC(),
	}
	if cacheErr == nil && cached.SHA256 == snapshot.SHA256 {
		return FetchResult{Snapshot: cloneSnapshot(snapshot), UsedCache: true}, nil
	}
	if f.DeferCacheCommit || !allowCacheCommit {
		return FetchResult{Snapshot: cloneSnapshot(snapshot), Updated: true}, nil
	}
	if err := f.CommitSnapshot(snapshot); err != nil {
		return stale(fmt.Errorf("write provider cache: %w", err))
	}
	return FetchResult{Snapshot: cloneSnapshot(snapshot), Updated: true}, nil
}

func (f *ProviderFetcher) CommitSnapshot(snapshot ProviderSnapshot) error {
	if f == nil {
		return errors.New("nil provider fetcher")
	}
	batch, err := f.prepareSnapshotBatch([]ProviderSnapshot{snapshot})
	if err != nil {
		return err
	}
	defer batch.close()
	if err := batch.publish(); err != nil {
		return err
	}
	batch.finalize()
	return nil
}

func (f *ProviderFetcher) staleResult(cached ProviderSnapshot, cacheErr error, warning error) (FetchResult, error) {
	warning = redactProviderError(warning)
	if cacheErr == nil {
		return FetchResult{Snapshot: cloneSnapshot(cached), UsedCache: true, Warning: warning}, nil
	}
	return FetchResult{}, fmt.Errorf("%w; no usable cache: %v", warning, cacheErr)
}

func (f *ProviderFetcher) cacheRoot(name string) string {
	return filepath.Join(f.CacheDir, name)
}

func (f *ProviderFetcher) readCache(name string, maxSize int64, sourceURL string) (ProviderSnapshot, error) {
	if !providerNamePattern.MatchString(name) {
		return ProviderSnapshot{}, errors.New("invalid provider cache name")
	}
	root := f.cacheRoot(name)
	currentVersion, err := currentCacheVersion(root)
	if err != nil {
		return ProviderSnapshot{}, err
	}
	metaBody, err := os.ReadFile(filepath.Join(currentVersion, "metadata.json"))
	if err != nil {
		return ProviderSnapshot{}, err
	}
	var metadata providerCacheMetadata
	if err := json.Unmarshal(metaBody, &metadata); err != nil {
		return ProviderSnapshot{}, fmt.Errorf("decode metadata: %w", err)
	}
	if metadata.SourceKey != digest([]byte(sourceURL)) {
		return ProviderSnapshot{}, errors.New("provider cache source URL mismatch")
	}
	body, err := readLimited(filepath.Join(currentVersion, "body"), maxSize)
	if err != nil {
		return ProviderSnapshot{}, err
	}
	if digest(body) != metadata.SHA256 {
		return ProviderSnapshot{}, errors.New("provider cache checksum mismatch")
	}
	return ProviderSnapshot{
		Name:         name,
		Body:         body,
		ETag:         metadata.ETag,
		LastModified: metadata.LastModified,
		SourceURL:    metadata.SourceURL,
		SourceKey:    metadata.SourceKey,
		SHA256:       metadata.SHA256,
		UpdatedAt:    metadata.UpdatedAt,
	}, nil
}

type cacheCandidate struct {
	snapshot   ProviderSnapshot
	root       string
	versions   string
	versionDir string
	oldTarget  string
	hadCurrent bool
}

type cachePublication struct {
	candidate  *cacheCandidate
	newTarget  string
	currentSet bool
}

type cacheBatch struct {
	fetcher      *ProviderFetcher
	candidates   []*cacheCandidate
	publications []cachePublication
	published    bool
	finalized    bool
}

func (f *ProviderFetcher) prepareSnapshotBatch(snapshots []ProviderSnapshot) (*cacheBatch, error) {
	if len(snapshots) == 0 {
		return &cacheBatch{fetcher: f, finalized: true}, nil
	}
	f.cacheMu.Lock()
	batch := &cacheBatch{fetcher: f}
	if err := f.preflightCacheRoots(snapshots); err != nil {
		f.cacheMu.Unlock()
		return nil, err
	}
	for _, snapshot := range snapshots {
		candidate, err := f.prepareCacheCandidate(snapshot)
		if err != nil {
			batch.cleanupCandidates()
			f.cacheMu.Unlock()
			return nil, err
		}
		batch.candidates = append(batch.candidates, candidate)
	}
	return batch, nil
}

func (f *ProviderFetcher) preflightCacheRoots(snapshots []ProviderSnapshot) error {
	if f.CacheDir == "" {
		return errors.New("cache directory is empty")
	}
	if info, err := os.Lstat(f.CacheDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("cache directory is not a controlled directory")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect cache directory: %w", err)
	}
	for _, snapshot := range snapshots {
		if !providerNamePattern.MatchString(snapshot.Name) {
			return errors.New("invalid provider cache name")
		}
		root := f.cacheRoot(snapshot.Name)
		if info, err := os.Lstat(root); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("provider %q cache root is not a controlled directory", snapshot.Name)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect provider %q cache root: %w", snapshot.Name, err)
		}
		versions := filepath.Join(root, "versions")
		if info, err := os.Lstat(versions); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("provider %q cache versions is not a controlled directory", snapshot.Name)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect provider %q cache versions: %w", snapshot.Name, err)
		}
		if _, ok, err := inspectCacheCurrent(root, versions); err != nil {
			return fmt.Errorf("provider %q cache current: %w", snapshot.Name, err)
		} else if ok {
			// inspectCacheCurrent performs the path and symlink containment checks.
		}
	}
	return nil
}

func inspectCacheCurrent(root, versions string) (string, bool, error) {
	current := filepath.Join(root, "current")
	info, err := os.Lstat(current)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", true, errors.New("current is not a symlink")
	}
	target, err := os.Readlink(current)
	if err != nil {
		return "", true, err
	}
	if filepath.IsAbs(target) || filepath.Clean(target) != target || filepath.Dir(target) != "versions" || filepath.Base(target) == "." || filepath.Base(target) == ".." {
		return "", true, fmt.Errorf("target %q is outside versions", target)
	}
	resolvedVersions, err := filepath.EvalSymlinks(versions)
	if err != nil {
		return "", true, err
	}
	resolvedCurrent, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", true, err
	}
	relative, err := filepath.Rel(resolvedVersions, resolvedCurrent)
	if err != nil || relative == "." || filepath.Dir(relative) != "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", true, errors.New("current resolves outside versions")
	}
	return target, true, nil
}

func currentCacheVersion(root string) (string, error) {
	target, ok, err := inspectCacheCurrent(root, filepath.Join(root, "versions"))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", os.ErrNotExist
	}
	version := filepath.Join(root, "versions", filepath.Base(target))
	if err := validateCacheVersion(version); err != nil {
		return "", err
	}
	return version, nil
}

func (f *ProviderFetcher) prepareCacheCandidate(snapshot ProviderSnapshot) (*cacheCandidate, error) {
	root := f.cacheRoot(snapshot.Name)
	versions := filepath.Join(root, "versions")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return nil, err
	}
	oldTarget, hadCurrent, err := inspectCacheCurrent(root, versions)
	if err != nil {
		return nil, err
	}
	versionDir, err := os.MkdirTemp(versions, "version-")
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(versionDir)
		}
	}()
	if err := writeFileSync(filepath.Join(versionDir, "body"), snapshot.Body, 0o600); err != nil {
		return nil, err
	}
	metadata := providerCacheMetadata{
		ETag:         snapshot.ETag,
		LastModified: snapshot.LastModified,
		SHA256:       snapshot.SHA256,
		SourceURL:    snapshot.SourceURL,
		SourceKey:    snapshot.SourceKey,
		UpdatedAt:    snapshot.UpdatedAt,
	}
	metadataBody, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	if err := writeFileSync(filepath.Join(versionDir, "metadata.json"), metadataBody, 0o600); err != nil {
		return nil, err
	}
	if err := validateCacheVersion(versionDir); err != nil {
		return nil, err
	}
	if err := syncDirectory(versionDir); err != nil {
		return nil, err
	}
	cleanup = false
	return &cacheCandidate{snapshot: snapshot, root: root, versions: versions, versionDir: versionDir, oldTarget: oldTarget, hadCurrent: hadCurrent}, nil
}

func (b *cacheBatch) publish() error {
	if b == nil || b.finalized {
		return nil
	}
	for _, candidate := range b.candidates {
		publication := cachePublication{candidate: candidate, newTarget: filepath.Join("versions", filepath.Base(candidate.versionDir))}
		if err := replaceCacheCurrent(candidate.root, publication.newTarget); err != nil {
			b.rollback()
			return err
		}
		publication.currentSet = true
		b.publications = append(b.publications, publication)
	}
	for _, candidate := range b.candidates {
		if err := retainCacheVersions(candidate.versions, filepath.Base(candidate.versionDir)); err != nil {
			b.rollback()
			return err
		}
	}
	for _, candidate := range b.candidates {
		if err := syncDirectory(candidate.root); err != nil {
			b.rollback()
			return err
		}
	}
	b.published = true
	return nil
}

func (b *cacheBatch) rollback() error {
	if b == nil {
		return nil
	}
	var firstErr error
	for i := len(b.publications) - 1; i >= 0; i-- {
		publication := b.publications[i]
		if !publication.currentSet {
			continue
		}
		candidate := publication.candidate
		var err error
		if candidate.hadCurrent {
			err = replaceCacheCurrent(candidate.root, candidate.oldTarget)
		} else {
			err = removeCacheCurrent(candidate.root, publication.newTarget)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	b.cleanupCandidates()
	b.publications = nil
	b.published = false
	return firstErr
}

func (b *cacheBatch) finalize() {
	if b == nil {
		return
	}
	b.published = true
	b.finalized = true
}

func (b *cacheBatch) close() {
	if b == nil {
		return
	}
	if !b.finalized {
		if !b.published {
			b.cleanupCandidates()
		}
		b.finalized = true
	}
	if b.fetcher != nil && len(b.candidates) > 0 {
		b.fetcher.cacheMu.Unlock()
		b.fetcher = nil
	}
}

func (b *cacheBatch) cleanupCandidates() {
	for _, candidate := range b.candidates {
		if candidate.versionDir != "" {
			_ = os.RemoveAll(candidate.versionDir)
		}
	}
}

func replaceCacheCurrent(root, target string) error {
	tmpFile, err := os.CreateTemp(root, ".current.tmp-")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(root, "current")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func removeCacheCurrent(root, expectedTarget string) error {
	target, ok, err := inspectCacheCurrent(root, filepath.Join(root, "versions"))
	if err != nil {
		return err
	}
	if !ok || target != expectedTarget {
		return nil
	}
	return os.Remove(filepath.Join(root, "current"))
}

func validateCacheVersion(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("cache version is not a controlled directory")
	}
	for _, name := range []string{"body", "metadata.json"} {
		fileInfo, err := os.Lstat(filepath.Join(path, name))
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("cache version %s is not a regular file", name)
		}
	}
	metadataBody, err := os.ReadFile(filepath.Join(path, "metadata.json"))
	if err != nil {
		return err
	}
	var metadata providerCacheMetadata
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		return err
	}
	if metadata.SHA256 == "" || metadata.SourceKey == "" {
		return errors.New("cache metadata is incomplete")
	}
	body, err := os.ReadFile(filepath.Join(path, "body"))
	if err != nil {
		return err
	}
	if digest(body) != metadata.SHA256 {
		return errors.New("cache version checksum mismatch")
	}
	return nil
}

func retainCacheVersions(versions, currentName string) error {
	entries, err := os.ReadDir(versions)
	if err != nil {
		return err
	}
	type versionEntry struct {
		name string
		info os.FileInfo
	}
	validOld := make([]versionEntry, 0, len(entries))
	changed := false
	for _, entry := range entries {
		path := filepath.Join(versions, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("cache version %q is not a controlled directory", entry.Name())
		}
		if entry.Name() == currentName {
			if err := validateCacheVersion(path); err != nil {
				return fmt.Errorf("current cache version %q: %w", entry.Name(), err)
			}
			continue
		}
		if err := validateCacheVersion(path); err != nil {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
			changed = true
			continue
		}
		validOld = append(validOld, versionEntry{name: entry.Name(), info: info})
	}
	sort.Slice(validOld, func(i, j int) bool {
		if validOld[i].info.ModTime().Equal(validOld[j].info.ModTime()) {
			return validOld[i].name > validOld[j].name
		}
		return validOld[i].info.ModTime().After(validOld[j].info.ModTime())
	})
	if len(validOld) > 1 {
		for _, entry := range validOld[1:] {
			if err := os.RemoveAll(filepath.Join(versions, entry.name)); err != nil {
				return err
			}
			changed = true
		}
	}
	if changed {
		return syncDirectory(versions)
	}
	return nil
}

func cloneFetchResult(result FetchResult) FetchResult {
	result.Snapshot = cloneSnapshot(result.Snapshot)
	return result
}

func cloneSnapshot(snapshot ProviderSnapshot) ProviderSnapshot {
	snapshot.Body = append([]byte(nil), snapshot.Body...)
	return snapshot
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func redactProviderURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "[redacted-url]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

var providerURLPattern = regexp.MustCompile(`https?://[^\s"]+`)

func redactProviderError(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(providerURLPattern.ReplaceAllStringFunc(err.Error(), redactProviderURL))
}

func writeFileSync(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func safeTransport(roundTripper http.RoundTripper) (http.RoundTripper, error) {
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("provider client transport must be *http.Transport for IP safety checks")
	}
	clone := transport.Clone()
	clone.Proxy = nil
	originalDial := clone.DialContext
	if originalDial == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		originalDial = dialer.DialContext
	}
	clone.DialContext = safeDialContext(originalDial)
	if clone.MaxResponseHeaderBytes == 0 || clone.MaxResponseHeaderBytes > 1<<20 {
		clone.MaxResponseHeaderBytes = 1 << 20
	}
	return clone, nil
}

func safeDialContext(original func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("split provider address %q: %w", address, err)
		}
		normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve provider host %q: %w", host, err)
		}
		var lastErr error
		for _, resolved := range ips {
			if blockedProviderIP(resolved.IP) && !authorizedSyntheticProviderIP(normalizedHost, resolved.IP) {
				lastErr = fmt.Errorf("resolved provider host %q to blocked address %s", host, resolved.IP)
				continue
			}
			conn, dialErr := original(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = errors.New("provider host has no usable address")
		}
		return nil, lastErr
	}
}

const authorizedSyntheticProviderHost = "download.readfun.me"

var authorizedSyntheticProviderAddress = net.ParseIP("198.18.11.216")

const authorizedSyntheticProviderSKKHost = "ruleset.skk.moe"

var authorizedSyntheticProviderSKKAddress = net.ParseIP("198.18.11.217")

func authorizedSyntheticProviderIP(host string, ip net.IP) bool {
	// This provider's authorized synthetic address is required for Mihomo rule conversion.
	return (host == authorizedSyntheticProviderHost && ip.Equal(authorizedSyntheticProviderAddress)) ||
		(host == authorizedSyntheticProviderSKKHost && ip.Equal(authorizedSyntheticProviderSKKAddress))
}

var blockedProviderNetworks = mustProviderNetworks([]string{
	"100.64.0.0/10",
	"198.18.0.0/15",
	"100.100.100.200/32",
	"168.63.129.16/32",
})

func mustProviderNetworks(values []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}

func blockedProviderIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range blockedProviderNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
