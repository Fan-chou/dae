package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type ProviderSnapshot struct {
	Name         string
	Body         []byte
	ETag         string
	LastModified string
	SHA256       string
	UpdatedAt    time.Time
}

type FetchResult struct {
	Snapshot  ProviderSnapshot
	UsedCache bool
	Updated   bool
	Warning   error
}

type ProviderFetcher struct {
	Client      *http.Client
	CacheDir    string
	Now         func() time.Time
	ValidateURL func(string) error
}

type providerCacheMetadata struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	SHA256       string    `json:"sha256"`
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
	if spec.Name == "" {
		return FetchResult{}, errors.New("provider name is empty")
	}
	if spec.Type == "" {
		spec.Type = "http"
	}
	if spec.Type != "http" {
		return FetchResult{}, fmt.Errorf("provider %q: fetcher only supports http, got %q", spec.Name, spec.Type)
	}
	validateURL := f.ValidateURL
	if validateURL == nil {
		validateURL = validateProviderURL
	}
	if err := validateURL(spec.URL); err != nil {
		return FetchResult{}, fmt.Errorf("provider %q: %w", spec.Name, err)
	}
	if f.CacheDir == "" {
		return FetchResult{}, errors.New("cache directory is empty")
	}
	cached, cacheErr := f.readCache(spec.Name)

	client := *f.Client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return validateURL(req.URL.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		return FetchResult{}, fmt.Errorf("create request: %w", err)
	}
	if cacheErr == nil {
		req.Header.Set("If-None-Match", cached.ETag)
		req.Header.Set("If-Modified-Since", cached.LastModified)
	}
	resp, err := client.Do(req)
	if err != nil {
		return f.staleResult(cached, cacheErr, fmt.Errorf("fetch provider: %w", err))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if cacheErr != nil {
			return FetchResult{}, fmt.Errorf("provider returned 304 without usable cache: %w", cacheErr)
		}
		return FetchResult{Snapshot: cloneSnapshot(cached), UsedCache: true}, nil
	case http.StatusOK:
		// Continue below.
	default:
		return f.staleResult(cached, cacheErr, fmt.Errorf("provider returned HTTP %s", resp.Status))
	}

	maxSize := spec.EffectiveMaxSize()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return f.staleResult(cached, cacheErr, fmt.Errorf("read provider: %w", err))
	}
	if int64(len(body)) > maxSize {
		return f.staleResult(cached, cacheErr, fmt.Errorf("provider response exceeds max_size %d", maxSize))
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
		SHA256:       digest(body),
		UpdatedAt:    now().UTC(),
	}
	if cacheErr == nil && cached.SHA256 == snapshot.SHA256 {
		return FetchResult{Snapshot: cloneSnapshot(snapshot), UsedCache: true}, nil
	}
	if err := f.writeCache(snapshot); err != nil {
		return f.staleResult(cached, cacheErr, fmt.Errorf("write provider cache: %w", err))
	}
	return FetchResult{Snapshot: cloneSnapshot(snapshot), Updated: true}, nil
}

func (f *ProviderFetcher) staleResult(cached ProviderSnapshot, cacheErr error, warning error) (FetchResult, error) {
	if cacheErr == nil {
		return FetchResult{Snapshot: cloneSnapshot(cached), UsedCache: true, Warning: warning}, nil
	}
	return FetchResult{}, fmt.Errorf("%w; no usable cache: %v", warning, cacheErr)
}

func (f *ProviderFetcher) cacheRoot(name string) string {
	return filepath.Join(f.CacheDir, name)
}

func (f *ProviderFetcher) readCache(name string) (ProviderSnapshot, error) {
	root := f.cacheRoot(name)
	metaBody, err := os.ReadFile(filepath.Join(root, "current", "metadata.json"))
	if err != nil {
		return ProviderSnapshot{}, err
	}
	var metadata providerCacheMetadata
	if err := json.Unmarshal(metaBody, &metadata); err != nil {
		return ProviderSnapshot{}, fmt.Errorf("decode metadata: %w", err)
	}
	body, err := os.ReadFile(filepath.Join(root, "current", "body"))
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
		SHA256:       metadata.SHA256,
		UpdatedAt:    metadata.UpdatedAt,
	}, nil
}

func (f *ProviderFetcher) writeCache(snapshot ProviderSnapshot) error {
	root := f.cacheRoot(snapshot.Name)
	if err := os.MkdirAll(filepath.Join(root, "versions"), 0o700); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp(filepath.Join(root, "versions"), ".tmp-")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	if err := os.WriteFile(filepath.Join(tmpDir, "body"), snapshot.Body, 0o600); err != nil {
		return err
	}
	metadata := providerCacheMetadata{
		ETag:         snapshot.ETag,
		LastModified: snapshot.LastModified,
		SHA256:       snapshot.SHA256,
		UpdatedAt:    snapshot.UpdatedAt,
	}
	metadataBody, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "metadata.json"), metadataBody, 0o600); err != nil {
		return err
	}
	currentTemp := filepath.Join(root, ".current.tmp")
	_ = os.Remove(currentTemp)
	if err := os.Symlink(filepath.Join("versions", filepath.Base(tmpDir)), currentTemp); err != nil {
		return err
	}
	if err := os.Rename(currentTemp, filepath.Join(root, "current")); err != nil {
		_ = os.Remove(currentTemp)
		return err
	}
	keep = true
	return nil
}

func cloneSnapshot(snapshot ProviderSnapshot) ProviderSnapshot {
	snapshot.Body = append([]byte(nil), snapshot.Body...)
	return snapshot
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
