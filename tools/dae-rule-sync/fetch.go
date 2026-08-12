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
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ProviderSnapshot struct {
	Name         string
	Body         []byte
	ETag         string
	LastModified string
	SourceURL    string
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
	Client       *http.Client
	CacheDir     string
	Now          func() time.Time
	ValidateURL  func(string) error
	ValidateBody func(ProviderSpec, []byte) error
	AllowPrivate bool
	flightMu     sync.Mutex
	flights      map[string]*providerFlight
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
	key := spec.Name + "\x00" + spec.URL
	f.flightMu.Lock()
	if f.flights == nil {
		f.flights = make(map[string]*providerFlight)
	}
	if existing, ok := f.flights[key]; ok {
		f.flightMu.Unlock()
		select {
		case <-existing.done:
			return cloneFetchResult(existing.result), existing.err
		case <-ctx.Done():
			return FetchResult{}, ctx.Err()
		}
	}
	flight := &providerFlight{done: make(chan struct{})}
	f.flights[key] = flight
	f.flightMu.Unlock()

	result, err := f.fetch(ctx, spec)
	f.flightMu.Lock()
	flight.result = cloneFetchResult(result)
	flight.err = err
	close(flight.done)
	delete(f.flights, key)
	f.flightMu.Unlock()
	return result, err
}

func (f *ProviderFetcher) fetch(ctx context.Context, spec ProviderSpec) (FetchResult, error) {
	if f == nil {
		return FetchResult{}, errors.New("nil provider fetcher")
	}
	if spec.Name == "" {
		return FetchResult{}, errors.New("provider name is empty")
	}
	if !providerNamePattern.MatchString(spec.Name) {
		return FetchResult{}, fmt.Errorf("provider name %q is not a safe identifier", spec.Name)
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
	cached, cacheErr := f.readCache(spec.Name, spec.EffectiveMaxSize(), spec.URL)

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
	if f.ValidateBody != nil {
		if err := f.ValidateBody(spec, body); err != nil {
			return f.staleResult(cached, cacheErr, fmt.Errorf("validate provider body: %w", err))
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
		SourceURL:    spec.URL,
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

func (f *ProviderFetcher) readCache(name string, maxSize int64, sourceURL string) (ProviderSnapshot, error) {
	if !providerNamePattern.MatchString(name) {
		return ProviderSnapshot{}, errors.New("invalid provider cache name")
	}
	root := f.cacheRoot(name)
	metaBody, err := os.ReadFile(filepath.Join(root, "current", "metadata.json"))
	if err != nil {
		return ProviderSnapshot{}, err
	}
	var metadata providerCacheMetadata
	if err := json.Unmarshal(metaBody, &metadata); err != nil {
		return ProviderSnapshot{}, fmt.Errorf("decode metadata: %w", err)
	}
	if metadata.SourceURL != sourceURL {
		return ProviderSnapshot{}, errors.New("provider cache source URL mismatch")
	}
	body, err := readLimited(filepath.Join(root, "current", "body"), maxSize)
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
		SourceURL:    snapshot.SourceURL,
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

func safeTransport(roundTripper http.RoundTripper) (http.RoundTripper, error) {
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("provider client transport must be *http.Transport for IP safety checks")
	}
	clone := transport.Clone()
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
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve provider host %q: %w", host, err)
		}
		var lastErr error
		for _, resolved := range ips {
			if blockedProviderIP(resolved.IP) {
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

func blockedProviderIP(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()
}
