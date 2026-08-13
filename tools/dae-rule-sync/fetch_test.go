package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestFetchWithFallbackValidatedRejectsOversizedFallback(t *testing.T) {
	const fallbackBody = "payload: [oversized-fallback.example]\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	fetcher := newTestProviderFetcher(server.Client(), t.TempDir())
	spec := ProviderSpec{
		Name:     "p",
		Type:     "http",
		URL:      server.URL,
		Behavior: "domain",
		Format:   "yaml",
		MaxSize:  4,
	}
	fallbackBytes := []byte(fallbackBody)
	fallback := ProviderSnapshot{
		Name:      spec.Name,
		Body:      fallbackBytes,
		SourceURL: spec.URL,
		SourceKey: digest([]byte(spec.URL)),
		SHA256:    digest(fallbackBytes),
		Behavior:  spec.Behavior,
		Format:    spec.Format,
	}

	result, err := fetcher.FetchWithFallbackValidated(
		context.Background(),
		spec,
		fallback,
		func(_ ProviderSpec, body []byte) error {
			if string(body) != fallbackBody {
				return fmt.Errorf("unexpected fallback body %q", body)
			}
			return nil
		},
	)
	if err == nil {
		t.Fatalf("FetchWithFallbackValidated() error = nil, result = %#v; want oversized fallback rejection", result)
	}
	if result.UsedCache {
		t.Fatalf("FetchWithFallbackValidated() result = %#v, want no successful fallback", result)
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

type fetchFlightProbeContext struct {
	context.Context
	entered     chan struct{}
	enteredOnce sync.Once
}

func (c *fetchFlightProbeContext) Done() <-chan struct{} {
	c.enteredOnce.Do(func() { close(c.entered) })
	return c.Context.Done()
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

func TestFetchWithFallbackValidatedIsolatesConcurrentCallers(t *testing.T) {
	const (
		freshBody        = "payload: [fresh.example]\n"
		leaderFallback   = "payload: [leader-fallback.example]\n"
		waiterFallback   = "payload: [waiter-fallback.example]\n"
		requestWaitLimit = 5 * time.Second
	)

	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	var requestOnce sync.Once
	var releaseOnce sync.Once
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		requestOnce.Do(func() { close(requestStarted) })
		<-releaseResponse
		_, _ = fmt.Fprint(w, freshBody)
	}))
	defer server.Close()
	release := func() {
		releaseOnce.Do(func() { close(releaseResponse) })
	}
	defer release()

	fetcher := newTestProviderFetcher(server.Client(), t.TempDir())
	spec := ProviderSpec{Name: "p", Type: "http", URL: server.URL, MaxSize: 1024}
	makeFallback := func(body string) ProviderSnapshot {
		bodyBytes := []byte(body)
		return ProviderSnapshot{
			Name:      spec.Name,
			Body:      bodyBytes,
			SourceKey: digest([]byte(spec.URL)),
			SHA256:    digest(bodyBytes),
		}
	}

	type fetchCall struct {
		result FetchResult
		err    error
	}
	leaderDone := make(chan fetchCall, 1)
	go func() {
		result, err := fetcher.FetchWithFallbackValidated(
			context.Background(),
			spec,
			makeFallback(leaderFallback),
			func(_ ProviderSpec, body []byte) error {
				if string(body) != freshBody {
					return fmt.Errorf("leader validator rejected %q", body)
				}
				return nil
			},
		)
		leaderDone <- fetchCall{result: result, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(requestWaitLimit):
		t.Fatal("timed out waiting for leader HTTP request barrier")
	}

	waiterPrepared := make(chan struct{})
	var waiterPrepareOnce sync.Once
	waiterDone := make(chan fetchCall, 1)
	go func() {
		result, err := fetcher.FetchWithFallbackValidated(
			context.Background(),
			spec,
			makeFallback(waiterFallback),
			func(_ ProviderSpec, body []byte) error {
				if string(body) == waiterFallback {
					waiterPrepareOnce.Do(func() { close(waiterPrepared) })
					return nil
				}
				return fmt.Errorf("strict waiter validator rejected %q", body)
			},
		)
		waiterDone <- fetchCall{result: result, err: err}
	}()

	select {
	case <-waiterPrepared:
	case <-time.After(requestWaitLimit):
		t.Fatal("timed out preparing waiter validator while leader flight was blocked")
	}
	release()

	var leader fetchCall
	select {
	case leader = <-leaderDone:
	case <-time.After(requestWaitLimit):
		t.Fatal("timed out waiting for leader result")
	}
	if leader.err != nil {
		t.Fatalf("leader FetchWithFallbackValidated() error = %v", leader.err)
	}
	if string(leader.result.Snapshot.Body) != freshBody || leader.result.UsedCache || !leader.result.Updated {
		t.Fatalf("leader result = %#v, want fresh non-cache update", leader.result)
	}

	var waiter fetchCall
	select {
	case waiter = <-waiterDone:
	case <-time.After(requestWaitLimit):
		t.Fatal("timed out waiting for waiter result")
	}
	if waiter.err != nil {
		t.Fatalf("waiter FetchWithFallbackValidated() error = %v", waiter.err)
	}
	if string(waiter.result.Snapshot.Body) != waiterFallback || !waiter.result.UsedCache || waiter.result.Updated || waiter.result.Warning == nil {
		t.Fatalf("waiter result = %#v, want its own validated fallback with warning", waiter.result)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want one shared request", got)
	}
}

func TestFetchWithFallbackValidatedIsolatesConcurrentMaxSize(t *testing.T) {
	const (
		freshBody      = "payload: [fresh-max-size.example]\n"
		leaderFallback = "payload: [leader-old]\n"
		waiterFallback = "payload: [waiter-old]\n"
		waitLimit      = 5 * time.Second
	)

	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	var requestOnce sync.Once
	var releaseOnce sync.Once
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		requestOnce.Do(func() { close(requestStarted) })
		<-releaseResponse
		_, _ = fmt.Fprint(w, freshBody)
	}))
	defer server.Close()
	release := func() {
		releaseOnce.Do(func() { close(releaseResponse) })
	}
	defer release()

	fetcher := newTestProviderFetcher(server.Client(), t.TempDir())
	leaderSpec := ProviderSpec{
		Name:     "p",
		Type:     "http",
		URL:      server.URL,
		Behavior: "domain",
		Format:   "yaml",
		MaxSize:  int64(len(freshBody) + 1),
	}
	waiterSpec := leaderSpec
	waiterSpec.MaxSize = int64(len(waiterFallback))
	makeFallback := func(spec ProviderSpec, body string) ProviderSnapshot {
		bodyBytes := []byte(body)
		return ProviderSnapshot{
			Name:      spec.Name,
			Body:      bodyBytes,
			SourceKey: digest([]byte(spec.URL)),
			SHA256:    digest(bodyBytes),
			Behavior:  spec.Behavior,
			Format:    spec.Format,
		}
	}

	type fetchCall struct {
		result FetchResult
		err    error
	}
	leaderDone := make(chan fetchCall, 1)
	go func() {
		result, err := fetcher.FetchWithFallbackValidated(
			context.Background(),
			leaderSpec,
			makeFallback(leaderSpec, leaderFallback),
			func(_ ProviderSpec, body []byte) error {
				if string(body) != freshBody && string(body) != leaderFallback {
					return fmt.Errorf("leader validator rejected %q", body)
				}
				return nil
			},
		)
		leaderDone <- fetchCall{result: result, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for leader HTTP request barrier")
	}

	waiterFallbackValidated := make(chan struct{})
	var waiterFallbackOnce sync.Once
	waiterEnteredFlight := make(chan struct{})
	waiterCtx := &fetchFlightProbeContext{
		Context: context.Background(),
		entered: waiterEnteredFlight,
	}
	waiterDone := make(chan fetchCall, 1)
	go func() {
		result, err := fetcher.FetchWithFallbackValidated(
			waiterCtx,
			waiterSpec,
			makeFallback(waiterSpec, waiterFallback),
			func(_ ProviderSpec, body []byte) error {
				switch string(body) {
				case waiterFallback:
					waiterFallbackOnce.Do(func() { close(waiterFallbackValidated) })
				case freshBody:
				default:
					return fmt.Errorf("waiter validator rejected %q", body)
				}
				return nil
			},
		)
		waiterDone <- fetchCall{result: result, err: err}
	}()

	select {
	case <-waiterFallbackValidated:
	case <-time.After(waitLimit):
		t.Fatal("timed out validating waiter fallback")
	}
	select {
	case <-waiterEnteredFlight:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for waiter to join the shared flight")
	}
	release()

	var leader fetchCall
	select {
	case leader = <-leaderDone:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for leader result")
	}
	if leader.err != nil {
		t.Fatalf("leader FetchWithFallbackValidated() error = %v", leader.err)
	}
	if string(leader.result.Snapshot.Body) != freshBody || leader.result.UsedCache || !leader.result.Updated {
		t.Fatalf("leader result = %#v, want fresh non-cache update", leader.result)
	}

	var waiter fetchCall
	select {
	case waiter = <-waiterDone:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for waiter result")
	}
	if waiter.err != nil {
		t.Fatalf("waiter FetchWithFallbackValidated() error = %v", waiter.err)
	}
	if string(waiter.result.Snapshot.Body) != waiterFallback || !waiter.result.UsedCache || waiter.result.Updated || waiter.result.Warning == nil {
		t.Fatalf("waiter result = %#v, want its own max-size-valid fallback with warning", waiter.result)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want one shared request", got)
	}
}

func TestFetchWithFallbackValidatedPropagatesWaiterCancellation(t *testing.T) {
	const (
		freshBody      = "payload: [fresh-cancellation.example]\n"
		leaderFallback = "payload: [leader-old]\n"
		waiterFallback = "payload: [waiter-old]\n"
		waitLimit      = 5 * time.Second
	)

	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	var requestOnce sync.Once
	var releaseOnce sync.Once
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		requestOnce.Do(func() { close(requestStarted) })
		<-releaseResponse
		_, _ = fmt.Fprint(w, freshBody)
	}))
	defer server.Close()
	release := func() {
		releaseOnce.Do(func() { close(releaseResponse) })
	}
	defer release()

	fetcher := newTestProviderFetcher(server.Client(), t.TempDir())
	spec := ProviderSpec{
		Name:     "p",
		Type:     "http",
		URL:      server.URL,
		Behavior: "domain",
		Format:   "yaml",
		MaxSize:  int64(len(freshBody) + 1),
	}
	makeFallback := func(body string) ProviderSnapshot {
		bodyBytes := []byte(body)
		return ProviderSnapshot{
			Name:      spec.Name,
			Body:      bodyBytes,
			SourceKey: digest([]byte(spec.URL)),
			SHA256:    digest(bodyBytes),
			Behavior:  spec.Behavior,
			Format:    spec.Format,
		}
	}

	type fetchCall struct {
		result FetchResult
		err    error
	}
	leaderDone := make(chan fetchCall, 1)
	go func() {
		result, err := fetcher.FetchWithFallbackValidated(
			context.Background(),
			spec,
			makeFallback(leaderFallback),
			func(_ ProviderSpec, body []byte) error {
				if string(body) != freshBody {
					return fmt.Errorf("leader validator rejected %q", body)
				}
				return nil
			},
		)
		leaderDone <- fetchCall{result: result, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for leader HTTP request barrier")
	}

	waiterFallbackValidated := make(chan struct{})
	var waiterFallbackOnce sync.Once
	waiterEnteredFlight := make(chan struct{})
	waiterBaseCtx, cancelWaiter := context.WithCancel(context.Background())
	defer cancelWaiter()
	waiterCtx := &fetchFlightProbeContext{
		Context: waiterBaseCtx,
		entered: waiterEnteredFlight,
	}
	waiterDone := make(chan fetchCall, 1)
	go func() {
		result, err := fetcher.FetchWithFallbackValidated(
			waiterCtx,
			spec,
			makeFallback(waiterFallback),
			func(_ ProviderSpec, body []byte) error {
				if string(body) == waiterFallback {
					waiterFallbackOnce.Do(func() { close(waiterFallbackValidated) })
					return nil
				}
				return fmt.Errorf("waiter validator rejected %q", body)
			},
		)
		waiterDone <- fetchCall{result: result, err: err}
	}()

	select {
	case <-waiterFallbackValidated:
	case <-time.After(waitLimit):
		t.Fatal("timed out validating waiter fallback")
	}
	select {
	case <-waiterEnteredFlight:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for waiter to join the shared flight")
	}
	cancelWaiter()

	var waiter fetchCall
	select {
	case waiter = <-waiterDone:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for canceled waiter result")
	}
	if !errors.Is(waiter.err, context.Canceled) {
		t.Fatalf("waiter error = %v, result = %#v; want context.Canceled without fallback success", waiter.err, waiter.result)
	}

	release()
	var leader fetchCall
	select {
	case leader = <-leaderDone:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for leader result after waiter cancellation")
	}
	if leader.err != nil {
		t.Fatalf("leader FetchWithFallbackValidated() error = %v", leader.err)
	}
	if string(leader.result.Snapshot.Body) != freshBody || leader.result.UsedCache || !leader.result.Updated {
		t.Fatalf("leader result = %#v, want fresh non-cache update", leader.result)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want one shared request", got)
	}
}

func TestFetchWithFallbackValidatedLeaderCancellationDoesNotCancelWaiter(t *testing.T) {
	const (
		freshBody         = "payload: [leader-cancellation-fresh.example]\n"
		leaderCancelLimit = time.Second
		waitLimit         = 5 * time.Second
	)

	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	var requestOnce sync.Once
	var releaseOnce sync.Once
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		requestOnce.Do(func() { close(requestStarted) })
		<-releaseResponse
		_, _ = fmt.Fprint(w, freshBody)
	}))
	defer server.Close()
	release := func() {
		releaseOnce.Do(func() { close(releaseResponse) })
	}
	defer release()

	fetcher := newTestProviderFetcher(server.Client(), t.TempDir())
	spec := ProviderSpec{
		Name:     "p",
		Type:     "http",
		URL:      server.URL,
		Behavior: "domain",
		Format:   "yaml",
		MaxSize:  1024,
	}
	makeFallback := func(body string) ProviderSnapshot {
		bodyBytes := []byte(body)
		return ProviderSnapshot{
			Name:      spec.Name,
			Body:      bodyBytes,
			SourceKey: digest([]byte(spec.URL)),
			SHA256:    digest(bodyBytes),
			Behavior:  spec.Behavior,
			Format:    spec.Format,
		}
	}

	type fetchCall struct {
		result FetchResult
		err    error
	}
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderDone := make(chan fetchCall, 1)
	go func() {
		result, err := fetcher.FetchWithFallbackValidated(
			leaderContext,
			spec,
			makeFallback("payload: [leader-old.example]\n"),
			func(_ ProviderSpec, body []byte) error {
				switch string(body) {
				case freshBody, "payload: [leader-old.example]\n":
					return nil
				default:
					return fmt.Errorf("leader validator rejected %q", body)
				}
			},
		)
		leaderDone <- fetchCall{result: result, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for leader HTTP request barrier")
	}

	waiterEnteredFlight := make(chan struct{})
	waiterContext := &fetchFlightProbeContext{
		Context: context.Background(),
		entered: waiterEnteredFlight,
	}
	waiterDone := make(chan fetchCall, 1)
	go func() {
		result, err := fetcher.FetchWithFallbackValidated(
			waiterContext,
			spec,
			makeFallback("payload: [waiter-old.example]\n"),
			func(_ ProviderSpec, body []byte) error {
				switch string(body) {
				case freshBody, "payload: [waiter-old.example]\n":
					return nil
				default:
					return fmt.Errorf("waiter validator rejected %q", body)
				}
			},
		)
		waiterDone <- fetchCall{result: result, err: err}
	}()

	select {
	case <-waiterEnteredFlight:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for waiter to join the shared flight")
	}
	cancelLeader()

	var leader fetchCall
	select {
	case leader = <-leaderDone:
		if !errors.Is(leader.err, context.Canceled) {
			t.Fatalf("leader error = %v, result = %#v; want context.Canceled while response is blocked", leader.err, leader.result)
		}
	case <-time.After(leaderCancelLimit):
		t.Fatal("timed out waiting for canceled leader while response was blocked")
	}
	release()

	var waiter fetchCall
	select {
	case waiter = <-waiterDone:
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for waiter result")
	}
	if waiter.err != nil {
		t.Fatalf("waiter FetchWithFallbackValidated() error = %v, result = %#v; want fresh response", waiter.err, waiter.result)
	}
	if string(waiter.result.Snapshot.Body) != freshBody || waiter.result.UsedCache || !waiter.result.Updated {
		t.Fatalf("waiter result = %#v, want fresh non-cache update", waiter.result)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want one shared request", got)
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
