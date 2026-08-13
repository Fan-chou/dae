package ruleprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func stage4ARefreshConfig(provider config.RuleProvider, routeProvider string) *config.Config {
	return &config.Config{
		RuleProvider: []config.RuleProvider{provider},
		Routing: config.Routing{
			Rules: []*config_parser.RoutingRule{{
				AndFunctions: []*config_parser.Function{{
					Name:   "ruleset",
					Params: []*config_parser.Param{{Val: routeProvider}},
				}},
				Outbound: config_parser.Function{Name: "proxy"},
			}},
		},
	}
}

func stage4ARefreshConfigForProviders(providers ...config.RuleProvider) *config.Config {
	rules := make([]*config_parser.RoutingRule, 0, len(providers))
	for _, provider := range providers {
		rules = append(rules, &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{{
				Name:   "ruleset",
				Params: []*config_parser.Param{{Val: provider.Name}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		})
	}
	return &config.Config{
		RuleProvider: providers,
		Routing: config.Routing{
			Rules: rules,
		},
	}
}

func assertStage4ARefreshKeepsRuleset(t *testing.T, conf *config.Config, routeProvider string) {
	t.Helper()
	if len(conf.Routing.Rules) != 1 {
		t.Fatalf("routing rules = %#v, want one unexpanded rule", conf.Routing.Rules)
	}
	rule := conf.Routing.Rules[0]
	if len(rule.AndFunctions) != 1 {
		t.Fatalf("routing rule functions = %#v, want one ruleset function", rule.AndFunctions)
	}
	ruleset := rule.AndFunctions[0]
	if ruleset.Name != "ruleset" {
		t.Fatalf("routing function name = %q, want ruleset", ruleset.Name)
	}
	if len(ruleset.Params) != 1 || ruleset.Params[0].Val != routeProvider {
		t.Fatalf("routing ruleset params = %#v, want provider %q", ruleset.Params, routeProvider)
	}
	if rule.Outbound.Name != "proxy" {
		t.Fatalf("routing outbound = %#v, want proxy", rule.Outbound)
	}
}

func stage4AReadPublishedSnapshot(t *testing.T, descriptor cacheDescriptor) (cacheSnapshot, currentState) {
	t.Helper()
	state, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("readCurrentState() error = %v", err)
	}
	if !state.exists {
		t.Fatalf("provider cache current is absent")
	}
	snapshot, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() error = %v", err)
	}
	return snapshot, state
}

func assertStage4ANoPublishedSnapshot(t *testing.T, descriptor cacheDescriptor) {
	t.Helper()
	state, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("readCurrentState() error = %v", err)
	}
	if state.exists {
		t.Fatalf("provider cache current = %#v, want absent", state)
	}
	if _, err := readCacheSnapshot(descriptor); err == nil {
		t.Fatal("readCacheSnapshot() error = nil, want no provider cache")
	}
}

func TestRefreshFileProviderReportsOutcomeAndPreservesRuleset(t *testing.T) {
	dir := t.TempDir()
	provider := config.RuleProvider{
		Name: "local", Type: "file", Path: "rules.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	conf := stage4ARefreshConfig(provider, provider.Name)
	path := filepath.Join(dir, provider.Path)
	firstBody := []byte("payload:\n  - first.example\n")
	secondBody := []byte("payload:\n  - second.example\n")
	if err := os.WriteFile(path, firstBody, 0o600); err != nil {
		t.Fatalf("WriteFile(first provider body) error = %v", err)
	}
	descriptor := testCacheDescriptor(t, provider, dir)

	report, err := Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}
	if report != (RefreshReport{Changed: true}) {
		t.Fatalf("first Refresh() report = %#v, want changed=true and no last-good fallback", report)
	}
	first, firstState := stage4AReadPublishedSnapshot(t, descriptor)
	if string(first.body) != string(firstBody) {
		t.Fatalf("first cache body = %q, want %q", first.body, firstBody)
	}
	assertStage4ARefreshKeepsRuleset(t, conf, provider.Name)

	report, err = Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("same-body Refresh() error = %v", err)
	}
	if report != (RefreshReport{}) {
		t.Fatalf("same-body Refresh() report = %#v, want unchanged without last-good fallback", report)
	}
	same, sameState := stage4AReadPublishedSnapshot(t, descriptor)
	if string(same.body) != string(firstBody) {
		t.Fatalf("same-body cache body = %q, want %q", same.body, firstBody)
	}
	if sameState.target != firstState.target {
		t.Fatalf("same-body current target = %q, want unchanged target %q", sameState.target, firstState.target)
	}
	assertStage4ARefreshKeepsRuleset(t, conf, provider.Name)

	if err := os.WriteFile(path, secondBody, 0o600); err != nil {
		t.Fatalf("WriteFile(second provider body) error = %v", err)
	}
	report, err = Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("changed-body Refresh() error = %v", err)
	}
	if report != (RefreshReport{Changed: true}) {
		t.Fatalf("changed-body Refresh() report = %#v, want changed=true and no last-good fallback", report)
	}
	changed, _ := stage4AReadPublishedSnapshot(t, descriptor)
	if string(changed.body) != string(secondBody) {
		t.Fatalf("changed-body cache body = %q, want %q", changed.body, secondBody)
	}
	assertStage4ARefreshKeepsRuleset(t, conf, provider.Name)
}

func TestRefreshHTTPProviderUsesLastGoodAfter503(t *testing.T) {
	status := http.StatusOK
	firstBody := "payload:\n  - first.example\n"
	server := newPublicHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = fmt.Fprint(w, firstBody)
	}))

	dir := t.TempDir()
	provider := config.RuleProvider{
		Name: "remote", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	conf := stage4ARefreshConfig(provider, provider.Name)
	descriptor := testCacheDescriptor(t, provider, dir)

	report, err := Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("initial HTTP Refresh() error = %v", err)
	}
	if report != (RefreshReport{Changed: true}) {
		t.Fatalf("initial HTTP Refresh() report = %#v, want changed=true and no last-good fallback", report)
	}
	initial, initialState := stage4AReadPublishedSnapshot(t, descriptor)
	if string(initial.body) != firstBody {
		t.Fatalf("initial HTTP cache body = %q, want %q", initial.body, firstBody)
	}
	assertStage4ARefreshKeepsRuleset(t, conf, provider.Name)

	status = http.StatusServiceUnavailable
	report, err = Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("503 HTTP Refresh() error = %v, want last-good recovery", err)
	}
	if report != (RefreshReport{UsedLastGood: true}) {
		t.Fatalf("503 HTTP Refresh() report = %#v, want unchanged with last-good fallback", report)
	}
	lastGood, lastGoodState := stage4AReadPublishedSnapshot(t, descriptor)
	if string(lastGood.body) != firstBody {
		t.Fatalf("503 HTTP cache body = %q, want first valid body %q", lastGood.body, firstBody)
	}
	if lastGoodState.target != initialState.target {
		t.Fatalf("503 HTTP current target = %q, want no new publish at %q", lastGoodState.target, initialState.target)
	}
	if lastGood.metadata != initial.metadata {
		t.Fatalf("503 HTTP cache metadata changed: initial=%#v lastGood=%#v", initial.metadata, lastGood.metadata)
	}
	assertStage4ARefreshKeepsRuleset(t, conf, provider.Name)
}

func TestRefreshSameGenerationBodyDifferentETagDoesNotReportChange(t *testing.T) {
	const (
		body       = "payload:\n  - stable.example\n"
		generation = "same-generation"
	)
	requestCount := 0
	server := newPublicHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		w.Header().Set(providerGenerationHeader, generation)
		w.Header().Set("ETag", fmt.Sprintf("\"etag-%d\"", requestCount))
		_, _ = fmt.Fprint(w, body)
	}))

	dir := t.TempDir()
	provider := config.RuleProvider{
		Name: "remote", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	conf := stage4ARefreshConfig(provider, provider.Name)
	descriptor := testCacheDescriptor(t, provider, dir)

	report, err := Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}
	if report != (RefreshReport{Changed: true}) {
		t.Fatalf("first Refresh() report = %#v, want changed=true", report)
	}
	first, firstState := stage4AReadPublishedSnapshot(t, descriptor)

	report, err = Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("same-generation same-body different-ETag Refresh() error = %v", err)
	}
	if report != (RefreshReport{}) {
		t.Fatalf("same-generation same-body different-ETag Refresh() report = %#v, want unchanged", report)
	}
	second, secondState := stage4AReadPublishedSnapshot(t, descriptor)
	if secondState.target != firstState.target {
		t.Fatalf("same-generation same-body different-ETag current target = %q, want unchanged target %q", secondState.target, firstState.target)
	}
	if second.metadata != first.metadata || string(second.body) != string(first.body) {
		t.Fatalf("same-generation same-body different-ETag published snapshot changed: first=%#v/%q second=%#v/%q", first.metadata, first.body, second.metadata, second.body)
	}
}

func TestRefreshMixedFreshAndLastGoodReportsBothOutcomes(t *testing.T) {
	providerA := config.RuleProvider{
		Name: "a", Type: "file", Path: "a.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	providerB := config.RuleProvider{
		Name: "b", Type: "file", Path: "b.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	oldBodyA := []byte("payload:\n  - a-old.example\n")
	newBodyA := []byte("payload:\n  - a-new.example\n")
	oldBodyB := []byte("payload:\n  - b-old.example\n")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, providerA.Path), oldBodyA, 0o600); err != nil {
		t.Fatalf("WriteFile(A initial body) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, providerB.Path), oldBodyB, 0o600); err != nil {
		t.Fatalf("WriteFile(B initial body) error = %v", err)
	}
	conf := stage4ARefreshConfigForProviders(providerA, providerB)
	descriptorA := testCacheDescriptor(t, providerA, dir)
	descriptorB := testCacheDescriptor(t, providerB, dir)

	report, err := Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("initial mixed-provider Refresh() error = %v", err)
	}
	if report != (RefreshReport{Changed: true}) {
		t.Fatalf("initial mixed-provider Refresh() report = %#v, want changed=true", report)
	}
	initialA, initialAState := stage4AReadPublishedSnapshot(t, descriptorA)
	initialB, initialBState := stage4AReadPublishedSnapshot(t, descriptorB)
	if string(initialA.body) != string(oldBodyA) || string(initialB.body) != string(oldBodyB) {
		t.Fatalf("initial mixed-provider snapshots = A:%q B:%q, want initial bodies", initialA.body, initialB.body)
	}

	if err := os.WriteFile(filepath.Join(dir, providerA.Path), newBodyA, 0o600); err != nil {
		t.Fatalf("WriteFile(A updated body) error = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, providerB.Path)); err != nil {
		t.Fatalf("Remove(B source) error = %v", err)
	}

	report, err = Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err != nil {
		t.Fatalf("mixed fresh/last-good Refresh() error = %v", err)
	}
	if report != (RefreshReport{Changed: true, UsedLastGood: true}) {
		t.Fatalf("mixed fresh/last-good Refresh() report = %#v, want changed=true and used-last-good=true", report)
	}
	currentA, currentAState := stage4AReadPublishedSnapshot(t, descriptorA)
	currentB, currentBState := stage4AReadPublishedSnapshot(t, descriptorB)
	if string(currentA.body) != string(newBodyA) || currentAState.target == initialAState.target {
		t.Fatalf("A after mixed fresh/last-good Refresh() = body:%q state:%#v, want new body and new current", currentA.body, currentAState)
	}
	if string(currentB.body) != string(oldBodyB) || currentBState.target != initialBState.target || currentB.metadata != initialB.metadata {
		t.Fatalf("B after mixed fresh/last-good Refresh() = body:%q state:%#v metadata:%#v, want unchanged last-good snapshot", currentB.body, currentBState, currentB.metadata)
	}
}

func TestRefreshRejectsInvalidRulesetWithoutPublishing(t *testing.T) {
	dir := t.TempDir()
	provider := config.RuleProvider{
		Name: "available", Type: "file", Path: "rules.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	if err := os.WriteFile(filepath.Join(dir, provider.Path), []byte("payload:\n  - valid.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(provider body) error = %v", err)
	}
	conf := stage4ARefreshConfig(provider, "missing")
	descriptor := testCacheDescriptor(t, provider, dir)

	report, err := Refresh(context.Background(), conf, dir, http.DefaultClient)
	if err == nil {
		t.Fatal("invalid ruleset Refresh() error = nil, want route expansion error")
	}
	if report != (RefreshReport{}) {
		t.Fatalf("invalid ruleset Refresh() report = %#v, want all false", report)
	}
	assertStage4ANoPublishedSnapshot(t, descriptor)
	assertStage4ARefreshKeepsRuleset(t, conf, "missing")
}

func TestRefreshCanceledContextDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	provider := config.RuleProvider{
		Name: "canceled", Type: "file", Path: "rules.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	if err := os.WriteFile(filepath.Join(dir, provider.Path), []byte("payload:\n  - canceled.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(provider body) error = %v", err)
	}
	conf := stage4ARefreshConfig(provider, provider.Name)
	descriptor := testCacheDescriptor(t, provider, dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report, err := Refresh(ctx, conf, dir, http.DefaultClient)
	if err == nil {
		t.Fatal("canceled Refresh() error = nil, want context cancellation error")
	}
	if report != (RefreshReport{}) {
		t.Fatalf("canceled Refresh() report = %#v, want all false", report)
	}
	assertStage4ANoPublishedSnapshot(t, descriptor)
	assertStage4ARefreshKeepsRuleset(t, conf, provider.Name)
}

type stage4ACancelAtPublishBoundaryContext struct {
	context.Context
	cancel   context.CancelFunc
	errCalls int
}

func (ctx *stage4ACancelAtPublishBoundaryContext) Err() error {
	ctx.errCalls++
	if ctx.errCalls == 3 {
		// Refresh has completed preparation and its final pre-publish check. The
		// test holds cachePublishMu, so the next operation waits for the lock.
		ctx.cancel()
		return nil
	}
	return ctx.Context.Err()
}

func TestRefreshCanceledWhileWaitingForPublishLockDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	provider := config.RuleProvider{
		Name: "locked", Type: "file", Path: "rules.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	if err := os.WriteFile(filepath.Join(dir, provider.Path), []byte("payload:\n  - locked.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(provider body) error = %v", err)
	}
	conf := stage4ARefreshConfig(provider, provider.Name)
	descriptor := testCacheDescriptor(t, provider, dir)
	baseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &stage4ACancelAtPublishBoundaryContext{Context: baseCtx, cancel: cancel}

	cachePublishMu.Lock()
	released := false
	defer func() {
		if !released {
			cachePublishMu.Unlock()
		}
	}()

	var report RefreshReport
	var refreshErr error
	done := make(chan struct{})
	go func() {
		report, refreshErr = Refresh(ctx, conf, dir, http.DefaultClient)
		close(done)
	}()

	select {
	case <-baseCtx.Done():
	case <-done:
		// A context-aware implementation may return before the held lock is
		// released; the result assertions below still cover the contract.
	}
	cachePublishMu.Unlock()
	released = true

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Refresh did not complete after publish lock release")
	}
	if !errors.Is(refreshErr, context.Canceled) {
		t.Errorf("canceled Refresh() error = %v, want context cancellation", refreshErr)
	}
	if report != (RefreshReport{}) {
		t.Errorf("canceled while waiting for publish lock Refresh() report = %#v, want all false", report)
	}
	assertStage4ANoPublishedSnapshot(t, descriptor)
	assertStage4ARefreshKeepsRuleset(t, conf, provider.Name)
}
