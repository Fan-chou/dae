package ruleprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	defaultMaxSize                      = 8 << 20
	maxSize                             = 64 << 20
	maxProviderRules                    = 100000
	maxProviderRuleLength               = 16 << 10
	maxExpandedRoutingRules             = 100000
	maxProviderYAMLNodes                = 100000
	maxProviderYAMLDepth                = 64
	maxHTTPTimeout                      = 45 * time.Second
	maxHTTPRedirects                    = 5
	maxResponseHeaderBytes              = 1 << 20
	cacheSchemaVersion                  = 2
	maxCacheMetadataSize                = 1 << 20
	maxCacheVersions                    = 3
	cacheTransactionVersion             = 1
	cacheInsecurePermissionBits         = 0o022
	providerGenerationHeader            = "X-Dae-Rule-Provider-Generation"
	maxProviderGenerationLength         = 256
	maxProviderGenerationHistoryEntries = 16
	maxProviderGenerationHistoryBytes   = maxProviderGenerationHistoryEntries * maxProviderGenerationLength
	batchIdentityBytes                  = 16
	batchIdentityLength                 = batchIdentityBytes * 2
)

var providerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

type ProviderRules struct {
	Functions []*config_parser.Function
}

type Registry map[string]ProviderRules

// RefreshReport describes whether Refresh published a new provider snapshot or
// continued using an existing last-good snapshot after a source failure.
type RefreshReport struct {
	Changed      bool
	UsedLastGood bool
}

// ErrProductionRuntimeDisabled is kept for source compatibility with callers
// that used the phase-0 gate. The production loader is now enabled and never
// returns this sentinel.
var ErrProductionRuntimeDisabled = errors.New("native rule provider runtime is disabled until security hardening is complete")

// loadOptions is intentionally unexported. Private-network access is only a
// same-package test hook; production callers can only use the safe Load path.
type loadOptions struct {
	allowPrivate bool
}

type preparedProvider struct {
	name                 string
	rules                ProviderRules
	generation           string
	batchIdentity        string
	usedLastGood         bool
	descriptor           cacheDescriptor
	candidate            *cacheCandidate
	expectedCurrent      currentState
	expectedCurrentKnown bool
}

type cacheCandidate struct {
	descriptor           cacheDescriptor
	body                 []byte
	etag                 string
	modified             string
	generation           string
	preparedAt           time.Time
	updatedAt            time.Time
	batchIdentity        string
	expectedCurrent      currentState
	expectedCurrentKnown bool
}

type cacheDescriptor struct {
	root       string
	name       string
	sourceType string
	source     string
	sourceKey  string
	behavior   string
	format     string
	maxSize    int64
}

// generationHistory is deliberately a fixed-size array so cacheMetadata stays
// comparable. Some callers use whole-metadata equality to verify that a
// failed publish did not mutate the current snapshot. The JSON representation
// is a compact variable-length array, while the in-memory representation keeps
// the history bounded regardless of metadata input.
type generationHistory [maxProviderGenerationHistoryEntries]string

func (history generationHistory) MarshalJSON() ([]byte, error) {
	values, err := history.values()
	if err != nil {
		return nil, err
	}
	return json.Marshal(values)
}

func (history *generationHistory) UnmarshalJSON(body []byte) error {
	if history == nil {
		return errors.New("provider generation history is nil")
	}
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return errors.New("provider generation history must be an array")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '[' {
		return errors.New("provider generation history must be an array")
	}

	var parsed generationHistory
	seen := make(map[string]struct{}, maxProviderGenerationHistoryEntries)
	totalBytes := 0
	index := 0
	for decoder.More() {
		if index >= maxProviderGenerationHistoryEntries {
			return fmt.Errorf("provider generation history exceeds %d entries", maxProviderGenerationHistoryEntries)
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("decode provider generation history entry: %w", err)
		}
		if _, err := validateProviderGeneration(value, "cache generation history entry"); err != nil {
			return err
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("cache generation history contains duplicate generation %q", value)
		}
		seen[value] = struct{}{}
		totalBytes += len(value)
		if totalBytes > maxProviderGenerationHistoryBytes {
			return fmt.Errorf("provider generation history exceeds %d bytes", maxProviderGenerationHistoryBytes)
		}
		parsed[index] = value
		index++
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != ']' {
		return errors.New("provider generation history is not a complete array")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("provider generation history has trailing data")
		}
		return err
	}
	*history = parsed
	return nil
}

func (history generationHistory) values() ([]string, error) {
	values := make([]string, 0, len(history))
	seen := make(map[string]struct{}, len(history))
	totalBytes := 0
	for index, value := range history {
		if value == "" {
			for _, trailing := range history[index+1:] {
				if trailing != "" {
					return nil, errors.New("provider generation history contains a gap")
				}
			}
			break
		}
		if _, err := validateProviderGeneration(value, "cache generation history entry"); err != nil {
			return nil, err
		}
		if _, ok := seen[value]; ok {
			return nil, fmt.Errorf("cache generation history contains duplicate generation %q", value)
		}
		seen[value] = struct{}{}
		totalBytes += len(value)
		if totalBytes > maxProviderGenerationHistoryBytes {
			return nil, fmt.Errorf("provider generation history exceeds %d bytes", maxProviderGenerationHistoryBytes)
		}
		values = append(values, value)
	}
	return values, nil
}

func (history generationHistory) contains(value string) bool {
	for _, entry := range history {
		if entry == "" {
			return false
		}
		if entry == value {
			return true
		}
	}
	return false
}

func prependGenerationHistory(history generationHistory, generation string) (generationHistory, error) {
	if generation == "" {
		return history, nil
	}
	if _, err := validateProviderGeneration(generation, "cache generation history entry"); err != nil {
		return generationHistory{}, err
	}
	values, err := history.values()
	if err != nil {
		return generationHistory{}, err
	}
	if len(values) > 0 && values[0] == generation {
		return history, nil
	}
	updated := generationHistory{}
	updated[0] = generation
	index := 1
	for _, value := range values {
		if value == generation {
			continue
		}
		if index >= len(updated) {
			break
		}
		updated[index] = value
		index++
	}
	return updated, nil
}

type cacheMetadata struct {
	SchemaVersion     int               `json:"schema_version"`
	ProviderName      string            `json:"provider_name"`
	SourceType        string            `json:"source_type"`
	Source            string            `json:"source"`
	SourceKey         string            `json:"source_key"`
	Behavior          string            `json:"behavior"`
	Format            string            `json:"format"`
	MaxSize           int64             `json:"max_size"`
	SHA256            string            `json:"sha256"`
	UpdatedAt         time.Time         `json:"updated_at"`
	ETag              string            `json:"etag,omitempty"`
	LastModified      string            `json:"last_modified,omitempty"`
	Generation        string            `json:"generation,omitempty"`
	GenerationHistory generationHistory `json:"generation_history,omitempty"`
	BatchIdentity     string            `json:"batch_identity,omitempty"`
}

type cacheSnapshot struct {
	body       []byte
	metadata   cacheMetadata
	generation string
}

type preparedCache struct {
	candidate  *cacheCandidate
	versionDir string
	old        currentState
}

type cacheTransaction struct {
	SchemaVersion int                              `json:"schema_version"`
	State         string                           `json:"state"`
	Generation    string                           `json:"generation"`
	BatchIdentity string                           `json:"batch_identity,omitempty"`
	Providers     map[string]cacheTransactionEntry `json:"providers"`
}

type cacheTransactionEntry struct {
	OldCurrent string `json:"old_current"`
	NewCurrent string `json:"new_current"`
}

type transactionLock struct {
	file *os.File
}

type fetchedBody struct {
	body         []byte
	etag         string
	lastModified string
	generation   string
	notModified  bool
}

func Load(ctx context.Context, providers []config.RuleProvider, baseDir string, client *http.Client) (Registry, error) {
	return loadWithOptions(ctx, providers, baseDir, client, loadOptions{})
}

func loadWithOptions(ctx context.Context, providers []config.RuleProvider, baseDir string, client *http.Client, options loadOptions) (Registry, error) {
	if len(providers) != 0 && baseDir != "" {
		if err := recoverPendingPublish(baseDir); err != nil {
			return nil, err
		}
	}
	registry, prepared, err := prepareProviders(ctx, providers, baseDir, client, options)
	if err != nil {
		return nil, err
	}
	if err := publishPrepared(prepared); err != nil {
		return nil, err
	}
	return registry, nil
}

func LoadAndExpand(ctx context.Context, conf *config.Config, baseDir string, client *http.Client) error {
	return loadAndExpandWithOptions(ctx, conf, baseDir, client, loadOptions{})
}

// Refresh prepares a complete provider snapshot, validates that the current
// routing rules can expand against it, then publishes any changed providers.
// It intentionally leaves conf.Routing.Rules unchanged so callers can retain
// ruleset() declarations for subsequent refreshes.
func Refresh(ctx context.Context, conf *config.Config, baseDir string, client *http.Client) (RefreshReport, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return RefreshReport{}, err
		}
	}
	if conf == nil {
		return RefreshReport{}, nil
	}
	if len(conf.RuleProvider) == 0 {
		if _, err := ExpandRoutingRules(conf.Routing.Rules, Registry{}); err != nil {
			return RefreshReport{}, err
		}
		return RefreshReport{}, nil
	}
	if baseDir != "" {
		if err := recoverPendingPublish(baseDir); err != nil {
			return RefreshReport{}, err
		}
	}
	registry, prepared, err := prepareProviders(ctx, conf.RuleProvider, baseDir, client, loadOptions{})
	if err != nil {
		return RefreshReport{}, err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return RefreshReport{}, err
		}
	}
	if _, err := ExpandRoutingRules(conf.Routing.Rules, registry); err != nil {
		return RefreshReport{}, err
	}

	hasCandidate := false
	usedLastGood := false
	for _, provider := range prepared {
		if provider.candidate != nil {
			hasCandidate = true
		}
		if provider.usedLastGood {
			usedLastGood = true
		}
	}
	if !hasCandidate {
		return RefreshReport{UsedLastGood: usedLastGood}, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return RefreshReport{}, err
		}
	}
	published, err := publishPreparedWithContext(ctx, prepared)
	if err != nil {
		return RefreshReport{}, err
	}
	return RefreshReport{Changed: published, UsedLastGood: usedLastGood}, nil
}

func loadAndExpandWithOptions(ctx context.Context, conf *config.Config, baseDir string, client *http.Client, options loadOptions) error {
	if conf == nil {
		return nil
	}
	if len(conf.RuleProvider) == 0 {
		rules, err := ExpandRoutingRules(conf.Routing.Rules, Registry{})
		if err != nil {
			return err
		}
		conf.Routing.Rules = rules
		return nil
	}
	if baseDir != "" {
		if err := recoverPendingPublish(baseDir); err != nil {
			return err
		}
	}
	registry, prepared, err := prepareProviders(ctx, conf.RuleProvider, baseDir, client, options)
	if err != nil {
		return err
	}
	rules, err := ExpandRoutingRules(conf.Routing.Rules, registry)
	if err != nil {
		return err
	}
	if err := publishPrepared(prepared); err != nil {
		return err
	}
	conf.Routing.Rules = rules
	return nil
}

func prepareProviders(ctx context.Context, providers []config.RuleProvider, baseDir string, client *http.Client, options loadOptions) (Registry, []preparedProvider, error) {
	if baseDir == "" {
		return nil, nil, fmt.Errorf("rule provider base directory is empty")
	}
	var err error
	baseDir, err = filepath.Abs(baseDir)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve rule provider base directory: %w", err)
	}
	if len(providers) != 0 {
		baseInfo, err := os.Lstat(baseDir)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect rule provider base directory: %w", err)
		}
		if baseInfo.Mode()&os.ModeSymlink != 0 || !baseInfo.IsDir() {
			return nil, nil, errors.New("rule provider base directory is not a directory")
		}
		resolvedBase, err := filepath.EvalSymlinks(baseDir)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve rule provider base directory: %w", err)
		}
		baseDir = resolvedBase
	}
	if client == nil {
		client = http.DefaultClient
	}
	if ctx == nil {
		ctx = context.Background()
	}

	normalized := make([]config.RuleProvider, len(providers))
	for i, provider := range providers {
		normalized[i] = normalizeProvider(provider)
		if err := validateProviderDefinition(normalized[i], baseDir, options.allowPrivate); err != nil {
			return nil, nil, err
		}
	}
	if !options.allowPrivate {
		if err := config.ValidateRuleProviders(normalized, baseDir); err != nil {
			return nil, nil, err
		}
	}

	registry := make(Registry, len(providers))
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range normalized {
		if _, ok := seen[provider.Name]; ok {
			return nil, nil, fmt.Errorf("duplicate rule provider %q", provider.Name)
		}
		seen[provider.Name] = struct{}{}
	}

	prepared, err := prepareStableProviderBatch(ctx, normalized, baseDir, client, options)
	if err != nil {
		return nil, nil, err
	}
	for index, provider := range normalized {
		registry[provider.Name] = prepared[index].rules
	}
	return registry, prepared, nil
}

func prepareStableProviderBatch(ctx context.Context, providers []config.RuleProvider, baseDir string, client *http.Client, options loadOptions) ([]preparedProvider, error) {
	prepared, err := prepareProviderBatch(ctx, providers, baseDir, client, options)
	if err != nil {
		return nil, err
	}
	if err := validateBatchGeneration(prepared); err != nil {
		return nil, err
	}
	if requiresUnversionedBatchIdentity(prepared) {
		// Retain the existing second fetch as an update probe. It does not prove
		// that independent providers share a remote generation; acceptance below
		// still requires either fresh candidates for every provider or a durable
		// common cache batch identity.
		prepared, err = prepareProviderBatch(ctx, providers, baseDir, client, options)
		if err != nil {
			return nil, err
		}
		if err := validateBatchGeneration(prepared); err != nil {
			return nil, err
		}
	}
	if err := validateUnversionedBatchConsistency(prepared); err != nil {
		return nil, err
	}
	return prepared, nil
}

func prepareProviderBatch(ctx context.Context, providers []config.RuleProvider, baseDir string, client *http.Client, options loadOptions) ([]preparedProvider, error) {
	prepared := make([]preparedProvider, len(providers))
	preparationErrors := make([]error, len(providers))
	// Keep the established request order for compatibility. Cross-provider
	// acceptance is decided only by generation tokens or cache batch identity.
	for index := len(providers) - 1; index >= 0; index-- {
		prepared[index], preparationErrors[index] = prepareProvider(ctx, providers[index], baseDir, client, options)
	}
	for index, provider := range providers {
		if err := preparationErrors[index]; err != nil {
			return nil, fmt.Errorf("rule provider %q: %w", provider.Name, err)
		}
	}
	return prepared, nil
}

// requiresUnversionedBatchIdentity identifies batches for which per-provider
// HTTP observations provide no common generation. A cache batch identity is
// the only durable proof that unchanged, revalidated, or last-good results
// were published together.
func requiresUnversionedBatchIdentity(prepared []preparedProvider) bool {
	if len(prepared) < 2 {
		return false
	}
	hasHTTP := false
	for _, provider := range prepared {
		if provider.generation != "" {
			return false
		}
		if provider.descriptor.sourceType == "http" {
			hasHTTP = true
		}
	}
	return hasHTTP
}

func validateUnversionedBatchConsistency(prepared []preparedProvider) error {
	if !requiresUnversionedBatchIdentity(prepared) {
		return nil
	}

	candidates := 0
	for _, provider := range prepared {
		if provider.candidate != nil {
			candidates++
		}
	}
	if candidates == len(prepared) {
		// Every provider has a fresh candidate. publishPrepared binds all of
		// them to one transaction-generated identity before any current pointer
		// is replaced, so this is a safe initial or complete batch update.
		return nil
	}
	if candidates != 0 {
		return errors.New("rule provider batch consistency fence rejects mixed fresh and cached results without a generation token")
	}

	batchIdentity := prepared[0].batchIdentity
	if batchIdentity == "" {
		return errors.New("rule provider batch consistency fence rejects cached results without a shared batch identity")
	}
	for _, provider := range prepared[1:] {
		if provider.batchIdentity != batchIdentity {
			return errors.New("rule provider batch consistency fence rejects cached results from different batches")
		}
	}
	return nil
}

func normalizeProvider(provider config.RuleProvider) config.RuleProvider {
	provider.Type = strings.ToLower(strings.TrimSpace(provider.Type))
	if provider.Type == "" {
		provider.Type = "http"
	}
	provider.Behavior = strings.ToLower(strings.TrimSpace(provider.Behavior))
	provider.Format = strings.ToLower(strings.TrimSpace(provider.Format))
	if provider.Format == "" {
		provider.Format = "yaml"
	}
	if provider.MaxSize == 0 {
		provider.MaxSize = defaultMaxSize
	}
	return provider
}

func validateProviderDefinition(provider config.RuleProvider, baseDir string, allowPrivate bool) error {
	if provider.Name == "" || !providerNamePattern.MatchString(provider.Name) {
		return fmt.Errorf("rule provider has invalid name %q", provider.Name)
	}
	if provider.MaxSize < 0 || provider.MaxSize > maxSize {
		return fmt.Errorf("rule provider %q: max_size %d is outside bounds", provider.Name, provider.MaxSize)
	}
	switch provider.Type {
	case "http":
		u, err := url.Parse(provider.URL)
		if err != nil {
			return fmt.Errorf("rule provider %q: invalid provider URL: %w", provider.Name, redactProviderError(err))
		}
		if err := validateURLShape(u); err != nil {
			return fmt.Errorf("rule provider %q: %w", provider.Name, err)
		}
		if !allowPrivate {
			if err := validatePublicURL(u); err != nil {
				return fmt.Errorf("rule provider %q: %w", provider.Name, err)
			}
		}
	case "file":
		if err := validateRelativeProviderPath(baseDir, provider.Path); err != nil {
			return fmt.Errorf("rule provider %q: %w", provider.Name, err)
		}
	default:
		return fmt.Errorf("rule provider %q has unsupported type %q", provider.Name, provider.Type)
	}
	switch provider.Behavior {
	case "domain", "ipcidr", "classical":
	default:
		return fmt.Errorf("rule provider %q has unsupported behavior %q", provider.Name, provider.Behavior)
	}
	switch provider.Format {
	case "yaml", "text":
	default:
		return fmt.Errorf("rule provider %q has unsupported format %q", provider.Name, provider.Format)
	}
	if provider.Interval < 0 {
		return fmt.Errorf("rule provider %q interval cannot be negative", provider.Name)
	}
	if provider.Path != "" {
		if err := validateRelativeProviderPath(baseDir, provider.Path); err != nil {
			return fmt.Errorf("rule provider %q: %w", provider.Name, err)
		}
	}
	return nil
}

func prepareProvider(ctx context.Context, provider config.RuleProvider, baseDir string, client *http.Client, options loadOptions) (preparedProvider, error) {
	descriptor, err := newCacheDescriptor(provider, baseDir)
	if err != nil {
		return preparedProvider{}, err
	}
	preparedAt := time.Now().UTC()
	expectedCurrent, expectedCurrentErr := readCurrentState(descriptor.root)
	if expectedCurrentErr != nil {
		return preparedProvider{}, fmt.Errorf("inspect provider cache %q: %w", provider.Name, expectedCurrentErr)
	}
	makePrepared := func(rules ProviderRules, generation, batchIdentity string, candidate *cacheCandidate, usedLastGood bool) preparedProvider {
		if candidate != nil {
			candidate.expectedCurrent = expectedCurrent
			candidate.expectedCurrentKnown = true
		}
		return preparedProvider{
			name:                 provider.Name,
			rules:                rules,
			generation:           generation,
			batchIdentity:        batchIdentity,
			usedLastGood:         usedLastGood,
			descriptor:           descriptor,
			candidate:            candidate,
			expectedCurrent:      expectedCurrent,
			expectedCurrentKnown: true,
		}
	}
	switch provider.Type {
	case "file":
		cached, cacheErr := readCacheSnapshot(descriptor)
		cachedRules, cachedRulesErr := parseCachedRules(cached, cacheErr, provider)
		body, readErr := readProviderFile(baseDir, provider.Path, provider.MaxSize)
		if readErr != nil {
			if cachedRulesErr == nil {
				return makePrepared(cachedRules, cacheSnapshotGeneration(cached), cacheSnapshotBatchIdentity(cached), nil, true), nil
			}
			return preparedProvider{}, fmt.Errorf("read provider file: %v; cache failed: %w", readErr, cachedRulesErr)
		}
		rules, parseErr := parseProviderBody(body, provider)
		if parseErr != nil {
			if cachedRulesErr == nil {
				return makePrepared(cachedRules, cacheSnapshotGeneration(cached), cacheSnapshotBatchIdentity(cached), nil, true), nil
			}
			return preparedProvider{}, fmt.Errorf("validate file provider body: %w", parseErr)
		}
		candidate := &cacheCandidate{
			descriptor:           descriptor,
			body:                 append([]byte(nil), body...),
			preparedAt:           preparedAt,
			updatedAt:            time.Now().UTC(),
			expectedCurrent:      expectedCurrent,
			expectedCurrentKnown: true,
		}
		batchIdentity := ""
		if cacheErr == nil &&
			cachedRulesErr == nil &&
			cached.metadata.SHA256 == digest(body) &&
			cacheMetadataMatches(cached.metadata, descriptor) &&
			cached.metadata.Generation == "" {
			candidate = nil
			batchIdentity = cacheSnapshotBatchIdentity(cached)
		}
		return makePrepared(rules, "", batchIdentity, candidate, false), nil
	case "http":
		cached, cacheErr := readCacheSnapshot(descriptor)
		cachedRules, cachedRulesErr := parseCachedRules(cached, cacheErr, provider)
		fetched, fetchErr := fetchHTTP(ctx, provider.URL, provider.MaxSize, client, options.allowPrivate, cached)
		if fetchErr != nil {
			if cachedRulesErr == nil {
				return makePrepared(cachedRules, cacheSnapshotGeneration(cached), cacheSnapshotBatchIdentity(cached), nil, true), nil
			}
			if isSecurityError(fetchErr) {
				return preparedProvider{}, fmt.Errorf("fetch rejected by provider security policy: %w", fetchErr)
			}
			return preparedProvider{}, fmt.Errorf("fetch failed: %v; cache failed: %w", redactProviderError(fetchErr), cachedRulesErr)
		}
		cachedGeneration := cacheSnapshotGeneration(cached)
		if !fetched.notModified && cachedRulesErr == nil && cachedGeneration != "" && fetched.generation == "" {
			return preparedProvider{}, fmt.Errorf("fresh provider response omitted generation token while cached generation %q is available", cachedGeneration)
		}
		if fetched.notModified {
			if cachedRulesErr != nil {
				return preparedProvider{}, fmt.Errorf("provider returned 304 without usable cache: %w", cachedRulesErr)
			}
			generation := cachedGeneration
			if fetched.generation != "" {
				if generation == "" {
					return preparedProvider{}, fmt.Errorf("provider returned 304 generation %q but cached snapshot has no generation", fetched.generation)
				}
				if fetched.generation != generation {
					return preparedProvider{}, fmt.Errorf("provider returned 304 generation %q inconsistent with cached generation %q", fetched.generation, generation)
				}
			}
			return makePrepared(cachedRules, generation, cacheSnapshotBatchIdentity(cached), nil, false), nil
		}
		rules, parseErr := parseProviderBody(fetched.body, provider)
		if parseErr != nil {
			if cachedRulesErr == nil {
				return makePrepared(cachedRules, cacheSnapshotGeneration(cached), cacheSnapshotBatchIdentity(cached), nil, true), nil
			}
			return preparedProvider{}, fmt.Errorf("validate fresh provider body: %w", parseErr)
		}
		candidate := &cacheCandidate{
			descriptor:           descriptor,
			body:                 append([]byte(nil), fetched.body...),
			etag:                 fetched.etag,
			modified:             fetched.lastModified,
			generation:           fetched.generation,
			preparedAt:           preparedAt,
			updatedAt:            time.Now().UTC(),
			expectedCurrent:      expectedCurrent,
			expectedCurrentKnown: true,
		}
		batchIdentity := ""
		if cacheErr == nil &&
			cachedRulesErr == nil &&
			cached.metadata.SHA256 == digest(fetched.body) &&
			cacheMetadataMatches(cached.metadata, descriptor) &&
			cached.metadata.ETag == fetched.etag &&
			cached.metadata.LastModified == fetched.lastModified &&
			cached.metadata.Generation == fetched.generation {
			candidate = nil
			batchIdentity = cacheSnapshotBatchIdentity(cached)
		}
		return makePrepared(rules, fetched.generation, batchIdentity, candidate, false), nil
	default:
		return preparedProvider{}, fmt.Errorf("unsupported provider type %q", provider.Type)
	}
}

func parseCachedRules(cached cacheSnapshot, cacheErr error, provider config.RuleProvider) (ProviderRules, error) {
	if cacheErr != nil {
		return ProviderRules{}, cacheErr
	}
	rules, err := parseProviderBody(cached.body, provider)
	if err != nil {
		return ProviderRules{}, fmt.Errorf("cached provider body is invalid: %w", err)
	}
	return rules, nil
}

func cacheSnapshotGeneration(snapshot cacheSnapshot) string {
	if snapshot.generation != "" {
		return snapshot.generation
	}
	return snapshot.metadata.Generation
}

func cacheSnapshotBatchIdentity(snapshot cacheSnapshot) string {
	return snapshot.metadata.BatchIdentity
}

func newCacheTransactionID() (string, error) {
	var random [batchIdentityBytes]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(random[:]), nil
}

func validateStoredBatchIdentity(batchIdentity string) error {
	if batchIdentity == "" {
		return nil
	}
	if len(batchIdentity) != batchIdentityLength {
		return fmt.Errorf("batch identity has invalid length %d", len(batchIdentity))
	}
	decoded, err := hex.DecodeString(batchIdentity)
	if err != nil || len(decoded) != batchIdentityBytes {
		return errors.New("batch identity is not canonical hexadecimal")
	}
	return nil
}

func validateBatchGeneration(prepared []preparedProvider) error {
	firstGeneration := ""
	firstProvider := ""
	for _, provider := range prepared {
		if provider.generation == "" {
			continue
		}
		if firstGeneration == "" {
			firstGeneration = provider.generation
			firstProvider = provider.name
			continue
		}
		if provider.generation != firstGeneration {
			return fmt.Errorf("rule provider generation mismatch in batch: provider %q differs from provider %q", provider.name, firstProvider)
		}
	}
	if firstGeneration == "" {
		return nil
	}
	for _, provider := range prepared {
		if provider.generation == "" {
			return fmt.Errorf("rule provider generation mismatch in batch: provider %q did not provide a generation token", provider.name)
		}
	}
	return nil
}

func parseProviderBody(body []byte, provider config.RuleProvider) (ProviderRules, error) {
	rules, err := parseBody(body, provider)
	if err != nil {
		return ProviderRules{}, err
	}
	if len(rules.Functions) == 0 {
		return ProviderRules{}, errors.New("provider contains no supported rules")
	}
	return rules, nil
}

func newCacheDescriptor(provider config.RuleProvider, baseDir string) (cacheDescriptor, error) {
	provider = normalizeProvider(provider)
	baseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return cacheDescriptor{}, fmt.Errorf("resolve rule provider base directory: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(baseDir); resolveErr == nil {
		baseDir = resolved
	} else if !os.IsNotExist(resolveErr) {
		return cacheDescriptor{}, fmt.Errorf("resolve rule provider base directory: %w", resolveErr)
	}
	sourceType := strings.ToLower(provider.Type)
	var source string
	switch sourceType {
	case "file":
		if err := validateRelativeProviderPath(baseDir, provider.Path); err != nil {
			return cacheDescriptor{}, err
		}
		absolute, err := filepath.Abs(filepath.Join(baseDir, filepath.Clean(provider.Path)))
		if err != nil {
			return cacheDescriptor{}, fmt.Errorf("resolve provider path: %w", err)
		}
		source = absolute
	case "http":
		u, err := url.Parse(provider.URL)
		if err != nil {
			return cacheDescriptor{}, fmt.Errorf("invalid provider URL: %w", redactProviderError(err))
		}
		if err := validateURLShape(u); err != nil {
			return cacheDescriptor{}, err
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Fragment = ""
		source = u.String()
	default:
		return cacheDescriptor{}, fmt.Errorf("unsupported provider type %q", provider.Type)
	}
	behavior := strings.ToLower(provider.Behavior)
	format := strings.ToLower(provider.Format)
	material := strings.Join([]string{
		provider.Name,
		sourceType,
		source,
		behavior,
		format,
		strconv.FormatInt(provider.MaxSize, 10),
		strconv.Itoa(cacheSchemaVersion),
	}, "\x00")
	return cacheDescriptor{
		root:       filepath.Join(baseDir, "persist.d", "rule-providers", provider.Name),
		name:       provider.Name,
		sourceType: sourceType,
		source:     redactProviderURL(source),
		sourceKey:  digest([]byte(material)),
		behavior:   behavior,
		format:     format,
		maxSize:    provider.MaxSize,
	}, nil
}

func fetchHTTP(ctx context.Context, rawURL string, max int64, baseClient *http.Client, allowPrivate bool, cached cacheSnapshot) (fetchedBody, error) {
	if max < 0 || max > maxSize {
		return fetchedBody{}, fmt.Errorf("max_size %d is outside bounds", max)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if baseClient == nil {
		baseClient = http.DefaultClient
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fetchedBody{}, redactProviderError(err)
	}
	if err := validateURLShape(u); err != nil {
		return fetchedBody{}, err
	}
	if !allowPrivate {
		if err := validatePublicURL(u); err != nil {
			return fetchedBody{}, securityError(err)
		}
	}

	client := *baseClient
	if client.Timeout <= 0 || client.Timeout > maxHTTPTimeout {
		client.Timeout = maxHTTPTimeout
	}
	if !allowPrivate {
		transport, err := safeTransport(client.Transport)
		if err != nil {
			return fetchedBody{}, securityError(err)
		}
		client.Transport = transport
		client.Jar = nil
		client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxHTTPRedirects {
				return securityError(errors.New("too many redirects"))
			}
			return securityError(validatePublicURL(request.URL))
		}
	} else {
		client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxHTTPRedirects {
				return errors.New("too many redirects")
			}
			return nil
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fetchedBody{}, redactProviderError(err)
	}
	if cached.body != nil && cached.metadata.ETag != "" {
		request.Header.Set("If-None-Match", cached.metadata.ETag)
	}
	if cached.body != nil && cached.metadata.LastModified != "" {
		request.Header.Set("If-Modified-Since", cached.metadata.LastModified)
	}
	response, err := client.Do(request)
	if err != nil {
		return fetchedBody{}, redactProviderFetchError(err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		generation, err := readProviderGenerationHeader(response.Header)
		if err != nil {
			return fetchedBody{}, err
		}
		return fetchedBody{
			etag:         boundedHeaderValue(response.Header.Get("ETag")),
			lastModified: boundedHeaderValue(response.Header.Get("Last-Modified")),
			generation:   generation,
			notModified:  true,
		}, nil
	}
	if response.StatusCode != http.StatusOK {
		return fetchedBody{}, fmt.Errorf("provider returned HTTP %s", response.Status)
	}
	generation, err := readProviderGenerationHeader(response.Header)
	if err != nil {
		return fetchedBody{}, err
	}
	body, err := readLimited(response.Body, max)
	if err != nil {
		return fetchedBody{}, err
	}
	if int64(len(body)) > max {
		return fetchedBody{}, fmt.Errorf("provider response exceeds max_size %d", max)
	}
	return fetchedBody{
		body:         body,
		etag:         boundedHeaderValue(response.Header.Get("ETag")),
		lastModified: boundedHeaderValue(response.Header.Get("Last-Modified")),
		generation:   generation,
	}, nil
}

func validateURLShape(value *url.URL) error {
	if value == nil || value.Opaque != "" || value.Host == "" {
		return errors.New("provider URL is not a valid HTTP(S) URL")
	}
	scheme := strings.ToLower(value.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("provider URL scheme %q is not allowed", value.Scheme)
	}
	if value.User != nil {
		return errors.New("provider URL userinfo is not allowed")
	}
	if strings.ContainsRune(value.Hostname(), '%') {
		return errors.New("provider URL host zones are not allowed")
	}
	return nil
}

func boundedHeaderValue(value string) string {
	if len(value) > 4096 {
		return ""
	}
	return value
}

func readProviderGenerationHeader(header http.Header) (string, error) {
	present := false
	valueSet := false
	var value string
	for key, candidate := range header {
		if !strings.EqualFold(key, providerGenerationHeader) {
			continue
		}
		present = true
		if len(candidate) != 1 || valueSet {
			return "", fmt.Errorf("provider generation header must contain exactly one value")
		}
		value = candidate[0]
		valueSet = true
	}
	if !present {
		return "", nil
	}
	if !valueSet {
		return "", fmt.Errorf("provider generation header must contain exactly one value")
	}
	return validateProviderGeneration(value, "provider generation header")
}

func validateProviderGeneration(value, source string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%s is empty", source)
	}
	if len(value) > maxProviderGenerationLength {
		return "", fmt.Errorf("%s exceeds %d bytes", source, maxProviderGenerationLength)
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%s is not valid UTF-8", source)
	}
	if strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%s must not contain surrounding whitespace", source)
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e || unicode.IsControl(char) || unicode.IsSpace(char) {
			return "", fmt.Errorf("%s contains invalid whitespace or control character", source)
		}
	}
	return value, nil
}

func validateStoredProviderGeneration(value string) error {
	if value == "" {
		return nil
	}
	_, err := validateProviderGeneration(value, "cache generation")
	return err
}

func readProviderFile(baseDir, relativePath string, max int64) ([]byte, error) {
	if err := validateRelativeProviderPath(baseDir, relativePath); err != nil {
		return nil, err
	}
	if max < 0 || max > maxSize {
		return nil, fmt.Errorf("max_size %d is outside bounds", max)
	}
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve provider base directory: %w", err)
	}
	baseResolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, fmt.Errorf("resolve provider base directory: %w", err)
	}
	clean := filepath.Clean(relativePath)
	resolvedPath := filepath.Join(baseResolved, clean)
	if !pathWithin(baseResolved, resolvedPath) {
		return nil, fmt.Errorf("provider path %q escapes base directory", relativePath)
	}
	return readRelativeRegularFile(baseResolved, clean, max)
}

func readRegularFile(path string, max int64) ([]byte, error) {
	if max < 0 || max > maxSize {
		return nil, fmt.Errorf("max_size %d is outside bounds", max)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("provider path is not a regular file")
	}
	body, err := readLimited(file, max)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("provider file exceeds max_size %d", max)
	}
	return body, nil
}

func readCacheRegularFile(path string, max int64) ([]byte, error) {
	if max < 0 || max > maxSize {
		return nil, fmt.Errorf("max_size %d is outside bounds", max)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("cache path is not a regular file")
	}
	if err := rejectInsecureCachePermissions(path, info); err != nil {
		return nil, err
	}
	body, err := readLimited(file, max)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("cache file exceeds max_size %d", max)
	}
	return body, nil
}

func readLimitedFile(path string, max int64) ([]byte, error) {
	return readRegularFile(path, max)
}

func readRelativeRegularFile(base, relativePath string, max int64) ([]byte, error) {
	baseFile, err := os.OpenFile(base, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open provider base directory: %w", err)
	}
	defer baseFile.Close()
	baseInfo, err := baseFile.Stat()
	if err != nil {
		return nil, err
	}
	if !baseInfo.IsDir() {
		return nil, errors.New("provider base directory is not a directory")
	}

	parts := splitRelativePath(relativePath)
	if len(parts) == 0 {
		return readRegularFileFromFile(baseFile, max)
	}
	directory := baseFile
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return nil, fmt.Errorf("provider path %q escapes base directory", relativePath)
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if index < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(directory.Fd()), part, flags, 0)
		if err != nil {
			return nil, fmt.Errorf("open provider path: %w", err)
		}
		opened := os.NewFile(uintptr(fd), filepath.Join(base, filepath.Join(parts[:index+1]...)))
		if opened == nil {
			_ = unix.Close(fd)
			return nil, errors.New("open provider path returned an invalid file")
		}
		if index == len(parts)-1 {
			if directory != baseFile {
				_ = directory.Close()
			}
			return readRegularFileFromFile(opened, max)
		}
		info, statErr := opened.Stat()
		if statErr != nil {
			_ = opened.Close()
			return nil, statErr
		}
		if !info.IsDir() {
			_ = opened.Close()
			return nil, errors.New("provider path component is not a directory")
		}
		if directory != baseFile {
			_ = directory.Close()
		}
		directory = opened
	}
	if directory != baseFile {
		_ = directory.Close()
	}
	return nil, errors.New("provider path is empty")
}

func readRegularFileFromFile(file *os.File, max int64) ([]byte, error) {
	if file == nil {
		return nil, errors.New("provider file is nil")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("provider path is not a regular file")
	}
	body, err := readLimited(file, max)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("provider file exceeds max_size %d", max)
	}
	return body, nil
}

func readLimited(reader io.Reader, max int64) ([]byte, error) {
	if max < 0 || max > maxSize {
		return nil, fmt.Errorf("max_size %d is outside bounds", max)
	}
	limit := max
	if max < math.MaxInt64 {
		limit++
	}
	return io.ReadAll(io.LimitReader(reader, limit))
}

func splitRelativePath(path string) []string {
	clean := filepath.Clean(path)
	return strings.FieldsFunc(clean, func(r rune) bool { return r == filepath.Separator })
}

func validateRelativeProviderPath(baseDir, providerPath string) error {
	if providerPath == "" || filepath.IsAbs(providerPath) || strings.IndexByte(providerPath, 0) >= 0 {
		return errors.New("provider path must be a non-empty relative path")
	}
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("resolve provider base directory: %w", err)
	}
	resolved, err := filepath.Abs(filepath.Join(base, filepath.Clean(providerPath)))
	if err != nil {
		return fmt.Errorf("resolve provider path: %w", err)
	}
	if !pathWithin(base, resolved) {
		return fmt.Errorf("provider path %q escapes base directory", providerPath)
	}
	return nil
}

func pathWithin(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func readCacheSnapshot(descriptor cacheDescriptor) (cacheSnapshot, error) {
	return readCacheSnapshotWithSourceBinding(descriptor, true)
}

// readCacheSnapshotForSourceChange is only used after a fresh candidate has
// been prepared. It keeps the normal descriptor binding when possible, and
// falls back to an identity-relaxed integrity read solely to compare the
// current generation/body and carry generation history across a source or
// semantic rotation. Callers gate the relaxed path with the candidate's
// current-identity CAS, and this snapshot is never used as preparation or
// last-good fallback data.
func readCacheSnapshotForSourceChange(descriptor cacheDescriptor) (cacheSnapshot, error) {
	snapshot, err := readCacheSnapshot(descriptor)
	if err == nil {
		return snapshot, nil
	}
	relaxed, relaxedErr := readCacheSnapshotWithSourceBinding(descriptor, false)
	if relaxedErr != nil {
		return cacheSnapshot{}, err
	}
	return relaxed, nil
}

func readCacheSnapshotWithSourceBinding(descriptor cacheDescriptor, requireSourceBinding bool) (cacheSnapshot, error) {
	if descriptor.maxSize == 0 {
		descriptor.maxSize = defaultMaxSize
	}
	if descriptor.maxSize < 0 || descriptor.maxSize > maxSize {
		return cacheSnapshot{}, fmt.Errorf("cache max_size %d is outside bounds", descriptor.maxSize)
	}
	current, err := readCurrentState(descriptor.root)
	if err != nil {
		return cacheSnapshot{}, err
	}
	if !current.exists {
		return cacheSnapshot{}, errors.New("cache current is missing")
	}
	metadataBody, err := readCacheRegularFile(filepath.Join(current.resolved, "metadata.json"), maxCacheMetadataSize)
	if err != nil {
		return cacheSnapshot{}, fmt.Errorf("read cache metadata: %w", err)
	}
	var metadata cacheMetadata
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		return cacheSnapshot{}, fmt.Errorf("decode cache metadata: %w", err)
	}
	if err := validateStoredProviderGeneration(metadata.Generation); err != nil {
		return cacheSnapshot{}, fmt.Errorf("validate cache generation: %w", err)
	}
	if err := validateStoredBatchIdentity(metadata.BatchIdentity); err != nil {
		return cacheSnapshot{}, fmt.Errorf("validate cache batch identity: %w", err)
	}
	if !cacheMetadataMatchesForSourceChange(metadata, descriptor) || (requireSourceBinding && !cacheMetadataMatches(metadata, descriptor)) {
		return cacheSnapshot{}, errors.New("cache metadata source mismatch")
	}
	bodyMaxSize := descriptor.maxSize
	if !requireSourceBinding {
		// The candidate descriptor may intentionally have a smaller max_size
		// than the current snapshot. Read the old body using the bound stored
		// limit so a valid snapshot is not truncated before generation/body
		// comparison.
		bodyMaxSize = metadata.MaxSize
		if bodyMaxSize == 0 {
			bodyMaxSize = defaultMaxSize
		}
		if bodyMaxSize < 0 || bodyMaxSize > maxSize {
			return cacheSnapshot{}, fmt.Errorf("cache max_size %d is outside bounds", metadata.MaxSize)
		}
	}
	body, err := readCacheRegularFile(filepath.Join(current.resolved, "body"), bodyMaxSize)
	if err != nil {
		return cacheSnapshot{}, fmt.Errorf("read cache body: %w", err)
	}
	if digest(body) != metadata.SHA256 {
		return cacheSnapshot{}, errors.New("cache checksum mismatch")
	}
	return cacheSnapshot{body: body, metadata: metadata, generation: metadata.Generation}, nil
}

func cacheMetadataMatchesExceptSource(metadata cacheMetadata, descriptor cacheDescriptor) bool {
	return metadata.SchemaVersion == cacheSchemaVersion &&
		metadata.ProviderName == descriptor.name &&
		metadata.SourceType == descriptor.sourceType &&
		metadata.Behavior == descriptor.behavior &&
		metadata.Format == descriptor.format &&
		metadata.MaxSize == descriptor.maxSize
}

func cacheMetadataMatchesForSourceChange(metadata cacheMetadata, descriptor cacheDescriptor) bool {
	// A fresh, already validated candidate is allowed to rotate every
	// descriptor field except provider identity. The old snapshot is used only
	// for its integrity-checked body and generation state during publication.
	return metadata.SchemaVersion == cacheSchemaVersion &&
		metadata.ProviderName == descriptor.name
}

func cacheMetadataMatches(metadata cacheMetadata, descriptor cacheDescriptor) bool {
	return cacheMetadataMatchesExceptSource(metadata, descriptor) &&
		metadata.Source == descriptor.source &&
		metadata.SourceKey == descriptor.sourceKey
}

func publishPrepared(prepared []preparedProvider) error {
	_, err := publishPreparedWithContext(context.Background(), prepared)
	return err
}

// publishPreparedWithContext returns whether it replaced at least one current
// cache snapshot. It keeps the established publishPrepared API for callers
// that do not need cancellation or the publication result.
func publishPreparedWithContext(ctx context.Context, prepared []preparedProvider) (bool, error) {
	cachePublishMu.Lock()
	defer cachePublishMu.Unlock()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
	transactionRoot, err := preparedTransactionRoot(prepared)
	if err != nil {
		return false, err
	}
	var transaction transactionLock
	if transactionRoot != "" {
		transaction, err = acquireTransactionLock(transactionRoot)
		if err != nil {
			return false, err
		}
		defer transaction.Close()
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
	transactionPath := ""
	if transactionRoot != "" {
		transactionPath = filepath.Join(transactionRoot, "transaction.journal")
		if err := recoverPendingPublishLocked(transactionRoot, transactionPath); err != nil {
			return false, fmt.Errorf("recover existing cache transaction journal before publish: %w", err)
		}
	}
	locks, err := acquireCacheLocks(prepared)
	if err != nil {
		return false, err
	}
	defer locks.Close()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
	if err := validatePreparedCandidates(prepared); err != nil {
		return false, err
	}
	if err := validateUnversionedBatchConsistency(prepared); err != nil {
		return false, err
	}

	hasCandidate := false
	for _, provider := range prepared {
		if provider.candidate != nil {
			hasCandidate = true
			break
		}
	}
	if !hasCandidate {
		return false, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
	transactionID, err := newCacheTransactionID()
	if err != nil {
		return false, fmt.Errorf("generate provider cache transaction identity: %w", err)
	}
	batchIdentity := ""
	if requiresUnversionedBatchIdentity(prepared) {
		batchIdentity = transactionID
		for index := range prepared {
			prepared[index].candidate.batchIdentity = batchIdentity
		}
	}

	caches := make([]preparedCache, 0, len(prepared))
	for index := range prepared {
		provider := prepared[index]
		if provider.candidate == nil {
			continue
		}
		candidate := provider.candidate
		if err := ensureCacheLayout(candidate.descriptor.root); err != nil {
			cleanupPreparedCaches(caches)
			return false, fmt.Errorf("prepare provider cache %q: %w", provider.name, err)
		}
		old, err := readCurrentState(candidate.descriptor.root)
		if err != nil {
			cleanupPreparedCaches(caches)
			return false, fmt.Errorf("inspect provider cache %q: %w", provider.name, err)
		}
		history := generationHistory{}
		if old.exists {
			currentSnapshot, err := readCacheSnapshotForSourceChange(candidate.descriptor)
			if err != nil {
				cleanupPreparedCaches(caches)
				return false, fmt.Errorf("inspect current provider cache %q: %w", provider.name, err)
			}
			history = currentSnapshot.metadata.GenerationHistory
			currentGeneration := cacheSnapshotGeneration(currentSnapshot)
			if currentGeneration != "" && candidate.generation != currentGeneration {
				history, err = prependGenerationHistory(history, currentGeneration)
				if err != nil {
					cleanupPreparedCaches(caches)
					return false, fmt.Errorf("prepare provider cache %q generation history: %w", provider.name, err)
				}
			}
		}
		versionDir, err := os.MkdirTemp(filepath.Join(candidate.descriptor.root, "versions"), "version-")
		if err != nil {
			cleanupPreparedCaches(caches)
			return false, fmt.Errorf("prepare provider cache %q: %w", provider.name, err)
		}
		metadata := cacheMetadata{
			SchemaVersion:     cacheSchemaVersion,
			ProviderName:      candidate.descriptor.name,
			SourceType:        candidate.descriptor.sourceType,
			Source:            candidate.descriptor.source,
			SourceKey:         candidate.descriptor.sourceKey,
			Behavior:          candidate.descriptor.behavior,
			Format:            candidate.descriptor.format,
			MaxSize:           candidate.descriptor.maxSize,
			SHA256:            digest(candidate.body),
			UpdatedAt:         candidate.updatedAt,
			ETag:              candidate.etag,
			LastModified:      candidate.modified,
			Generation:        candidate.generation,
			GenerationHistory: history,
			BatchIdentity:     candidate.batchIdentity,
		}
		metadataBody, err := json.Marshal(metadata)
		if err == nil && len(metadataBody) > maxCacheMetadataSize {
			err = fmt.Errorf("cache metadata exceeds %d bytes", maxCacheMetadataSize)
		}
		if err == nil {
			err = writeFileSync(filepath.Join(versionDir, "body"), candidate.body, 0o600)
		}
		if err == nil {
			err = writeFileSync(filepath.Join(versionDir, "metadata.json"), metadataBody, 0o600)
		}
		if err == nil {
			err = syncDirectory(versionDir)
		}
		if err == nil {
			err = syncDirectory(filepath.Join(candidate.descriptor.root, "versions"))
		}
		if err != nil {
			_ = os.RemoveAll(versionDir)
			cleanupPreparedCaches(caches)
			return false, fmt.Errorf("prepare provider cache %q: %w", provider.name, err)
		}
		prepared[index].expectedCurrent = old
		caches = append(caches, preparedCache{candidate: candidate, versionDir: versionDir, old: old})
	}
	if len(caches) == 0 {
		return false, nil
	}

	transactionRecord := cacheTransaction{
		SchemaVersion: cacheTransactionVersion,
		State:         "publishing",
		Generation:    transactionID,
		BatchIdentity: batchIdentity,
		Providers:     make(map[string]cacheTransactionEntry, len(prepared)),
	}
	newCurrent := make(map[string]string, len(caches))
	for _, cache := range caches {
		newCurrent[cache.candidate.descriptor.name] = filepath.Join("versions", filepath.Base(cache.versionDir))
	}
	for _, provider := range prepared {
		old := provider.expectedCurrent
		newTarget := old.target
		if candidateTarget, ok := newCurrent[provider.name]; ok {
			newTarget = candidateTarget
		}
		transactionRecord.Providers[provider.name] = cacheTransactionEntry{
			OldCurrent: old.target,
			NewCurrent: newTarget,
		}
	}
	if err := writeCacheTransaction(transactionPath, transactionRecord); err != nil {
		cleanupPreparedCaches(caches)
		return false, fmt.Errorf("write cache transaction journal: %w", err)
	}

	for index := range caches {
		if err := replaceCurrent(caches[index].candidate.descriptor.root, filepath.Base(caches[index].versionDir)); err != nil {
			rollbackErr := rollbackCaches(caches, index-1)
			if rollbackErr == nil {
				cleanupPreparedCaches(caches)
				_ = removeCacheTransaction(transactionPath)
			}
			return false, combinePublishErrors(caches[index].candidate.descriptor.name, "replace current", err, rollbackErr)
		}
		if err := syncDirectory(caches[index].candidate.descriptor.root); err != nil {
			rollbackErr := rollbackCaches(caches, index)
			if rollbackErr == nil {
				cleanupPreparedCaches(caches)
				_ = removeCacheTransaction(transactionPath)
			}
			return false, combinePublishErrors(caches[index].candidate.descriptor.name, "sync current", err, rollbackErr)
		}
	}

	transactionRecord.State = "committed"
	if err := writeCacheTransaction(transactionPath, transactionRecord); err != nil {
		return false, fmt.Errorf("commit cache transaction journal: %w", err)
	}
	if err := removeCacheTransaction(transactionPath); err != nil {
		return false, fmt.Errorf("remove cache transaction journal: %w", err)
	}
	for _, cache := range caches {
		if err := pruneCacheVersions(cache.candidate.descriptor.root, maxCacheVersions); err != nil {
			return false, fmt.Errorf("prune provider cache %q: %w", cache.candidate.descriptor.name, err)
		}
	}
	return true, nil
}

func validatePreparedCandidates(prepared []preparedProvider) error {
	for index := range prepared {
		provider := prepared[index]
		candidate := provider.candidate
		expected := provider.expectedCurrent
		expectedKnown := provider.expectedCurrentKnown
		if !expectedKnown && candidate != nil && candidate.expectedCurrentKnown {
			expected = candidate.expectedCurrent
			expectedKnown = true
		}
		if !expectedKnown {
			return fmt.Errorf("reject provider cache batch %q: expected current identity is unavailable", provider.name)
		}
		current, err := readCurrentState(provider.descriptor.root)
		if err != nil {
			return fmt.Errorf("recheck provider cache %q before publish: %w", provider.name, err)
		}
		identityMatches := expected.exists == current.exists && (!expected.exists || expected.target == current.target)
		var snapshot cacheSnapshot
		if candidate != nil {
			if err := validateStoredProviderGeneration(candidate.generation); err != nil {
				return fmt.Errorf("reject provider cache candidate %q: %w", provider.name, err)
			}
		}
		if current.exists && (candidate != nil || !identityMatches) {
			if candidate != nil && identityMatches {
				snapshot, err = readCacheSnapshotForSourceChange(provider.descriptor)
			} else {
				snapshot, err = readCacheSnapshot(provider.descriptor)
			}
			if err != nil {
				return fmt.Errorf("recheck provider cache %q before publish: %w", provider.name, err)
			}
			currentGeneration := cacheSnapshotGeneration(snapshot)
			if candidate != nil && candidate.generation != "" && candidate.generation != currentGeneration && snapshot.metadata.GenerationHistory.contains(candidate.generation) {
				return fmt.Errorf("reject provider cache candidate %q: generation %q was already accepted and is not the current generation", provider.name, candidate.generation)
			}
			if candidate != nil && candidate.generation != "" && candidate.generation == currentGeneration {
				if !bytes.Equal(candidate.body, snapshot.body) {
					return fmt.Errorf("reject provider cache candidate %q: generation %q is already bound to a different body", provider.name, candidate.generation)
				}
				if cacheMetadataMatches(snapshot.metadata, candidate.descriptor) {
					// A generation token identifies an immutable body. If the current
					// snapshot is the same source and body, merge the candidate into
					// that snapshot instead of publishing a duplicate version.
					prepared[index].candidate = nil
					prepared[index].expectedCurrent = current
					candidate.expectedCurrent = current
					candidate.expectedCurrentKnown = true
					continue
				}
			}
		}
		if identityMatches {
			prepared[index].expectedCurrent = current
			if candidate != nil {
				candidate.expectedCurrent = current
				candidate.expectedCurrentKnown = true
			}
			continue
		}
		if !current.exists {
			return fmt.Errorf("reject stale provider cache candidate %q: current cache identity changed during preparation", provider.name)
		}
		currentGeneration := cacheSnapshotGeneration(snapshot)
		preparedGeneration := provider.generation
		if preparedGeneration == "" && candidate != nil {
			preparedGeneration = candidate.generation
		}
		if preparedGeneration == currentGeneration && candidate != nil && bytes.Equal(candidate.body, snapshot.body) {
			// The current version was replaced while this candidate was being
			// prepared, but it is the same logical snapshot. Keep the newer
			// current identity and avoid publishing stale metadata.
			prepared[index].candidate = nil
			prepared[index].expectedCurrent = current
			continue
		}
		return fmt.Errorf("reject stale provider cache candidate %q: expected current identity changed during preparation", provider.name)
	}
	return nil
}

type cacheLocks struct {
	files []*os.File
}

func preparedTransactionRoot(prepared []preparedProvider) (string, error) {
	var transactionRoot string
	for _, provider := range prepared {
		descriptor := provider.descriptor
		if descriptor.root == "" && provider.candidate != nil {
			descriptor = provider.candidate.descriptor
		}
		if descriptor.root == "" {
			return "", fmt.Errorf("rule provider %q has no cache descriptor", provider.name)
		}
		root := filepath.Dir(descriptor.root)
		if transactionRoot == "" {
			transactionRoot = root
			continue
		}
		if transactionRoot != root {
			return "", errors.New("rule provider caches do not share a transaction root")
		}
	}
	if transactionRoot != "" {
		if err := ensureCacheDirectory(filepath.Dir(transactionRoot)); err != nil {
			return "", fmt.Errorf("prepare rule provider persistence root: %w", err)
		}
		if err := ensureCacheDirectory(transactionRoot); err != nil {
			return "", fmt.Errorf("prepare rule provider transaction root: %w", err)
		}
	}
	return transactionRoot, nil
}

func acquireTransactionLock(transactionRoot string) (transactionLock, error) {
	file, err := os.OpenFile(filepath.Join(transactionRoot, ".transaction.lock"), os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return transactionLock{}, fmt.Errorf("lock rule provider transaction: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return transactionLock{}, fmt.Errorf("lock rule provider transaction: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return transactionLock{}, fmt.Errorf("lock rule provider transaction: %w", err)
	}
	return transactionLock{file: file}, nil
}

func (lock transactionLock) Close() {
	if lock.file == nil {
		return
	}
	_ = unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	_ = lock.file.Close()
}

func acquireCacheLocks(prepared []preparedProvider) (cacheLocks, error) {
	roots := make(map[string]struct{})
	for _, provider := range prepared {
		root := provider.descriptor.root
		if root == "" && provider.candidate != nil {
			root = provider.candidate.descriptor.root
		}
		if root == "" {
			return cacheLocks{}, fmt.Errorf("rule provider %q has no cache descriptor", provider.name)
		}
		if err := ensureCacheLayout(root); err != nil {
			return cacheLocks{}, fmt.Errorf("prepare provider cache %q: %w", provider.name, err)
		}
		roots[root] = struct{}{}
	}
	ordered := make([]string, 0, len(roots))
	for root := range roots {
		ordered = append(ordered, root)
	}
	sort.Strings(ordered)
	return acquireCacheLocksForRoots(ordered)
}

func acquireCacheLocksForRoots(ordered []string) (cacheLocks, error) {
	locks := cacheLocks{files: make([]*os.File, 0, len(ordered))}
	for _, root := range ordered {
		file, err := os.OpenFile(filepath.Join(root, ".lock"), os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			locks.Close()
			return cacheLocks{}, fmt.Errorf("lock provider cache %q: %w", filepath.Base(root), err)
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			locks.Close()
			return cacheLocks{}, fmt.Errorf("lock provider cache %q: %w", filepath.Base(root), err)
		}
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
			_ = file.Close()
			locks.Close()
			return cacheLocks{}, fmt.Errorf("lock provider cache %q: %w", filepath.Base(root), err)
		}
		locks.files = append(locks.files, file)
	}
	return locks, nil
}

func (locks cacheLocks) Close() {
	for index := len(locks.files) - 1; index >= 0; index-- {
		file := locks.files[index]
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}
}

type currentState struct {
	exists   bool
	target   string
	resolved string
}

var cachePublishMu sync.Mutex

func cacheTransactionPath(baseDir string) (string, error) {
	baseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolve rule provider base directory: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(baseDir); resolveErr == nil {
		baseDir = resolved
	} else if !os.IsNotExist(resolveErr) {
		return "", fmt.Errorf("resolve rule provider base directory: %w", resolveErr)
	}
	return filepath.Join(baseDir, "persist.d", "rule-providers", "transaction.journal"), nil
}

func recoverPendingPublish(baseDir string) error {
	transactionPath, err := cacheTransactionPath(baseDir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(transactionPath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect cache transaction journal: %w", err)
	}

	cachePublishMu.Lock()
	defer cachePublishMu.Unlock()
	transactionRoot := filepath.Dir(transactionPath)
	if err := requireCachePersistenceDirectory(transactionRoot); err != nil {
		return fmt.Errorf("prepare rule provider transaction root: %w", err)
	}
	transactionLock, err := acquireTransactionLock(transactionRoot)
	if err != nil {
		return err
	}
	defer transactionLock.Close()

	return recoverPendingPublishLocked(transactionRoot, transactionPath)
}

func recoverPendingPublishLocked(transactionRoot, transactionPath string) error {
	if _, err := os.Lstat(transactionPath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect cache transaction journal: %w", err)
	}

	journalBody, err := readCacheRegularFile(transactionPath, maxCacheMetadataSize)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read cache transaction journal: %w", err)
	}
	var transaction cacheTransaction
	if err := json.Unmarshal(journalBody, &transaction); err != nil {
		return fmt.Errorf("decode cache transaction journal: %w", err)
	}
	if transaction.SchemaVersion != cacheTransactionVersion {
		return fmt.Errorf("unsupported cache transaction schema version %d", transaction.SchemaVersion)
	}
	if transaction.State != "publishing" && transaction.State != "committed" {
		return fmt.Errorf("unsupported cache transaction state %q", transaction.State)
	}
	if err := validateStoredBatchIdentity(transaction.BatchIdentity); err != nil {
		return fmt.Errorf("validate cache transaction batch identity: %w", err)
	}
	if transaction.BatchIdentity != "" && transaction.BatchIdentity != transaction.Generation {
		return errors.New("cache transaction batch identity does not match transaction generation")
	}
	if len(transaction.Providers) == 0 {
		return errors.New("cache transaction journal has no providers")
	}

	providerNames := make([]string, 0, len(transaction.Providers))
	roots := make([]string, 0, len(transaction.Providers))
	for name, entry := range transaction.Providers {
		if !providerNamePattern.MatchString(name) {
			return fmt.Errorf("cache transaction has invalid provider name %q", name)
		}
		root := filepath.Join(transactionRoot, name)
		if err := requireExistingCacheRoot(root); err != nil {
			return fmt.Errorf("inspect provider cache %q during recovery: %w", name, err)
		}
		if err := validateJournalCurrent(root, entry.OldCurrent, true); err != nil {
			return fmt.Errorf("validate old current for provider %q: %w", name, err)
		}
		if err := validateJournalCurrent(root, entry.NewCurrent, true); err != nil {
			return fmt.Errorf("validate new current for provider %q: %w", name, err)
		}
		providerNames = append(providerNames, name)
		roots = append(roots, root)
	}
	sort.Strings(providerNames)
	sort.Strings(roots)
	locks, err := acquireCacheLocksForRoots(roots)
	if err != nil {
		return err
	}
	defer locks.Close()

	if transaction.State == "committed" && transactionCurrentsMatch(transactionRoot, transaction.Providers, transaction.BatchIdentity) {
		if err := removeCacheTransaction(transactionPath); err != nil {
			return fmt.Errorf("remove committed cache transaction journal: %w", err)
		}
		for _, name := range providerNames {
			if err := pruneCacheVersions(filepath.Join(transactionRoot, name), maxCacheVersions); err != nil {
				return fmt.Errorf("prune recovered provider cache %q: %w", name, err)
			}
		}
		return nil
	}

	for _, name := range providerNames {
		entry := transaction.Providers[name]
		state := currentState{}
		if entry.OldCurrent != "" {
			state = currentState{exists: true, target: entry.OldCurrent}
		}
		root := filepath.Join(transactionRoot, name)
		if err := restoreCurrent(root, state); err != nil {
			return fmt.Errorf("restore provider cache %q: %w", name, err)
		}
		if err := syncDirectory(root); err != nil {
			return fmt.Errorf("sync restored provider cache %q: %w", name, err)
		}
	}
	if err := removeCacheTransaction(transactionPath); err != nil {
		return fmt.Errorf("remove recovered cache transaction journal: %w", err)
	}
	for _, name := range providerNames {
		if err := pruneCacheVersions(filepath.Join(transactionRoot, name), maxCacheVersions); err != nil {
			return fmt.Errorf("prune recovered provider cache %q: %w", name, err)
		}
	}
	return nil
}

func validateJournalCurrent(root, target string, allowEmpty bool) error {
	if err := requireExistingCacheRoot(root); err != nil {
		return err
	}
	return validateCacheCurrentTarget(root, target, allowEmpty)
}

func validateCacheCurrentTarget(root, target string, allowEmpty bool) error {
	if target == "" {
		if allowEmpty {
			return nil
		}
		return errors.New("cache current target is empty")
	}
	if filepath.IsAbs(target) || filepath.Clean(target) != target {
		return errors.New("cache current target is not a clean relative path")
	}
	version := filepath.Base(target)
	if version == "" || version == "." || version == ".." || strings.ContainsAny(version, `/\\`) || target != filepath.Join("versions", version) {
		return errors.New("cache current target is not canonical")
	}
	versions := filepath.Join(root, "versions")
	if err := requireCacheDirectory(versions); err != nil {
		return err
	}
	versionPath := filepath.Join(root, target)
	if !pathWithin(versions, versionPath) || versionPath == versions {
		return errors.New("cache current target is outside versions directory")
	}
	if err := requireCacheDirectory(versionPath); err != nil {
		return fmt.Errorf("cache current target is not a directory: %w", err)
	}
	return nil
}

func transactionCurrentsMatch(transactionRoot string, entries map[string]cacheTransactionEntry, batchIdentity string) bool {
	for name, entry := range entries {
		state, err := readCurrentState(filepath.Join(transactionRoot, name))
		if err != nil {
			return false
		}
		if entry.NewCurrent == "" {
			if state.exists {
				return false
			}
			continue
		}
		if !state.exists || state.target != entry.NewCurrent {
			return false
		}
		if batchIdentity != "" && !currentCacheHasBatchIdentity(state, batchIdentity) {
			return false
		}
	}
	return true
}

func currentCacheHasBatchIdentity(state currentState, batchIdentity string) bool {
	metadataBody, err := readCacheRegularFile(filepath.Join(state.resolved, "metadata.json"), maxCacheMetadataSize)
	if err != nil {
		return false
	}
	var metadata cacheMetadata
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		return false
	}
	if err := validateStoredBatchIdentity(metadata.BatchIdentity); err != nil {
		return false
	}
	return metadata.BatchIdentity == batchIdentity
}

func writeCacheTransaction(path string, transaction cacheTransaction) error {
	body, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	if len(body) > maxCacheMetadataSize {
		return fmt.Errorf("cache transaction journal exceeds %d bytes", maxCacheMetadataSize)
	}
	directory := filepath.Dir(path)
	if err := ensureCacheDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".transaction-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := writeFileSync(temporaryPath, body, 0o600); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	return syncDirectory(directory)
}

func removeCacheTransaction(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func pruneCacheVersions(root string, limit int) error {
	if limit < 1 {
		return errors.New("cache version retention limit must be positive")
	}
	current, err := readCurrentState(root)
	if err != nil {
		return err
	}
	versions := filepath.Join(root, "versions")
	if err := requireCacheDirectory(versions); err != nil {
		return err
	}
	entries, err := os.ReadDir(versions)
	if err != nil {
		return err
	}
	type versionEntry struct {
		name    string
		modTime time.Time
	}
	versionEntries := make([]versionEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(versions, entry.Name()))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		versionEntries = append(versionEntries, versionEntry{name: entry.Name(), modTime: info.ModTime()})
	}
	sort.Slice(versionEntries, func(i, j int) bool {
		if versionEntries[i].modTime.Equal(versionEntries[j].modTime) {
			return versionEntries[i].name > versionEntries[j].name
		}
		return versionEntries[i].modTime.After(versionEntries[j].modTime)
	})
	keep := make(map[string]struct{}, limit)
	if current.exists {
		keep[filepath.Base(current.target)] = struct{}{}
	}
	for _, entry := range versionEntries {
		if len(keep) >= limit {
			break
		}
		keep[entry.name] = struct{}{}
	}
	removed := false
	for _, entry := range versionEntries {
		if _, ok := keep[entry.name]; ok {
			continue
		}
		if err := os.RemoveAll(filepath.Join(versions, entry.name)); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncDirectory(versions)
	}
	return nil
}

func readCurrentState(root string) (currentState, error) {
	if err := requireExistingCacheRoot(root); err != nil {
		if os.IsNotExist(err) {
			return currentState{}, nil
		}
		return currentState{}, err
	}
	current := filepath.Join(root, "current")
	info, err := os.Lstat(current)
	if os.IsNotExist(err) {
		return currentState{}, nil
	}
	if err != nil {
		return currentState{}, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return currentState{}, errors.New("cache current is not a symlink")
	}
	target, err := os.Readlink(current)
	if err != nil {
		return currentState{}, err
	}
	if target == "" || filepath.IsAbs(target) {
		return currentState{}, errors.New("cache current target is not relative")
	}
	if err := validateCacheCurrentTarget(root, target, false); err != nil {
		return currentState{}, err
	}
	versions := filepath.Join(root, "versions")
	if err := requireCacheDirectory(versions); err != nil {
		return currentState{}, err
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return currentState{}, err
	}
	versionsResolved, err := filepath.EvalSymlinks(versions)
	if err != nil || !pathWithin(versionsResolved, resolved) || resolved == versionsResolved {
		return currentState{}, errors.New("cache current escapes versions directory")
	}
	versionPath := filepath.Join(root, filepath.Clean(target))
	if !pathWithin(versions, versionPath) {
		return currentState{}, errors.New("cache current target is outside versions directory")
	}
	if err := requireCacheDirectory(versionPath); err != nil {
		return currentState{}, fmt.Errorf("cache current target is not a directory: %w", err)
	}
	return currentState{exists: true, target: target, resolved: resolved}, nil
}

func replaceCurrent(root, version string) error {
	if version == "" || filepath.Base(version) != version || version == "." || version == ".." {
		return errors.New("invalid cache version")
	}
	if err := requireCacheDirectory(root); err != nil {
		return err
	}
	versionPath := filepath.Join(root, "versions", version)
	versionInfo, err := os.Lstat(versionPath)
	if err != nil {
		return err
	}
	if versionInfo.Mode()&os.ModeSymlink != 0 || !versionInfo.IsDir() {
		return errors.New("cache version is not a directory")
	}
	tmp, err := os.CreateTemp(root, ".current-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}
	if err := os.Symlink(filepath.Join("versions", version), tmpName); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(root, "current")); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func restoreCurrent(root string, state currentState) error {
	current := filepath.Join(root, "current")
	if !state.exists {
		err := os.Remove(current)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if state.target == "" || filepath.IsAbs(state.target) {
		return errors.New("invalid previous cache current target")
	}
	if err := validateJournalCurrent(root, state.target, false); err != nil {
		return fmt.Errorf("validate previous cache current target: %w", err)
	}
	tmp, err := os.CreateTemp(root, ".restore-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}
	if err := os.Symlink(state.target, tmpName); err != nil {
		return err
	}
	if err := os.Rename(tmpName, current); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func cleanupPreparedCaches(caches []preparedCache) {
	for _, cache := range caches {
		_ = os.RemoveAll(cache.versionDir)
	}
}

func rollbackCaches(caches []preparedCache, last int) error {
	var rollbackErrs []error
	for index := last; index >= 0; index-- {
		cache := caches[index]
		if err := restoreCurrent(cache.candidate.descriptor.root, cache.old); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("restore provider cache %q: %w", cache.candidate.descriptor.name, err))
			continue
		}
		if err := syncDirectory(cache.candidate.descriptor.root); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("sync restored provider cache %q: %w", cache.candidate.descriptor.name, err))
		}
	}
	return errors.Join(rollbackErrs...)
}

func combinePublishErrors(name, operation string, publishErr, rollbackErr error) error {
	if rollbackErr == nil {
		return fmt.Errorf("publish provider cache %q: %s: %w", name, operation, publishErr)
	}
	return fmt.Errorf("publish provider cache %q: %s: %w; rollback: %v", name, operation, publishErr, rollbackErr)
}

func ensureCacheLayout(root string) error {
	providerRoot := filepath.Dir(root)
	persistRoot := filepath.Dir(providerRoot)
	for _, path := range []string{persistRoot, providerRoot, root, filepath.Join(root, "versions")} {
		if err := ensureCacheDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func ensureCacheDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache directory %q is a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("cache path %q is not a directory", path)
	}
	return os.Chmod(path, 0o700)
}

func requireCachePersistenceDirectory(path string) error {
	if err := requireCacheDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return requireCacheDirectory(path)
}

func requireCacheDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("cache path %q is not a directory", path)
	}
	if err := rejectInsecureCachePermissions(path, info); err != nil {
		return err
	}
	return nil
}

func rejectInsecureCachePermissions(path string, info os.FileInfo) error {
	if info.Mode().Perm()&cacheInsecurePermissionBits != 0 {
		return fmt.Errorf("cache path %q is group/world-writable", path)
	}
	return nil
}

func requireExistingCacheRoot(root string) error {
	if err := requireCacheDirectory(filepath.Dir(filepath.Dir(root))); err != nil {
		return err
	}
	if err := requireCacheDirectory(filepath.Dir(root)); err != nil {
		return err
	}
	if err := requireCacheDirectory(root); err != nil {
		if os.IsNotExist(err) {
			return err
		}
		return errors.New("cache root is not a directory")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return err
	}
	if filepath.Clean(resolved) != filepath.Clean(abs) {
		return errors.New("cache root path contains a symlink")
	}
	return nil
}

func writeFileSync(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, mode)
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

func parseBody(body []byte, provider config.RuleProvider) (ProviderRules, error) {
	provider = normalizeProvider(provider)
	if provider.MaxSize < 0 || provider.MaxSize > maxSize {
		return ProviderRules{}, fmt.Errorf("max_size %d is outside bounds", provider.MaxSize)
	}
	if int64(len(body)) > provider.MaxSize {
		return ProviderRules{}, fmt.Errorf("provider body exceeds max_size %d", provider.MaxSize)
	}
	if provider.Behavior != "domain" && provider.Behavior != "ipcidr" && provider.Behavior != "classical" {
		return ProviderRules{}, fmt.Errorf("unsupported provider behavior %q", provider.Behavior)
	}
	if strings.EqualFold(provider.Format, "text") {
		return parseTextProviderBody(body, provider)
	}
	items, err := providerItems(body, provider.Format)
	if err != nil {
		return ProviderRules{}, err
	}
	return parseProviderItems(items, provider)
}

func parseTextProviderBody(body []byte, provider config.RuleProvider) (ProviderRules, error) {
	if err := preflightProviderTextBody(body); err != nil {
		return ProviderRules{}, err
	}
	result := ProviderRules{}
	seen := make(map[string]struct{})
	lineCount := 0
	for start := 0; ; {
		lineCount++
		if lineCount > maxProviderRules {
			return ProviderRules{}, fmt.Errorf("provider contains too many rules: %d", lineCount)
		}
		end, trimmed, tooLong := scanProviderTextLine(body, start)
		if tooLong {
			return ProviderRules{}, fmt.Errorf("provider rule exceeds %d bytes", maxProviderRuleLength)
		}
		if err := appendProviderRule(&result, seen, string(trimmed), strings.ToLower(provider.Behavior)); err != nil {
			return ProviderRules{}, err
		}
		if end == len(body) {
			break
		}
		start = end + 1
	}
	if len(result.Functions) == 0 {
		return ProviderRules{}, errors.New("provider contains no supported rules")
	}
	return result, nil
}

func preflightProviderTextBody(body []byte) error {
	lineCount := 0
	for start := 0; ; {
		lineCount++
		if lineCount > maxProviderRules {
			return fmt.Errorf("provider contains too many rules: %d", lineCount)
		}
		end, _, tooLong := scanProviderTextLine(body, start)
		if tooLong {
			return fmt.Errorf("provider rule exceeds %d bytes", maxProviderRuleLength)
		}
		if end == len(body) {
			return nil
		}
		start = end + 1
	}
}

func parseProviderItems(items []string, provider config.RuleProvider) (ProviderRules, error) {
	if len(items) > maxProviderRules {
		return ProviderRules{}, fmt.Errorf("provider contains too many rules: %d", len(items))
	}
	result := ProviderRules{}
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(strings.TrimPrefix(item, "\ufeff"))
		if len(trimmed) > maxProviderRuleLength {
			return ProviderRules{}, fmt.Errorf("provider rule exceeds %d bytes", maxProviderRuleLength)
		}
		if err := appendProviderRule(&result, seen, trimmed, strings.ToLower(provider.Behavior)); err != nil {
			return ProviderRules{}, err
		}
	}
	if len(result.Functions) == 0 {
		return ProviderRules{}, errors.New("provider contains no supported rules")
	}
	return result, nil
}

func appendProviderRule(result *ProviderRules, seen map[string]struct{}, trimmed, behavior string) error {
	function, err := parseItem(trimmed, behavior)
	if err != nil {
		return err
	}
	if function == nil {
		return nil
	}
	key := functionKey(function)
	if _, ok := seen[key]; ok {
		return nil
	}
	seen[key] = struct{}{}
	result.Functions = append(result.Functions, function)
	if len(result.Functions) > maxProviderRules {
		return fmt.Errorf("provider contains too many supported rules")
	}
	return nil
}

func scanProviderTextLine(body []byte, start int) (int, []byte, bool) {
	scanStart := start
	if len(body)-scanStart >= 3 && body[scanStart] == 0xef && body[scanStart+1] == 0xbb && body[scanStart+2] == 0xbf {
		scanStart += 3
	}
	end := scanStart
	trimmedStart := -1
	trimmedEnd := scanStart
	for end < len(body) && body[end] != '\n' {
		runeValue, size := utf8.DecodeRune(body[end:])
		if !unicode.IsSpace(runeValue) {
			if trimmedStart < 0 {
				trimmedStart = end
			}
			trimmedEnd = end + size
			if trimmedEnd-trimmedStart > maxProviderRuleLength {
				return end, nil, true
			}
		}
		end += size
	}
	if trimmedStart < 0 {
		return end, body[end:end], false
	}
	return end, body[trimmedStart:trimmedEnd], false
}

func providerItems(body []byte, format string) ([]string, error) {
	if strings.EqualFold(format, "text") {
		items := make([]string, 0)
		lineCount := 0
		for start := 0; ; {
			lineCount++
			if lineCount > maxProviderRules {
				return nil, fmt.Errorf("provider contains too many rules: %d", lineCount)
			}
			end, _, tooLong := scanProviderTextLine(body, start)
			if tooLong {
				return nil, fmt.Errorf("provider rule exceeds %d bytes", maxProviderRuleLength)
			}
			items = append(items, string(body[start:end]))
			if end == len(body) {
				break
			}
			start = end + 1
		}
		return items, nil
	}
	if format != "" && !strings.EqualFold(format, "yaml") {
		return nil, fmt.Errorf("unsupported provider format %q", format)
	}
	if err := validateProviderYAML(body); err != nil {
		return nil, err
	}
	var envelope struct {
		Payload []string `yaml:"payload"`
	}
	if err := yaml.Unmarshal(body, &envelope); err == nil && envelope.Payload != nil {
		return envelope.Payload, nil
	}
	var list []string
	if err := yaml.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse yaml provider: %w", err)
	}
	return list, nil
}

func validateProviderYAML(body []byte) error {
	if err := preflightProviderYAML(body); err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("parse yaml provider: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("provider yaml contains multiple documents")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse yaml provider: %w", err)
	}
	nodes := 0
	var walk func(*yaml.Node, int) error
	walk = func(node *yaml.Node, depth int) error {
		if node == nil {
			return nil
		}
		if depth > maxProviderYAMLDepth {
			return fmt.Errorf("provider yaml nesting exceeds %d levels", maxProviderYAMLDepth)
		}
		nodes++
		if nodes > maxProviderYAMLNodes {
			return fmt.Errorf("provider yaml contains too many nodes: %d", nodes)
		}
		if node.Kind == yaml.AliasNode {
			return errors.New("provider yaml aliases are not allowed")
		}
		for _, child := range node.Content {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(&root, 0)
}

func preflightProviderYAML(body []byte) error {
	if err := preflightProviderYAMLScalars(body); err != nil {
		return err
	}
	nodes := 0
	rootStarted := false
	indentStack := make([]int, 0, maxProviderYAMLDepth)
	var flowState yamlFlowState
	blockScalarIndent := -1
	blockScalarBytes := 0
	addNodes := func(count int) error {
		if count <= 0 {
			return nil
		}
		if nodes > maxProviderYAMLNodes-count {
			return fmt.Errorf("provider yaml contains too many nodes: %d", nodes+count)
		}
		nodes += count
		return nil
	}

	for lineStart := 0; lineStart <= len(body); {
		lineEnd := lineStart
		for lineEnd < len(body) && body[lineEnd] != '\n' {
			lineEnd++
		}
		line := body[lineStart:lineEnd]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if lineEnd < len(body) {
			lineStart = lineEnd + 1
		} else {
			lineStart = len(body) + 1
		}

		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		contentStart := indent
		if blockScalarIndent >= 0 {
			if contentStart == len(line) || indent > blockScalarIndent {
				blockScalarBytes += len(line) - contentStart
				if blockScalarBytes > maxProviderRuleLength {
					return fmt.Errorf("provider yaml scalar exceeds %d bytes", maxProviderRuleLength)
				}
				continue
			}
			blockScalarIndent = -1
			blockScalarBytes = 0
		}
		flowStateBefore := flowState
		flowInfo := flowState.scan(line[contentStart:])
		contentEnd := contentStart + flowInfo.contentEnd
		if contentEnd <= contentStart {
			continue
		}
		content := line[contentStart:contentEnd]
		if bytes.Equal(content, []byte("---")) || bytes.Equal(content, []byte("...")) {
			if bytes.Equal(content, []byte("...")) {
				rootStarted = true
			}
			continue
		}
		if flowInfo.hasAliasOrAnchor {
			return errors.New("provider yaml aliases and anchors are not allowed")
		}

		for len(indentStack) > 0 && indent < indentStack[len(indentStack)-1] {
			indentStack = indentStack[:len(indentStack)-1]
		}
		if len(indentStack) == 0 || indent > indentStack[len(indentStack)-1] {
			indentStack = append(indentStack, indent)
		}
		sequencePos, sequenceMarkers := 0, 0
		if flowStateBefore.quote == 0 {
			sequencePos, sequenceMarkers = yamlSequencePrefix(content)
		}
		depth := len(indentStack) + sequenceMarkers + flowInfo.maxDepth
		if depth > maxProviderYAMLDepth {
			return fmt.Errorf("provider yaml nesting exceeds %d levels", maxProviderYAMLDepth)
		}
		firstNode := !rootStarted
		if firstNode {
			rootStarted = true
			if err := addNodes(1); err != nil {
				return err
			}
		}

		if sequenceMarkers > 0 {
			if err := addNodes(sequenceMarkers); err != nil {
				return err
			}
			rest := content[sequencePos:]
			if colon := yamlMappingColonWithState(rest, flowStateBefore); colon >= 0 {
				if err := addNodes(1); err != nil {
					return err
				}
				valueStart := colon + 1
				for valueStart < len(rest) && isYAMLBlank(rest[valueStart]) {
					valueStart++
				}
				if valueStart < len(rest) {
					if err := addNodes(1); err != nil {
						return err
					}
					if yamlBlockScalarIndicator(rest[valueStart:]) {
						blockScalarIndent = indent
					} else if len(rest)-valueStart > maxProviderRuleLength {
						return fmt.Errorf("provider yaml scalar exceeds %d bytes", maxProviderRuleLength)
					}
				}
			} else if len(rest) > maxProviderRuleLength {
				return fmt.Errorf("provider yaml scalar exceeds %d bytes", maxProviderRuleLength)
			}
		} else if colon := yamlMappingColonWithState(content, flowStateBefore); colon >= 0 {
			if err := addNodes(1); err != nil {
				return err
			}
			valueStart := colon + 1
			for valueStart < len(content) && isYAMLBlank(content[valueStart]) {
				valueStart++
			}
			if valueStart < len(content) {
				if err := addNodes(1); err != nil {
					return err
				}
				if yamlBlockScalarIndicator(content[valueStart:]) {
					blockScalarIndent = indent
				} else if len(content)-valueStart > maxProviderRuleLength {
					return fmt.Errorf("provider yaml scalar exceeds %d bytes", maxProviderRuleLength)
				}
			}
		} else if !firstNode {
			if err := addNodes(1); err != nil {
				return err
			}
		} else if len(content) > maxProviderRuleLength {
			return fmt.Errorf("provider yaml scalar exceeds %d bytes", maxProviderRuleLength)
		}
		if err := addNodes(flowInfo.nodes); err != nil {
			return err
		}
	}
	return nil
}

type yamlScalarPreflightState struct {
	kind               byte
	quote              byte
	escaped            bool
	baseIndent         int
	length             int
	blockIndent        int
	blockContentIndent int
	blockLines         int
}

const (
	yamlScalarPreflightNone  byte = 0
	yamlScalarPreflightPlain byte = 1
	yamlScalarPreflightQuote byte = 2
	yamlScalarPreflightBlock byte = 3
)

func preflightProviderYAMLScalars(body []byte) error {
	var scalar yamlScalarPreflightState
	for lineStart := 0; lineStart <= len(body); {
		lineEnd := lineStart
		for lineEnd < len(body) && body[lineEnd] != '\n' {
			lineEnd++
		}
		line := body[lineStart:lineEnd]
		if lineStart == 0 && len(line) >= 3 && bytes.Equal(line[:3], []byte{0xef, 0xbb, 0xbf}) {
			line = line[3:]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if lineEnd < len(body) {
			lineStart = lineEnd + 1
		} else {
			lineStart = len(body) + 1
		}

		if scalar.kind == yamlScalarPreflightBlock {
			consumed, err := scalar.consumeBlockLine(line)
			if err != nil {
				return err
			}
			if consumed {
				continue
			}
			scalar = yamlScalarPreflightState{}
		}
		if scalar.kind == yamlScalarPreflightQuote {
			consumed, err := scalar.consumeQuotedLine(line)
			if err != nil {
				return err
			}
			if consumed {
				continue
			}
			scalar = yamlScalarPreflightState{}
		}
		if scalar.kind == yamlScalarPreflightPlain {
			consumed, err := scalar.consumePlainLine(line)
			if err != nil {
				return err
			}
			if consumed {
				continue
			}
			scalar = yamlScalarPreflightState{}
		}

		if err := startYAMLScalarPreflight(&scalar, line); err != nil {
			return err
		}
	}
	return nil
}

func startYAMLScalarPreflight(scalar *yamlScalarPreflightState, line []byte) error {
	indent := yamlLineIndent(line)
	contentStart := indent
	contentEnd := yamlLineContentEnd(line, contentStart)
	if contentEnd <= contentStart {
		return nil
	}
	content := line[contentStart:contentEnd]
	if bytes.Equal(content, []byte("---")) || bytes.Equal(content, []byte("...")) || content[0] == '%' {
		return nil
	}

	sequencePos, sequenceMarkers := yamlSequencePrefix(content)
	valueStart := -1
	baseIndent := indent
	if sequenceMarkers > 0 {
		rest := content[sequencePos:]
		if colon := yamlMappingColon(rest); colon >= 0 {
			valueStart = contentStart + sequencePos + colon + 1
		} else {
			valueStart = contentStart + sequencePos
		}
	} else if colon := yamlMappingColon(content); colon >= 0 {
		valueStart = contentStart + colon + 1
	}
	if valueStart < 0 {
		valueStart = contentStart
	}
	for valueStart < contentEnd && isYAMLBlank(line[valueStart]) {
		valueStart++
	}
	if valueStart >= contentEnd {
		return nil
	}

	value := line[valueStart:contentEnd]
	if value[0] == '[' || value[0] == '{' {
		return nil
	}
	if yamlBlockScalarIndicator(value) {
		scalar.kind = yamlScalarPreflightBlock
		scalar.blockIndent = baseIndent
		if explicit, ok := yamlBlockScalarIndent(value); ok {
			scalar.blockContentIndent = baseIndent + explicit
		}
		return nil
	}
	if value[0] == '\'' || value[0] == '"' {
		scalar.kind = yamlScalarPreflightQuote
		scalar.quote = value[0]
		scalar.baseIndent = baseIndent
		return scalar.consumeQuotedFragment(value[1:])
	}

	if err := scalar.add(lenYAMLScalarContent(value)); err != nil {
		return err
	}
	scalar.kind = yamlScalarPreflightPlain
	scalar.baseIndent = baseIndent
	return nil
}

func (scalar *yamlScalarPreflightState) add(length int) error {
	if length <= 0 {
		return nil
	}
	if scalar.length > maxProviderRuleLength-length {
		return fmt.Errorf("provider yaml scalar exceeds %d bytes", maxProviderRuleLength)
	}
	scalar.length += length
	return nil
}

func (scalar *yamlScalarPreflightState) consumeQuotedLine(line []byte) (bool, error) {
	indent := yamlLineIndent(line)
	if err := scalar.add(1); err != nil {
		return true, err
	}
	if err := scalar.consumeQuotedFragment(line[indent:]); err != nil {
		return true, err
	}
	if scalar.kind == yamlScalarPreflightNone {
		return true, nil
	}
	return true, nil
}

func (scalar *yamlScalarPreflightState) consumeQuotedFragment(fragment []byte) error {
	for index := 0; index < len(fragment); index++ {
		char := fragment[index]
		if scalar.quote == '"' {
			if scalar.escaped {
				scalar.escaped = false
				if err := scalar.add(1); err != nil {
					return err
				}
				continue
			}
			if char == '\\' {
				scalar.escaped = true
				continue
			}
			if char == scalar.quote {
				scalar.kind = yamlScalarPreflightNone
				return nil
			}
			if err := scalar.add(1); err != nil {
				return err
			}
			continue
		}
		if char == scalar.quote {
			if index+1 < len(fragment) && fragment[index+1] == scalar.quote {
				if err := scalar.add(1); err != nil {
					return err
				}
				index++
				continue
			}
			scalar.kind = yamlScalarPreflightNone
			return nil
		}
		if err := scalar.add(1); err != nil {
			return err
		}
	}
	return nil
}

func (scalar *yamlScalarPreflightState) consumePlainLine(line []byte) (bool, error) {
	indent := yamlLineIndent(line)
	contentStart := indent
	contentEnd := yamlLineContentEnd(line, contentStart)
	if contentEnd <= contentStart {
		return true, scalar.add(1)
	}
	if indent <= scalar.baseIndent {
		return false, nil
	}
	content := line[contentStart:contentEnd]
	if _, sequenceMarkers := yamlSequencePrefix(content); sequenceMarkers > 0 || yamlMappingColon(content) >= 0 {
		return false, nil
	}
	if err := scalar.add(1); err != nil {
		return true, err
	}
	if err := scalar.add(lenYAMLScalarContent(content)); err != nil {
		return true, err
	}
	return true, nil
}

func (scalar *yamlScalarPreflightState) consumeBlockLine(line []byte) (bool, error) {
	indent := yamlLineIndent(line)
	contentStart := indent
	blank := contentStart == len(line)
	if blank {
		if err := scalar.add(1); err != nil {
			return true, err
		}
		scalar.blockLines++
		return true, nil
	}
	if scalar.blockContentIndent == 0 {
		if indent <= scalar.blockIndent {
			return false, nil
		}
		scalar.blockContentIndent = indent
	}
	if indent < scalar.blockContentIndent {
		return false, nil
	}
	contentStart = scalar.blockContentIndent
	if scalar.blockLines > 0 {
		if err := scalar.add(1); err != nil {
			return true, err
		}
	}
	if err := scalar.add(len(line) - contentStart); err != nil {
		return true, err
	}
	scalar.blockLines++
	return true, nil
}

func lenYAMLScalarContent(content []byte) int {
	start := 0
	end := len(content)
	for start < end && isYAMLBlank(content[start]) {
		start++
	}
	for end > start && isYAMLBlank(content[end-1]) {
		end--
	}
	return end - start
}

func yamlLineIndent(line []byte) int {
	indent := 0
	for indent < len(line) && line[indent] == ' ' {
		indent++
	}
	return indent
}

func yamlLineContentEnd(line []byte, start int) int {
	var state yamlFlowState
	return start + state.scan(line[start:]).contentEnd
}

func yamlHasAliasOrAnchor(content []byte) bool {
	var state yamlFlowState
	return state.scan(content).hasAliasOrAnchor
}

func yamlSequencePrefix(content []byte) (int, int) {
	position := 0
	markers := 0
	for position < len(content) && content[position] == '-' && (position+1 == len(content) || isYAMLBlank(content[position+1])) {
		markers++
		position++
		for position < len(content) && isYAMLBlank(content[position]) {
			position++
		}
	}
	return position, markers
}

func yamlMappingColon(content []byte) int {
	return yamlMappingColonWithState(content, yamlFlowState{})
}

func yamlMappingColonWithState(content []byte, state yamlFlowState) int {
	quote := state.quote
	escaped := state.escaped
	baseFlowDepth := state.depth
	flowDepth := baseFlowDepth
	for index := 0; index < len(content); index++ {
		char := content[index]
		if quote == '"' {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		if quote == '\'' {
			if char == quote {
				if index+1 < len(content) && content[index+1] == quote {
					index++
					continue
				}
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
		case '#':
			if index == 0 || isYAMLBlank(content[index-1]) {
				return -1
			}
		case '[', '{':
			flowDepth++
		case ']', '}':
			if flowDepth > 0 {
				flowDepth--
			}
		case ':':
			if flowDepth == baseFlowDepth && (index+1 == len(content) || isYAMLBlank(content[index+1]) || content[index+1] == '[' || content[index+1] == '{') {
				return index
			}
		}
	}
	return -1
}

func yamlFlowInfo(content []byte) (int, int) {
	var state yamlFlowState
	info := state.scan(content)
	return info.depth, info.nodes
}

type yamlFlowState struct {
	quote   byte
	escaped bool
	depth   int
}

type yamlFlowLineInfo struct {
	contentEnd       int
	depth            int
	maxDepth         int
	nodes            int
	hasAliasOrAnchor bool
}

func (state *yamlFlowState) scan(content []byte) yamlFlowLineInfo {
	info := yamlFlowLineInfo{
		contentEnd: len(content),
		depth:      state.depth,
		maxDepth:   state.depth,
	}
	quote := state.quote
	escaped := state.escaped
	depth := state.depth
	for index := 0; index < len(content); index++ {
		char := content[index]
		if quote == '"' {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		if quote == '\'' {
			if char == quote {
				if index+1 < len(content) && content[index+1] == quote {
					index++
					continue
				}
				quote = 0
			}
			continue
		}
		if char == '#' && (index == 0 || isYAMLBlank(content[index-1])) {
			info.contentEnd = index
			break
		}
		switch char {
		case '\'', '"':
			quote = char
		case '&', '*':
			if index == 0 || isYAMLDelimiter(content[index-1]) {
				info.hasAliasOrAnchor = true
			}
		case '[', '{':
			depth++
			info.nodes++
			if depth > info.maxDepth {
				info.maxDepth = depth
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth > 0 {
				info.nodes++
			}
		}
	}
	state.quote = quote
	state.escaped = escaped
	state.depth = depth
	info.depth = depth
	return info
}

func yamlBlockScalarIndicator(content []byte) bool {
	if len(content) == 0 || (content[0] != '|' && content[0] != '>') {
		return false
	}
	position := 1
	seenChomping := false
	seenIndent := false
	for position < len(content) {
		char := content[position]
		switch {
		case char == '+' || char == '-':
			if seenChomping {
				return false
			}
			seenChomping = true
		case char >= '1' && char <= '9':
			if seenIndent {
				return false
			}
			seenIndent = true
		case isYAMLBlank(char):
			for position < len(content) && isYAMLBlank(content[position]) {
				position++
			}
			return position == len(content) || content[position] == '#'
		case char == '#':
			return true
		default:
			return false
		}
		position++
	}
	return true
}

func yamlBlockScalarIndent(content []byte) (int, bool) {
	if !yamlBlockScalarIndicator(content) {
		return 0, false
	}
	position := 1
	if position < len(content) && (content[position] == '+' || content[position] == '-') {
		position++
	}
	if position < len(content) && content[position] >= '1' && content[position] <= '9' {
		return int(content[position] - '0'), true
	}
	return 0, false
}

func isYAMLBlank(char byte) bool {
	return char == ' ' || char == '\t'
}

func isYAMLDelimiter(char byte) bool {
	return isYAMLBlank(char) || char == '[' || char == '{' || char == ',' || char == ':' || char == '?'
}

func parseItem(raw, behavior string) (*config_parser.Function, error) {
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, ";") {
		return nil, nil
	}
	if behavior != "domain" && behavior != "ipcidr" && behavior != "classical" {
		return nil, fmt.Errorf("unsupported provider behavior %q", behavior)
	}
	if !utf8.ValidString(raw) {
		return nil, errors.New("provider rule is not valid UTF-8")
	}
	for _, char := range raw {
		if unicode.IsControl(char) {
			return nil, errors.New("provider rule contains a control character")
		}
	}
	parts := strings.SplitN(raw, ",", 2)
	kind := strings.ToUpper(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(raw)
	if len(parts) == 2 {
		value = strings.TrimSpace(parts[1])
	}
	if strings.HasPrefix(raw, "+.") {
		kind = "DOMAIN-SUFFIX"
		value = strings.TrimSpace(strings.TrimPrefix(raw, "+."))
	}
	if kind == "" || value == "" {
		return nil, errors.New("provider rule has an empty value")
	}
	switch kind {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX":
		if behavior == "ipcidr" {
			return nil, fmt.Errorf("domain rule %q is unsupported in ipcidr provider", raw)
		}
		if kind != "DOMAIN-REGEX" && strings.Contains(value, ",") {
			return nil, fmt.Errorf("domain rule %q has multiple values", raw)
		}
		if kind == "DOMAIN-REGEX" {
			if _, err := regexp.Compile(value); err != nil {
				return nil, fmt.Errorf("invalid domain regex %q: %w", value, err)
			}
		}
		key := map[string]string{"DOMAIN": "full", "DOMAIN-SUFFIX": "suffix", "DOMAIN-KEYWORD": "keyword", "DOMAIN-REGEX": "regex"}[kind]
		return &config_parser.Function{Name: "domain", Params: []*config_parser.Param{{Key: key, Val: value}}}, nil
	case "IP-CIDR", "IP-CIDR6":
		if behavior == "domain" {
			return nil, fmt.Errorf("IP-CIDR rule %q is unsupported in domain provider", raw)
		}
		prefix, err := parseProviderPrefix(value)
		if err != nil {
			return nil, err
		}
		if kind == "IP-CIDR6" && prefix.Addr().Is4() {
			return nil, fmt.Errorf("IP-CIDR6 rule %q is not IPv6", raw)
		}
		if kind == "IP-CIDR" && !prefix.Addr().Is4() {
			return nil, fmt.Errorf("IP-CIDR rule %q is not IPv4", raw)
		}
		return &config_parser.Function{Name: "dip", Params: []*config_parser.Param{{Val: prefix.Masked().String()}}}, nil
	case "DOMAIN-WILDCARD", "GEOSITE", "GEOIP", "IP-ASN", "PROCESS-NAME", "DST-PORT", "SRC-IP-CIDR", "NETWORK", "AND", "OR", "NOT":
		return nil, fmt.Errorf("unsupported provider rule type %q", kind)
	}
	if strings.ContainsAny(raw, " ,\t\r") {
		return nil, fmt.Errorf("unsupported provider rule %q", raw)
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		if behavior == "domain" {
			return nil, fmt.Errorf("IP address %q is unsupported in domain provider", raw)
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		return &config_parser.Function{Name: "dip", Params: []*config_parser.Param{{Val: netip.PrefixFrom(addr, bits).String()}}}, nil
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		if behavior == "domain" {
			return nil, fmt.Errorf("CIDR %q is unsupported in domain provider", raw)
		}
		return &config_parser.Function{Name: "dip", Params: []*config_parser.Param{{Val: prefix.Masked().String()}}}, nil
	}
	if behavior == "ipcidr" {
		return nil, fmt.Errorf("invalid CIDR %q", raw)
	}
	if behavior != "domain" && behavior != "classical" {
		return nil, fmt.Errorf("unsupported provider behavior %q", behavior)
	}
	return &config_parser.Function{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: raw}}}, nil
}

func parseProviderPrefix(value string) (netip.Prefix, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", value)
	}
	for _, option := range parts[1:] {
		if !strings.EqualFold(strings.TrimSpace(option), "no-resolve") {
			return netip.Prefix{}, fmt.Errorf("unsupported CIDR option %q", strings.TrimSpace(option))
		}
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(parts[0]))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", value, err)
	}
	return prefix, nil
}

func functionKey(function *config_parser.Function) string {
	if function == nil {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(function.Name)
	for _, param := range function.Params {
		if param == nil {
			builder.WriteByte(0)
			continue
		}
		builder.WriteByte(0)
		builder.WriteString(param.Key)
		builder.WriteByte(0)
		builder.WriteString(param.Val)
	}
	return builder.String()
}

func ExpandRoutingRules(rules []*config_parser.RoutingRule, registry Registry) ([]*config_parser.RoutingRule, error) {
	if len(rules) > maxExpandedRoutingRules {
		return nil, fmt.Errorf("expanded routing rules exceed %d", maxExpandedRoutingRules)
	}
	result := make([]*config_parser.RoutingRule, 0, len(rules))
	for _, rule := range rules {
		expanded, err := expandRule(rule, registry)
		if err != nil {
			return nil, err
		}
		if len(result) > maxExpandedRoutingRules || len(expanded) > maxExpandedRoutingRules-len(result) {
			return nil, fmt.Errorf("expanded routing rules exceed %d", maxExpandedRoutingRules)
		}
		result = append(result, expanded...)
	}
	return result, nil
}

func expandRule(rule *config_parser.RoutingRule, registry Registry) ([]*config_parser.RoutingRule, error) {
	if rule == nil {
		return nil, errors.New("routing rule is nil")
	}
	current := []*config_parser.RoutingRule{cloneRule(rule)}
	for index, function := range rule.AndFunctions {
		if function == nil {
			return nil, errors.New("routing rule contains a nil function")
		}
		if function.Name != "ruleset" {
			continue
		}
		if function.Not {
			return nil, fmt.Errorf("negated ruleset() is not supported")
		}
		if len(function.Params) != 1 || function.Params[0] == nil || function.Params[0].Key != "" || function.Params[0].Val == "" || len(function.Params[0].AndFunctions) != 0 {
			return nil, fmt.Errorf("ruleset() requires one provider name")
		}
		provider, ok := registry[function.Params[0].Val]
		if !ok {
			return nil, fmt.Errorf("routing rule references unknown rule provider %q", function.Params[0].Val)
		}
		if len(provider.Functions) == 0 {
			return nil, fmt.Errorf("routing rule references empty rule provider %q", function.Params[0].Val)
		}
		for _, replacement := range provider.Functions {
			if replacement == nil {
				return nil, fmt.Errorf("routing rule references invalid rule provider %q", function.Params[0].Val)
			}
		}
		if len(current) > maxExpandedRoutingRules/len(provider.Functions) {
			return nil, fmt.Errorf("ruleset expansion exceeds %d routing rules", maxExpandedRoutingRules)
		}
		next := make([]*config_parser.RoutingRule, 0, len(current)*len(provider.Functions))
		for _, candidate := range current {
			for _, replacement := range provider.Functions {
				copy := cloneRule(candidate)
				copy.AndFunctions[index] = cloneFunction(replacement)
				next = append(next, copy)
			}
		}
		current = next
	}
	return current, nil
}

func cloneRule(rule *config_parser.RoutingRule) *config_parser.RoutingRule {
	if rule == nil {
		return nil
	}
	copy := &config_parser.RoutingRule{Outbound: *cloneFunction(&rule.Outbound)}
	copy.AndFunctions = make([]*config_parser.Function, len(rule.AndFunctions))
	for i, function := range rule.AndFunctions {
		copy.AndFunctions[i] = cloneFunction(function)
	}
	return copy
}

func cloneFunction(function *config_parser.Function) *config_parser.Function {
	if function == nil {
		return nil
	}
	copy := *function
	copy.Params = make([]*config_parser.Param, len(function.Params))
	for i, param := range function.Params {
		if param == nil {
			continue
		}
		paramCopy := *param
		paramCopy.Annotation = append([]*config_parser.Param(nil), param.Annotation...)
		paramCopy.AndFunctions = append([]*config_parser.Function(nil), param.AndFunctions...)
		copy.Params[i] = &paramCopy
	}
	return &copy
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

func redactProviderError(err error) error {
	if err == nil {
		return nil
	}
	switch typed := err.(type) {
	case *url.Error:
		if typed == nil {
			return errors.New("provider request failed")
		}
		return &url.Error{
			Op:  typed.Op,
			URL: redactProviderURL(typed.URL),
			Err: redactProviderError(typed.Err),
		}
	case *providerSecurityError:
		if typed == nil {
			return errors.New("provider security policy rejected request")
		}
		return &providerSecurityError{err: redactProviderError(typed.err)}
	}
	message := err.Error()
	if strings.Contains(message, `parse "`) || strings.Contains(message, "invalid URL escape") {
		return errors.New("provider URL is invalid")
	}
	if index := strings.IndexByte(message, '?'); index >= 0 {
		message = message[:index] + "?[redacted]"
	} else if index := strings.IndexByte(message, '&'); index >= 0 && strings.Contains(message[index:], "=") {
		message = message[:index] + "&[redacted]"
	}
	return errors.New(message)
}

func redactProviderFetchError(err error) error {
	if err == nil {
		return nil
	}
	redacted := redactProviderError(err)
	if isSecurityError(err) {
		return securityError(redacted)
	}
	return redacted
}
