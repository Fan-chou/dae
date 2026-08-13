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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"golang.org/x/sys/unix"
)

var runSyncMu sync.Mutex

type SyncOptions struct {
	ManifestPath    string
	CacheDir        string
	RoutesOutput    string
	GroupsInputPath string
	GroupsOutput    string
	GenerationDir   string
	Client          *http.Client
	Strict          bool
	AllowPrivate    bool
}

type ProviderSyncReport struct {
	Name        string `json:"name"`
	Updated     bool   `json:"updated"`
	UsedCache   bool   `json:"used_cache"`
	SHA256      string `json:"sha256"`
	RuleCount   int    `json:"rule_count"`
	Unsupported int    `json:"unsupported"`
	Warning     string `json:"warning,omitempty"`
}

type SyncReport struct {
	Providers []ProviderSyncReport  `json:"providers"`
	Routes    ConversionReport      `json:"routes"`
	Groups    GroupConversionReport `json:"groups"`
}

func RunSync(ctx context.Context, options SyncOptions) (SyncReport, error) {
	runSyncMu.Lock()
	defer runSyncMu.Unlock()

	if options.ManifestPath == "" {
		return SyncReport{}, fmt.Errorf("manifest path is required")
	}
	if options.GenerationDir != "" && (options.RoutesOutput != "" || options.GroupsOutput != "") {
		return SyncReport{}, errors.New("generation output cannot be combined with direct routes or groups output")
	}
	generationMode := options.GenerationDir != ""
	var generationRoot generationRootState
	var generationLock *generationLock
	var previousSnapshots map[string]ProviderSnapshot
	if generationMode {
		var err error
		generationRoot, err = openGenerationRoot(options.GenerationDir)
		if err != nil {
			return SyncReport{}, fmt.Errorf("prepare generation root: %w", err)
		}
		generationLock, err = acquireGenerationLock(ctx, generationRoot.root)
		if err != nil {
			return SyncReport{}, fmt.Errorf("acquire generation lock: %w", err)
		}
		defer generationLock.close()
		generationRoot, err = resolveGenerationRoot(generationRoot)
		if err != nil {
			return SyncReport{}, fmt.Errorf("resolve current generation: %w", err)
		}
		if generationRoot.previousID != "" {
			previousSnapshots, err = readGenerationProviderSnapshots(filepath.Join(generationRoot.generations, generationRoot.previousID))
			if err != nil {
				return SyncReport{}, fmt.Errorf("read previous generation provider snapshots: %w", err)
			}
		}
	}
	manifestBody, err := os.ReadFile(options.ManifestPath)
	if err != nil {
		return SyncReport{}, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := ParseManifest(manifestBody)
	if err != nil {
		return SyncReport{}, err
	}
	baseDir, err := filepath.Abs(filepath.Dir(options.ManifestPath))
	if err != nil {
		return SyncReport{}, fmt.Errorf("resolve manifest directory: %w", err)
	}
	validateURL := validateProviderURL
	if options.AllowPrivate {
		validateURL = validateTestURL
	}
	if err := validateManifestWithURL(manifest, baseDir, validateURL); err != nil {
		return SyncReport{}, err
	}
	if !generationMode && options.CacheDir == "" {
		options.CacheDir = filepath.Join(baseDir, "persist.d", "rule-providers")
	}
	fetcher := NewProviderFetcher(options.Client, options.CacheDir)
	fetcher.DeferCacheCommit = true
	fetcher.ValidateBody = func(spec ProviderSpec, body []byte) error {
		_, err := ParseProvider(body, spec)
		return err
	}
	if options.AllowPrivate {
		fetcher.ValidateURL = validateTestURL
		fetcher.AllowPrivate = true
	}

	sets := make(map[string]ParsedRuleSet, len(manifest.Providers))
	snapshots := make(map[string]ProviderSnapshot, len(manifest.Providers))
	providerRoutes := make(map[string][]RouteSpec, len(manifest.Routes))
	for _, route := range manifest.Routes {
		providerRoutes[route.Provider] = append(providerRoutes[route.Provider], route)
	}
	pendingSnapshots := make([]ProviderSnapshot, 0, len(manifest.Providers))
	report := SyncReport{Providers: make([]ProviderSyncReport, 0, len(manifest.Providers))}
	generationReused := generationMode
	for _, spec := range manifest.Providers {
		var snapshot ProviderSnapshot
		var fetchResult FetchResult
		if generationMode {
			snapshot, fetchResult, err = loadGenerationProvider(ctx, fetcher, spec, baseDir, previousSnapshots[spec.Name], providerRoutes[spec.Name], options.Strict)
		} else {
			snapshot, fetchResult, err = loadProvider(ctx, fetcher, spec, baseDir)
		}
		if err != nil {
			return SyncReport{}, fmt.Errorf("provider %q: %w", spec.Name, err)
		}
		if !generationMode || !isHTTPProvider(spec) {
			if generationMode {
				snapshot.Behavior = normalizedProviderBehavior(spec)
				snapshot.Format = normalizedProviderFormat(spec)
			} else {
				snapshot.Behavior = spec.Behavior
				snapshot.Format = spec.Format
			}
		}
		parsed, err := ParseProvider(snapshot.Body, spec)
		if err != nil {
			return SyncReport{}, fmt.Errorf("provider %q: %w", spec.Name, err)
		}
		if (!generationMode || !isHTTPProvider(spec)) && len(providerRoutes[spec.Name]) > 0 && len(parsed.Domains)+len(parsed.Prefixes) == 0 {
			return SyncReport{}, fmt.Errorf("provider %q has no convertible rules", spec.Name)
		}
		sets[spec.Name] = parsed
		snapshots[spec.Name] = snapshot
		if !generationMode && fetchResult.Updated && !fetchResult.UsedCache && isHTTPProvider(spec) {
			pendingSnapshots = append(pendingSnapshots, fetchResult.Snapshot)
		}
		if generationMode && (!fetchResult.UsedCache || fetchResult.Updated) {
			generationReused = false
		}
		providerReport := ProviderSyncReport{
			Name:        spec.Name,
			Updated:     fetchResult.Updated,
			UsedCache:   fetchResult.UsedCache,
			SHA256:      snapshot.SHA256,
			RuleCount:   len(parsed.Domains) + len(parsed.Prefixes),
			Unsupported: len(parsed.Unsupported),
		}
		if fetchResult.Warning != nil {
			providerReport.Warning = fetchResult.Warning.Error()
		}
		report.Providers = append(report.Providers, providerReport)
	}

	routes, routeReport, err := GenerateDaeRoutes(manifest, sets, options.Strict)
	if err != nil {
		return SyncReport{}, err
	}
	report.Routes = routeReport
	if (options.RoutesOutput != "" || options.GenerationDir != "") && routeReport.Generated == 0 {
		return SyncReport{}, fmt.Errorf("refusing to replace routes output with zero generated rules")
	}

	var groups []byte
	if options.GroupsInputPath != "" {
		groupsBody, err := os.ReadFile(options.GroupsInputPath)
		if err != nil {
			return SyncReport{}, fmt.Errorf("read mihomo groups input: %w", err)
		}
		mihomoConfig, err := ParseMihomoConfig(groupsBody)
		if err != nil {
			return SyncReport{}, err
		}
		groupsText, groupReport, err := GenerateFlatDaeGroups(mihomoConfig)
		if err != nil {
			return SyncReport{}, err
		}
		report.Groups = groupReport
		if options.GenerationDir == "" && options.GroupsOutput == "" {
			return SyncReport{}, fmt.Errorf("groups output is required when groups input is set")
		}
		if groupReport.Converted == 0 {
			return SyncReport{}, fmt.Errorf("refusing to replace groups output with zero converted groups")
		}
		groups = []byte(groupsText)
	}
	if generationMode {
		if options.GroupsInputPath == "" {
			return SyncReport{}, fmt.Errorf("groups input is required when generation directory is set")
		}
		selectedSnapshots := make([]ProviderSnapshot, 0, len(manifest.Providers))
		for _, spec := range manifest.Providers {
			selectedSnapshots = append(selectedSnapshots, snapshots[spec.Name])
		}
		if generationReused {
			unchanged, err := generationMatchesCurrent(generationRoot, []byte(routes), groups, selectedSnapshots)
			if err != nil {
				return SyncReport{}, fmt.Errorf("compare current generation: %w", err)
			}
			if unchanged {
				return report, nil
			}
		}
		generationPublication, err := beginGenerationPublicationAt(generationRoot, []byte(routes), groups, selectedSnapshots)
		if err != nil {
			return SyncReport{}, fmt.Errorf("prepare generation: %w", err)
		}
		if err := generationPublication.publish(); err != nil {
			if !generationPublication.published {
				_ = generationPublication.rollback()
			}
			return SyncReport{}, fmt.Errorf("publish generation: %w", err)
		}
		if err := generationPublication.finalize(); err != nil {
			return SyncReport{}, fmt.Errorf("retain generation: %w", err)
		}
		return report, nil
	}
	cacheBatch, err := fetcher.prepareSnapshotBatch(pendingSnapshots)
	if err != nil {
		return SyncReport{}, fmt.Errorf("prepare provider cache: %w", err)
	}
	defer cacheBatch.close()
	var outputCandidates []outputCandidate
	if options.GroupsInputPath != "" {
		candidate, err := prepareOutputCandidate(options.GroupsOutput, groups)
		if err != nil {
			return SyncReport{}, fmt.Errorf("write groups: %w", err)
		}
		outputCandidates = append(outputCandidates, candidate)
	}
	if options.RoutesOutput != "" {
		candidate, err := prepareOutputCandidate(options.RoutesOutput, []byte(routes))
		if err != nil {
			cleanupOutputCandidates(outputCandidates)
			return SyncReport{}, fmt.Errorf("write routes: %w", err)
		}
		outputCandidates = append(outputCandidates, candidate)
	}
	outputPublication, err := beginOutputBatchPublication(outputCandidates)
	if err != nil {
		return SyncReport{}, fmt.Errorf("publish outputs: %w", err)
	}
	if err := cacheBatch.publish(); err != nil {
		_ = outputPublication.rollback()
		return SyncReport{}, fmt.Errorf("commit provider cache: %w", err)
	}
	outputPublication.finalize()
	cacheBatch.finalize()
	return report, nil
}

// generationMatchesCurrent permits a failed HTTP revalidation to retain the
// current generation only when every selected input is already represented by
// that generation. Fresh responses and any output or binding difference keep
// the normal publication path.
func generationMatchesCurrent(state generationRootState, routes, groups []byte, snapshots []ProviderSnapshot) (bool, error) {
	if state.previousID == "" {
		return false, nil
	}
	metadata, err := readGenerationMetadata(filepath.Join(state.generations, state.previousID), state.previousID)
	if err != nil {
		return false, err
	}
	if metadata.RoutesSHA256 != digest(routes) || metadata.GroupsSHA256 != digest(groups) || len(metadata.Providers) != len(snapshots) {
		return false, nil
	}
	for _, snapshot := range snapshots {
		binding, ok := metadata.Providers[snapshot.Name]
		if !ok || binding.SHA256 != snapshot.SHA256 || binding.SourceKey != snapshot.SourceKey || binding.Behavior != snapshot.Behavior || binding.Format != snapshot.Format {
			return false, nil
		}
	}
	return true, nil
}

func isHTTPProvider(spec ProviderSpec) bool {
	return spec.Type == "http" || (spec.Type == "" && spec.URL != "")
}

func loadProvider(ctx context.Context, fetcher *ProviderFetcher, spec ProviderSpec, baseDir string) (ProviderSnapshot, FetchResult, error) {
	typeName := spec.Type
	if typeName == "" {
		if spec.URL != "" {
			typeName = "http"
		} else if spec.Data != "" {
			typeName = "inline"
		} else {
			typeName = "file"
		}
	}
	spec.Type = typeName
	switch typeName {
	case "http":
		result, err := fetcher.Fetch(ctx, spec)
		return result.Snapshot, result, err
	case "file":
		body, err := readProviderFile(baseDir, spec.Path, spec.EffectiveMaxSize())
		if err != nil {
			return ProviderSnapshot{}, FetchResult{}, err
		}
		snapshot := snapshotFromBody(spec.Name, body, time.Now().UTC())
		snapshot.SourceKey = providerSourceKey(spec)
		return snapshot, FetchResult{Snapshot: snapshot, Updated: true}, nil
	case "inline":
		snapshot := snapshotFromBody(spec.Name, []byte(spec.Data), time.Now().UTC())
		snapshot.SourceKey = providerSourceKey(spec)
		return snapshot, FetchResult{Snapshot: snapshot, Updated: true}, nil
	default:
		return ProviderSnapshot{}, FetchResult{}, fmt.Errorf("unsupported provider type %q", typeName)
	}
}

func loadGenerationProvider(ctx context.Context, fetcher *ProviderFetcher, spec ProviderSpec, baseDir string, fallback ProviderSnapshot, routes []RouteSpec, strict bool) (ProviderSnapshot, FetchResult, error) {
	typeName := spec.Type
	if typeName == "" {
		if spec.URL != "" {
			typeName = "http"
		} else if spec.Data != "" {
			typeName = "inline"
		} else {
			typeName = "file"
		}
	}
	spec.Type = typeName
	switch typeName {
	case "http":
		result, err := fetcher.FetchWithFallbackValidated(ctx, spec, fallback, generationProviderValidator(spec, routes, strict))
		return result.Snapshot, result, err
	case "file", "inline":
		return loadProvider(ctx, fetcher, spec, baseDir)
	default:
		return ProviderSnapshot{}, FetchResult{}, fmt.Errorf("unsupported provider type %q", typeName)
	}
}

// generationProviderValidator applies the route-level acceptance rules while
// the HTTP response is still eligible for a provider-local fallback. Direct
// output keeps its established aggregate conversion behavior.
func generationProviderValidator(spec ProviderSpec, routes []RouteSpec, strict bool) func(ProviderSpec, []byte) error {
	return func(_ ProviderSpec, body []byte) error {
		parsed, err := ParseProvider(body, spec)
		if err != nil {
			return err
		}
		for _, route := range routes {
			kind := strings.ToLower(route.Kind)
			if kind == "" {
				kind = strings.ToLower(spec.Behavior)
			}
			if (kind == "domain" && len(parsed.Domains) == 0) || (kind == "ipcidr" && len(parsed.Prefixes) == 0) {
				return fmt.Errorf("provider %q has no convertible %s rules", spec.Name, kind)
			}
			if strict && len(parsed.Unsupported) > 0 {
				return fmt.Errorf("provider %q contains %d unsupported rules", spec.Name, len(parsed.Unsupported))
			}
		}
		return nil
	}
}

func providerSourceKey(spec ProviderSpec) string {
	switch spec.Type {
	case "http":
		return digest([]byte(spec.URL))
	case "file":
		return digest([]byte("file:" + filepath.Clean(spec.Path)))
	default:
		return digest([]byte("inline:" + spec.Name))
	}
}

func readProviderFile(baseDir, providerPath string, maxSize int64) ([]byte, error) {
	if err := validateRelativePath(baseDir, providerPath); err != nil {
		return nil, err
	}
	baseResolved, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve provider base directory: %w", err)
	}
	candidate, err := filepath.Abs(filepath.Join(baseDir, filepath.Clean(providerPath)))
	if err != nil {
		return nil, fmt.Errorf("resolve provider path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, fmt.Errorf("resolve provider file: %w", err)
	}
	rel, err := filepath.Rel(baseResolved, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("provider path %q resolves outside base directory", providerPath)
	}
	fd, err := unix.Open(resolved, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open provider file safely: %w", err)
	}
	file := os.NewFile(uintptr(fd), resolved)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open provider file safely: invalid file handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat provider file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("provider path %q is not a regular file", providerPath)
	}
	return readLimitedReader(file, maxSize)
}

func readLimited(path string, maxSize int64) ([]byte, error) {
	if maxSize <= 0 || maxSize > maxProviderMaxSize {
		return nil, fmt.Errorf("invalid max_size %d", maxSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLimitedReader(file, maxSize)
}

func readLimitedReader(reader io.Reader, maxSize int64) ([]byte, error) {
	if maxSize <= 0 || maxSize > maxProviderMaxSize {
		return nil, fmt.Errorf("invalid max_size %d", maxSize)
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxSize {
		return nil, fmt.Errorf("provider content exceeds max_size %d", maxSize)
	}
	return body, nil
}

func snapshotFromBody(name string, body []byte, updatedAt time.Time) ProviderSnapshot {
	sum := sha256.Sum256(body)
	return ProviderSnapshot{
		Name:      name,
		Body:      append([]byte(nil), body...),
		SHA256:    hex.EncodeToString(sum[:]),
		UpdatedAt: updatedAt,
	}
}

type outputCandidate struct {
	targetPath string
	tempPath   string
}

type outputPublication struct {
	targetPath   string
	backupPath   string
	hadPrevious  bool
	newInstalled bool
}

func prepareOutputCandidate(path string, body []byte) (outputCandidate, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return outputCandidate{}, fmt.Errorf("create output directory: %w", err)
	}
	if err := validateOutputTarget(path); err != nil {
		return outputCandidate{}, err
	}

	tmp, err := os.CreateTemp(dir, ".dae-rule-sync-*.tmp")
	if err != nil {
		return outputCandidate{}, err
	}
	tmpName := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return outputCandidate{}, err
	}
	if _, err := tmp.Write(body); err != nil {
		return outputCandidate{}, err
	}
	if err := tmp.Sync(); err != nil {
		return outputCandidate{}, err
	}
	if err := tmp.Close(); err != nil {
		return outputCandidate{}, err
	}
	keep = true
	return outputCandidate{targetPath: path, tempPath: tmpName}, nil
}

func validateOutputTarget(path string) error {
	dir := filepath.Dir(path)
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat output directory %q: %w", dir, err)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("output parent %q is not a directory", dir)
	}
	if dirInfo.Mode().Perm()&0o222 == 0 {
		return fmt.Errorf("output parent directory %q is not writable", dir)
	}
	if err := unix.Access(dir, unix.W_OK); err != nil {
		return fmt.Errorf("output parent directory %q is not writable: %w", dir, err)
	}

	targetInfo, err := os.Stat(path)
	if err == nil {
		if targetInfo.IsDir() {
			return fmt.Errorf("output target %q is a directory", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat output target %q: %w", path, err)
	}
	if _, err := os.Lstat(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat output target %q: %w", path, err)
	}
	return nil
}

func validateOutputBatch(candidates []outputCandidate) error {
	for _, candidate := range candidates {
		if err := validateOutputTarget(candidate.targetPath); err != nil {
			return err
		}
		info, err := os.Lstat(candidate.tempPath)
		if err != nil {
			return fmt.Errorf("stat output candidate %q: %w", candidate.tempPath, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output candidate %q is not a regular file", candidate.tempPath)
		}
	}
	return nil
}

func cleanupOutputCandidates(candidates []outputCandidate) {
	for _, candidate := range candidates {
		if candidate.tempPath != "" {
			_ = os.Remove(candidate.tempPath)
		}
	}
}

func createOutputBackup(dir string) (string, error) {
	backup, err := os.CreateTemp(dir, ".dae-rule-sync-backup-*.tmp")
	if err != nil {
		return "", err
	}
	backupName := backup.Name()
	keep := false
	defer func() {
		if !keep {
			_ = backup.Close()
			_ = os.Remove(backupName)
		}
	}()
	if err := backup.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(backupName); err != nil {
		return "", err
	}
	keep = true
	return backupName, nil
}

func beginOutputPublication(candidate outputCandidate) (outputPublication, error) {
	publication := outputPublication{targetPath: candidate.targetPath}
	targetInfo, err := os.Lstat(candidate.targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return publication, nil
		}
		return publication, fmt.Errorf("inspect output target %q: %w", candidate.targetPath, err)
	}
	if targetInfo.IsDir() {
		return publication, fmt.Errorf("output target %q is a directory", candidate.targetPath)
	}

	backupPath, err := createOutputBackup(filepath.Dir(candidate.targetPath))
	if err != nil {
		return publication, fmt.Errorf("prepare backup for output %q: %w", candidate.targetPath, err)
	}
	if err := os.Rename(candidate.targetPath, backupPath); err != nil {
		_ = os.Remove(backupPath)
		return publication, fmt.Errorf("backup output %q: %w", candidate.targetPath, err)
	}
	publication.backupPath = backupPath
	publication.hadPrevious = true
	return publication, nil
}

func rollbackOutputPublication(publication outputPublication) error {
	var rollbackErr error
	if publication.newInstalled {
		if err := os.Remove(publication.targetPath); err != nil && !os.IsNotExist(err) {
			rollbackErr = fmt.Errorf("remove new output %q: %w", publication.targetPath, err)
		}
	}
	if publication.hadPrevious {
		if err := os.Rename(publication.backupPath, publication.targetPath); err != nil {
			restoreErr := fmt.Errorf("restore output %q: %w", publication.targetPath, err)
			if rollbackErr != nil {
				return fmt.Errorf("%v; %w", rollbackErr, restoreErr)
			}
			return restoreErr
		}
	}
	return rollbackErr
}

func rollbackOutputPublications(publications []outputPublication) error {
	var rollbackErr error
	for i := len(publications) - 1; i >= 0; i-- {
		if err := rollbackOutputPublication(publications[i]); err != nil {
			if rollbackErr == nil {
				rollbackErr = err
			} else {
				rollbackErr = fmt.Errorf("%v; %w", rollbackErr, err)
			}
		}
	}
	return rollbackErr
}

type outputBatchPublication struct {
	candidates   []outputCandidate
	publications []outputPublication
	finalized    bool
}

func beginOutputBatchPublication(candidates []outputCandidate) (*outputBatchPublication, error) {
	publication := &outputBatchPublication{candidates: candidates}
	if len(candidates) == 0 {
		publication.finalized = true
		return publication, nil
	}
	if err := validateOutputBatch(candidates); err != nil {
		cleanupOutputCandidates(candidates)
		return nil, err
	}
	for _, candidate := range candidates {
		entry, err := beginOutputPublication(candidate)
		if err != nil {
			rollbackErr := rollbackOutputPublications(publication.publications)
			cleanupOutputCandidates(candidates)
			if rollbackErr != nil {
				return nil, fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
			}
			return nil, err
		}
		if err := os.Rename(candidate.tempPath, candidate.targetPath); err != nil {
			rollbackErr := rollbackOutputPublication(entry)
			if previousErr := rollbackOutputPublications(publication.publications); previousErr != nil {
				if rollbackErr == nil {
					rollbackErr = previousErr
				} else {
					rollbackErr = fmt.Errorf("%v; %w", rollbackErr, previousErr)
				}
			}
			cleanupOutputCandidates(candidates)
			if rollbackErr != nil {
				return nil, fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
			}
			return nil, err
		}
		entry.newInstalled = true
		publication.publications = append(publication.publications, entry)
	}
	return publication, nil
}

func (p *outputBatchPublication) rollback() error {
	if p == nil || p.finalized {
		return nil
	}
	err := rollbackOutputPublications(p.publications)
	cleanupOutputCandidates(p.candidates)
	p.finalized = true
	return err
}

func (p *outputBatchPublication) finalize() {
	if p == nil || p.finalized {
		return
	}
	for _, publication := range p.publications {
		if publication.hadPrevious {
			_ = os.Remove(publication.backupPath)
		}
	}
	cleanupOutputCandidates(p.candidates)
	p.finalized = true
}

func publishOutputBatch(candidates []outputCandidate) error {
	publication, err := beginOutputBatchPublication(candidates)
	if err != nil {
		return err
	}
	publication.finalize()
	return nil
}

func writeAtomic(path string, body []byte) error {
	candidate, err := prepareOutputCandidate(path, body)
	if err != nil {
		return err
	}
	return publishOutputBatch([]outputCandidate{candidate})
}

type generationMetadata struct {
	SchemaVersion      int                                  `json:"schema_version"`
	Generation         string                               `json:"generation"`
	PreviousGeneration string                               `json:"previous_generation,omitempty"`
	RoutesSHA256       string                               `json:"routes_sha256"`
	GroupsSHA256       string                               `json:"groups_sha256"`
	Providers          map[string]generationProviderBinding `json:"providers"`
}

type generationProviderBinding struct {
	SHA256         string `json:"sha256"`
	SourceKey      string `json:"source_key"`
	MetadataSHA256 string `json:"metadata_sha256"`
	Behavior       string `json:"behavior,omitempty"`
	Format         string `json:"format,omitempty"`
}

type generationProviderMetadata struct {
	SchemaVersion int       `json:"schema_version"`
	Name          string    `json:"name"`
	ETag          string    `json:"etag,omitempty"`
	LastModified  string    `json:"last_modified,omitempty"`
	SHA256        string    `json:"sha256"`
	SourceURL     string    `json:"source_url,omitempty"`
	SourceKey     string    `json:"source_key"`
	Behavior      string    `json:"behavior,omitempty"`
	Format        string    `json:"format,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type generationRootState struct {
	root        string
	generations string
	previousID  string
}

type generationLock struct{ file *os.File }

func openGenerationRoot(root string) (generationRootState, error) {
	if root == "" {
		return generationRootState{}, errors.New("generation directory is empty")
	}
	resolved, err := secureGenerationDirectory(root)
	if err != nil {
		return generationRootState{}, err
	}
	return generationRootState{root: resolved, generations: filepath.Join(resolved, "generations")}, nil
}

func resolveGenerationRoot(state generationRootState) (generationRootState, error) {
	if err := secureMkdirAll(state.generations, 0o750); err != nil {
		return generationRootState{}, fmt.Errorf("create generations directory: %w", err)
	}
	if err := validateGenerationEntries(state.generations); err != nil {
		return generationRootState{}, err
	}
	previousID, err := validateCurrentLink(state.root, state.generations)
	if err != nil {
		return generationRootState{}, err
	}
	state.previousID = previousID
	return state, nil
}

// generation.lock is the stable generation-root publication lock. It is kept
// separate from current so readers never need to observe a lock transition.
func acquireGenerationLock(ctx context.Context, root string) (*generationLock, error) {
	fd, err := unix.Open(filepath.Join(root, "generation.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(root, "generation.lock"))
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open generation lock: invalid file handle")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &generationLock{file: file}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *generationLock) close() {
	if l == nil || l.file == nil {
		return
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}

type generationPublication struct {
	root          string
	generations   string
	currentTarget string
	candidateDir  string
	published     bool
	finalized     bool
}

func beginGenerationPublication(root string, routes, groups []byte) (*generationPublication, error) {
	state, err := openGenerationRoot(root)
	if err != nil {
		return nil, err
	}
	state, err = resolveGenerationRoot(state)
	if err != nil {
		return nil, err
	}
	return beginGenerationPublicationAt(state, routes, groups, nil)
}

func beginGenerationPublicationAt(state generationRootState, routes, groups []byte, snapshots []ProviderSnapshot) (*generationPublication, error) {
	candidateDir, err := os.MkdirTemp(state.generations, "generation-")
	if err != nil {
		return nil, fmt.Errorf("create generation candidate: %w", err)
	}
	keepCandidate := false
	defer func() {
		if !keepCandidate {
			_ = os.RemoveAll(candidateDir)
		}
	}()

	generationID := filepath.Base(candidateDir)
	metadata := generationMetadata{SchemaVersion: 2, Generation: generationID, PreviousGeneration: state.previousID, RoutesSHA256: digest(routes), GroupsSHA256: digest(groups), Providers: make(map[string]generationProviderBinding, len(snapshots))}
	if err := writeGenerationProviderSnapshots(candidateDir, snapshots, metadata.Providers); err != nil {
		return nil, err
	}
	metadataBody, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode generation metadata: %w", err)
	}
	files := []struct {
		name string
		body []byte
	}{
		{name: "routes.dae", body: routes},
		{name: "groups.dae", body: groups},
		{name: "metadata.json", body: metadataBody},
	}
	for _, file := range files {
		if err := writeFileSync(filepath.Join(candidateDir, file.name), file.body, 0o600); err != nil {
			return nil, fmt.Errorf("write generation %s: %w", file.name, err)
		}
	}
	if err := validateGenerationCandidate(candidateDir, generationID, routes, groups); err != nil {
		return nil, err
	}
	if err := syncDirectory(candidateDir); err != nil {
		return nil, fmt.Errorf("sync generation candidate: %w", err)
	}
	if err := syncDirectory(state.generations); err != nil {
		return nil, fmt.Errorf("sync generations directory: %w", err)
	}
	keepCandidate = true
	return &generationPublication{
		root:          state.root,
		generations:   state.generations,
		currentTarget: filepath.Join("generations", generationID),
		candidateDir:  candidateDir,
	}, nil
}

func writeGenerationProviderSnapshots(candidateDir string, snapshots []ProviderSnapshot, bindings map[string]generationProviderBinding) error {
	providersDir := filepath.Join(candidateDir, "providers")
	if err := os.Mkdir(providersDir, 0o700); err != nil {
		return fmt.Errorf("create generation providers directory: %w", err)
	}
	for _, snapshot := range snapshots {
		if !providerNamePattern.MatchString(snapshot.Name) || snapshot.SHA256 != digest(snapshot.Body) || snapshot.SourceKey == "" {
			return fmt.Errorf("invalid generation provider snapshot %q", snapshot.Name)
		}
		providerDir := filepath.Join(providersDir, snapshot.Name)
		if err := os.Mkdir(providerDir, 0o700); err != nil {
			return fmt.Errorf("create generation provider %q: %w", snapshot.Name, err)
		}
		if err := writeFileSync(filepath.Join(providerDir, "body"), snapshot.Body, 0o600); err != nil {
			return fmt.Errorf("write generation provider %q body: %w", snapshot.Name, err)
		}
		metadata := generationProviderMetadata{SchemaVersion: 1, Name: snapshot.Name, ETag: snapshot.ETag, LastModified: snapshot.LastModified, SHA256: snapshot.SHA256, SourceURL: redactProviderURL(snapshot.SourceURL), SourceKey: snapshot.SourceKey, Behavior: snapshot.Behavior, Format: snapshot.Format, UpdatedAt: snapshot.UpdatedAt}
		metadataBody, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			return fmt.Errorf("encode generation provider %q metadata: %w", snapshot.Name, err)
		}
		if err := writeFileSync(filepath.Join(providerDir, "metadata.json"), metadataBody, 0o600); err != nil {
			return fmt.Errorf("write generation provider %q metadata: %w", snapshot.Name, err)
		}
		if err := syncDirectory(providerDir); err != nil {
			return fmt.Errorf("sync generation provider %q: %w", snapshot.Name, err)
		}
		bindings[snapshot.Name] = generationProviderBinding{SHA256: snapshot.SHA256, SourceKey: snapshot.SourceKey, MetadataSHA256: digest(metadataBody), Behavior: snapshot.Behavior, Format: snapshot.Format}
	}
	return syncDirectory(providersDir)
}

func (p *generationPublication) publish() error {
	if p == nil || p.finalized {
		return nil
	}
	if err := replaceGenerationCurrent(p.root, p.currentTarget); err != nil {
		return err
	}
	p.published = true
	if err := syncDirectory(p.root); err != nil {
		return fmt.Errorf("sync generation root: %w", err)
	}
	return nil
}

func replaceGenerationCurrent(root, target string) error {
	currentTempFile, err := os.CreateTemp(root, ".current.tmp-")
	if err != nil {
		return err
	}
	currentTemp := currentTempFile.Name()
	if err := currentTempFile.Close(); err != nil {
		_ = os.Remove(currentTemp)
		return err
	}
	if err := os.Remove(currentTemp); err != nil {
		return err
	}
	if err := os.Symlink(target, currentTemp); err != nil {
		return err
	}
	if targetBody, err := os.Readlink(currentTemp); err != nil || targetBody != target {
		_ = os.Remove(currentTemp)
		if err != nil {
			return err
		}
		return fmt.Errorf("current symlink candidate target %q, want %q", targetBody, target)
	}
	if err := os.Rename(currentTemp, filepath.Join(root, "current")); err != nil {
		_ = os.Remove(currentTemp)
		return err
	}
	return nil
}

func (p *generationPublication) rollback() error {
	if p == nil {
		return nil
	}
	var firstErr error
	if p.published {
		return nil
	}
	if err := os.RemoveAll(p.candidateDir); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}
	if err := syncDirectory(p.generations); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := syncDirectory(p.root); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (p *generationPublication) finalize() error {
	if p == nil || p.finalized {
		return nil
	}
	if err := retainLatestGenerations(p.generations, filepath.Base(p.currentTarget)); err != nil {
		return err
	}
	p.finalized = true
	return nil
}

func publishGeneration(root string, routes, groups []byte) error {
	p, err := beginGenerationPublication(root, routes, groups)
	if err != nil {
		return err
	}
	if err := p.publish(); err != nil {
		if !p.published {
			_ = p.rollback()
		}
		return err
	}
	if err := p.finalize(); err != nil {
		return err
	}
	return nil
}

func secureGenerationDirectory(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve generation directory: %w", err)
	}
	absPath = filepath.Clean(absPath)
	if err := secureMkdirAll(absPath, 0o750); err != nil {
		return "", fmt.Errorf("create generation directory: %w", err)
	}
	return absPath, nil
}

func secureMkdirAll(path string, mode os.FileMode) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	absPath = filepath.Clean(absPath)
	volume := filepath.VolumeName(absPath)
	rest := strings.TrimPrefix(absPath, volume)
	current := volume
	if strings.HasPrefix(rest, string(filepath.Separator)) {
		current += string(filepath.Separator)
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			if err := os.Mkdir(current, mode); err != nil && !os.IsExist(err) {
				return err
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if current == absPath || !trustedGenerationParentSymlink(current) {
				return fmt.Errorf("generation path component %q is a symlink", current)
			}
			resolvedInfo, err := os.Stat(current)
			if err != nil {
				return err
			}
			info = resolvedInfo
		}
		if !info.IsDir() {
			return fmt.Errorf("generation path component %q is not a directory", current)
		}
	}
	return nil
}

func trustedGenerationParentSymlink(path string) bool {
	path = filepath.Clean(path)
	var expected string
	switch path {
	case string(filepath.Separator) + "var":
		expected = string(filepath.Separator) + "private" + string(filepath.Separator) + "var"
	case string(filepath.Separator) + "tmp":
		expected = string(filepath.Separator) + "private" + string(filepath.Separator) + "tmp"
	default:
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.Clean(resolved) == expected
}

func validateGenerationEntries(generationsRoot string) error {
	entries, err := os.ReadDir(generationsRoot)
	if err != nil {
		return fmt.Errorf("read generations directory: %w", err)
	}
	for _, entry := range entries {
		path := filepath.Join(generationsRoot, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect generation %q: %w", entry.Name(), err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("generation %q is a symlink", entry.Name())
		}
		if !info.IsDir() {
			return fmt.Errorf("generation %q is not a directory", entry.Name())
		}
	}
	return nil
}

func validateCurrentLink(root, generationsRoot string) (string, error) {
	currentPath := filepath.Join(root, "current")
	info, err := os.Lstat(currentPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect current symlink: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("current is not a symlink")
	}
	target, err := os.Readlink(currentPath)
	if err != nil {
		return "", fmt.Errorf("read current symlink: %w", err)
	}
	if filepath.IsAbs(target) || filepath.Clean(target) != target || filepath.Dir(target) != "generations" || filepath.Base(target) == "." || filepath.Base(target) == ".." {
		return "", fmt.Errorf("current symlink target %q is outside generations", target)
	}
	generationsResolved, err := filepath.EvalSymlinks(generationsRoot)
	if err != nil {
		return "", fmt.Errorf("resolve generations directory: %w", err)
	}
	currentResolved, err := filepath.EvalSymlinks(currentPath)
	if err != nil {
		return "", fmt.Errorf("resolve current generation: %w", err)
	}
	relative, err := filepath.Rel(generationsResolved, currentResolved)
	if err != nil || relative == "." || filepath.Dir(relative) != "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return "", fmt.Errorf("current generation resolves outside generations directory")
	}
	resolvedInfo, err := os.Stat(currentResolved)
	if err != nil {
		return "", fmt.Errorf("stat current generation: %w", err)
	}
	if !resolvedInfo.IsDir() {
		return "", fmt.Errorf("current generation is not a directory")
	}
	if err := validateStoredGeneration(currentResolved, filepath.Base(target)); err != nil {
		return "", fmt.Errorf("validate current generation: %w", err)
	}
	return filepath.Base(target), nil
}

func retainLatestGenerations(generationsRoot, currentID string) error {
	currentMetadata, err := readGenerationMetadata(filepath.Join(generationsRoot, currentID), currentID)
	if err != nil {
		return fmt.Errorf("validate current generation %q: %w", currentID, err)
	}
	keep := map[string]bool{currentID: true}
	if previous := currentMetadata.PreviousGeneration; previous != "" && previous != currentID {
		keep[previous] = true
	}
	entries, err := os.ReadDir(generationsRoot)
	if err != nil {
		return fmt.Errorf("read generations for cleanup: %w", err)
	}
	changed := false
	for _, entry := range entries {
		path := filepath.Join(generationsRoot, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect generation %q for cleanup: %w", entry.Name(), err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove unsafe generation %q: %w", entry.Name(), err)
			}
			changed = true
			continue
		}
		if !keep[entry.Name()] {
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("remove old generation %q: %w", entry.Name(), err)
			}
			changed = true
			continue
		}
		if err := validateStoredGeneration(path, entry.Name()); err != nil {
			if entry.Name() == currentID {
				return fmt.Errorf("validate current generation %q: %w", entry.Name(), err)
			}
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("remove invalid predecessor %q: %w", entry.Name(), err)
			}
			changed = true
		}
	}
	if changed {
		if err := syncDirectory(generationsRoot); err != nil {
			return fmt.Errorf("sync generations after cleanup: %w", err)
		}
	}
	return nil
}

func validateStoredGeneration(candidateDir, generationID string) error {
	readRegular := func(name string) ([]byte, error) {
		path := filepath.Join(candidateDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("generation %s is not a regular file", name)
		}
		return os.ReadFile(path)
	}
	metadataBody, err := readRegular("metadata.json")
	if err != nil {
		return err
	}
	var metadata generationMetadata
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		return err
	}
	if metadata.SchemaVersion != 2 || metadata.Generation != generationID || metadata.Providers == nil {
		return errors.New("generation metadata is incomplete")
	}
	routes, err := readRegular("routes.dae")
	if err != nil {
		return err
	}
	groups, err := readRegular("groups.dae")
	if err != nil {
		return err
	}
	if metadata.RoutesSHA256 != digest(routes) || metadata.GroupsSHA256 != digest(groups) {
		return errors.New("generation metadata does not match contents")
	}
	if _, err := readGenerationProviders(candidateDir, metadata); err != nil {
		return err
	}
	sections, err := config_parser.Parse("global {}\n" + string(groups) + "routing {\n" + string(routes) + "  fallback: direct\n}\n")
	if err != nil {
		return err
	}
	if _, err := config.New(sections); err != nil {
		return err
	}
	return nil
}

func readGenerationMetadata(candidateDir, generationID string) (generationMetadata, error) {
	metadataBody, err := os.ReadFile(filepath.Join(candidateDir, "metadata.json"))
	if err != nil {
		return generationMetadata{}, err
	}
	var metadata generationMetadata
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		return generationMetadata{}, err
	}
	if metadata.SchemaVersion != 2 || metadata.Generation != generationID || metadata.Providers == nil {
		return generationMetadata{}, errors.New("generation metadata is incomplete")
	}
	return metadata, nil
}

func readGenerationProviderSnapshots(candidateDir string) (map[string]ProviderSnapshot, error) {
	metadata, err := readGenerationMetadata(candidateDir, filepath.Base(candidateDir))
	if err != nil {
		return nil, err
	}
	return readGenerationProviders(candidateDir, metadata)
}

func readGenerationProviders(candidateDir string, metadata generationMetadata) (map[string]ProviderSnapshot, error) {
	providersDir := filepath.Join(candidateDir, "providers")
	info, err := os.Lstat(providersDir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("generation providers is not a controlled directory")
	}
	entries, err := os.ReadDir(providersDir)
	if err != nil {
		return nil, err
	}
	if len(entries) != len(metadata.Providers) {
		return nil, errors.New("generation provider metadata does not match entries")
	}
	snapshots := make(map[string]ProviderSnapshot, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		binding, ok := metadata.Providers[name]
		if !ok || !providerNamePattern.MatchString(name) {
			return nil, fmt.Errorf("unexpected generation provider %q", name)
		}
		providerDir := filepath.Join(providersDir, name)
		providerInfo, err := os.Lstat(providerDir)
		if err != nil || providerInfo.Mode()&os.ModeSymlink != 0 || !providerInfo.IsDir() {
			return nil, fmt.Errorf("generation provider %q is not a controlled directory", name)
		}
		readRegular := func(file string) ([]byte, error) {
			path := filepath.Join(providerDir, file)
			fileInfo, err := os.Lstat(path)
			if err != nil || !fileInfo.Mode().IsRegular() {
				return nil, fmt.Errorf("generation provider %q %s is not a regular file", name, file)
			}
			return os.ReadFile(path)
		}
		body, err := readRegular("body")
		if err != nil {
			return nil, err
		}
		metadataBody, err := readRegular("metadata.json")
		if err != nil {
			return nil, err
		}
		var providerMetadata generationProviderMetadata
		if err := json.Unmarshal(metadataBody, &providerMetadata); err != nil {
			return nil, err
		}
		if providerMetadata.SchemaVersion != 1 || providerMetadata.Name != name || providerMetadata.SHA256 != digest(body) || providerMetadata.SourceKey == "" || redactProviderURL(providerMetadata.SourceURL) != providerMetadata.SourceURL {
			return nil, fmt.Errorf("generation provider %q metadata does not match contents", name)
		}
		if binding.SHA256 != providerMetadata.SHA256 || binding.SourceKey != providerMetadata.SourceKey || binding.MetadataSHA256 != digest(metadataBody) || binding.Behavior != providerMetadata.Behavior || binding.Format != providerMetadata.Format {
			return nil, fmt.Errorf("generation provider %q binding does not match metadata", name)
		}
		snapshots[name] = ProviderSnapshot{Name: name, Body: body, ETag: providerMetadata.ETag, LastModified: providerMetadata.LastModified, SourceURL: providerMetadata.SourceURL, SourceKey: providerMetadata.SourceKey, SHA256: providerMetadata.SHA256, UpdatedAt: providerMetadata.UpdatedAt, Behavior: providerMetadata.Behavior, Format: providerMetadata.Format}
	}
	return snapshots, nil
}

func validateGenerationCandidate(candidateDir, generationID string, routes, groups []byte) error {
	readRegular := func(name string) ([]byte, error) {
		path := filepath.Join(candidateDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("stat generation %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("generation %s is not a regular file", name)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read generation %s: %w", name, err)
		}
		return body, nil
	}

	routesBody, err := readRegular("routes.dae")
	if err != nil {
		return err
	}
	if digest(routesBody) != digest(routes) {
		return fmt.Errorf("generation routes checksum mismatch")
	}
	groupsBody, err := readRegular("groups.dae")
	if err != nil {
		return err
	}
	if digest(groupsBody) != digest(groups) {
		return fmt.Errorf("generation groups checksum mismatch")
	}
	metadataBody, err := readRegular("metadata.json")
	if err != nil {
		return err
	}
	var metadata generationMetadata
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		return fmt.Errorf("decode generation metadata: %w", err)
	}
	if metadata.Generation != generationID {
		return fmt.Errorf("generation metadata id %q, want %q", metadata.Generation, generationID)
	}
	if metadata.RoutesSHA256 != digest(routesBody) {
		return fmt.Errorf("generation metadata routes checksum mismatch")
	}
	if metadata.GroupsSHA256 != digest(groupsBody) {
		return fmt.Errorf("generation metadata groups checksum mismatch")
	}
	if metadata.SchemaVersion != 2 || metadata.Providers == nil {
		return fmt.Errorf("generation metadata is incomplete")
	}
	if _, err := readGenerationProviders(candidateDir, metadata); err != nil {
		return fmt.Errorf("validate generation provider snapshots: %w", err)
	}
	sections, err := config_parser.Parse("global {}\n" + string(groupsBody) + "routing {\n" + string(routesBody) + "  fallback: direct\n}\n")
	if err != nil {
		return fmt.Errorf("parse generation DAE config: %w", err)
	}
	if _, err := config.New(sections); err != nil {
		return fmt.Errorf("validate generation DAE config: %w", err)
	}
	return nil
}

func validateTestURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid url %q", raw)
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
	return nil
}

func (r SyncReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
