package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type SyncOptions struct {
	ManifestPath    string
	CacheDir        string
	RoutesOutput    string
	GroupsInputPath string
	GroupsOutput    string
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
	if options.ManifestPath == "" {
		return SyncReport{}, fmt.Errorf("manifest path is required")
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
	if options.CacheDir == "" {
		options.CacheDir = filepath.Join(baseDir, "persist.d", "rule-providers")
	}
	fetcher := NewProviderFetcher(options.Client, options.CacheDir)
	if options.AllowPrivate {
		fetcher.ValidateURL = validateTestURL
	}

	sets := make(map[string]ParsedRuleSet, len(manifest.Providers))
	report := SyncReport{Providers: make([]ProviderSyncReport, 0, len(manifest.Providers))}
	for _, spec := range manifest.Providers {
		snapshot, fetchResult, err := loadProvider(ctx, fetcher, spec, baseDir)
		if err != nil {
			return SyncReport{}, fmt.Errorf("provider %q: %w", spec.Name, err)
		}
		parsed, err := ParseProvider(snapshot.Body, spec)
		if err != nil {
			return SyncReport{}, fmt.Errorf("provider %q: %w", spec.Name, err)
		}
		sets[spec.Name] = parsed
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
	if options.RoutesOutput != "" {
		if err := writeAtomic(options.RoutesOutput, []byte(routes)); err != nil {
			return SyncReport{}, fmt.Errorf("write routes: %w", err)
		}
	}

	if options.GroupsInputPath != "" {
		groupsBody, err := os.ReadFile(options.GroupsInputPath)
		if err != nil {
			return SyncReport{}, fmt.Errorf("read mihomo groups input: %w", err)
		}
		mihomoConfig, err := ParseMihomoConfig(groupsBody)
		if err != nil {
			return SyncReport{}, err
		}
		groups, groupReport, err := GenerateFlatDaeGroups(mihomoConfig)
		if err != nil {
			return SyncReport{}, err
		}
		report.Groups = groupReport
		if options.GroupsOutput == "" {
			return SyncReport{}, fmt.Errorf("groups output is required when groups input is set")
		}
		if err := writeAtomic(options.GroupsOutput, []byte(groups)); err != nil {
			return SyncReport{}, fmt.Errorf("write groups: %w", err)
		}
	}
	return report, nil
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
		if err := validateRelativePath(baseDir, spec.Path); err != nil {
			return ProviderSnapshot{}, FetchResult{}, err
		}
		body, err := readLimited(filepath.Join(baseDir, filepath.Clean(spec.Path)), spec.EffectiveMaxSize())
		if err != nil {
			return ProviderSnapshot{}, FetchResult{}, err
		}
		snapshot := snapshotFromBody(spec.Name, body, time.Now().UTC())
		return snapshot, FetchResult{Snapshot: snapshot, Updated: true}, nil
	case "inline":
		snapshot := snapshotFromBody(spec.Name, []byte(spec.Data), time.Now().UTC())
		return snapshot, FetchResult{Snapshot: snapshot, Updated: true}, nil
	default:
		return ProviderSnapshot{}, FetchResult{}, fmt.Errorf("unsupported provider type %q", typeName)
	}
}

func readLimited(path string, maxSize int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxSize {
		return nil, fmt.Errorf("file exceeds max_size %d", maxSize)
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

func writeAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".dae-rule-sync-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	keep = true
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
