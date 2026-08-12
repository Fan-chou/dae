package main

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultProviderMaxSize  = 8 << 20
	defaultProviderInterval = time.Hour
	maxProviderMaxSize      = 64 << 20
	maxProviderInterval     = 30 * 24 * time.Hour
)

var providerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

type Manifest struct {
	Providers []ProviderSpec `yaml:"providers"`
	Routes    []RouteSpec    `yaml:"routes"`
}

type ProviderSpec struct {
	Name     string        `yaml:"name"`
	Type     string        `yaml:"type"`
	URL      string        `yaml:"url"`
	Path     string        `yaml:"path"`
	Data     string        `yaml:"data"`
	Behavior string        `yaml:"behavior"`
	Format   string        `yaml:"format"`
	Interval time.Duration `yaml:"-"`
	MaxSize  int64         `yaml:"-"`
}

type RouteSpec struct {
	Provider string `yaml:"provider"`
	Outbound string `yaml:"outbound"`
	Kind     string `yaml:"kind"`
}

func (p *ProviderSpec) UnmarshalYAML(node *yaml.Node) error {
	type rawProvider struct {
		Name     string    `yaml:"name"`
		Type     string    `yaml:"type"`
		URL      string    `yaml:"url"`
		Path     string    `yaml:"path"`
		Data     string    `yaml:"data"`
		Behavior string    `yaml:"behavior"`
		Format   string    `yaml:"format"`
		Interval string    `yaml:"interval"`
		MaxSize  yaml.Node `yaml:"max_size"`
	}
	var raw rawProvider
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("decode provider: %w", err)
	}
	p.Name = raw.Name
	p.Type = strings.ToLower(strings.TrimSpace(raw.Type))
	p.URL = strings.TrimSpace(raw.URL)
	p.Path = strings.TrimSpace(raw.Path)
	p.Data = raw.Data
	p.Behavior = strings.ToLower(strings.TrimSpace(raw.Behavior))
	p.Format = strings.ToLower(strings.TrimSpace(raw.Format))
	if raw.Interval != "" {
		interval, err := time.ParseDuration(raw.Interval)
		if err != nil {
			return fmt.Errorf("invalid interval %q: %w", raw.Interval, err)
		}
		p.Interval = interval
	}
	if raw.MaxSize.Kind != 0 {
		maxSize, err := parseByteSize(raw.MaxSize)
		if err != nil {
			return fmt.Errorf("invalid max_size: %w", err)
		}
		p.MaxSize = maxSize
	}
	return nil
}

func ParseManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	return manifest, nil
}

func ValidateManifest(manifest Manifest, baseDir string) error {
	return validateManifestWithURL(manifest, baseDir, validateProviderURL)
}

func validateManifestWithURL(manifest Manifest, baseDir string, validateURL func(string) error) error {
	if baseDir == "" {
		return fmt.Errorf("base directory is empty")
	}
	baseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("resolve base directory: %w", err)
	}
	seen := make(map[string]struct{}, len(manifest.Providers))
	providers := make(map[string]ProviderSpec, len(manifest.Providers))
	for i, provider := range manifest.Providers {
		if !providerNamePattern.MatchString(provider.Name) {
			return fmt.Errorf("provider %d has invalid name %q", i, provider.Name)
		}
		if _, ok := seen[provider.Name]; ok {
			return fmt.Errorf("duplicate provider %q", provider.Name)
		}
		seen[provider.Name] = struct{}{}
		providers[provider.Name] = provider

		if provider.Type == "" {
			if provider.URL != "" {
				provider.Type = "http"
			} else {
				provider.Type = "file"
			}
		}
		switch provider.Type {
		case "http", "file", "inline":
		default:
			return fmt.Errorf("provider %q has unsupported type %q", provider.Name, provider.Type)
		}
		if provider.Type == "http" {
			if err := validateURL(provider.URL); err != nil {
				return fmt.Errorf("provider %q: %w", provider.Name, err)
			}
		} else if provider.Type == "file" && provider.Path == "" {
			return fmt.Errorf("provider %q: file provider requires path", provider.Name)
		}
		if provider.Type == "inline" && provider.URL != "" {
			return fmt.Errorf("provider %q: inline provider cannot set url", provider.Name)
		}
		if provider.Type == "inline" && provider.Data == "" {
			return fmt.Errorf("provider %q: inline provider requires data", provider.Name)
		}
		if provider.Behavior == "" {
			return fmt.Errorf("provider %q: behavior is required", provider.Name)
		}
		switch provider.Behavior {
		case "domain", "ipcidr", "classical":
		default:
			return fmt.Errorf("provider %q has unsupported behavior %q", provider.Name, provider.Behavior)
		}
		if provider.Format == "" {
			provider.Format = "yaml"
		}
		switch provider.Format {
		case "yaml", "text":
		default:
			return fmt.Errorf("provider %q has unsupported format %q", provider.Name, provider.Format)
		}
		if provider.Interval < 0 {
			return fmt.Errorf("provider %q has negative interval", provider.Name)
		}
		if provider.Interval > maxProviderInterval {
			return fmt.Errorf("provider %q interval exceeds %s", provider.Name, maxProviderInterval)
		}
		if provider.MaxSize < 0 {
			return fmt.Errorf("provider %q has negative max_size", provider.Name)
		}
		if provider.MaxSize > maxProviderMaxSize {
			return fmt.Errorf("provider %q max_size exceeds %d bytes", provider.Name, maxProviderMaxSize)
		}
		if provider.Path != "" {
			if err := validateRelativePath(baseDir, provider.Path); err != nil {
				return fmt.Errorf("provider %q: %w", provider.Name, err)
			}
		}
	}
	for i, route := range manifest.Routes {
		if _, ok := providers[route.Provider]; !ok {
			return fmt.Errorf("route %d references unknown provider %q", i, route.Provider)
		}
		if route.Outbound == "" {
			return fmt.Errorf("route %d has empty outbound", i)
		}
		if err := validateRouteOutbound(route.Outbound); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
		kind := strings.ToLower(route.Kind)
		providerBehavior := providers[route.Provider].Behavior
		if kind == "" {
			if providerBehavior == "classical" {
				return fmt.Errorf("route %d for classical provider %q requires explicit kind", i, route.Provider)
			}
			kind = providerBehavior
		}
		if kind != "domain" && kind != "ipcidr" {
			return fmt.Errorf("route %d has unsupported route kind %q", i, route.Kind)
		}
		if providerBehavior != "classical" && providerBehavior != kind {
			return fmt.Errorf("route %d kind %q does not match provider %q behavior %q", i, kind, route.Provider, providerBehavior)
		}
	}
	return nil
}

func validateProviderURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid url %q", raw)
	}
	if u.User != nil {
		return fmt.Errorf("url userinfo is not allowed")
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "http":
	default:
		return fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	if numericAddressLike(host) {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()) {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	if strings.Contains(host, "%") {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	return nil
}

func numericAddressLike(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validateRelativePath(baseDir, path string) error {
	if filepath.IsAbs(path) {
		return fmt.Errorf("path must be relative")
	}
	clean := filepath.Clean(path)
	joined, err := filepath.Abs(filepath.Join(baseDir, clean))
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	rel, err := filepath.Rel(baseDir, joined)
	if err != nil {
		return fmt.Errorf("compare path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q escapes base directory", path)
	}
	return nil
}

func parseByteSize(node yaml.Node) (int64, error) {
	value := strings.TrimSpace(node.Value)
	if value == "" {
		return 0, fmt.Errorf("empty size")
	}
	if number, err := strconv.ParseInt(value, 10, 64); err == nil {
		return number, nil
	}
	upper := strings.ToUpper(strings.ReplaceAll(value, " ", ""))
	units := []struct {
		suffix string
		factor int64
	}{
		{"GIB", 1 << 30}, {"GB", 1 << 30},
		{"MIB", 1 << 20}, {"MB", 1 << 20},
		{"KIB", 1 << 10}, {"KB", 1 << 10},
		{"B", 1},
	}
	for _, unit := range units {
		if !strings.HasSuffix(upper, unit.suffix) {
			continue
		}
		number := strings.TrimSuffix(upper, unit.suffix)
		parsed, err := strconv.ParseInt(number, 10, 64)
		if err != nil || parsed < 0 {
			break
		}
		if parsed > (1<<63-1)/unit.factor {
			return 0, fmt.Errorf("size %q overflows int64", value)
		}
		return parsed * unit.factor, nil
	}
	return 0, fmt.Errorf("invalid size %q", value)
}

func (p ProviderSpec) EffectiveInterval() time.Duration {
	if p.Interval <= 0 {
		return defaultProviderInterval
	}
	return p.Interval
}

func (p ProviderSpec) EffectiveMaxSize() int64 {
	if p.MaxSize <= 0 {
		return defaultProviderMaxSize
	}
	return p.MaxSize
}
