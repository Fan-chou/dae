package config

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type RuleProvider struct {
	Name     string        `mapstructure:"_"`
	Type     string        `mapstructure:"type" default:"http"`
	URL      string        `mapstructure:"url"`
	Path     string        `mapstructure:"path"`
	Behavior string        `mapstructure:"behavior" required:""`
	Format   string        `mapstructure:"format" default:"yaml"`
	Interval time.Duration `mapstructure:"interval" default:"1h"`
	MaxSize  int64         `mapstructure:"max_size" default:"8388608"`
}

var ruleProviderNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

func ValidateRuleProviders(providers []RuleProvider, baseDir string) error {
	if baseDir == "" {
		return fmt.Errorf("rule provider base directory is empty")
	}
	baseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("resolve rule provider base directory: %w", err)
	}
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if !ruleProviderNamePattern.MatchString(provider.Name) {
			return fmt.Errorf("rule provider has invalid name %q", provider.Name)
		}
		if _, ok := seen[provider.Name]; ok {
			return fmt.Errorf("duplicate rule provider %q", provider.Name)
		}
		seen[provider.Name] = struct{}{}
		switch strings.ToLower(provider.Type) {
		case "http":
			if err := validateRuleProviderURL(provider.URL); err != nil {
				return fmt.Errorf("rule provider %q: %w", provider.Name, err)
			}
		case "file":
			if provider.Path == "" {
				return fmt.Errorf("rule provider %q: file provider requires path", provider.Name)
			}
		default:
			return fmt.Errorf("rule provider %q has unsupported type %q", provider.Name, provider.Type)
		}
		switch strings.ToLower(provider.Behavior) {
		case "domain", "ipcidr", "classical":
		default:
			return fmt.Errorf("rule provider %q has unsupported behavior %q", provider.Name, provider.Behavior)
		}
		switch strings.ToLower(provider.Format) {
		case "yaml", "text":
		default:
			return fmt.Errorf("rule provider %q has unsupported format %q", provider.Name, provider.Format)
		}
		if provider.Interval < 0 {
			return fmt.Errorf("rule provider %q interval cannot be negative", provider.Name)
		}
		if provider.MaxSize < 0 {
			return fmt.Errorf("rule provider %q max_size cannot be negative", provider.Name)
		}
		if provider.Path != "" {
			if err := validateRuleProviderPath(baseDir, provider.Path); err != nil {
				return fmt.Errorf("rule provider %q: %w", provider.Name, err)
			}
		}
	}
	return nil
}

func validateRuleProviderURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid url %q", raw)
	}
	if u.User != nil {
		return fmt.Errorf("url userinfo is not allowed")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()) {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	return nil
}

func validateRuleProviderPath(baseDir, path string) error {
	if filepath.IsAbs(path) {
		return fmt.Errorf("path must be relative")
	}
	resolved, err := filepath.Abs(filepath.Join(baseDir, filepath.Clean(path)))
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	rel, err := filepath.Rel(baseDir, resolved)
	if err != nil {
		return fmt.Errorf("compare path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q escapes base directory", path)
	}
	return nil
}
