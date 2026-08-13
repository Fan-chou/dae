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

const maxRuleProviderSize int64 = 64 << 20

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
		providerType := strings.ToLower(strings.TrimSpace(provider.Type))
		if providerType == "" {
			providerType = "http"
		}
		providerFormat := strings.ToLower(strings.TrimSpace(provider.Format))
		if providerFormat == "" {
			providerFormat = "yaml"
		}
		switch providerType {
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
		switch strings.ToLower(strings.TrimSpace(provider.Behavior)) {
		case "domain", "ipcidr", "classical":
		default:
			return fmt.Errorf("rule provider %q has unsupported behavior %q", provider.Name, provider.Behavior)
		}
		switch providerFormat {
		case "yaml", "text":
		default:
			return fmt.Errorf("rule provider %q has unsupported format %q", provider.Name, provider.Format)
		}
		if provider.Interval < 0 {
			return fmt.Errorf("rule provider %q interval cannot be negative", provider.Name)
		}
		if provider.MaxSize < 0 || provider.MaxSize > maxRuleProviderSize {
			return fmt.Errorf("rule provider %q max_size is outside bounds", provider.Name)
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
	if err != nil || u.Opaque != "" || u.Host == "" {
		return fmt.Errorf("invalid url %q", redactRuleProviderURL(raw))
	}
	if u.User != nil {
		return fmt.Errorf("url userinfo is not allowed")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" || host == "metadata" || strings.Contains(host, "%") || numericAddressLike(host) {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil && blockedRuleProviderIP(ip) {
		return fmt.Errorf("url host %q is not allowed", host)
	}
	return nil
}

func redactRuleProviderURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[redacted-url]"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func validateRuleProviderPath(baseDir, path string) error {
	if path == "" || filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
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

func numericAddressLike(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

var blockedRuleProviderNetworks = mustRuleProviderNetworks([]string{
	"0.0.0.0/8",
	"192.0.0.0/24",
	"192.88.99.0/24", // 6to4 relay anycast addresses.
	"192.0.2.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"100.64.0.0/10",
	"100.100.100.200/32",
	"168.63.129.16/32",
	"169.254.169.254/32",
	"64:ff9b::/96",   // NAT64 IPv4-embedded well-known prefix.
	"64:ff9b:1::/48", // NAT64 local-use prefix.
	"100::/64",
	"100:0:0:1::/64", // IANA Dummy IPv6 range.
	"5f00::/16",      // IPv6 SRv6 SID range.
	"2001:0::/32",
	"2001:2::/48",
	"2001:10::/28", // ORCHIDv1.
	"2001:20::/28", // ORCHIDv2.
	"2001:db8::/32",
	"2002::/16", // 6to4.
	"3fff::/20",
	"fec0::/10", // IPv6 site-local range.
})

func mustRuleProviderNetworks(values []string) []*net.IPNet {
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

func blockedRuleProviderIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range blockedRuleProviderNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
