package ruleprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"gopkg.in/yaml.v3"
)

const (
	defaultMaxSize = 8 << 20
	maxSize        = 64 << 20
)

// ErrProductionRuntimeDisabled keeps the unfinished native provider runtime
// out of the production configuration path until its snapshot and security
// guarantees are complete. Low-level Load calls remain available for isolated
// tests and for the later hardened implementation.
var ErrProductionRuntimeDisabled = errors.New("native rule provider runtime is disabled until security hardening is complete")

type ProviderRules struct {
	Functions []*config_parser.Function
}

type Registry map[string]ProviderRules

type LoadOptions struct {
	AllowPrivate bool
}

func Load(ctx context.Context, providers []config.RuleProvider, baseDir string, client *http.Client) (Registry, error) {
	return LoadWithOptions(ctx, providers, baseDir, client, LoadOptions{})
}

func LoadWithOptions(ctx context.Context, providers []config.RuleProvider, baseDir string, client *http.Client, options LoadOptions) (Registry, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("rule provider base directory is empty")
	}
	if client == nil {
		client = http.DefaultClient
	}
	if !options.AllowPrivate {
		if err := config.ValidateRuleProviders(providers, baseDir); err != nil {
			return nil, err
		}
	}
	registry := make(Registry, len(providers))
	for _, provider := range providers {
		body, err := loadBody(ctx, provider, baseDir, client, options)
		if err != nil {
			return nil, fmt.Errorf("rule provider %q: %w", provider.Name, err)
		}
		rules, err := parseBody(body, provider)
		if err != nil {
			return nil, fmt.Errorf("rule provider %q: %w", provider.Name, err)
		}
		registry[provider.Name] = rules
	}
	return registry, nil
}

func LoadAndExpand(ctx context.Context, conf *config.Config, baseDir string, client *http.Client) error {
	if conf == nil || len(conf.RuleProvider) == 0 {
		return nil
	}
	return ErrProductionRuntimeDisabled
}

func loadBody(ctx context.Context, provider config.RuleProvider, baseDir string, client *http.Client, options LoadOptions) ([]byte, error) {
	max := provider.MaxSize
	if max == 0 {
		max = defaultMaxSize
	}
	if max < 0 || max > maxSize {
		return nil, fmt.Errorf("max_size %d is outside bounds", max)
	}
	switch strings.ToLower(provider.Type) {
	case "file":
		return readLimitedFile(filepath.Join(baseDir, filepath.Clean(provider.Path)), max)
	case "http":
		body, err := fetchHTTP(ctx, provider.URL, max, client, options.AllowPrivate)
		cachePath := providerCachePath(provider, baseDir)
		if err == nil {
			if cachePath != "" {
				if writeErr := writeAtomic(cachePath, body); writeErr != nil {
					return nil, fmt.Errorf("write cache: %w", writeErr)
				}
			}
			return body, nil
		}
		if cachePath == "" {
			return nil, err
		}
		cached, cacheErr := readLimitedFile(cachePath, max)
		if cacheErr != nil {
			return nil, fmt.Errorf("fetch failed: %v; cache failed: %w", err, cacheErr)
		}
		return cached, nil
	default:
		return nil, fmt.Errorf("unsupported provider type %q", provider.Type)
	}
}

func providerCachePath(provider config.RuleProvider, baseDir string) string {
	if provider.Path != "" {
		return filepath.Join(baseDir, filepath.Clean(provider.Path))
	}
	return filepath.Join(baseDir, "persist.d", "rule-providers", provider.Name+".yaml")
}

func fetchHTTP(ctx context.Context, rawURL string, max int64, baseClient *http.Client, allowPrivate bool) ([]byte, error) {
	client := *baseClient
	if client.Timeout == 0 {
		client.Timeout = 45 * time.Second
	}
	if !allowPrivate {
		transport, err := safeTransport(client.Transport)
		if err != nil {
			return nil, err
		}
		client.Transport = transport
		client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return validatePublicURL(request.URL)
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned HTTP %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("provider response exceeds max_size %d", max)
	}
	return body, nil
}

func readLimitedFile(path string, max int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("provider file exceeds max_size %d", max)
	}
	return body, nil
}

func writeAtomic(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rule-provider-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(name)
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func parseBody(body []byte, provider config.RuleProvider) (ProviderRules, error) {
	items, err := providerItems(body, provider.Format)
	if err != nil {
		return ProviderRules{}, err
	}
	result := ProviderRules{}
	seen := make(map[string]struct{})
	for _, item := range items {
		function, err := parseItem(strings.TrimSpace(strings.TrimPrefix(item, "\ufeff")), strings.ToLower(provider.Behavior))
		if err != nil {
			return ProviderRules{}, err
		}
		if function == nil {
			continue
		}
		key := functionKey(function)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result.Functions = append(result.Functions, function)
	}
	return result, nil
}

func providerItems(body []byte, format string) ([]string, error) {
	if strings.EqualFold(format, "text") {
		return strings.Split(string(body), "\n"), nil
	}
	if format != "" && !strings.EqualFold(format, "yaml") {
		return nil, fmt.Errorf("unsupported provider format %q", format)
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

func parseItem(raw, behavior string) (*config_parser.Function, error) {
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, ";") {
		return nil, nil
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
	if value == "" {
		return nil, nil
	}
	switch kind {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX":
		if behavior == "ipcidr" {
			return nil, nil
		}
		key := map[string]string{"DOMAIN": "full", "DOMAIN-SUFFIX": "suffix", "DOMAIN-KEYWORD": "keyword", "DOMAIN-REGEX": "regex"}[kind]
		return &config_parser.Function{Name: "domain", Params: []*config_parser.Param{{Key: key, Val: value}}}, nil
	case "IP-CIDR", "IP-CIDR6":
		if behavior == "domain" {
			return nil, nil
		}
		prefix, err := netip.ParsePrefix(strings.SplitN(value, ",", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		return &config_parser.Function{Name: "dip", Params: []*config_parser.Param{{Val: prefix.Masked().String()}}}, nil
	default:
		if !strings.ContainsAny(raw, " ,\t\r") {
			if prefix, err := netip.ParsePrefix(raw); err == nil && behavior != "domain" {
				return &config_parser.Function{Name: "dip", Params: []*config_parser.Param{{Val: prefix.Masked().String()}}}, nil
			}
			if behavior == "domain" || behavior == "classical" {
				return &config_parser.Function{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: raw}}}, nil
			}
		}
		return nil, fmt.Errorf("unsupported provider rule %q", raw)
	}
}

func functionKey(function *config_parser.Function) string {
	if function == nil {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(function.Name)
	for _, param := range function.Params {
		builder.WriteByte(0)
		builder.WriteString(param.Key)
		builder.WriteByte(0)
		builder.WriteString(param.Val)
	}
	return builder.String()
}

func ExpandRoutingRules(rules []*config_parser.RoutingRule, registry Registry) ([]*config_parser.RoutingRule, error) {
	result := make([]*config_parser.RoutingRule, 0, len(rules))
	for _, rule := range rules {
		expanded, err := expandRule(rule, registry)
		if err != nil {
			return nil, err
		}
		result = append(result, expanded...)
	}
	return result, nil
}

func expandRule(rule *config_parser.RoutingRule, registry Registry) ([]*config_parser.RoutingRule, error) {
	current := []*config_parser.RoutingRule{cloneRule(rule)}
	for index, function := range rule.AndFunctions {
		if function.Name != "ruleset" {
			continue
		}
		if function.Not {
			return nil, fmt.Errorf("negated ruleset() is not supported")
		}
		if len(function.Params) != 1 || function.Params[0].Key != "" || function.Params[0].Val == "" {
			return nil, fmt.Errorf("ruleset() requires one provider name")
		}
		provider, ok := registry[function.Params[0].Val]
		if !ok {
			return nil, fmt.Errorf("routing rule references unknown rule provider %q", function.Params[0].Val)
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
