package main

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// MihomoProviderNormalization is the ordered, source-oriented representation
// of Mihomo rule-provider declarations. Routes and DAT bindings are
// intentionally not part of this result: a provider declaration only
// describes where and how rules are obtained.
type MihomoProviderNormalization struct {
	Providers      []ProviderSpec
	NameMap        map[string]string
	ReverseNameMap map[string]string
	SourceIndex    map[string]int
}

const maxMihomoProviderNameLength = 64

// NormalizeMihomoRuleProviders converts Mihomo rule-provider declarations to
// the existing ProviderSpec model while preserving declaration order and
// source indexes. baseDir is used for the same relative-path boundary that
// applies to manifest providers.
func NormalizeMihomoRuleProviders(document MihomoRoutingDocument, baseDir string) (MihomoProviderNormalization, error) {
	if strings.TrimSpace(baseDir) == "" {
		return MihomoProviderNormalization{}, fmt.Errorf("provider base directory is empty")
	}

	ordered, err := orderedMihomoRuleProviders(document)
	if err != nil {
		return MihomoProviderNormalization{}, err
	}

	result := MihomoProviderNormalization{
		Providers:      make([]ProviderSpec, 0, len(ordered)),
		NameMap:        make(map[string]string, len(ordered)),
		ReverseNameMap: make(map[string]string, len(ordered)),
		SourceIndex:    make(map[string]int, len(ordered)),
	}
	for _, provider := range ordered {
		if err := validateMihomoProviderName(provider.Name); err != nil {
			return MihomoProviderNormalization{}, fmt.Errorf("rule-provider: %w", err)
		}
		if _, exists := result.NameMap[provider.Name]; exists {
			return MihomoProviderNormalization{}, fmt.Errorf("duplicate rule-provider %q", provider.Name)
		}

		safeName := safeMihomoProviderName(provider.Name)
		if previous, exists := result.ReverseNameMap[safeName]; exists && previous != provider.Name {
			return MihomoProviderNormalization{}, fmt.Errorf(
				"rule-providers %q and %q map to the same safe provider name %q",
				previous, provider.Name, safeName,
			)
		}

		spec, err := normalizeMihomoRuleProvider(provider, safeName, baseDir)
		if err != nil {
			return MihomoProviderNormalization{}, err
		}
		result.Providers = append(result.Providers, spec)
		result.NameMap[provider.Name] = safeName
		result.ReverseNameMap[safeName] = provider.Name
		result.SourceIndex[provider.Name] = provider.SourceIndex
	}
	return result, nil
}

func orderedMihomoRuleProviders(document MihomoRoutingDocument) ([]MihomoRuleProvider, error) {
	if len(document.ProviderValues) > 0 {
		if len(document.ProviderOrder) > 0 && len(document.ProviderOrder) != len(document.ProviderValues) {
			return nil, fmt.Errorf("rule-provider order and values have different lengths")
		}
		ordered := append([]MihomoRuleProvider(nil), document.ProviderValues...)
		if len(document.ProviderOrder) > 0 {
			for index, name := range document.ProviderOrder {
				if ordered[index].Name != name {
					return nil, fmt.Errorf("rule-provider order entry %q does not match declaration %q", name, ordered[index].Name)
				}
			}
		}
		return ordered, nil
	}

	if len(document.ProviderOrder) > 0 {
		ordered := make([]MihomoRuleProvider, 0, len(document.ProviderOrder))
		seen := make(map[string]struct{}, len(document.ProviderOrder))
		for _, name := range document.ProviderOrder {
			if _, exists := seen[name]; exists {
				return nil, fmt.Errorf("duplicate rule-provider %q", name)
			}
			seen[name] = struct{}{}
			provider, exists := document.Providers[name]
			if !exists {
				return nil, fmt.Errorf("rule-provider order references missing provider %q", name)
			}
			ordered = append(ordered, provider)
		}
		if len(document.Providers) != len(ordered) {
			return nil, fmt.Errorf("rule-provider map contains declarations missing from order")
		}
		return ordered, nil
	}

	if len(document.Providers) == 0 {
		return nil, nil
	}
	// A manually assembled document may not have the parser's ordered views.
	// Sort this fallback so the API remains deterministic, while parsed
	// documents always retain their source order above.
	names := make([]string, 0, len(document.Providers))
	for name := range document.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([]MihomoRuleProvider, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, document.Providers[name])
	}
	return ordered, nil
}

func validateMihomoProviderName(name string) error {
	if name == "" || strings.TrimSpace(name) == "" {
		return fmt.Errorf("provider name is empty")
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("provider %q has invalid UTF-8 name", name)
	}
	return nil
}

func safeMihomoProviderName(name string) string {
	if len(name) <= maxMihomoProviderNameLength && providerNamePattern.MatchString(name) {
		return name
	}
	digest := sha256.Sum256([]byte(name))
	return fmt.Sprintf("mihomo_%x", digest[:6])
}

func normalizeMihomoRuleProvider(provider MihomoRuleProvider, safeName, baseDir string) (ProviderSpec, error) {
	providerType := strings.ToLower(strings.TrimSpace(provider.Type))
	urlValue := strings.TrimSpace(provider.URL)
	pathValue := strings.TrimSpace(provider.Path)
	if providerType == "" {
		if urlValue != "" {
			providerType = "http"
		} else {
			providerType = "file"
		}
	}
	switch providerType {
	case "http":
		if err := validateProviderURL(urlValue); err != nil {
			return ProviderSpec{}, fmt.Errorf("rule-provider %q: %w", provider.Name, redactProviderError(err))
		}
	case "file":
		if pathValue == "" {
			return ProviderSpec{}, fmt.Errorf("rule-provider %q: file provider requires path", provider.Name)
		}
		if urlValue != "" {
			return ProviderSpec{}, fmt.Errorf("rule-provider %q: file provider cannot set url", provider.Name)
		}
	default:
		return ProviderSpec{}, fmt.Errorf("rule-provider %q has unsupported type %q", provider.Name, provider.Type)
	}
	if pathValue != "" {
		if err := validateRelativePath(baseDir, pathValue); err != nil {
			return ProviderSpec{}, fmt.Errorf("rule-provider %q: %w", provider.Name, err)
		}
	}

	behavior := strings.ToLower(strings.TrimSpace(provider.Behavior))
	switch behavior {
	case "domain", "ipcidr", "classical":
	default:
		if behavior == "" {
			return ProviderSpec{}, fmt.Errorf("rule-provider %q: behavior is required", provider.Name)
		}
		return ProviderSpec{}, fmt.Errorf("rule-provider %q has unsupported behavior %q", provider.Name, provider.Behavior)
	}

	format := strings.ToLower(strings.TrimSpace(provider.Format))
	if format == "" {
		format = "yaml"
	}
	switch format {
	case "yaml", "text":
	default:
		return ProviderSpec{}, fmt.Errorf("rule-provider %q has unsupported format %q", provider.Name, provider.Format)
	}
	if provider.Interval < 0 {
		return ProviderSpec{}, fmt.Errorf("rule-provider %q has negative interval", provider.Name)
	}
	if provider.Interval > maxProviderInterval {
		return ProviderSpec{}, fmt.Errorf("rule-provider %q interval exceeds %s", provider.Name, maxProviderInterval)
	}

	return ProviderSpec{
		Name:     safeName,
		Type:     providerType,
		URL:      urlValue,
		Path:     pathValue,
		Behavior: behavior,
		Format:   format,
		Interval: provider.Interval,
	}, nil
}
