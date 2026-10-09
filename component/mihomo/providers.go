/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/config"
)

const (
	maxProviderNameLength = 64
	// MaxProviderInterval bounds a rule-provider refresh interval.
	MaxProviderInterval = 30 * 24 * time.Hour
)

var providerIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// ProviderTable is the set of rule-providers a document declares, with the
// internal name each one is known by. Fetching, caching, last-good handling
// and refreshing are done by component/ruleprovider; the converter only names
// providers and hands the used ones over as config.RuleProvider.
type ProviderTable struct {
	declared []Provider
	safe     map[string]string // original -> internal name
}

// NewProviderTable validates every declared provider, used or not, and assigns
// internal names. Internal names double as cache directory names, so they stay
// the original name whenever that is already a valid identifier. baseDir is the
// configuration directory file providers are resolved against.
func NewProviderTable(declared []Provider, baseDir string) (*ProviderTable, error) {
	originals := make([]string, len(declared))
	lowered := make([]config.RuleProvider, len(declared))
	for i, p := range declared {
		switch {
		case strings.TrimSpace(p.Name) == "":
			return nil, fmt.Errorf("rule-provider: provider name is empty")
		case !utf8.ValidString(p.Name):
			return nil, fmt.Errorf("rule-provider: provider name is not valid UTF-8")
		}
		originals[i] = p.Name
		rp, err := lowerProvider(p, p.Name)
		if err != nil {
			return nil, err
		}
		lowered[i] = rp
	}
	names, err := assignSafeNames(originals, safeProviderName, providerIdentifier, maxProviderNameLength, nil)
	if err != nil {
		return nil, err
	}
	// URL and path checks (private and metadata addresses, userinfo, schemes,
	// escaping paths) are the ones the native rule providers enforce.
	for i := range lowered {
		lowered[i].Name = names[i]
	}
	if err := config.ValidateRuleProviders(lowered, baseDir); err != nil {
		return nil, err
	}
	t := &ProviderTable{declared: declared, safe: make(map[string]string, len(declared))}
	for i, p := range declared {
		t.safe[p.Name] = names[i]
	}
	return t, nil
}

// Names maps each declared provider's original name to its internal name.
func (t *ProviderTable) Names() map[string]string {
	out := make(map[string]string, len(t.safe))
	for k, v := range t.safe {
		out[k] = v
	}
	return out
}

// Select returns the providers named in used (original names), in declaration
// order, as config.RuleProvider values ready for component/ruleprovider. Names
// that are not declared are an error. Providers nobody uses are not returned:
// they are never fetched.
func (t *ProviderTable) Select(used []string) ([]config.RuleProvider, error) {
	want := make(map[string]struct{}, len(used))
	for _, name := range used {
		if _, ok := t.safe[name]; !ok {
			return nil, fmt.Errorf("RULE-SET provider %q is undeclared", name)
		}
		want[name] = struct{}{}
	}
	var out []config.RuleProvider
	for _, p := range t.declared {
		if _, ok := want[p.Name]; !ok {
			continue
		}
		rp, err := lowerProvider(p, t.safe[p.Name])
		if err != nil {
			return nil, err
		}
		out = append(out, rp)
	}
	return out, nil
}

func safeProviderName(name string) string {
	if len(name) <= maxProviderNameLength && providerIdentifier.MatchString(name) {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("mihomo_%x", sum[:6])
}

// lowerProvider checks one declaration and converts it. Errors name the
// provider but never carry its URL, which may hold an access token.
func lowerProvider(p Provider, internal string) (config.RuleProvider, error) {
	typ := strings.ToLower(strings.TrimSpace(p.Type))
	url := strings.TrimSpace(p.URL)
	path := strings.TrimSpace(p.Path)
	if typ == "" {
		if url != "" {
			typ = "http"
		} else {
			typ = "file"
		}
	}
	switch typ {
	case "http":
		if url == "" {
			return config.RuleProvider{}, fmt.Errorf("rule-provider %q: http provider requires url", p.Name)
		}
	case "file":
		if path == "" {
			return config.RuleProvider{}, fmt.Errorf("rule-provider %q: file provider requires path", p.Name)
		}
		if url != "" {
			return config.RuleProvider{}, fmt.Errorf("rule-provider %q: file provider cannot set url", p.Name)
		}
	default:
		return config.RuleProvider{}, fmt.Errorf("rule-provider %q has unsupported type %q", p.Name, p.Type)
	}

	behavior := strings.ToLower(strings.TrimSpace(p.Behavior))
	switch behavior {
	case "domain", "ipcidr", "classical":
	case "":
		return config.RuleProvider{}, fmt.Errorf("rule-provider %q: behavior is required", p.Name)
	default:
		return config.RuleProvider{}, fmt.Errorf("rule-provider %q has unsupported behavior %q", p.Name, p.Behavior)
	}

	format := strings.ToLower(strings.TrimSpace(p.Format))
	if format == "" {
		format = "yaml"
	}
	switch format {
	case "yaml", "text":
	default:
		return config.RuleProvider{}, fmt.Errorf("rule-provider %q has unsupported format %q", p.Name, p.Format)
	}

	switch {
	case p.Interval < 0:
		return config.RuleProvider{}, fmt.Errorf("rule-provider %q has negative interval", p.Name)
	case p.Interval > MaxProviderInterval:
		return config.RuleProvider{}, fmt.Errorf("rule-provider %q interval exceeds %s", p.Name, MaxProviderInterval)
	}

	return config.RuleProvider{
		Name:     internal,
		Type:     typ,
		URL:      url,
		Path:     path,
		Behavior: behavior,
		Format:   format,
		Interval: p.Interval,
	}, nil
}
