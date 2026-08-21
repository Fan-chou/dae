/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	FakeIPMatchDomainRule    = "domain-rule"
	FakeIPFilterModeSkip     = "skip"
	FakeIPFilterModeOnly     = "only"
	FakeIPDefaultInet4Range  = "198.18.0.0/15"
	FakeIPDefaultInet6Range  = "fd00:daee::/96"
	FakeIPDefaultTTL         = 60
	FakeIPDefaultMaxEntries  = 32768
	FakeIPHardMaxEntries     = 32768
	FakeIPDefaultPath        = "persist.d/fakeip/"
	FakeIPRequiredPathPrefix = "persist.d/fakeip"
	FakeIPMinTTL             = 30
	FakeIPMaxTTL             = 60
)

// FakeIP is dns.fakeip: selective FakeIP for names that traffic routing can
// already prove will take a proxy group. Default is off.
type FakeIP struct {
	Enable        bool                      `mapstructure:"enable" default:"false"`
	Inet4Range    string                    `mapstructure:"inet4_range" default:"198.18.0.0/15"`
	Inet6Range    string                    `mapstructure:"inet6_range" default:"fd00:daee::/96"`
	Match         string                    `mapstructure:"match" default:"domain-rule"`
	Ttl           int                       `mapstructure:"ttl" default:"60"`
	MaxEntries    int                       `mapstructure:"max_entries" default:"32768"`
	Path          string                    `mapstructure:"path" default:"persist.d/fakeip/"`
	FilterMode    string                    `mapstructure:"filter_mode" default:"skip"`
	FilterBuiltin bool                      `mapstructure:"filter_builtin" default:"true"`
	Filter        []*config_parser.Function `mapstructure:"_"`
}

func (f FakeIP) Inet4Prefix() (netip.Prefix, error) {
	return parseFakeIPPrefix(f.Inet4Range, true)
}

func (f FakeIP) Inet6Prefix() (netip.Prefix, error) {
	return parseFakeIPPrefix(f.Inet6Range, false)
}

func (f FakeIP) Validate() error {
	if f.Match != "" && f.Match != FakeIPMatchDomainRule {
		return fmt.Errorf("dns.fakeip.match: only %q is supported", FakeIPMatchDomainRule)
	}
	switch f.FilterMode {
	case "", FakeIPFilterModeSkip, FakeIPFilterModeOnly:
	default:
		return fmt.Errorf("dns.fakeip.filter_mode: unknown %q", f.FilterMode)
	}
	if f.Ttl == 1 {
		return fmt.Errorf("dns.fakeip.ttl: TTL=1 is not allowed")
	}
	if f.Ttl < 0 {
		return fmt.Errorf("dns.fakeip.ttl: must be >= 0")
	}
	if f.Ttl != 0 && (f.Ttl < FakeIPMinTTL || f.Ttl > FakeIPMaxTTL) {
		return fmt.Errorf("dns.fakeip.ttl: want %d-%d, got %d", FakeIPMinTTL, FakeIPMaxTTL, f.Ttl)
	}
	if f.MaxEntries < 0 {
		return fmt.Errorf("dns.fakeip.max_entries: must be >= 0")
	}
	if f.MaxEntries > FakeIPHardMaxEntries {
		return fmt.Errorf("dns.fakeip.max_entries: hard cap is %d", FakeIPHardMaxEntries)
	}
	if _, err := f.Inet4Prefix(); err != nil {
		return fmt.Errorf("dns.fakeip.inet4_range: %w", err)
	}
	if _, err := f.Inet6Prefix(); err != nil {
		return fmt.Errorf("dns.fakeip.inet6_range: %w", err)
	}
	if err := ValidateFakeIPPath(f.Path); err != nil {
		return err
	}
	for _, fn := range f.Filter {
		if fn == nil {
			return fmt.Errorf("dns.fakeip.filter: nil function")
		}
		if fn.Name != consts.Function_QName {
			return fmt.Errorf("dns.fakeip.filter: only qname() is allowed, got %q", fn.Name)
		}
	}
	return nil
}

func (f FakeIP) ResolvedTTL() int {
	if f.Ttl == 0 {
		return FakeIPDefaultTTL
	}
	return f.Ttl
}

func (f FakeIP) ResolvedMaxEntries() int {
	if f.MaxEntries == 0 {
		return FakeIPDefaultMaxEntries
	}
	return f.MaxEntries
}

func (f FakeIP) ResolvedFilterMode() string {
	if f.FilterMode == "" {
		return FakeIPFilterModeSkip
	}
	return f.FilterMode
}

func ValidateFakeIPPath(path string) error {
	if path == "" {
		return nil
	}
	cleaned := filepath.ToSlash(filepath.Clean(path))
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("dns.fakeip.path: must not contain ..")
	}
	if filepath.IsAbs(path) {
		if !strings.Contains(cleaned, FakeIPRequiredPathPrefix) {
			return fmt.Errorf("dns.fakeip.path: must stay under %s/", FakeIPRequiredPathPrefix)
		}
		return nil
	}
	if cleaned != FakeIPRequiredPathPrefix && !strings.HasPrefix(cleaned, FakeIPRequiredPathPrefix+"/") {
		return fmt.Errorf("dns.fakeip.path: must stay under %s/", FakeIPRequiredPathPrefix)
	}
	return nil
}

func parseFakeIPPrefix(raw string, ipv4 bool) (netip.Prefix, error) {
	if raw == "" {
		if ipv4 {
			raw = FakeIPDefaultInet4Range
		} else {
			raw = FakeIPDefaultInet6Range
		}
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix = prefix.Masked()
	if ipv4 {
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("want IPv4 prefix, got %s", prefix)
		}
		if prefix.Bits() < 8 {
			return netip.Prefix{}, fmt.Errorf("IPv4 prefix %s is too wide", prefix)
		}
		return prefix, nil
	}
	if !prefix.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("want IPv6 prefix, got %s", prefix)
	}
	// Allocation pool, not a declaration ULA. /48 is forbidden as a linear pool.
	if prefix.Bits() < 96 {
		return netip.Prefix{}, fmt.Errorf("IPv6 allocation pool %s is too wide (use /96 or /112)", prefix)
	}
	return prefix, nil
}

func parseFakeIPSection(section *config_parser.Section) (FakeIP, error) {
	var rest []*config_parser.Item
	var filter []*config_parser.Function
	for _, item := range section.Items {
		switch val := item.Value.(type) {
		case *config_parser.Section:
			if val.Name != "filter" {
				return FakeIP{}, fmt.Errorf("unexpected key: %v", val.Name)
			}
			fns, err := parseFakeIPFilterItems(val.Items)
			if err != nil {
				return FakeIP{}, err
			}
			filter = append(filter, fns...)
		case *config_parser.Param:
			if val.Key == "filter" {
				if val.AndFunctions == nil {
					return FakeIP{}, fmt.Errorf("dns.fakeip.filter is not a KeyableString")
				}
				filter = append(filter, val.AndFunctions...)
				continue
			}
			rest = append(rest, item)
		case *config_parser.RoutingRule:
			return FakeIP{}, fmt.Errorf("cannot use routing rule in dns.fakeip: %v", val.String(true, false, false))
		default:
			return FakeIP{}, fmt.Errorf("unexpected type in dns.fakeip: %v", item.Type)
		}
	}
	fake := FakeIP{}
	if err := ParamParser(reflect.ValueOf(&fake), &config_parser.Section{Name: "fakeip", Items: rest}, nil); err != nil {
		return FakeIP{}, err
	}
	fake.Filter = filter
	if err := fake.Validate(); err != nil {
		return FakeIP{}, err
	}
	return fake, nil
}

func parseFakeIPFilterItems(items []*config_parser.Item) ([]*config_parser.Function, error) {
	var filter []*config_parser.Function
	for _, item := range items {
		switch val := item.Value.(type) {
		case *config_parser.RoutingRule:
			// Current dae-config grammar requires `qname(...) -> skip`.
			// Outbound is ignored; only qname() functions are kept.
			if len(val.AndFunctions) == 0 {
				return nil, fmt.Errorf("dns.fakeip.filter: empty rule")
			}
			filter = append(filter, val.AndFunctions...)
		case *config_parser.Param:
			if val.AndFunctions == nil {
				return nil, fmt.Errorf("dns.fakeip.filter: unsupported %v", val.String(true, false))
			}
			filter = append(filter, val.AndFunctions...)
		default:
			return nil, fmt.Errorf("dns.fakeip.filter: unsupported item %v", item.Type)
		}
	}
	return filter, nil
}
