package main

import (
	"fmt"
	"net/netip"
	"strings"

	"gopkg.in/yaml.v3"
)

type DomainKind string

const (
	DomainFull    DomainKind = "full"
	DomainSuffix  DomainKind = "suffix"
	DomainKeyword DomainKind = "keyword"
	DomainRegex   DomainKind = "regex"
)

type DomainRule struct {
	Kind  DomainKind
	Value string
}

type UnsupportedRule struct {
	Raw    string
	Reason string
}

type ParsedRuleSet struct {
	Domains     []DomainRule
	Prefixes    []netip.Prefix
	Unsupported []UnsupportedRule
}

type ConversionReport struct {
	Generated   int
	Skipped     int
	Unsupported []UnsupportedRule
}

func ParseProvider(data []byte, spec ProviderSpec) (ParsedRuleSet, error) {
	items, err := providerItems(data, spec.Format)
	if err != nil {
		return ParsedRuleSet{}, err
	}
	behavior := strings.ToLower(spec.Behavior)
	if behavior != "domain" && behavior != "ipcidr" && behavior != "classical" {
		return ParsedRuleSet{}, fmt.Errorf("unsupported provider behavior %q", spec.Behavior)
	}
	result := ParsedRuleSet{}
	seenDomains := make(map[DomainRule]struct{})
	seenPrefixes := make(map[netip.Prefix]struct{})
	for _, item := range items {
		item = strings.TrimSpace(strings.TrimPrefix(item, "\ufeff"))
		if item == "" || strings.HasPrefix(item, "#") || strings.HasPrefix(item, ";") {
			continue
		}
		kind, value, prefix, unsupported, parseErr := parseProviderItem(item, behavior)
		if parseErr != nil {
			return ParsedRuleSet{}, parseErr
		}
		if unsupported != nil {
			result.Unsupported = append(result.Unsupported, *unsupported)
			continue
		}
		if prefix.IsValid() {
			prefix = prefix.Masked()
			if _, ok := seenPrefixes[prefix]; !ok {
				seenPrefixes[prefix] = struct{}{}
				result.Prefixes = append(result.Prefixes, prefix)
			}
			continue
		}
		rule := DomainRule{Kind: kind, Value: value}
		if _, ok := seenDomains[rule]; ok {
			continue
		}
		seenDomains[rule] = struct{}{}
		result.Domains = append(result.Domains, rule)
	}
	return result, nil
}

func providerItems(data []byte, format string) ([]string, error) {
	if strings.ToLower(format) == "text" {
		return strings.Split(string(data), "\n"), nil
	}
	if format == "" || strings.ToLower(format) == "yaml" {
		var envelope struct {
			Payload []string `yaml:"payload"`
		}
		if err := yaml.Unmarshal(data, &envelope); err == nil && envelope.Payload != nil {
			return envelope.Payload, nil
		}
		var list []string
		if err := yaml.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("parse yaml provider: %w", err)
		}
		return list, nil
	}
	return nil, fmt.Errorf("unsupported provider format %q", format)
}

func parseProviderItem(raw, behavior string) (DomainKind, string, netip.Prefix, *UnsupportedRule, error) {
	if strings.HasPrefix(raw, "+.") {
		value := strings.TrimSpace(strings.TrimPrefix(raw, "+."))
		if value == "" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "empty suffix"}, nil
		}
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		return DomainSuffix, value, netip.Prefix{}, nil, nil
	}
	parts := strings.SplitN(raw, ",", 2)
	kind := strings.ToUpper(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(raw)
	if len(parts) == 2 {
		value = strings.TrimSpace(parts[1])
	}
	if kind == "" || value == "" {
		return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "empty rule"}, nil
	}

	switch kind {
	case "DOMAIN":
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		return DomainFull, value, netip.Prefix{}, nil, nil
	case "DOMAIN-SUFFIX":
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		return DomainSuffix, value, netip.Prefix{}, nil, nil
	case "DOMAIN-KEYWORD":
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		return DomainKeyword, value, netip.Prefix{}, nil, nil
	case "DOMAIN-REGEX":
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		return DomainRegex, value, netip.Prefix{}, nil, nil
	case "IP-CIDR", "IP-CIDR6":
		if behavior == "domain" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "ip entry in domain provider"}, nil
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(strings.SplitN(value, ",", 2)[0]))
		if err != nil {
			return "", "", netip.Prefix{}, nil, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		return "", "", prefix, nil, nil
	case "DOMAIN-WILDCARD", "GEOSITE", "GEOIP", "IP-ASN", "PROCESS-NAME", "DST-PORT", "SRC-IP-CIDR", "NETWORK", "AND", "OR", "NOT":
		return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: fmt.Sprintf("unsupported classical rule %s", kind)}, nil
	}

	if !strings.ContainsAny(raw, " ,\t\r") {
		if behavior == "ipcidr" {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil {
				return "", "", prefix, nil, nil
			}
			return "", "", netip.Prefix{}, nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		return DomainSuffix, raw, netip.Prefix{}, nil, nil
	}
	return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: fmt.Sprintf("unsupported rule type %s", kind)}, nil
}

func GenerateDaeRoutes(manifest Manifest, sets map[string]ParsedRuleSet, strict bool) (string, ConversionReport, error) {
	var output strings.Builder
	var report ConversionReport
	for _, route := range manifest.Routes {
		set, ok := sets[route.Provider]
		if !ok {
			return "", report, fmt.Errorf("route references missing provider %q", route.Provider)
		}
		if len(set.Unsupported) > 0 {
			if strict {
				return "", report, fmt.Errorf("provider %q contains %d unsupported rules", route.Provider, len(set.Unsupported))
			}
			report.Unsupported = append(report.Unsupported, set.Unsupported...)
			report.Skipped += len(set.Unsupported)
		}
		kind := strings.ToLower(route.Kind)
		if kind == "" {
			kind = "domain"
		}
		switch kind {
		case "domain":
			for _, domain := range set.Domains {
				fmt.Fprintf(&output, "domain(%s: %s) -> %s\n", domain.Kind, daeQuote(domain.Value), route.Outbound)
				report.Generated++
			}
		case "ipcidr":
			for _, prefix := range set.Prefixes {
				fmt.Fprintf(&output, "dip(%s) -> %s\n", daeQuote(prefix.String()), route.Outbound)
				report.Generated++
			}
		default:
			return "", report, fmt.Errorf("unsupported route kind %q", route.Kind)
		}
	}
	return output.String(), report, nil
}

func daeQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "'", `\'`)
	return "'" + value + "'"
}
