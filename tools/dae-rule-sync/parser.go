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

// canonicalizeMihomoDomainName lowercases DOMAIN / DOMAIN-SUFFIX /
// DOMAIN-KEYWORD values. kdae's domain matcher only accepts lowercase
// characters; DNS matching is case-insensitive, so this preserves Mihomo intent.
func canonicalizeMihomoDomainName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
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

const generationDATRuleThreshold = 256

type generationDATSpec struct {
	Provider     string
	Kind         string
	RelativePath string
	Domains      []DomainRule
	Prefixes     []netip.Prefix
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
		if err := validateProviderYAML(data); err != nil {
			return nil, err
		}
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

func validateProviderYAML(data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse yaml provider: %w", err)
	}
	const maxNodes = 100000
	nodes := 0
	var walk func(*yaml.Node, int) error
	walk = func(node *yaml.Node, depth int) error {
		if node == nil {
			return nil
		}
		if depth > 64 {
			return fmt.Errorf("provider yaml nesting exceeds 64 levels")
		}
		nodes++
		if nodes > maxNodes {
			return fmt.Errorf("provider yaml contains too many nodes")
		}
		if node.Kind == yaml.AliasNode {
			return fmt.Errorf("provider yaml aliases are not allowed")
		}
		for _, child := range node.Content {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(&root, 0); err != nil {
		return err
	}
	return nil
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
		return DomainSuffix, canonicalizeMihomoDomainName(value), netip.Prefix{}, nil, nil
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
		return DomainFull, canonicalizeMihomoDomainName(value), netip.Prefix{}, nil, nil
	case "DOMAIN-SUFFIX":
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		return DomainSuffix, canonicalizeMihomoDomainName(value), netip.Prefix{}, nil, nil
	case "DOMAIN-KEYWORD":
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		return DomainKeyword, canonicalizeMihomoDomainName(value), netip.Prefix{}, nil, nil
	case "DOMAIN-REGEX":
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		return DomainRegex, value, netip.Prefix{}, nil, nil
	case "DOMAIN-WILDCARD":
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "domain entry in ipcidr provider"}, nil
		}
		if len(strings.Split(raw, ",")) != 2 {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "DOMAIN-WILDCARD requires exactly one pattern"}, nil
		}
		wildcardRegex, err := mihomoDomainWildcardRegex(value)
		if err != nil {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: err.Error()}, nil
		}
		return DomainRegex, wildcardRegex, netip.Prefix{}, nil, nil
	case "IP-CIDR", "IP-CIDR6":
		if behavior == "domain" {
			return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: "ip entry in domain provider"}, nil
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(strings.SplitN(value, ",", 2)[0]))
		if err != nil {
			return "", "", netip.Prefix{}, nil, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		return "", "", prefix, nil, nil
	case "GEOSITE", "GEOIP", "IP-ASN", "PROCESS-NAME", "DST-PORT", "SRC-IP-CIDR", "NETWORK", "AND", "OR", "NOT":
		return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: fmt.Sprintf("unsupported classical rule %s", kind)}, nil
	}

	if !strings.ContainsAny(raw, " ,	\r") {
		if behavior == "ipcidr" || behavior == "classical" {
			if addr, err := netip.ParseAddr(raw); err == nil {
				bits := 128
				if addr.Is4() {
					bits = 32
				}
				return "", "", netip.PrefixFrom(addr, bits), nil, nil
			}
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				return "", "", prefix, nil, nil
			}
			if behavior == "ipcidr" {
				return "", "", netip.Prefix{}, nil, fmt.Errorf("invalid CIDR %q", raw)
			}
		}
		if behavior == "ipcidr" {
			return "", "", netip.Prefix{}, nil, fmt.Errorf("invalid CIDR %q", raw)
		}
		return DomainSuffix, canonicalizeMihomoDomainName(raw), netip.Prefix{}, nil, nil
	}
	return "", "", netip.Prefix{}, &UnsupportedRule{Raw: raw, Reason: fmt.Sprintf("unsupported rule type %s", kind)}, nil
}

func GenerateDaeRoutes(manifest Manifest, sets map[string]ParsedRuleSet, strict bool) (string, ConversionReport, error) {
	routes, report, _, err := generateDaeRoutes(manifest, sets, strict, false)
	return routes, report, err
}

func GenerateGenerationDaeRoutes(manifest Manifest, sets map[string]ParsedRuleSet, strict bool) (string, ConversionReport, []generationDATSpec, error) {
	return generateDaeRoutes(manifest, sets, strict, true)
}

func generateDaeRoutes(manifest Manifest, sets map[string]ParsedRuleSet, strict, useDAT bool) (string, ConversionReport, []generationDATSpec, error) {
	providerBehaviors := make(map[string]string, len(manifest.Providers))
	for _, provider := range manifest.Providers {
		providerBehaviors[provider.Name] = strings.ToLower(provider.Behavior)
	}
	var output strings.Builder
	var report ConversionReport
	var artifacts []generationDATSpec
	specIndices := make(map[string]int)
	for _, route := range manifest.Routes {
		set, ok := sets[route.Provider]
		if !ok {
			return "", report, nil, fmt.Errorf("route references missing provider %q", route.Provider)
		}
		if err := validateRouteOutbound(route.Outbound); err != nil {
			return "", report, nil, fmt.Errorf("route for provider %q: %w", route.Provider, err)
		}
		kind := strings.ToLower(route.Kind)
		if kind == "" {
			kind = providerBehaviors[route.Provider]
			if kind == "classical" {
				return "", report, nil, fmt.Errorf("route for classical provider %q requires explicit kind", route.Provider)
			}
		}
		if kind != "domain" && kind != "ipcidr" {
			return "", report, nil, fmt.Errorf("unsupported route kind %q", route.Kind)
		}
		behavior := providerBehaviors[route.Provider]
		if behavior != "classical" && behavior != "" && behavior != kind {
			return "", report, nil, fmt.Errorf("route kind %q does not match provider %q behavior %q", kind, route.Provider, behavior)
		}
		if (kind == "domain" && len(set.Domains) == 0) || (kind == "ipcidr" && len(set.Prefixes) == 0) {
			return "", report, nil, fmt.Errorf("provider %q has no convertible %s rules", route.Provider, kind)
		}
		if len(set.Unsupported) > 0 {
			if strict {
				return "", report, nil, fmt.Errorf("provider %q contains %d unsupported rules", route.Provider, len(set.Unsupported))
			}
			report.Unsupported = append(report.Unsupported, set.Unsupported...)
			report.Skipped += len(set.Unsupported)
		}
		switch kind {
		case "domain":
			for _, domain := range set.Domains {
				if err := validateDaeLiteral(domain.Value); err != nil {
					return "", report, nil, fmt.Errorf("provider %q rule: %w", route.Provider, err)
				}
			}
			if useDAT && len(set.Domains) >= generationDATRuleThreshold {
				key := route.Provider + "\x00" + kind
				if _, ok := specIndices[key]; !ok {
					specIndices[key] = len(artifacts)
					artifacts = append(artifacts, generationDATSpec{
						Provider:     route.Provider,
						Kind:         kind,
						RelativePath: "generated/geosite/" + route.Provider + ".dat",
						Domains:      append([]DomainRule(nil), set.Domains...),
					})
				}
				fmt.Fprintf(&output, "domain(ext: %s) -> %s\n", daeQuote("generated/geosite/"+route.Provider+".dat:"+route.Provider), route.Outbound)
				report.Generated += len(set.Domains)
				continue
			}
			for _, domain := range set.Domains {
				fmt.Fprintf(&output, "domain(%s: %s) -> %s\n", domain.Kind, daeQuote(domain.Value), route.Outbound)
				report.Generated++
			}
		case "ipcidr":
			if useDAT && len(set.Prefixes) >= generationDATRuleThreshold {
				key := route.Provider + "\x00" + kind
				if _, ok := specIndices[key]; !ok {
					specIndices[key] = len(artifacts)
					artifacts = append(artifacts, generationDATSpec{
						Provider:     route.Provider,
						Kind:         kind,
						RelativePath: "generated/geoip/" + route.Provider + ".dat",
						Prefixes:     append([]netip.Prefix(nil), set.Prefixes...),
					})
				}
				fmt.Fprintf(&output, "dip(ext: %s) -> %s\n", daeQuote("generated/geoip/"+route.Provider+".dat:"+route.Provider), route.Outbound)
				report.Generated += len(set.Prefixes)
				continue
			}
			for _, prefix := range set.Prefixes {
				fmt.Fprintf(&output, "dip(%s) -> %s\n", daeQuote(prefix.String()), route.Outbound)
				report.Generated++
			}
		}
	}
	return output.String(), report, artifacts, nil
}

func daeQuote(value string) string {
	if strings.Contains(value, "'") && !strings.Contains(value, `"`) {
		return `"` + value + `"`
	}
	return "'" + value + "'"
}

func validateDaeLiteral(value string) error {
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("rule value contains a control character")
	}
	if strings.Contains(value, "'") && strings.Contains(value, `"`) {
		return fmt.Errorf("rule value contains both quote characters")
	}
	return nil
}

func validateRouteOutbound(outbound string) error {
	if outbound == "" {
		return fmt.Errorf("outbound is empty")
	}
	if !providerNamePattern.MatchString(outbound) {
		return fmt.Errorf("outbound %q is not a safe identifier", outbound)
	}
	return nil
}
