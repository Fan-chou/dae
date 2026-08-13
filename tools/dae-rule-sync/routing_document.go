package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// MihomoRoutingDocument is the lossless, source-oriented subset of a Mihomo
// configuration needed by the routing compiler. It deliberately does not
// decode or evaluate script expressions.
//
// Providers and sub-rules are available both as ordered definitions and as
// name-indexed views. The ordered views are the authoritative representation
// when source order matters; the maps are convenience indexes for later
// reference validation.
type MihomoRoutingDocument struct {
	// These fields reuse the existing proxy and proxy-group element models
	// without changing ParseMihomoConfig or ParseMihomoConfigStrict.
	Proxies []MihomoProxy
	Groups  []MihomoGroup

	Providers      map[string]MihomoRuleProvider
	ProviderOrder  []string
	ProviderValues []MihomoRuleProvider

	Rules []MihomoRule

	SubRules      map[string][]MihomoRule
	SubRuleOrder  []string
	SubRuleValues []MihomoSubRule

	// ScriptPresent and ScriptSourceLine describe only the top-level script
	// section. ScriptRefs records references from rules without retaining or
	// interpreting the expression body.
	ScriptPresent    bool
	ScriptSourceLine int
	ScriptRefs       []MihomoScriptReference

	// IgnoredFields contains unknown top-level field names in source order.
	// The unsupported-but-recognized script section is also reported here.
	IgnoredFields []string
}

// MihomoRuleProvider is a rule-provider declaration with its source position.
// Raw retains the complete provider mapping for later stages that need fields
// not used by this extractor; it is never rendered in an error message.
type MihomoRuleProvider struct {
	Name     string
	Type     string
	URL      string
	Path     string
	Behavior string
	Format   string
	Interval time.Duration

	SourceIndex int
	SourceLine  int
	Raw         yaml.Node
}

// MihomoRule is an unparsed Mihomo rule. Raw and Value intentionally contain
// the original scalar text; expression parsing belongs to a later compiler
// and must not happen in the document extractor.
type MihomoRule struct {
	Raw         string
	Value       string
	SourceIndex int
	SourceLine  int
}

// MihomoSubRule is the named, ordered representation of one sub-rules entry.
// MihomoRoutingDocument.SubRules remains a map for convenient lookup while
// SubRuleValues preserves the source order and the definition's source line.
type MihomoSubRule struct {
	Name        string
	Rules       []MihomoRule
	SourceIndex int
	SourceLine  int
}

// MihomoScriptReference is deliberately metadata-only. Shortcut is the
// referenced name from a SCRIPT rule; no script expression is retained or
// evaluated by this package.
type MihomoScriptReference struct {
	Shortcut    string
	SourceIndex int
	SourceLine  int
}

// ParseMihomoRoutingDocument extracts routing-related sections from a complete
// Mihomo YAML document. Unlike ParseMihomoConfigStrict, unknown top-level
// fields are recorded rather than rejected, so a full Mihomo config can be
// inspected without pretending that unsupported sections are understood.
func ParseMihomoRoutingDocument(data []byte) (MihomoRoutingDocument, error) {
	root, err := decodeSingleYAMLDocument(data)
	if err != nil {
		return MihomoRoutingDocument{}, fmt.Errorf("parse Mihomo routing document: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0] == nil {
		return MihomoRoutingDocument{}, errors.New("parse Mihomo routing document: top level must be one YAML mapping")
	}
	root = *root.Content[0]
	if root.Kind != yaml.MappingNode {
		return MihomoRoutingDocument{}, fmt.Errorf("parse Mihomo routing document: top level must be a mapping, got %s", yamlNodeKind(root.Kind))
	}

	document := MihomoRoutingDocument{
		Providers: make(map[string]MihomoRuleProvider),
		SubRules:  make(map[string][]MihomoRule),
	}
	seenFields := make(map[string]struct{}, len(root.Content)/2)
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i]
		value := root.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return MihomoRoutingDocument{}, fmt.Errorf("parse Mihomo routing document: top-level field name at line %d is not a string", key.Line)
		}
		name := key.Value
		if _, exists := seenFields[name]; exists {
			return MihomoRoutingDocument{}, fmt.Errorf("parse Mihomo routing document: duplicate top-level field %q", name)
		}
		seenFields[name] = struct{}{}

		switch name {
		case "proxies":
			if err := decodeMihomoRoutingSequence(value, "proxies", &document.Proxies); err != nil {
				return MihomoRoutingDocument{}, err
			}
		case "proxy-groups":
			if err := decodeMihomoRoutingSequence(value, "proxy-groups", &document.Groups); err != nil {
				return MihomoRoutingDocument{}, err
			}
		case "rule-providers":
			providers, order, values, err := parseMihomoRuleProviders(value)
			if err != nil {
				return MihomoRoutingDocument{}, err
			}
			document.Providers = providers
			document.ProviderOrder = order
			document.ProviderValues = values
		case "rules":
			rules, err := parseMihomoRules(value, "rules")
			if err != nil {
				return MihomoRoutingDocument{}, err
			}
			document.Rules = rules
		case "sub-rules":
			subRules, order, values, err := parseMihomoSubRules(value)
			if err != nil {
				return MihomoRoutingDocument{}, err
			}
			document.SubRules = subRules
			document.SubRuleOrder = order
			document.SubRuleValues = values
		case "script":
			if value.Kind != yaml.MappingNode {
				return MihomoRoutingDocument{}, invalidRoutingSectionType("script", value)
			}
			document.ScriptPresent = true
			document.ScriptSourceLine = value.Line
			document.IgnoredFields = append(document.IgnoredFields, name)
		default:
			document.IgnoredFields = append(document.IgnoredFields, name)
		}
	}

	document.ScriptRefs = collectMihomoScriptReferences(document.Rules, document.SubRuleValues)
	return document, nil
}

func decodeSingleYAMLDocument(data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		return nil, errors.New("empty YAML document")
	}
	var extra yaml.Node
	err := decoder.Decode(&extra)
	if err == nil {
		return nil, errors.New("multiple YAML documents are not allowed")
	}
	if !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &root, nil
}

func decodeMihomoRoutingSequence(node *yaml.Node, section string, target any) error {
	if node.Kind != yaml.SequenceNode {
		return invalidRoutingSectionType(section, node)
	}
	if err := node.Decode(target); err != nil {
		return fmt.Errorf("parse Mihomo routing document: decode %s: %w", section, err)
	}
	return nil
}

func parseMihomoRuleProviders(node *yaml.Node) (map[string]MihomoRuleProvider, []string, []MihomoRuleProvider, error) {
	if node.Kind != yaml.MappingNode {
		return nil, nil, nil, invalidRoutingSectionType("rule-providers", node)
	}
	providers := make(map[string]MihomoRuleProvider, len(node.Content)/2)
	order := make([]string, 0, len(node.Content)/2)
	values := make([]MihomoRuleProvider, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		name, err := routingMappingName(key, "rule-provider")
		if err != nil {
			return nil, nil, nil, err
		}
		if _, exists := providers[name]; exists {
			return nil, nil, nil, fmt.Errorf("parse Mihomo routing document: duplicate rule-provider %q", name)
		}
		if value.Kind != yaml.MappingNode {
			return nil, nil, nil, invalidNamedRoutingSectionType("rule-provider", name, value)
		}
		provider, err := decodeMihomoRuleProvider(name, value, len(order), key.Line)
		if err != nil {
			return nil, nil, nil, err
		}
		providers[name] = provider
		order = append(order, name)
		values = append(values, provider)
	}
	return providers, order, values, nil
}

func decodeMihomoRuleProvider(name string, node *yaml.Node, sourceIndex, sourceLine int) (MihomoRuleProvider, error) {
	provider := MihomoRuleProvider{
		Name:        name,
		SourceIndex: sourceIndex,
		SourceLine:  sourceLine,
		Raw:         *node,
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return MihomoRuleProvider{}, fmt.Errorf("parse Mihomo routing document: rule-provider %q has a non-string field name at line %d", name, key.Line)
		}
		if value.Kind != yaml.ScalarNode {
			// Unknown or structured provider options are retained by Raw. The
			// extractor does not need to assign semantics to them.
			continue
		}
		switch key.Value {
		case "type":
			provider.Type = value.Value
		case "behavior":
			provider.Behavior = value.Value
		case "format":
			provider.Format = value.Value
		case "url":
			provider.URL = value.Value
		case "path":
			provider.Path = value.Value
		case "interval":
			interval, err := parseMihomoProviderInterval(value)
			if err != nil {
				return MihomoRuleProvider{}, fmt.Errorf("parse Mihomo routing document: rule-provider %q has invalid interval", name)
			}
			provider.Interval = interval
		}
	}
	return provider, nil
}

func parseMihomoProviderInterval(node *yaml.Node) (time.Duration, error) {
	if node.Tag == "!!int" {
		seconds, err := strconv.ParseInt(node.Value, 10, 64)
		if err != nil || seconds < 0 {
			return 0, errors.New("invalid interval")
		}
		return time.Duration(seconds) * time.Second, nil
	}
	if strings.TrimSpace(node.Value) == "" {
		return 0, errors.New("invalid interval")
	}
	interval, err := time.ParseDuration(node.Value)
	if err != nil || interval < 0 {
		return 0, errors.New("invalid interval")
	}
	return interval, nil
}

func parseMihomoRules(node *yaml.Node, section string) ([]MihomoRule, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, invalidRoutingSectionType(section, node)
	}
	rules := make([]MihomoRule, 0, len(node.Content))
	for index, item := range node.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return nil, fmt.Errorf("parse Mihomo routing document: %s item %d at line %d must be a string", section, index, item.Line)
		}
		rules = append(rules, MihomoRule{
			Raw:         item.Value,
			Value:       item.Value,
			SourceIndex: index,
			SourceLine:  item.Line,
		})
	}
	return rules, nil
}

func parseMihomoSubRules(node *yaml.Node) (map[string][]MihomoRule, []string, []MihomoSubRule, error) {
	if node.Kind != yaml.MappingNode {
		return nil, nil, nil, invalidRoutingSectionType("sub-rules", node)
	}
	subRules := make(map[string][]MihomoRule, len(node.Content)/2)
	order := make([]string, 0, len(node.Content)/2)
	values := make([]MihomoSubRule, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		name, err := routingMappingName(key, "sub-rule")
		if err != nil {
			return nil, nil, nil, err
		}
		if _, exists := subRules[name]; exists {
			return nil, nil, nil, fmt.Errorf("parse Mihomo routing document: duplicate sub-rule %q", name)
		}
		rules, err := parseMihomoRules(value, "sub-rule "+name)
		if err != nil {
			return nil, nil, nil, err
		}
		subRules[name] = rules
		order = append(order, name)
		values = append(values, MihomoSubRule{
			Name:        name,
			Rules:       rules,
			SourceIndex: len(order) - 1,
			SourceLine:  key.Line,
		})
	}
	return subRules, order, values, nil
}

func collectMihomoScriptReferences(rules []MihomoRule, subRules []MihomoSubRule) []MihomoScriptReference {
	refs := make([]MihomoScriptReference, 0)
	collect := func(rule MihomoRule) {
		parts := strings.SplitN(rule.Raw, ",", 3)
		if len(parts) < 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "SCRIPT") {
			return
		}
		refs = append(refs, MihomoScriptReference{
			Shortcut:    strings.TrimSpace(parts[1]),
			SourceIndex: rule.SourceIndex,
			SourceLine:  rule.SourceLine,
		})
	}
	for _, rule := range rules {
		collect(rule)
	}
	for _, subRule := range subRules {
		for _, rule := range subRule.Rules {
			collect(rule)
		}
	}
	return refs
}

func routingMappingName(node *yaml.Node, kind string) (string, error) {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", fmt.Errorf("parse Mihomo routing document: %s name at line %d is not a string", kind, node.Line)
	}
	if strings.TrimSpace(node.Value) == "" {
		return "", fmt.Errorf("parse Mihomo routing document: %s name at line %d is empty", kind, node.Line)
	}
	return node.Value, nil
}

func invalidRoutingSectionType(section string, node *yaml.Node) error {
	return fmt.Errorf("parse Mihomo routing document: section %q must be %s, got %s", section, routingExpectedKind(section), yamlNodeKind(node.Kind))
}

func invalidNamedRoutingSectionType(kind, name string, node *yaml.Node) error {
	return fmt.Errorf("parse Mihomo routing document: %s %q must be a mapping, got %s", kind, name, yamlNodeKind(node.Kind))
}

func routingExpectedKind(section string) string {
	switch section {
	case "rule-providers", "sub-rules":
		return "a mapping"
	case "proxies", "proxy-groups", "rules":
		return "a sequence"
	case "script":
		return "a mapping"
	default:
		return "a valid YAML section"
	}
}

func yamlNodeKind(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "empty"
	}
}
