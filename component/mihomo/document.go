/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Package mihomo lowers a complete Mihomo YAML document into dae nodes,
// groups and routing rules. The document is untrusted data: it is decoded
// with hard size limits, never executed, and anything that cannot be lowered
// with identical semantics is rejected instead of approximated.
package mihomo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// MaxYAMLNodes bounds the alias-expanded node count of a document.
	MaxYAMLNodes = 2_000_000
	// MaxYAMLDepth bounds mapping/sequence nesting.
	MaxYAMLDepth = 64
)

// Document is the routing-relevant subset of a Mihomo configuration.
// Element order is the source order and is authoritative.
type Document struct {
	Proxies   []Entry
	Groups    []Entry
	Providers []Provider
	Rules     []Rule
	SubRules  []SubRule

	// ScriptPresent records a top-level script section. It is never read.
	ScriptPresent bool
	// Ignored lists unknown top-level keys in source order. Their content is
	// not retained.
	Ignored []string
}

// Entry is a proxy or proxy-group mapping. Name and Type are extracted; the
// remaining fields are decoded by the node/group lowerers from Node.
type Entry struct {
	Name string
	Type string
	Line int
	Node *yaml.Node
}

// Provider is one rule-providers entry.
type Provider struct {
	Name     string
	Type     string
	URL      string
	Path     string
	Behavior string
	Format   string
	Interval time.Duration
	Line     int
}

// Rule is one unparsed rules/sub-rules item.
type Rule struct {
	Raw   string
	Index int
	Line  int
}

// SubRule is one named sub-rules sequence.
type SubRule struct {
	Name  string
	Rules []Rule
	Line  int
}

// Parse decodes data into a Document. Error messages carry section and
// element names, indexes and line numbers, never field values.
func Parse(data []byte) (*Document, error) {
	root, err := decodeOneDocument(data)
	if err != nil {
		return nil, err
	}
	if err := checkLimits(root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("mihomo: top level must be a mapping")
	}

	doc := &Document{}
	seen := make(map[string]struct{}, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("mihomo: line %d: top-level key must be a string", key.Line)
		}
		name := key.Value
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("mihomo: line %d: duplicate top-level key %q", key.Line, name)
		}
		seen[name] = struct{}{}
		var err error
		switch name {
		case "proxies":
			doc.Proxies, err = parseEntries(value, "proxies")
		case "proxy-groups":
			doc.Groups, err = parseEntries(value, "proxy-groups")
		case "rule-providers":
			doc.Providers, err = parseProviders(value)
		case "rules":
			doc.Rules, err = parseRules(value, "rules")
		case "sub-rules":
			doc.SubRules, err = parseSubRules(value)
		case "script":
			doc.ScriptPresent = true
		default:
			doc.Ignored = append(doc.Ignored, name)
		}
		if err != nil {
			return nil, err
		}
	}
	return doc, nil
}

func decodeOneDocument(data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("mihomo: empty document")
		}
		return nil, fmt.Errorf("mihomo: invalid YAML: %w", sanitizeYAMLError(err))
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("mihomo: empty document")
	}
	var extra yaml.Node
	switch err := decoder.Decode(&extra); {
	case err == nil:
		return nil, errors.New("mihomo: multiple YAML documents are not allowed")
	case !errors.Is(err, io.EOF):
		return nil, fmt.Errorf("mihomo: invalid YAML: %w", sanitizeYAMLError(err))
	}
	return doc.Content[0], nil
}

// sanitizeYAMLError drops yaml.v3 detail that may quote document content.
func sanitizeYAMLError(err error) error {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		return errors.New("type error")
	}
	// Parser errors look like "yaml: line 3: did not find expected key";
	// they describe structure, not values.
	return err
}

// checkLimits bounds the alias-expanded size and depth of a node tree in time
// proportional to the unexpanded tree.
func checkLimits(root *yaml.Node) error {
	type stat struct{ nodes, depth int }
	memo := make(map[*yaml.Node]stat)
	var walk func(n *yaml.Node) (stat, error)
	walk = func(n *yaml.Node) (stat, error) {
		if n == nil {
			return stat{}, nil
		}
		if st, ok := memo[n]; ok {
			return st, nil
		}
		var st stat
		switch n.Kind {
		case yaml.AliasNode:
			target, err := walk(n.Alias)
			if err != nil {
				return stat{}, err
			}
			st = stat{nodes: 1 + target.nodes, depth: target.depth}
		default:
			st = stat{nodes: 1}
			deepest := 0
			for _, child := range n.Content {
				c, err := walk(child)
				if err != nil {
					return stat{}, err
				}
				st.nodes += c.nodes
				if st.nodes > MaxYAMLNodes {
					return stat{}, fmt.Errorf("mihomo: document exceeds %d expanded YAML nodes", MaxYAMLNodes)
				}
				if c.depth > deepest {
					deepest = c.depth
				}
			}
			st.depth = deepest
			if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
				st.depth++
			}
		}
		if st.nodes > MaxYAMLNodes {
			return stat{}, fmt.Errorf("mihomo: document exceeds %d expanded YAML nodes", MaxYAMLNodes)
		}
		if st.depth > MaxYAMLDepth {
			return stat{}, fmt.Errorf("mihomo: document nesting exceeds %d levels", MaxYAMLDepth)
		}
		memo[n] = st
		return st, nil
	}
	_, err := walk(root)
	return err
}

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func parseEntries(node *yaml.Node, section string) ([]Entry, error) {
	node = resolve(node)
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("mihomo: line %d: %s must be a sequence", node.Line, section)
	}
	entries := make([]Entry, 0, len(node.Content))
	for index, item := range node.Content {
		item = resolve(item)
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("mihomo: line %d: %s[%d] must be a mapping", item.Line, section, index)
		}
		var head struct {
			Name string `yaml:"name"`
			Type string `yaml:"type"`
		}
		if err := item.Decode(&head); err != nil {
			return nil, fmt.Errorf("mihomo: line %d: %s[%d] has an invalid name or type", item.Line, section, index)
		}
		if head.Name == "" {
			return nil, fmt.Errorf("mihomo: line %d: %s[%d] has no name", item.Line, section, index)
		}
		entries = append(entries, Entry{Name: head.Name, Type: head.Type, Line: item.Line, Node: item})
	}
	return entries, nil
}

func parseProviders(node *yaml.Node) ([]Provider, error) {
	node = resolve(node)
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("mihomo: line %d: rule-providers must be a mapping", node.Line)
	}
	var providers []Provider
	seen := make(map[string]struct{})
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], resolve(node.Content[i+1])
		if key.Kind != yaml.ScalarNode || key.Value == "" {
			return nil, fmt.Errorf("mihomo: line %d: rule-provider name must be a non-empty string", key.Line)
		}
		if _, dup := seen[key.Value]; dup {
			return nil, fmt.Errorf("mihomo: line %d: duplicate rule-provider %q", key.Line, key.Value)
		}
		seen[key.Value] = struct{}{}
		if value.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("mihomo: line %d: rule-provider %q must be a mapping", value.Line, key.Value)
		}
		var raw struct {
			Type     string `yaml:"type"`
			URL      string `yaml:"url"`
			Path     string `yaml:"path"`
			Behavior string `yaml:"behavior"`
			Format   string `yaml:"format"`
			Interval int64  `yaml:"interval"`
		}
		if err := value.Decode(&raw); err != nil {
			return nil, fmt.Errorf("mihomo: line %d: rule-provider %q has invalid fields", value.Line, key.Value)
		}
		if raw.Interval < 0 {
			return nil, fmt.Errorf("mihomo: line %d: rule-provider %q has a negative interval", value.Line, key.Value)
		}
		providers = append(providers, Provider{
			Name: key.Value, Type: raw.Type, URL: raw.URL, Path: raw.Path,
			Behavior: raw.Behavior, Format: raw.Format,
			Interval: time.Duration(raw.Interval) * time.Second, Line: key.Line,
		})
	}
	return providers, nil
}

func parseRules(node *yaml.Node, section string) ([]Rule, error) {
	node = resolve(node)
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("mihomo: line %d: %s must be a sequence", node.Line, section)
	}
	rules := make([]Rule, 0, len(node.Content))
	for index, item := range node.Content {
		item = resolve(item)
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return nil, fmt.Errorf("mihomo: line %d: %s[%d] must be a string", item.Line, section, index)
		}
		rules = append(rules, Rule{Raw: item.Value, Index: index, Line: item.Line})
	}
	return rules, nil
}

func parseSubRules(node *yaml.Node) ([]SubRule, error) {
	node = resolve(node)
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("mihomo: line %d: sub-rules must be a mapping", node.Line)
	}
	var out []SubRule
	seen := make(map[string]struct{})
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.Value == "" {
			return nil, fmt.Errorf("mihomo: line %d: sub-rule name must be a non-empty string", key.Line)
		}
		if _, dup := seen[key.Value]; dup {
			return nil, fmt.Errorf("mihomo: line %d: duplicate sub-rule %q", key.Line, key.Value)
		}
		seen[key.Value] = struct{}{}
		rules, err := parseRules(node.Content[i+1], "sub-rules."+key.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, SubRule{Name: key.Value, Rules: rules, Line: key.Line})
	}
	return out, nil
}
