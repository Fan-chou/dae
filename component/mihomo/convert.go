/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"errors"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// Options carries everything the conversion needs besides the document.
type Options struct {
	// BaseDir is the configuration directory file rule-providers resolve to.
	BaseDir string
	// Validate checks that dae can parse each generated node link. Nil skips.
	Validate LinkValidator
	// ResolveDNS maps an original proxy name to its resolve_dns server.
	ResolveDNS map[string]string
	// IsolateTransportGroups lists internal group names that get a private
	// transport per node.
	IsolateTransportGroups []string
	// MaxExpandedRules overrides DefaultMaxExpandedRules when positive.
	MaxExpandedRules int
}

// Report says what the conversion left out or changed, so a person can see
// why a rule behaves differently from Mihomo's. It never holds credentials.
type Report struct {
	// Events lists skipped rules and ignored conditions or options.
	Events []Event
	// UnusedProviders are declared rule-providers no rule refers to; they are
	// validated but never fetched.
	UnusedProviders []string
	// IgnoredFields are top-level keys the conversion does not read.
	IgnoredFields []string
	// ScriptPresent records an unused top-level script section.
	ScriptPresent bool
}

// Result is a whole Mihomo configuration lowered to dae objects. Rules still
// refer to rule sets by ruleset(name); the native rule provider loader
// fetches Providers and expands them.
type Result struct {
	Nodes     []Node
	Groups    []Group // declared groups in source order, then node wrappers
	Rules     []*config_parser.RoutingRule
	Fallback  string // internal outbound name; empty means dae's default
	Providers []config.RuleProvider
	Report    Report
}

// Convert lowers a parsed document. It fails as a whole when anything it
// covers cannot be represented exactly (a node, a group, a provider
// declaration, the sub-rule graph, an active SCRIPT); individual rules that
// cannot be represented are skipped and reported instead.
func Convert(doc *Document, opts Options) (*Result, error) {
	nodes, err := ConvertProxiesWith(doc.Proxies, ProxyOptions{Validate: opts.Validate, ResolveDNS: opts.ResolveDNS})
	if err != nil {
		return nil, err
	}
	groups, err := ConvertGroups(doc.Groups, nodes, GroupOptions{IsolateTransportGroups: opts.IsolateTransportGroups})
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, errors.New("Mihomo routing requires at least one proxy")
	}
	if len(groups) == 0 {
		return nil, errors.New("Mihomo routing requires at least one proxy group")
	}

	table, err := NewProviderTable(doc.Providers, opts.BaseDir)
	if err != nil {
		return nil, err
	}

	// First pass: names known so far. Targets are original proxy or group
	// names; knowing them is enough to expand sub-rules and find what is used.
	outbounds := make(map[string]string, len(nodes)+len(groups))
	used := make(map[string]struct{}, len(nodes)+len(groups))
	for _, n := range nodes {
		outbounds[n.Name] = n.Safe
		used[n.Safe] = struct{}{}
	}
	for _, g := range groups {
		outbounds[g.Name] = g.Safe
		used[g.Safe] = struct{}{}
	}
	env := RuleEnv{Providers: table.Names(), Outbounds: outbounds, MaxExpandedRules: opts.MaxExpandedRules}
	prepared, err := prepareRules(doc.Rules, doc.SubRules, env)
	if err != nil {
		return nil, err
	}

	// A rule that names a proxy directly goes to a one-member group around it.
	wrappers, err := planNodeWrappers(prepared.Targets, nodes, groups, used)
	if err != nil {
		return nil, err
	}
	wrapperGroups, err := buildWrapperGroups(wrappers, nodes)
	if err != nil {
		return nil, err
	}
	for _, w := range wrappers {
		outbounds[w.Original] = w.Group
	}

	lowered, err := prepared.lower(env, false)
	if err != nil {
		return nil, err
	}
	if len(lowered.Rules) == 0 && lowered.Fallback == "" {
		// Applying this would send everything direct. Keep what is running.
		return nil, errors.New("Mihomo routing produced no usable rules")
	}
	providers, err := table.Select(lowered.UsedProviders)
	if err != nil {
		return nil, err
	}

	usedSet := make(map[string]bool, len(lowered.UsedProviders))
	for _, name := range lowered.UsedProviders {
		usedSet[name] = true
	}
	var unused []string
	for _, p := range doc.Providers {
		if !usedSet[p.Name] {
			unused = append(unused, p.Name)
		}
	}

	return &Result{
		Nodes:     nodes,
		Groups:    append(append([]Group(nil), groups...), wrapperGroups...),
		Rules:     lowered.Rules,
		Fallback:  lowered.Fallback,
		Providers: providers,
		Report: Report{
			Events:          lowered.Events,
			UnusedProviders: unused,
			IgnoredFields:   doc.Ignored,
			ScriptPresent:   doc.ScriptPresent,
		},
	}, nil
}
