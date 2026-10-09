/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/mihomo"
	"github.com/daeuniverse/dae/config"
)

// Origins of an item in the effective configuration.
const (
	originConfig = "config"
	originMihomo = "mihomo"
)

// EffectiveConfig is a read-only view of the configuration that is running,
// after the Mihomo source has been converted and merged. It is meant to be
// read by a person: node links and credentials are never part of it, and rule
// sets are shown as ruleset(name) instead of being expanded to one rule per
// entry.
type EffectiveConfig struct {
	LoadedAt time.Time    `json:"loaded_at"`
	Mihomo   MihomoStatus `json:"mihomo"`
	// Subscriptions is how many subscriptions the configuration lists; their
	// nodes are fetched when dae starts and are not part of this view.
	Subscriptions int                 `json:"subscriptions"`
	Nodes         []EffectiveNode     `json:"nodes"`
	Groups        []EffectiveGroup    `json:"groups"`
	RuleProviders []EffectiveProvider `json:"rule_providers"`
	Rules         []EffectiveRule     `json:"rules"`
	Fallback      EffectiveFallback   `json:"fallback"`
}

type EffectiveNode struct {
	Tag         string `json:"tag"`
	DisplayName string `json:"display_name,omitempty"`
	// Endpoint is the protocol and host:port, nothing else.
	Endpoint string `json:"endpoint"`
	Origin   string `json:"origin"`
}

type EffectiveGroup struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name,omitempty"`
	Policy      string   `json:"policy"`
	Members     []string `json:"members"`
	Options     []string `json:"options,omitempty"`
	Wrapper     bool     `json:"wrapper,omitempty"`
	Origin      string   `json:"origin"`
}

type EffectiveProvider struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Behavior string `json:"behavior"`
	Source   string `json:"source"`
	Interval string `json:"interval,omitempty"`
	Origin   string `json:"origin"`
}

type EffectiveRule struct {
	Index  int    `json:"index"`
	Text   string `json:"text"`
	Origin string `json:"origin"`
}

type EffectiveFallback struct {
	Outbound string `json:"outbound"`
	Origin   string `json:"origin"`
}

// endpointOf reduces a node link to "scheme host:port". Anything that is not a
// URL with a host shows only a generic label.
func endpointOf(link string) string {
	u, err := url.Parse(link)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "(link)"
	}
	return u.Scheme + " " + u.Host
}

func sourceOf(p config.RuleProvider) string {
	if p.URL == "" {
		return p.Path
	}
	u, err := url.Parse(p.URL)
	if err != nil || u.Host == "" {
		return "(url)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// buildEffectiveConfig describes conf. merge says where the converted Mihomo
// source starts in each list; nil means everything is from the configuration.
func buildEffectiveConfig(conf *config.Config, merge *mihomoMerge) *EffectiveConfig {
	originAt := func(index, start int) string {
		if merge != nil && index >= start {
			return originMihomo
		}
		return originConfig
	}
	view := &EffectiveConfig{
		LoadedAt:      time.Now(),
		Mihomo:        CurrentMihomoStatus(),
		Subscriptions: len(conf.Subscription),
	}

	displayNode := map[string]string{}
	displayGroup := map[string]struct {
		name    string
		wrapper bool
	}{}
	if merge != nil {
		for _, n := range merge.Result.Nodes {
			displayNode[n.Safe] = n.Name
		}
		for _, g := range merge.Result.Groups {
			displayGroup[g.Safe] = struct {
				name    string
				wrapper bool
			}{g.Name, g.Wrapper}
		}
	}

	for i, n := range conf.Node {
		tag, link := common.GetTagFromLinkLikePlaintext(string(n))
		node := EffectiveNode{Tag: tag, Endpoint: endpointOf(link), Origin: originAt(i, nodeStart(merge))}
		if d := displayNode[tag]; node.Origin == originMihomo && d != "" && d != tag {
			node.DisplayName = d
		}
		view.Nodes = append(view.Nodes, node)
	}
	for i, g := range conf.Group {
		origin := originAt(i, groupStart(merge))
		item := EffectiveGroup{
			Name:    g.Name,
			Policy:  mihomo.GroupPolicy(g),
			Members: mihomo.GroupMembers(g),
			Options: mihomo.GroupSettings(g),
			Origin:  origin,
		}
		if info, ok := displayGroup[g.Name]; ok && origin == originMihomo {
			item.Wrapper = info.wrapper
			if info.name != g.Name {
				item.DisplayName = info.name
			}
		}
		view.Groups = append(view.Groups, item)
	}
	for i, p := range conf.RuleProvider {
		item := EffectiveProvider{
			Name: p.Name, Type: p.Type, Behavior: p.Behavior, Source: sourceOf(p),
			Origin: originAt(i, providerStart(merge)),
		}
		if p.Interval > 0 {
			item.Interval = p.Interval.String()
		}
		view.RuleProviders = append(view.RuleProviders, item)
	}
	for i, r := range conf.Routing.Rules {
		view.Rules = append(view.Rules, EffectiveRule{
			Index: i + 1, Text: mihomo.DescribeRule(r), Origin: originAt(i, ruleStart(merge)),
		})
	}
	if fb, err := config.ParseFunctionOrString(conf.Routing.Fallback); err == nil {
		view.Fallback.Outbound = fb.Name
	}
	view.Fallback.Origin = originConfig
	if merge != nil && merge.Result.Fallback != "" {
		view.Fallback.Origin = originMihomo
	}
	return view
}

func nodeStart(m *mihomoMerge) int {
	if m == nil {
		return 0
	}
	return m.nodeStart
}
func groupStart(m *mihomoMerge) int {
	if m == nil {
		return 0
	}
	return m.groupStart
}
func providerStart(m *mihomoMerge) int {
	if m == nil {
		return 0
	}
	return m.providerStart
}
func ruleStart(m *mihomoMerge) int {
	if m == nil {
		return 0
	}
	return m.ruleStart
}

// Text renders the view for reading in a terminal or a browser tab.
func (e *EffectiveConfig) Text() string {
	var b strings.Builder
	tag := func(origin string) string {
		if origin == originMihomo {
			return "[mihomo] "
		}
		return "[config] "
	}
	fmt.Fprintf(&b, "loaded: %s\n", e.LoadedAt.Format(time.RFC3339))
	if e.Mihomo.Enabled {
		state := "ok"
		switch {
		case e.Mihomo.Error != "":
			state = "error: " + e.Mihomo.Error
		case e.Mihomo.UsedLastGood:
			state = "using the last good copy"
		}
		fmt.Fprintf(&b, "mihomo source: %s (%s)\n", e.Mihomo.Source, state)
	} else {
		b.WriteString("mihomo source: not configured\n")
	}
	if e.Subscriptions > 0 {
		fmt.Fprintf(&b, "subscriptions: %d (their nodes are fetched at start and not listed here)\n", e.Subscriptions)
	}
	fmt.Fprintf(&b, "\nnodes (%d):\n", len(e.Nodes))
	for _, n := range e.Nodes {
		name := n.Tag
		if n.DisplayName != "" {
			name = fmt.Sprintf("%s (%q)", n.Tag, n.DisplayName)
		}
		fmt.Fprintf(&b, "  %s%s  %s\n", tag(n.Origin), name, n.Endpoint)
	}
	fmt.Fprintf(&b, "\ngroups (%d):\n", len(e.Groups))
	for _, g := range e.Groups {
		name := g.Name
		if g.DisplayName != "" {
			name = fmt.Sprintf("%s (%q)", g.Name, g.DisplayName)
		}
		fmt.Fprintf(&b, "  %s%s  %s  <- %s", tag(g.Origin), name, g.Policy, strings.Join(g.Members, ", "))
		opts := g.Options
		if g.Wrapper {
			opts = append(opts, "wraps a single node for rules that name it")
		}
		if len(opts) > 0 {
			fmt.Fprintf(&b, "  [%s]", strings.Join(opts, "; "))
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "\nrule sets (%d):\n", len(e.RuleProviders))
	for _, p := range e.RuleProviders {
		fmt.Fprintf(&b, "  %s%s  %s/%s  %s", tag(p.Origin), p.Name, p.Type, p.Behavior, p.Source)
		if p.Interval != "" {
			fmt.Fprintf(&b, "  every %s", p.Interval)
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "\nrules (%d, first match wins; ruleset(x) stands for the entries of rule set x):\n", len(e.Rules))
	for _, r := range e.Rules {
		fmt.Fprintf(&b, "  %3d. %s%s\n", r.Index, tag(r.Origin), r.Text)
	}
	fmt.Fprintf(&b, "\nfallback: %s%s\n", tag(e.Fallback.Origin), e.Fallback.Outbound)

	if len(e.Mihomo.SkippedRules) > 0 {
		fmt.Fprintf(&b, "\nMihomo rules left out or changed (%d):\n", len(e.Mihomo.SkippedRules))
		for _, ev := range e.Mihomo.SkippedRules {
			fmt.Fprintf(&b, "  [%s] rule %d, line %d: %s\n        %s\n", ev.Kind, ev.Index, ev.Line, ev.Rule, ev.Reason)
		}
	}
	if len(e.Mihomo.UnusedProviders) > 0 {
		fmt.Fprintf(&b, "Mihomo rule sets declared but unused (never fetched): %s\n", strings.Join(e.Mihomo.UnusedProviders, ", "))
	}
	if len(e.Mihomo.IgnoredFields) > 0 {
		fmt.Fprintf(&b, "Mihomo top-level keys not read: %s\n", strings.Join(e.Mihomo.IgnoredFields, ", "))
	}
	return b.String()
}

var effectiveState struct {
	mu      sync.Mutex
	pending []pendingEffective // most recent last
	current *EffectiveConfig
}

type pendingEffective struct {
	conf *config.Config
	view *EffectiveConfig
}

const maxPendingEffective = 8

// rememberEffectiveConfig keeps the view built for conf until conf becomes the
// running configuration. Several configurations are read that never run (a
// validation, a reload that fails), so only a few are kept.
func rememberEffectiveConfig(conf *config.Config, view *EffectiveConfig) {
	effectiveState.mu.Lock()
	defer effectiveState.mu.Unlock()
	effectiveState.pending = append(effectiveState.pending, pendingEffective{conf, view})
	if len(effectiveState.pending) > maxPendingEffective {
		effectiveState.pending = effectiveState.pending[len(effectiveState.pending)-maxPendingEffective:]
	}
}

// publishEffectiveConfig makes the view of conf the one the API serves. It is
// called when conf starts running. A configuration that did not go through
// readConfig is described from conf alone.
func publishEffectiveConfig(conf *config.Config) {
	effectiveState.mu.Lock()
	defer effectiveState.mu.Unlock()
	var view *EffectiveConfig
	for _, p := range effectiveState.pending {
		if p.conf == conf {
			view = p.view
		}
	}
	if view == nil {
		view = buildEffectiveConfig(conf, nil)
	}
	view.LoadedAt = time.Now()
	view.Mihomo = CurrentMihomoStatus()
	effectiveState.current = view
	effectiveState.pending = nil
}

// CurrentEffectiveConfig returns the view of the running configuration, or nil
// before any configuration is running.
func CurrentEffectiveConfig() *EffectiveConfig {
	effectiveState.mu.Lock()
	defer effectiveState.mu.Unlock()
	return effectiveState.current
}
