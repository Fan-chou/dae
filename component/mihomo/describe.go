/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// maxDescribedParams caps how many values of one condition are listed; a rule
// set can hold thousands.
const maxDescribedParams = 6

// Endpoint describes where a node connects, without credentials: its
// protocol and host:port. A link carries secrets in its user info and query,
// and neither is ever shown.
func (n Node) Endpoint() string {
	u, err := url.Parse(n.Link)
	if err != nil || u.Host == "" {
		return n.Protocol
	}
	return n.Protocol + " " + u.Host
}

// DescribeRule renders a routing rule on one line, decoding route_expr into
// readable and/or/not form so an ordered rule can be checked by eye.
func DescribeRule(r *config_parser.RoutingRule) string {
	var cond string
	switch {
	case len(r.AndFunctions) == 0:
		cond = "(always)"
	default:
		parts := make([]string, len(r.AndFunctions))
		for i, f := range r.AndFunctions {
			parts[i] = describeFunction(f)
		}
		cond = strings.Join(parts, " && ")
	}
	return cond + " -> " + r.Outbound.String(true, false, true)
}

func describeFunction(f *config_parser.Function) string {
	if f.Name == "route_expr" {
		e, err := routing.DecodeOrderedExpr(f)
		if err != nil {
			return "route_expr(unreadable)"
		}
		return describeExpr(e)
	}
	return describeAtom(f)
}

func describeExpr(e *routing.OrderedExpr) string {
	if e.Op == "atom" {
		return describeAtom(e.Atom)
	}
	if e.Op == "not" && len(e.Children) == 1 {
		return "!(" + describeExpr(e.Children[0]) + ")"
	}
	sep := " && "
	if e.Op == "or" {
		sep = " || "
	}
	parts := make([]string, len(e.Children))
	for i, c := range e.Children {
		parts[i] = describeExpr(c)
	}
	return "(" + strings.Join(parts, sep) + ")"
}

func describeAtom(f *config_parser.Function) string {
	var b strings.Builder
	if f.Not {
		b.WriteByte('!')
	}
	b.WriteString(f.Name)
	b.WriteByte('(')
	for i, p := range f.Params {
		if i == maxDescribedParams {
			fmt.Fprintf(&b, ", … +%d more", len(f.Params)-maxDescribedParams)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		if p.Key != "" {
			b.WriteString(p.Key + ": ")
		}
		b.WriteString(p.Val)
	}
	b.WriteByte(')')
	return b.String()
}

// DescribeGroup renders a group's name, policy and members on one line.
func DescribeGroup(g Group) string {
	return DescribeConfigGroup(g.Name, g.Config, g.Wrapper)
}

// DescribeConfigGroup renders any dae group on one line. display is the name
// the group had in its source when that differs from cfg.Name.
func DescribeConfigGroup(display string, cfg config.Group, wrapper bool) string {
	name := cfg.Name
	if display != "" && display != cfg.Name {
		name = fmt.Sprintf("%s (%q)", cfg.Name, display)
	}
	policy := "?"
	if fns, err := config.ParseFunctionListOrString(cfg.Policy); err == nil && len(fns) > 0 {
		policy = fns[0].String(true, false, true)
	}
	var members []string
	for _, filter := range cfg.Filter {
		for _, f := range filter {
			members = append(members, describeAtom(f))
		}
	}
	line := fmt.Sprintf("%s  %s  <- %s", name, policy, strings.Join(members, ", "))
	if opts := groupOptions(cfg, wrapper); len(opts) > 0 {
		line += "  [" + strings.Join(opts, "; ") + "]"
	}
	return line
}

// GroupSettings lists the notable settings of a group, for display.
func GroupSettings(cfg config.Group) []string { return groupOptions(cfg, false) }

func groupOptions(cfg config.Group, wrapper bool) []string {
	var opts []string
	if len(cfg.TcpCheckUrl) > 0 {
		opts = append(opts, "url="+strings.Join(cfg.TcpCheckUrl, ","))
	}
	if cfg.CheckIntervalSet {
		opts = append(opts, "interval="+cfg.CheckInterval.String())
	}
	if cfg.CheckToleranceSet {
		opts = append(opts, "tolerance="+cfg.CheckTolerance.String())
	}
	if cfg.LazySet {
		opts = append(opts, fmt.Sprintf("lazy=%t", cfg.Lazy))
	}
	if cfg.IsolateTransport {
		opts = append(opts, "isolate_transport")
	}
	if cfg.QualityMode != "" && cfg.QualityMode != "off" {
		opts = append(opts, "quality="+cfg.QualityMode)
	}
	if wrapper {
		opts = append(opts, "wraps a single node for rules that name it")
	}
	return opts
}

// GroupMembers lists a group's member filters as text, for display.
func GroupMembers(cfg config.Group) []string {
	var members []string
	for _, filter := range cfg.Filter {
		for _, f := range filter {
			members = append(members, describeAtom(f))
		}
	}
	return members
}

// GroupPolicy renders a group's selection policy as text.
func GroupPolicy(cfg config.Group) string {
	if fns, err := config.ParseFunctionListOrString(cfg.Policy); err == nil && len(fns) > 0 {
		return fns[0].String(true, false, true)
	}
	return "?"
}

// Describe renders what the conversion produced, for a person to read.
// Credentials are never included.
func (r *Result) Describe() string {
	var b strings.Builder
	display := make(map[string]string, len(r.Groups))
	for _, g := range r.Groups {
		display[g.Safe] = g.Name
	}

	fmt.Fprintf(&b, "nodes (%d):\n", len(r.Nodes))
	for _, n := range r.Nodes {
		if n.Name != n.Safe {
			fmt.Fprintf(&b, "  %s (%q)  %s\n", n.Safe, n.Name, n.Endpoint())
		} else {
			fmt.Fprintf(&b, "  %s  %s\n", n.Safe, n.Endpoint())
		}
	}
	fmt.Fprintf(&b, "groups (%d):\n", len(r.Groups))
	for _, g := range r.Groups {
		fmt.Fprintf(&b, "  %s\n", DescribeGroup(g))
	}
	fmt.Fprintf(&b, "rule sets (%d, fetched when the config loads):\n", len(r.Providers))
	for _, p := range r.Providers {
		fmt.Fprintf(&b, "  %s  %s/%s", p.Name, p.Type, p.Behavior)
		if p.Interval > 0 {
			fmt.Fprintf(&b, "  every %s", p.Interval)
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "rules (%d, matched in this order; ruleset(x) is expanded from its rule set):\n", len(r.Rules))
	for i, rule := range r.Rules {
		fmt.Fprintf(&b, "  %3d. %s\n", i+1, DescribeRule(rule))
	}
	if r.Fallback != "" {
		fmt.Fprintf(&b, "fallback (from MATCH): %s\n", r.Fallback)
	} else {
		b.WriteString("fallback: none in the Mihomo source (the configured fallback stays)\n")
	}

	if len(r.Report.Events) > 0 {
		fmt.Fprintf(&b, "left out or changed (%d):\n", len(r.Report.Events))
		for _, e := range r.Report.Events {
			fmt.Fprintf(&b, "  [%s] rule %d, line %d: %s\n        %s\n", e.Kind, e.Index, e.Line, e.Raw, e.Reason)
		}
	}
	if len(r.Report.UnusedProviders) > 0 {
		fmt.Fprintf(&b, "declared but unused rule sets (never fetched): %s\n", strings.Join(r.Report.UnusedProviders, ", "))
	}
	if len(r.Report.IgnoredFields) > 0 {
		fmt.Fprintf(&b, "top-level keys not read: %s\n", strings.Join(r.Report.IgnoredFields, ", "))
	}
	if r.Report.ScriptPresent {
		b.WriteString("a script section is present but no rule uses it\n")
	}
	return b.String()
}
