/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// DefaultMaxExpandedRules bounds the dae rules produced from all top-level
// rules together.
const DefaultMaxExpandedRules = 1024

// RuleEnv carries the names the rule lowering resolves against.
type RuleEnv struct {
	// Providers maps an original RULE-SET name to its internal provider name.
	Providers map[string]string
	// Outbounds maps an original proxy or group name to its internal outbound
	// name. DIRECT and REJECT are built in.
	Outbounds map[string]string
	// MaxExpandedRules overrides DefaultMaxExpandedRules when positive.
	MaxExpandedRules int
}

// knownTarget reports whether name is something Mihomo would accept as a rule
// target: a built-in, a proxy, or a group.
func (e RuleEnv) knownTarget(name string) bool {
	switch strings.ToUpper(name) {
	case "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE":
		return strings.ToUpper(name) == name
	}
	_, ok := e.Outbounds[name]
	return ok
}

// EventKind classifies a rule that was not lowered exactly.
type EventKind string

const (
	// EventSkip: the whole rule was left out because it cannot be represented.
	EventSkip EventKind = "skip"
	// EventIgnore: one condition was treated as never matching (IN-PORT,
	// IP-ASN). In an AND the rule disappears; in an OR only that branch does.
	EventIgnore EventKind = "ignore"
)

// Event records a rule that was skipped or partly ignored. Reason never
// contains credentials; Raw is the rule text as written.
type Event struct {
	Kind        EventKind
	Index, Line int
	Raw         string
	Reason      string
}

// LoweredRules is the result of lowering the top-level rules.
type LoweredRules struct {
	// Rules are the dae routing rules in match order, up to the first MATCH.
	Rules []*config_parser.RoutingRule
	// Fallback is the outbound of the first MATCH rule, or "" if none.
	Fallback string
	Events   []Event
	// UsedProviders are the original names of the rule sets the rules refer
	// to, in first-use order. Only these need to be fetched.
	UsedProviders []string
}

// unsupportedError marks a rule that parses but cannot be lowered exactly.
// It results in a skipped rule, never a failed conversion.
type unsupportedError struct{ reason string }

func (e *unsupportedError) Error() string { return e.reason }

func unsupported(format string, args ...any) error {
	return &unsupportedError{reason: fmt.Sprintf(format, args...)}
}

type lowerer struct {
	env    RuleEnv
	limit  int
	events []Event
	logged map[string]struct{}
	cur    *parsedRule
	// noCompact disables merging of adjacent compatible rules. Only tests set
	// it, to prove that merging does not change what a program matches.
	noCompact bool
}

func newLowerer(env RuleEnv) *lowerer {
	limit := env.MaxExpandedRules
	if limit <= 0 {
		limit = DefaultMaxExpandedRules
	}
	return &lowerer{env: env, limit: limit, logged: map[string]struct{}{}}
}

// outRule is one dae rule on its way out. ordered is set for rules that keep
// their evaluation order; they are encoded to route_expr only once merging is
// done, because merging works on the expression tree.
type outRule struct {
	rule    *config_parser.RoutingRule
	ordered *routing.OrderedExpr
}

func (l *lowerer) record(kind EventKind, key, reason string) {
	id := fmt.Sprintf("%s:%d:%d:%s:%s", kind, l.cur.index, l.cur.line, l.cur.raw, key)
	if _, dup := l.logged[id]; dup {
		return
	}
	l.logged[id] = struct{}{}
	l.events = append(l.events, Event{Kind: kind, Index: l.cur.index, Line: l.cur.line, Raw: l.cur.raw, Reason: reason})
}

// LowerRules parses and lowers rules, expanding the SUB-RULE calls reachable
// from them. A syntax error (in any rule or sub-rule, used or not), an active
// SCRIPT, or a sub-rule graph that cannot be expanded fails the whole call; a
// rule that parses but has no exact dae equivalent is skipped and reported in
// Events, which is the compatibility policy for individual rules.
func LowerRules(rules []Rule, subRules []SubRule, env RuleEnv) (*LoweredRules, error) {
	return lowerRules(rules, subRules, env, false)
}

func lowerRules(rules []Rule, subRules []SubRule, env RuleEnv, noCompact bool) (*LoweredRules, error) {
	p, err := prepareRules(rules, subRules, env)
	if err != nil {
		return nil, err
	}
	return p.lower(env, noCompact)
}

// preparedRules is the result of everything that does not depend on how
// outbounds are named: syntax, sub-rule expansion, and the facts the caller
// needs before it can name them (which providers and which targets are used).
type preparedRules struct {
	rules  []*parsedRule
	events []Event
	// Providers and Targets are original names, in first-use order and sorted
	// order respectively.
	Providers []string
	Targets   []string
}

func prepareRules(rules []Rule, subRules []SubRule, env RuleEnv) (*preparedRules, error) {
	top, err := parseRuleList(rules)
	if err != nil {
		return nil, err
	}
	defs := make(map[string]*parsedSubRule, len(subRules))
	for _, sr := range subRules {
		// Every definition is parsed even when unreferenced: a malformed
		// rule is a mistake in the document, not something to hide.
		body, err := parseRuleList(sr.Rules)
		if err != nil {
			return nil, err
		}
		defs[sr.Name] = &parsedSubRule{name: sr.Name, line: sr.Line, rules: body}
	}
	expanded, events, err := expandSubRules(top, defs, env.knownTarget)
	if err != nil {
		return nil, err
	}
	used, err := usedProviders(expanded, env.Providers)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var targets []string
	for _, r := range expanded {
		if t := strings.TrimSpace(r.action.target); t != "" && !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	sort.Strings(targets)
	return &preparedRules{rules: expanded, events: events, Providers: used, Targets: targets}, nil
}

func (p *preparedRules) lower(env RuleEnv, noCompact bool) (*LoweredRules, error) {
	l := newLowerer(env)
	l.noCompact = noCompact
	l.events = append(l.events, p.events...)
	out, err := l.lowerTop(p.rules)
	if err != nil {
		return nil, err
	}
	out.UsedProviders = p.Providers
	return out, nil
}

// UndeclaredProviderError is a RULE-SET that names no rule-provider. Mihomo
// refuses to load such a configuration, so it is not a rule to skip.
type UndeclaredProviderError struct {
	Index, Line int
	Name        string
}

func (e *UndeclaredProviderError) Error() string {
	return fmt.Sprintf("RULE-SET provider %q at index %d line %d is undeclared", e.Name, e.Index, e.Line)
}

// usedProviders lists, in first-use order, the providers the expanded rules
// refer to, and fails on a reference to one that was never declared.
func usedProviders(rules []*parsedRule, declared map[string]string) ([]string, error) {
	var used []string
	seen := map[string]bool{}
	var walk func(r *parsedRule, e *expr) error
	walk = func(r *parsedRule, e *expr) error {
		if e == nil {
			return nil
		}
		if e.kind == kindRuleSet {
			if _, ok := declared[e.provider]; !ok {
				return &UndeclaredProviderError{Index: r.index, Line: r.line, Name: e.provider}
			}
			if !seen[e.provider] {
				seen[e.provider] = true
				used = append(used, e.provider)
			}
		}
		for _, c := range e.children {
			if err := walk(r, c); err != nil {
				return err
			}
		}
		return walk(r, e.guard)
	}
	for _, r := range rules {
		if err := walk(r, r.expr); err != nil {
			return nil, err
		}
	}
	return used, nil
}

func parseRuleList(rules []Rule) ([]*parsedRule, error) {
	parsed := make([]*parsedRule, 0, len(rules))
	for _, r := range rules {
		p, err := parseRule(r)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, p)
	}
	return parsed, nil
}

func (l *lowerer) lowerTop(rules []*parsedRule) (*LoweredRules, error) {
	out := &LoweredRules{}
	var all []*outRule
	for _, rule := range rules {
		l.cur = rule
		remaining := l.limit - len(all)
		if remaining <= 0 {
			l.record(EventSkip, "", fmt.Sprintf("expanded routing rules exceed %d", l.limit))
			break
		}
		lowered, err := l.lowerRule(rule, remaining)
		var unsup *unsupportedError
		switch {
		case errors.As(err, &unsup):
			l.record(EventSkip, err.Error(), err.Error())
			continue
		case err != nil:
			return nil, err
		}
		for _, r := range lowered {
			all = l.appendCompact(all, r)
		}
	}
	// A MATCH is a first-match catch-all: it becomes the fallback and any
	// later rule is unreachable.
	for _, item := range all {
		rule := item.rule
		if item.ordered != nil {
			f, err := encodeOrdered(item.ordered)
			if err != nil {
				return nil, err
			}
			rule.AndFunctions = []*config_parser.Function{f}
		}
		if len(rule.AndFunctions) == 0 {
			if out.Fallback == "" {
				out.Fallback = rule.Outbound.Name
			}
			continue
		}
		if out.Fallback != "" {
			continue
		}
		out.Rules = append(out.Rules, rule)
	}
	out.Events = l.events
	return out, nil
}

func (l *lowerer) lowerRule(rule *parsedRule, limit int) ([]*outRule, error) {
	e, err := l.ruleOptions(rule.expr, rule.action)
	if err != nil {
		return nil, err
	}
	// Mihomo ignores action-level options on outer logical rules.
	if rule.action.hasOption("no-resolve") && (e.kind == kindAtom || e.kind == kindRuleSet) {
		c := *e
		c.noResolve = true
		e = &c
	}

	if needsOrdered(e, false) {
		oe, err := l.ordered(e, false, false)
		if err != nil {
			return nil, err
		}
		out, err := l.action(rule.action)
		if err != nil {
			return nil, err
		}
		return []*outRule{{rule: &config_parser.RoutingRule{Outbound: *out}, ordered: oe}}, nil
	}

	terms, err := l.terms(e, false, limit)
	if err != nil {
		return nil, err
	}
	out, err := l.action(rule.action)
	if err != nil {
		return nil, err
	}
	if len(terms) > limit {
		return nil, unsupported("expanded routing rules exceed %d", limit)
	}
	rules := make([]*outRule, 0, len(terms))
	for _, term := range terms {
		rules = append(rules, &outRule{rule: &config_parser.RoutingRule{AndFunctions: term, Outbound: *out}})
	}
	return rules, nil
}

// encodeOrdered turns an ordered tree into the function placed in a rule: a
// bare atom stays a plain function, anything else becomes route_expr.
func encodeOrdered(oe *routing.OrderedExpr) (*config_parser.Function, error) {
	// A negated rule set cannot stay a bare function: the provider loader
	// expands a plain ruleset() into alternatives, which a negation cannot
	// distribute over, but it does handle the negation inside route_expr.
	negatedSet := oe.Op == "atom" && oe.Atom.Not && (oe.Atom.Name == "ruleset" || oe.Atom.Name == "ruleset_no_resolve")
	if oe.Op == "atom" && oe.MemoID == 0 && !negatedSet {
		return oe.Atom, nil
	}
	return routing.EncodeOrderedExpr(oe)
}

// needsOrdered reports whether the expression must keep its evaluation order
// and structure (route_expr): a no-resolve predicate makes resolving the
// destination observable, and a negated rule set cannot be spelled as a flat
// rule.
func needsOrdered(e *expr, negated bool) bool {
	if e.noResolve || e.memoID != 0 {
		return true
	}
	switch e.kind {
	case kindAtom:
		return e.atom != nil && isSourceIPAtom(e.atom.typ) && e.atom.hasOption("no-resolve")
	case kindRuleSet:
		return negated
	case kindNot:
		return needsOrdered(e.children[0], !negated)
	case kindAnd, kindOr:
		for _, c := range e.children {
			if needsOrdered(c, negated) {
				return true
			}
		}
	}
	return false
}

// neverMatches reports an atom that lowers to "no terms": IN-PORT and IP-ASN
// depend on runtime data that is not modeled, so terms() treats them as a
// branch that never matches, negated or not.
func neverMatches(e *expr) bool {
	if e.kind != kindAtom || e.atom == nil || e.memoID != 0 {
		return false
	}
	typ := strings.ToUpper(e.atom.typ)
	return typ == "IN-PORT" || typ == "IP-ASN"
}

// hasLiveBranch reports whether at least one branch can match. An OR whose
// branches never match keeps them all, so the rule still has an atom.
func hasLiveBranch(children []*expr) bool {
	for _, c := range children {
		if !neverMatches(c) {
			return true
		}
	}
	return false
}

// withoutAlwaysTrue drops the MATCH conjuncts of an AND. Lowering spells an
// unconditional MATCH as port(0-65535), which costs a match entry in every
// routing walk and is not a real transport predicate. When every conjunct is
// MATCH the list is returned unchanged so the rule keeps one atom.
func withoutAlwaysTrue(children []*expr, negated bool) []*expr {
	kept := make([]*expr, 0, len(children))
	for _, c := range children {
		if !negated && c.kind == kindAtom && c.memoID == 0 && !c.noResolve &&
			c.atom != nil && strings.EqualFold(c.atom.typ, "MATCH") {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		return children
	}
	return kept
}

type term []*config_parser.Function

// terms lowers e to a disjunction of conjunctions. An empty result is "never
// matches"; one empty term is "always matches".
func (l *lowerer) terms(e *expr, negated bool, limit int) ([]term, error) {
	switch e.kind {
	case kindAtom:
		switch typ := strings.ToUpper(e.atom.typ); {
		case typ == "IN-PORT" || typ == "IP-ASN":
			// Depends on runtime data that is deliberately not modeled: treat
			// the condition as a branch that never matches.
			l.record(EventIgnore, typ, fmt.Sprintf("atom %q", typ))
			return nil, nil
		case typ == "MATCH":
			if negated {
				return nil, unsupported("NOT MATCH has no exact kdae routing equivalent")
			}
			return []term{{}}, nil
		}
		f, err := l.lowerAtom(*e.atom, negated)
		if err != nil {
			return nil, err
		}
		return []term{{f}}, nil

	case kindRuleSet:
		if negated {
			return nil, unsupported("NOT RULE-SET cannot be represented exactly")
		}
		safe, ok := l.env.Providers[e.provider]
		if !ok || strings.TrimSpace(safe) == "" {
			return nil, unsupported("RULE-SET provider %q has no safe provider mapping", e.provider)
		}
		return []term{{{Name: "ruleset", Params: []*config_parser.Param{{Val: safe}}}}}, nil

	case kindSubRule:
		return nil, unsupported("SUB-RULE expression must be expanded before lowering")

	case kindNot:
		return l.terms(e.children[0], !negated, limit)

	case kindAnd, kindOr:
		// De Morgan: a negated AND is an OR of negated children and vice versa.
		conjunction := (e.kind == kindAnd) != negated
		if conjunction {
			result := []term{{}}
			for _, c := range e.children {
				t, err := l.terms(c, negated, limit)
				if err != nil {
					return nil, err
				}
				if result, err = combine(result, t, limit); err != nil {
					return nil, err
				}
			}
			return result, nil
		}
		var result []term
		for _, c := range e.children {
			t, err := l.terms(c, negated, limit-len(result))
			if err != nil {
				return nil, err
			}
			for _, item := range t {
				result = l.appendTerm(result, item)
				if len(result) > limit {
					return nil, unsupported("expanded routing rules exceed %d", limit)
				}
			}
		}
		return result, nil
	}
	return nil, unsupported("unknown expression kind")
}

func combine(left, right []term, limit int) ([]term, error) {
	if len(left) == 0 || len(right) == 0 {
		return []term{}, nil
	}
	if len(left) > limit/len(right) {
		return nil, unsupported("expanded routing rules exceed %d", limit)
	}
	out := make([]term, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			t := make(term, 0, len(a)+len(b))
			t = append(append(t, a...), b...)
			out = append(out, t)
		}
	}
	return out, nil
}

// ordered builds the evaluation-order-preserving form used for route_expr.
func (l *lowerer) ordered(e *expr, inhibit, negated bool) (*routing.OrderedExpr, error) {
	if e.memoID != 0 {
		// A SUB-RULE guard: build it once, tag it with the call's memo id,
		// and apply any negation around the tagged node.
		id := e.memoID
		c := *e
		c.memoID = 0
		result, err := l.ordered(&c, inhibit, false)
		if err != nil {
			return nil, err
		}
		if result.MemoID != 0 {
			// The guard folded down to a node that already carries a memo id
			// (a nested SUB-RULE guard). Keep both ids by tagging a wrapper.
			result = &routing.OrderedExpr{Op: "and", Children: []*routing.OrderedExpr{result}}
		}
		result.MemoID = id
		if negated {
			result = &routing.OrderedExpr{Op: "not", Children: []*routing.OrderedExpr{result}}
		}
		return result, nil
	}
	inhibit = inhibit || e.noResolve
	switch e.kind {
	case kindNot:
		return l.ordered(e.children[0], inhibit, !negated)
	case kindAnd, kindOr:
		op := "and"
		if (e.kind == kindOr) != negated {
			op = "or"
		}
		out := &routing.OrderedExpr{Op: op}
		children, dropFalse := e.children, false
		switch op {
		case "and":
			children = withoutAlwaysTrue(children, negated)
		case "or":
			dropFalse = hasLiveBranch(children)
		}
		for _, c := range children {
			if dropFalse && neverMatches(c) {
				// `X OR false` is X. terms() is what reports the ignored atom,
				// so call it for the event and keep the branch out of the tree.
				if _, err := l.terms(c, negated, 1); err != nil {
					return nil, err
				}
				continue
			}
			child, err := l.ordered(c, inhibit, negated)
			if err != nil {
				return nil, err
			}
			out.Children = append(out.Children, child)
		}
		if len(out.Children) == 1 {
			// `X AND true` is X. The memo branch above wraps a result that
			// already carries a memo id before it tags it.
			return out.Children[0], nil
		}
		return out, nil
	case kindAtom:
		ts, err := l.terms(e, negated, 1)
		if err != nil {
			return nil, err
		}
		// No terms: constant false. One empty term (MATCH): constant true.
		f := &config_parser.Function{Name: "port", Not: len(ts) == 0, Params: []*config_parser.Param{{Val: "0-65535"}}}
		if len(ts) != 0 && len(ts[0]) != 0 {
			f = ts[0][0]
		}
		if inhibit && (f.Name == "dip" || f.Name == "ip") {
			f.Name = "ip_no_resolve"
		}
		return &routing.OrderedExpr{Op: "atom", Atom: f}, nil
	case kindRuleSet:
		safe, ok := l.env.Providers[e.provider]
		if !ok {
			return nil, unsupported("unknown provider %s", e.provider)
		}
		name := "ruleset"
		if inhibit {
			name = "ruleset_no_resolve"
		}
		return &routing.OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: name, Not: negated, Params: []*config_parser.Param{{Val: safe}}}}, nil
	}
	return nil, unsupported("unsupported ordered expression")
}

func (l *lowerer) action(a action) (*config_parser.Function, error) {
	target := strings.TrimSpace(a.target)
	if target == "" || strings.EqualFold(target, "MATCH") {
		return nil, unsupported("action target does not identify an outbound")
	}
	switch strings.ToUpper(target) {
	case "DIRECT":
		return &config_parser.Function{Name: "direct"}, nil
	case "REJECT", "REJECT-DROP":
		// Compatibility policy: silently dropping is lowered to block.
		return &config_parser.Function{Name: "block"}, nil
	}
	name, ok := l.env.Outbounds[target]
	if !ok || strings.TrimSpace(name) == "" {
		return nil, unsupported("outbound %q has no safe outbound mapping", target)
	}
	return &config_parser.Function{Name: name}, nil
}

// ---- atoms ----

func (l *lowerer) lowerAtom(a atom, negated bool) (*config_parser.Function, error) {
	if len(a.args) == 0 {
		return nil, unsupported("Mihomo atom %q has no value", a.typ)
	}
	value := a.args[0]
	typ := strings.ToUpper(a.typ)
	options, err := l.atomOptions(typ, a.options())
	if err != nil {
		return nil, err
	}
	if typ == "DOMAIN-WILDCARD" {
		re, err := routing.WildcardDomainRegex(value)
		if err != nil {
			return nil, unsupported("%v", err)
		}
		value = re
	}
	if strings.TrimSpace(value) == "" {
		return nil, unsupported("Mihomo atom %q has an empty value", a.typ)
	}
	params := []*config_parser.Param{{Val: value}}
	param := params[0]

	var name, key string
	switch typ {
	case "DOMAIN":
		name, key = "domain", "full"
	case "DOMAIN-SUFFIX":
		name, key = "domain", "suffix"
	case "DOMAIN-KEYWORD":
		name, key = "domain", "keyword"
	case "DOMAIN-REGEX", "DOMAIN-WILDCARD":
		name, key = "domain", "regex"
	case "IP-CIDR":
		name = "dip"
	case "IP-CIDR6":
		name = "ip"
	case "SRC-IP-CIDR":
		name = "sip"
	case "DST-PORT":
		name = "dport"
	case "SRC-PORT":
		name = "sport"
	case "NETWORK":
		name = "l4proto"
		v := strings.ToLower(param.Val)
		if v != "tcp" && v != "udp" {
			return nil, unsupported("unsupported NETWORK value %q", param.Val)
		}
		param.Val = v
	case "PROCESS-NAME":
		name = "pname"
	case "SRC-MAC":
		// Fork rule type. The payload is one or more MAC addresses joined by
		// "/", compared case-insensitively. Negation is not exact: for traffic
		// whose MAC is unknown, NOT(SRC-MAC) matches in Mihomo, while dae's
		// negated mac() deliberately excludes unknown MACs.
		if negated {
			return nil, unsupported("NOT SRC-MAC has no exact kdae equivalent")
		}
		macs, err := parseSrcMAC(value)
		if err != nil {
			return nil, err
		}
		name = "mac"
		params = params[:0]
		for _, m := range macs {
			params = append(params, &config_parser.Param{Val: m})
		}
	case "DSCP":
		// The 6-bit DSCP of the IP header, which is what dae's dscp reads.
		// Mihomo's payload is a list of numbers and ranges (46, 0-10/46).
		values, err := parseDSCP(value)
		if err != nil {
			return nil, err
		}
		name = "dscp"
		params = params[:0]
		for _, v := range values {
			params = append(params, &config_parser.Param{Val: strconv.Itoa(v)})
		}
	default:
		return nil, unsupported("unsupported Mihomo atom %q", a.typ)
	}
	if hasOption(options, "src") && (typ == "IP-CIDR" || typ == "IP-CIDR6") {
		name = "sip"
	}
	if (name == "ip" || name == "dip") && hasOption(options, "no-resolve") {
		name = "ip_no_resolve"
	}
	if key != "" {
		param.Key = key
		if key == "full" || key == "suffix" || key == "keyword" {
			param.Val = strings.ToLower(strings.TrimSpace(param.Val))
		}
	}
	if hasOption(options, "match-mac") {
		if name == "sip" {
			if param.Key == "" {
				param.Key = "match_mac"
			}
		} else {
			// IP-CIDR without src: the fork ignores it and keeps the rule.
			l.ignoredOption("match-mac", "only source IP rules read it")
		}
	}
	return &config_parser.Function{Name: name, Not: negated, Params: params}, nil
}

// atomOptions returns the options that mean something for this atom type and
// records the others as ignored: Mihomo reads no-resolve and src for IP rules
// only, and the deployed fork's match-mac only modifies a source-IP rule.
func (l *lowerer) atomOptions(typ string, options []string) ([]string, error) {
	var applicable []string
	for _, option := range options {
		option = strings.TrimSpace(option)
		switch {
		case strings.EqualFold(option, "match-mac"), strings.EqualFold(option, "no-resolve"), strings.EqualFold(option, "src"):
			if isSourceIPAtom(typ) {
				applicable = append(applicable, option)
			} else {
				l.ignoredOption(option, "applies to IP rules only")
			}
		default:
			l.ignoredOption(option, "unknown to Mihomo")
		}
	}
	return applicable, nil
}

// parseSrcMAC splits a SRC-MAC payload and returns the distinct addresses in
// canonical lower-case form.
func parseSrcMAC(payload string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(payload, "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, unsupported("source MAC couldn't be empty")
		}
		hw, err := net.ParseMAC(part)
		if err != nil || len(hw) != 6 {
			return nil, unsupported("invalid source MAC")
		}
		canonical := hw.String()
		if !seen[canonical] {
			seen[canonical] = true
			out = append(out, canonical)
		}
	}
	return out, nil
}

// parseDSCP expands a Mihomo DSCP payload ("46", "0-10/46", "10,20") to values.
func parseDSCP(payload string) ([]int, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" || payload == "*" {
		return nil, unsupported("DSCP matching every value has no exact kdae equivalent")
	}
	seen := map[int]bool{}
	var values []int
	for _, part := range strings.FieldsFunc(payload, func(r rune) bool { return r == '/' || r == ',' }) {
		lo, hi, isRange := strings.Cut(strings.Trim(part, "[ ]"), "-")
		start, err := strconv.Atoi(strings.Trim(lo, "[ ]"))
		if err != nil || start < 0 {
			return nil, unsupported("invalid DSCP value")
		}
		end := start
		if isRange {
			if end, err = strconv.Atoi(strings.Trim(hi, "[ ]")); err != nil || end < start {
				return nil, unsupported("invalid DSCP range")
			}
		}
		if end > 63 {
			return nil, unsupported("DSCP cannot exceed 63")
		}
		for v := start; v <= end; v++ {
			if !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
	}
	if len(values) == 0 {
		return nil, unsupported("invalid DSCP value")
	}
	return values, nil
}

// ---- rule options ----

func isSourceIPAtom(typ string) bool {
	switch strings.ToUpper(typ) {
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
		return true
	}
	return false
}

func acceptsMatchMac(a atom, srcFromAction bool) bool {
	switch strings.ToUpper(a.typ) {
	case "SRC-IP-CIDR":
		return true
	case "IP-CIDR", "IP-CIDR6":
		return srcFromAction || a.hasOption("src")
	}
	return false
}

func exprSearch(e *expr, match func(atom) bool) bool {
	switch e.kind {
	case kindAtom:
		return e.atom != nil && match(*e.atom)
	case kindNot, kindAnd, kindOr:
		for _, c := range e.children {
			if exprSearch(c, match) {
				return true
			}
		}
	}
	return false
}

// ruleOptions applies the options that follow a rule's outbound. Upstream
// Mihomo reads only no-resolve and src, and only for IP rules; every other
// option is ignored and the rule stays active. The same is done here, with an
// ignore event so the report shows what was dropped.
//
// src on a rule set is the exception: Mihomo honors it (the provider's
// addresses are matched against the source) and dae has no source-address form
// of a rule set, so that rule is skipped.
//
// match-mac is not in upstream Mihomo; the deployed fork (feat: extend source
// IP rules by MAC) reads it only as a source-IP modifier: SRC-IP-CIDR, or
// IP-CIDR/IP-CIDR6 together with src. On an IP-CIDR without src the fork
// ignores it and the rule stays a destination rule; on any other rule the
// parameter is unknown and ignored. The same is done here.
func (l *lowerer) ruleOptions(e *expr, a action) (*expr, error) {
	srcFromAction := a.hasOption("src")
	hasSourceIP := exprSearch(e, func(x atom) bool { return isSourceIPAtom(x.typ) })
	for _, option := range a.options {
		switch option = strings.TrimSpace(option); {
		case strings.EqualFold(option, "no-resolve"):
		case strings.EqualFold(option, "src"):
			switch {
			case hasSourceIP:
			case e.kind == kindRuleSet:
				return nil, unsupported("Mihomo rule option %q on a rule set has no exact kdae equivalent", option)
			default:
				l.ignoredOption(option, "applies to IP rules only")
			}
		case strings.EqualFold(option, "match-mac"):
			if !exprSearch(e, func(x atom) bool { return acceptsMatchMac(x, srcFromAction) }) {
				l.ignoredOption(option, "only source IP rules read it")
			}
		default:
			l.ignoredOption(option, "unknown to Mihomo")
		}
	}
	if hasOption(a.options, "src") && hasSourceIP {
		e = withOption(e, "src")
	}
	if hasOption(a.options, "match-mac") && exprSearch(e, func(x atom) bool { return acceptsMatchMac(x, false) }) {
		e = withOption(e, "match-mac")
	}
	return e, nil
}

func (l *lowerer) ignoredOption(option, why string) {
	l.record(EventIgnore, "option:"+strings.ToLower(option), fmt.Sprintf("option %q ignored (%s)", option, why))
}

// withOption returns e with option appended to every atom it applies to.
func withOption(e *expr, option string) *expr {
	switch e.kind {
	case kindAtom:
		if e.atom == nil {
			return e
		}
		applies := false
		switch option {
		case "match-mac":
			applies = acceptsMatchMac(*e.atom, false)
		case "src":
			applies = isSourceIPAtom(e.atom.typ)
		}
		if !applies || (len(e.atom.args) > 1 && hasOption(e.atom.args[1:], option)) {
			return e
		}
		c := *e
		a := *e.atom
		a.args = append(append([]string(nil), e.atom.args...), option)
		c.atom = &a
		return &c
	case kindNot, kindAnd, kindOr:
		c := *e
		c.children = make([]*expr, len(e.children))
		for i, child := range e.children {
			c.children[i] = withOption(child, option)
		}
		return &c
	}
	return e
}
