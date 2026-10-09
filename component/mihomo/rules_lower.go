/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"errors"
	"fmt"
	"regexp"
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
	expanded, err := expandSubRules(top, defs)
	if err != nil {
		return nil, err
	}
	l := newLowerer(env)
	l.noCompact = noCompact
	return l.lowerTop(expanded)
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
	if err := validateRuleOptions(rule.expr, rule.action); err != nil {
		return nil, err
	}
	e, err := applyRuleOptions(rule.expr, rule.action.options)
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
	if oe.Op == "atom" && oe.MemoID == 0 {
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
		return e.atom != nil && e.atom.hasOption("no-resolve")
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
		f, err := lowerAtom(*e.atom, negated)
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
		for _, c := range e.children {
			child, err := l.ordered(c, inhibit, negated)
			if err != nil {
				return nil, err
			}
			out.Children = append(out.Children, child)
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

func lowerAtom(a atom, negated bool) (*config_parser.Function, error) {
	if len(a.args) == 0 {
		return nil, unsupported("Mihomo atom %q has no value", a.typ)
	}
	value, options := a.args[0], a.options()
	if err := validateAtomOptions(a.typ, options); err != nil {
		return nil, err
	}
	typ := strings.ToUpper(a.typ)
	if typ == "DOMAIN-WILDCARD" {
		re, err := wildcardRegex(value)
		if err != nil {
			return nil, err
		}
		value = re
	}
	if strings.TrimSpace(value) == "" {
		return nil, unsupported("Mihomo atom %q has an empty value", a.typ)
	}
	param := &config_parser.Param{Val: value}

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
		if name != "sip" {
			return nil, unsupported("Mihomo atom %q option %q requires a source IP matcher", a.typ, "match-mac")
		}
		if param.Key == "" {
			param.Key = "match_mac"
		}
	}
	return &config_parser.Function{Name: name, Not: negated, Params: []*config_parser.Param{param}}, nil
}

func validateAtomOptions(typ string, options []string) error {
	typ = strings.ToUpper(typ)
	isIP := typ == "IP-CIDR" || typ == "IP-CIDR6" || typ == "SRC-IP-CIDR"
	for _, option := range options {
		switch option = strings.TrimSpace(option); {
		case strings.EqualFold(option, "no-resolve"), strings.EqualFold(option, "match-mac"):
			if !isIP {
				return unsupported("Mihomo atom %q option %q has no exact kdae equivalent", typ, option)
			}
		case strings.EqualFold(option, "src"):
			if typ != "IP-CIDR" && typ != "IP-CIDR6" && typ != "SRC-IP-CIDR" {
				return unsupported("Mihomo atom %q option %q has no exact kdae equivalent", typ, option)
			}
		default:
			return unsupported("unsupported Mihomo atom %q option %q", typ, option)
		}
	}
	return nil
}

// wildcardRegex converts Mihomo's DOMAIN-WILDCARD (* and ?) to the anchored
// full-string regex dae's domain matcher takes. Domains are matched in lower
// case, so the pattern is lowered before its literals are quoted.
func wildcardRegex(pattern string) (string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", unsupported("DOMAIN-WILDCARD has an empty pattern")
	}
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range strings.ToLower(pattern) {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return b.String(), nil
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

func validateRuleOptions(e *expr, a action) error {
	srcFromAction := a.hasOption("src")
	for _, option := range a.options {
		switch option = strings.TrimSpace(option); {
		case strings.EqualFold(option, "no-resolve"):
		case strings.EqualFold(option, "src"):
			if !exprSearch(e, func(x atom) bool { return isSourceIPAtom(x.typ) }) {
				return unsupported("Mihomo rule option %q has no source IP matcher", option)
			}
		case strings.EqualFold(option, "match-mac"):
			if !exprSearch(e, func(x atom) bool { return acceptsMatchMac(x, srcFromAction) }) {
				return unsupported("Mihomo rule option %q has no source IP matcher", option)
			}
		default:
			return unsupported("unsupported Mihomo rule option %q", option)
		}
	}
	return nil
}

func applyRuleOptions(e *expr, options []string) (*expr, error) {
	if hasOption(options, "src") {
		if !exprSearch(e, func(x atom) bool { return isSourceIPAtom(x.typ) }) {
			return nil, unsupported("Mihomo rule option %q has no source IP matcher", "src")
		}
		e = withOption(e, "src")
	}
	if hasOption(options, "match-mac") {
		if !exprSearch(e, func(x atom) bool { return acceptsMatchMac(x, false) }) {
			return nil, unsupported("Mihomo rule option %q has no source IP matcher", "match-mac")
		}
		e = withOption(e, "match-mac")
	}
	return e, nil
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
