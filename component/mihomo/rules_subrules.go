/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// MaxSubRuleDepth bounds nested SUB-RULE calls from a top-level rule.
	MaxSubRuleDepth = 32
	// MaxCompiledRules bounds the rules after expansion, ordinary top-level
	// rules included. It only protects the converter from a hostile document;
	// the budget that matters for dae is DefaultMaxExpandedRules, applied to
	// the rules that remain after adjacent ones are merged.
	MaxCompiledRules = 50000
)

// Sentinels for SubRuleError.Kind. A document that trips one of these cannot
// be converted at all, unlike a rule that is merely skipped.
var (
	ErrSubRuleUndefined = errors.New("undefined Mihomo sub-rule")
	ErrSubRuleCycle     = errors.New("Mihomo sub-rule cycle")
	ErrSubRuleEmpty     = errors.New("empty Mihomo sub-rule")
	ErrSubRuleDepth     = errors.New("Mihomo sub-rule expansion depth exceeded")
	ErrSubRuleLimit     = errors.New("Mihomo sub-rule expansion limit exceeded")
	ErrSubRuleEmbedded  = errors.New("embedded Mihomo SUB-RULE is not representable")
	ErrSubRuleCall      = errors.New("invalid Mihomo SUB-RULE call")
)

// SubRuleError locates the call or rule that made expansion fail.
type SubRuleError struct {
	Index, Line int
	Name        string
	Reason      string
	Kind        error
}

func (e *SubRuleError) Error() string {
	name := ""
	if e.Name != "" {
		name = fmt.Sprintf(" %q", e.Name)
	}
	return fmt.Sprintf("compile Mihomo sub-rule%s at index %d line %d: %s", name, e.Index, e.Line, e.Reason)
}

func (e *SubRuleError) Unwrap() error { return e.Kind }

type parsedSubRule struct {
	name  string
	line  int
	rules []*parsedRule
}

type expander struct {
	defs    map[string]*parsedSubRule
	emitted int
	memo    int
}

// expandSubRules inlines every SUB-RULE call reachable from the top-level
// rules. A call's guard becomes an inherited condition of each rule in the
// called sub-rule, evaluated once per call (memoID). Definitions nobody
// calls are ignored.
//
// SUB-RULE is only valid as a whole top-level rule or sub-rule line. Mihomo
// itself refuses to load one nested inside AND/OR/NOT ("unsupported rule type
// [SUB-RULE] on logic rule"): a sub-rule selects an outbound, so it has no
// meaning as a yes/no condition. There is no reference behavior to preserve,
// so such a rule is rejected rather than given an invented meaning. (A
// SUB-RULE's own guard may of course be an AND/OR/NOT expression.)
func expandSubRules(top []*parsedRule, defs map[string]*parsedSubRule) ([]*parsedRule, error) {
	x := &expander{defs: defs}
	out := make([]*parsedRule, 0, len(top))
	for _, rule := range top {
		if rule.expr.kind == kindSubRule {
			expanded, err := x.call(rule, nil, 1, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, expanded...)
			continue
		}
		if err := rejectEmbedded(rule); err != nil {
			return nil, err
		}
		if err := x.emit(rule); err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

func (x *expander) call(call *parsedRule, inherited *expr, depth int, path []string) ([]*parsedRule, error) {
	fail := func(kind error, name, format string, args ...any) error {
		return &SubRuleError{Index: call.index, Line: call.line, Name: name, Reason: fmt.Sprintf(format, args...), Kind: kind}
	}
	name := call.expr.subRule
	if strings.TrimSpace(name) == "" {
		return nil, fail(ErrSubRuleUndefined, "", "SUB-RULE expression has no referenced name")
	}
	if call.action.target != "" || len(call.action.options) != 0 {
		return nil, fail(ErrSubRuleCall, name, "SUB-RULE call cannot carry an action or options")
	}
	if containsSubRule(call.expr.guard) {
		return nil, fail(ErrSubRuleEmbedded, "", "SUB-RULE inside AND/OR/NOT is not valid Mihomo (it refuses to load such a rule: a sub-rule yields an outbound, not a yes/no condition)")
	}
	guard := combineGuards(inherited, call.expr.guard)
	x.memo++
	guard.memoID = x.memo
	return x.named(name, guard, depth, path, call)
}

func (x *expander) named(name string, guard *expr, depth int, path []string, call *parsedRule) ([]*parsedRule, error) {
	fail := func(kind error, index, line int, format string, args ...any) error {
		return &SubRuleError{Index: index, Line: line, Name: name, Reason: fmt.Sprintf(format, args...), Kind: kind}
	}
	if depth > MaxSubRuleDepth {
		return nil, fail(ErrSubRuleDepth, call.index, call.line, "maximum depth %d exceeded", MaxSubRuleDepth)
	}
	for _, ancestor := range path {
		if ancestor == name {
			cycle := append(append([]string(nil), path...), name)
			return nil, fail(ErrSubRuleCycle, call.index, call.line, "cycle detected: %s", strings.Join(cycle, " -> "))
		}
	}
	def, ok := x.defs[name]
	if !ok {
		return nil, fail(ErrSubRuleUndefined, call.index, call.line, "referenced sub-rule is not defined")
	}
	if len(def.rules) == 0 {
		return nil, fail(ErrSubRuleEmpty, 0, def.line, "referenced sub-rule has no rules")
	}

	next := append(append([]string(nil), path...), name)
	var out []*parsedRule
	for _, child := range def.rules {
		if child.expr.kind == kindSubRule {
			expanded, err := x.call(child, guard, depth+1, next)
			if err != nil {
				return nil, err
			}
			out = append(out, expanded...)
			continue
		}
		if err := rejectEmbedded(child); err != nil {
			return nil, err
		}
		leaf := *child
		leaf.expr = child.expr.clone()
		// The option belongs to the leaf's own predicate, so attach it before
		// the call guard turns the condition into an AND.
		if leaf.action.hasOption("no-resolve") && (leaf.expr.kind == kindAtom || leaf.expr.kind == kindRuleSet) {
			leaf.expr.noResolve = true
		}
		leaf.expr = combineGuards(guard, leaf.expr)
		if err := x.emit(&leaf); err != nil {
			return nil, err
		}
		out = append(out, &leaf)
	}
	return out, nil
}

func (x *expander) emit(rule *parsedRule) error {
	if x.emitted >= MaxCompiledRules {
		return &SubRuleError{Index: rule.index, Line: rule.line, Reason: fmt.Sprintf("expanded rules exceed %d", MaxCompiledRules), Kind: ErrSubRuleLimit}
	}
	x.emitted++
	return nil
}

func rejectEmbedded(rule *parsedRule) error {
	if !containsSubRule(rule.expr) {
		return nil
	}
	return &SubRuleError{
		Index: rule.index, Line: rule.line, Kind: ErrSubRuleEmbedded,
		Reason: "SUB-RULE inside AND/OR/NOT is not valid Mihomo (it refuses to load such a rule: a sub-rule yields an outbound, not a yes/no condition)",
	}
}

func containsSubRule(e *expr) bool {
	if e == nil {
		return false
	}
	if e.kind == kindSubRule {
		return true
	}
	for _, c := range e.children {
		if containsSubRule(c) {
			return true
		}
	}
	return false
}

// combineGuards returns inherited AND child as a fresh tree; with nothing
// inherited it is just a copy of child.
func combineGuards(inherited, child *expr) *expr {
	if inherited == nil {
		return child.clone()
	}
	return &expr{kind: kindAnd, children: []*expr{inherited.clone(), child.clone()}}
}
