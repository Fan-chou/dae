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

// ErrScriptUnsupported marks an active SCRIPT rule. Script expressions are
// never evaluated, so a configuration that depends on one cannot be lowered.
var ErrScriptUnsupported = errors.New("Mihomo SCRIPT rules are unsupported")

type exprKind int

const (
	kindAtom exprKind = iota
	kindAnd
	kindOr
	kindNot
	kindRuleSet
	kindSubRule
)

// expr is a parsed rule condition. Only the field group matching kind is
// meaningful.
type expr struct {
	kind     exprKind
	children []*expr // and/or/not

	atom *atom // kindAtom

	provider string // kindRuleSet: original provider name

	subRule string // kindSubRule: referenced sub-rule name
	guard   *expr  // kindSubRule: condition inherited by the sub-rule's rules

	// noResolve is an explicit "do not resolve the destination" request on an
	// atom or rule set. Mihomo applies it to the condition, not the outbound.
	noResolve bool

	// memoID is non-zero on the guard of one SUB-RULE call: every rule
	// expanded from that call shares the guard's evaluation, so a guard with
	// side effects (resolving a name) is decided once per call.
	memoID int
}

func (e *expr) clone() *expr {
	if e == nil {
		return nil
	}
	c := *e
	if e.atom != nil {
		a := *e.atom
		a.args = append([]string(nil), e.atom.args...)
		c.atom = &a
	}
	c.children = make([]*expr, len(e.children))
	for i, child := range e.children {
		c.children[i] = child.clone()
	}
	c.guard = e.guard.clone()
	return &c
}

// atom is one leaf condition: typ is upper-case and args[0] is the match
// value; the remaining args are Mihomo condition parameters (no-resolve, src,
// match-mac) kept in source order rather than discarded.
type atom struct {
	typ  string
	args []string
}

func (a atom) value() string {
	if len(a.args) == 0 {
		return ""
	}
	return a.args[0]
}

func (a atom) options() []string {
	if len(a.args) < 2 {
		return nil
	}
	return a.args[1:]
}

func (a atom) hasOption(name string) bool { return hasOption(a.options(), name) }

type action struct {
	target  string
	options []string
}

func (a action) hasOption(name string) bool { return hasOption(a.options, name) }

// parsedRule is one rule or sub-rule item with its source position.
type parsedRule struct {
	index, line int
	raw         string
	expr        *expr
	action      action
	// isSubRule is set for SUB-RULE entries: they have no outbound action.
	isSubRule bool
}

// ParseError is a rule that is not valid Mihomo syntax. It is fatal for the
// whole conversion, unlike a rule that parses but cannot be lowered.
type ParseError struct {
	Index, Line int
	Reason      string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("parse Mihomo rule at index %d line %d: %s", e.Index, e.Line, e.Reason)
}

// ScriptError reports an active SCRIPT rule.
type ScriptError struct {
	Index, Line int
	Shortcut    string
}

func (e *ScriptError) Error() string {
	if e.Shortcut == "" {
		return fmt.Sprintf("parse Mihomo rule at index %d line %d: SCRIPT is unsupported", e.Index, e.Line)
	}
	return fmt.Sprintf("parse Mihomo rule at index %d line %d: SCRIPT %q is unsupported", e.Index, e.Line, e.Shortcut)
}

func (e *ScriptError) Unwrap() error { return ErrScriptUnsupported }

func parseRule(r Rule) (*parsedRule, error) {
	fail := func(reason string) error { return &ParseError{Index: r.Index, Line: r.Line, Reason: reason} }
	fields, err := splitFields(r.Raw)
	if err != nil {
		return nil, fail(err.Error())
	}
	for i := range fields {
		fields[i] = unquote(fields[i])
		if fields[i] == "" {
			return nil, fail("empty rule field")
		}
	}
	rule := &parsedRule{index: r.Index, line: r.Line, raw: r.Raw}
	switch typ := strings.ToUpper(fields[0]); typ {
	case "SCRIPT":
		return nil, scriptError(r, fields[1:])

	case "AND", "OR", "NOT":
		if len(fields) < 3 {
			return nil, fail(typ + " rule requires condition and action")
		}
		// One expression payload; any further fields are action options.
		e, err := parseLogic(typ, fields[1], r)
		if err != nil {
			return nil, asParseError(r, err)
		}
		act, err := parseAction(fields[2], fields[3:])
		if err != nil {
			return nil, fail(err.Error())
		}
		rule.expr, rule.action = e, act

	case "RULE-SET":
		if len(fields) < 3 {
			return nil, fail("RULE-SET rule requires provider and action")
		}
		act, err := parseAction(fields[2], fields[3:])
		if err != nil {
			return nil, fail(err.Error())
		}
		rule.expr = &expr{kind: kindRuleSet, provider: fields[1]}
		rule.action = act

	case "SUB-RULE":
		if len(fields) < 3 {
			return nil, fail("SUB-RULE requires guard and sub-rule name")
		}
		guard, err := parseExpression(fields[1], r)
		if err != nil {
			return nil, asParseError(r, err)
		}
		// The third field is the referenced sub-rule, not an outbound; any
		// extension fields are kept as options instead of being dropped.
		rule.expr = &expr{kind: kindSubRule, subRule: fields[2], guard: guard}
		rule.action = action{options: append([]string(nil), fields[3:]...)}
		rule.isSubRule = true

	case "MATCH":
		if len(fields) < 2 {
			return nil, fail("MATCH rule requires action")
		}
		act, err := parseAction(fields[1], fields[2:])
		if err != nil {
			return nil, fail(err.Error())
		}
		rule.expr = &expr{kind: kindAtom, atom: &atom{typ: "MATCH"}}
		rule.action = act

	default:
		if len(fields) < 3 {
			return nil, fail(typ + " rule requires condition and action")
		}
		act, err := parseAction(fields[2], fields[3:])
		if err != nil {
			return nil, fail(err.Error())
		}
		rule.expr = &expr{kind: kindAtom, atom: &atom{typ: typ, args: unquoteAll(fields[1:2])}}
		rule.action = act
	}
	return rule, nil
}

func parseExpression(raw string, r Rule) (*expr, error) {
	fields, err := splitFields(raw)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		fields[i] = unquote(fields[i])
		if fields[i] == "" {
			return nil, errors.New("empty condition field")
		}
	}
	if len(fields) == 1 && isWrapped(fields[0]) {
		return parseExpression(fields[0][1:len(fields[0])-1], r)
	}
	switch typ := strings.ToUpper(fields[0]); typ {
	case "SCRIPT":
		return nil, scriptError(r, fields[1:])
	case "AND", "OR", "NOT":
		if len(fields) != 2 {
			return nil, fmt.Errorf("nested %s condition requires one expression payload", typ)
		}
		return parseLogic(typ, fields[1], r)
	case "RULE-SET":
		if len(fields) < 2 || fields[1] == "" {
			return nil, errors.New("RULE-SET condition requires provider")
		}
		for _, option := range fields[2:] {
			if option != "no-resolve" {
				return nil, errors.New("unsupported RULE-SET condition parameter")
			}
		}
		return &expr{kind: kindRuleSet, provider: fields[1], noResolve: len(fields) > 2}, nil
	case "SUB-RULE":
		if len(fields) != 3 || fields[2] == "" {
			return nil, errors.New("SUB-RULE condition requires guard and sub-rule name")
		}
		guard, err := parseExpression(fields[1], r)
		if err != nil {
			return nil, err
		}
		return &expr{kind: kindSubRule, subRule: fields[2], guard: guard}, nil
	default:
		if len(fields) < 2 {
			return nil, fmt.Errorf("%s condition requires a value", typ)
		}
		// Keep the whole payload: for a known atom the first field is the
		// value and the rest are condition parameters, so nested no-resolve
		// or match-mac neither become extra match values nor disappear.
		return &expr{kind: kindAtom, atom: &atom{typ: typ, args: unquoteAll(fields[1:])}}, nil
	}
}

func parseLogic(typ, raw string, r Rule) (*expr, error) {
	payload := unquote(raw)
	if !isWrapped(payload) {
		return nil, fmt.Errorf("%s condition payload must be parenthesized", typ)
	}
	parts, err := splitFields(payload[1 : len(payload)-1])
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("%s condition has empty payload", typ)
	}
	children := make([]*expr, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return nil, fmt.Errorf("%s condition has empty child", typ)
		}
		child, err := parseExpression(part, r)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	kind := kindAnd
	switch typ {
	case "OR":
		kind = kindOr
	case "NOT":
		kind = kindNot
		if len(children) != 1 {
			return nil, errors.New("NOT condition requires exactly one child")
		}
	}
	return &expr{kind: kind, children: children}, nil
}

func parseAction(target string, options []string) (action, error) {
	target = unquote(target)
	if target == "" {
		return action{}, errors.New("empty action target")
	}
	clean := make([]string, len(options))
	for i, option := range options {
		clean[i] = unquote(option)
		if clean[i] == "" {
			return action{}, errors.New("empty action option")
		}
	}
	return action{target: target, options: clean}, nil
}

func scriptError(r Rule, fields []string) error {
	shortcut := ""
	if len(fields) > 0 {
		shortcut = unquote(fields[0])
	}
	return &ScriptError{Index: r.Index, Line: r.Line, Shortcut: shortcut}
}

// asParseError attaches the rule position to errors from nested parsing while
// leaving a script error intact.
func asParseError(r Rule, err error) error {
	var script *ScriptError
	if errors.As(err, &script) {
		return err
	}
	return &ParseError{Index: r.Index, Line: r.Line, Reason: err.Error()}
}

// unquoteAll unquotes atom arguments a second time, as the field splitter
// already did once: a doubly quoted value is a literal quoted string.
func unquoteAll(fields []string) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = unquote(f)
	}
	return out
}

func hasOption(options []string, name string) bool {
	for _, option := range options {
		if strings.EqualFold(strings.TrimSpace(option), name) {
			return true
		}
	}
	return false
}

// splitFields splits on top-level commas, honoring quotes and parentheses.
func splitFields(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("empty rule field")
	}
	var fields []string
	start, depth := 0, 0
	var quote byte
	escaped := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote != 0 {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, errors.New("unexpected closing parenthesis")
			}
		case ',':
			if depth == 0 {
				field := strings.TrimSpace(raw[start:i])
				if field == "" {
					return nil, errors.New("empty rule field")
				}
				fields = append(fields, field)
				start = i + 1
			}
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote")
	}
	if depth != 0 {
		return nil, errors.New("unclosed parentheses")
	}
	last := strings.TrimSpace(raw[start:])
	if last == "" {
		return nil, errors.New("empty rule field")
	}
	return append(fields, last), nil
}

// unquote trims a field and strips one pair of matching quotes, resolving
// \\ and an escaped quote of the same kind.
func unquote(field string) string {
	field = strings.TrimSpace(field)
	if len(field) < 2 || (field[0] != '\'' && field[0] != '"') || field[len(field)-1] != field[0] {
		return field
	}
	quote := field[0]
	body := field[1 : len(field)-1]
	var out strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) && (body[i+1] == quote || body[i+1] == '\\') {
			out.WriteByte(body[i+1])
			i++
			continue
		}
		out.WriteByte(body[i])
	}
	return out.String()
}

// isWrapped reports whether value is one parenthesized group spanning the
// whole string.
func isWrapped(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
		return false
	}
	depth := 0
	var quote byte
	escaped := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if quote != 0 {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(value)-1 {
				return false
			}
		}
	}
	return quote == 0 && depth == 0
}
