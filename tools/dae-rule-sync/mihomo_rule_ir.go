package main

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// MihomoRuleSource identifies the original rule without changing its text.
// SourceIndex is relative to rules or to the containing sub-rule.
type MihomoRuleSource struct {
	SourceIndex int
	SourceLine  int
	Raw         string
}

// MihomoRuleIR is the ordered, typed representation of rules and sub-rules.
// ParseMihomoRuleIR leaves provider content unloaded; the provider binding
// layer may return the same IR shape with explicit provider-data expressions.
// No dae route is generated at this layer.
type MihomoRuleIR struct {
	Rules    []MihomoRuleIRRule
	SubRules []MihomoSubRuleIR
}

type MihomoRuleIRRule struct {
	MihomoRuleSource
	Expr MihomoExpr
	// CallTrace is empty for ordinary source rules. The sub-rule compiler
	// records calls from outermost to innermost while retaining the leaf rule's
	// own source metadata in MihomoRuleSource.
	CallTrace []MihomoSubRuleCall
	Action    MihomoAction
}

// MihomoSubRuleCall identifies one SUB-RULE edge used to produce an expanded
// leaf rule. Source is the call-site source, not the referenced definition's
// header source.
type MihomoSubRuleCall struct {
	Name   string
	Source MihomoRuleSource
	Guard  MihomoExpr
}

type MihomoSubRuleIR struct {
	Name        string
	SourceIndex int
	SourceLine  int
	Rules       []MihomoRuleIRRule
}

type MihomoExprKind string

const (
	MihomoExprAtom         MihomoExprKind = "atom"
	MihomoExprAnd          MihomoExprKind = "and"
	MihomoExprOr           MihomoExprKind = "or"
	MihomoExprNot          MihomoExprKind = "not"
	MihomoExprRuleSet      MihomoExprKind = "rule-set"
	MihomoExprProviderData MihomoExprKind = "provider-data"
	MihomoExprSubRule      MihomoExprKind = "sub-rule"
)

// MihomoExpr is a tagged expression tree. Exactly one of Atom, Children,
// ProviderRef, ProviderDataRef, or SubRuleRef is populated according to Kind.
type MihomoExpr struct {
	Kind            MihomoExprKind
	Raw             string
	Atom            *MihomoAtom
	Children        []MihomoExpr
	ProviderRef     *MihomoRuleSetRef
	ProviderDataRef *MihomoProviderDataRef
	SubRuleRef      *MihomoSubRuleRef
}

type MihomoAtom struct {
	// Type is upper-case for known and unknown atom types alike, so a later
	// capability lowerer can dispatch without reparsing the source text.
	Type  string
	Value string
	// Arguments preserves every field after Type in source order. For a known
	// atom the first argument is the match value and the remaining arguments
	// are Mihomo condition parameters (for example no-resolve or src); they
	// are deliberately kept here instead of being discarded or folded into
	// the value list. Unknown atoms retain all fields as well so an explicit
	// unsupported diagnostic can be produced later.
	Arguments []string
	Known     bool
	Raw       string
}

type MihomoRuleSetRef struct {
	Provider string
}

// MihomoProviderDataKind identifies the concrete data represented by a
// provider-data expression. Actions and source order remain on the enclosing
// rule/expression and are intentionally absent here.
type MihomoProviderDataKind string

const (
	MihomoProviderDataDomain MihomoProviderDataKind = "domain"
	MihomoProviderDataIPCIDR MihomoProviderDataKind = "ipcidr"
)

// MihomoProviderDataRef is the bound data behind one Mihomo RULE-SET. The
// ProviderCode is always the normalized safe provider name. DAT-backed data
// may omit the inline slices because generationDATSpec retains the complete
// payload for the later writer.
type MihomoProviderDataRef struct {
	ProviderCode    string
	Kind            MihomoProviderDataKind
	Domains         []DomainRule
	Prefixes        []netip.Prefix
	UseDAT          bool
	DATRelativePath string
}

// MihomoProviderRef is an alias kept as the provider-oriented name for the
// same RULE-SET leaf.
type MihomoProviderRef = MihomoRuleSetRef

type MihomoSubRuleRef struct {
	Name  string
	Guard MihomoExpr
}

type MihomoAction struct {
	Target string
	// Options contains the raw Mihomo parameters that follow the outbound
	// target. Mihomo applies these to the rule condition (for example
	// no-resolve), so lowerers must not assume they are outbound features.
	Options   []string
	NoResolve bool
}

var ErrMihomoRuleScriptUnsupported = errors.New("Mihomo SCRIPT rules are unsupported")

type MihomoRuleParseError struct {
	Source MihomoRuleSource
	Reason string
}

func (e *MihomoRuleParseError) Error() string {
	return fmt.Sprintf("parse Mihomo rule at index %d line %d: %s", e.Source.SourceIndex, e.Source.SourceLine, e.Reason)
}

type MihomoScriptUnsupportedError struct {
	Source   MihomoRuleSource
	Shortcut string
}

func (e *MihomoScriptUnsupportedError) Error() string {
	if e.Shortcut == "" {
		return fmt.Sprintf("parse Mihomo rule at index %d line %d: SCRIPT is unsupported", e.Source.SourceIndex, e.Source.SourceLine)
	}
	return fmt.Sprintf("parse Mihomo rule at index %d line %d: SCRIPT %q is unsupported", e.Source.SourceIndex, e.Source.SourceLine, e.Shortcut)
}

func (e *MihomoScriptUnsupportedError) Unwrap() error { return ErrMihomoRuleScriptUnsupported }

// ParseMihomoRuleIR parses both top-level rules and named sub-rules while
// preserving the source order already captured by ParseMihomoRoutingDocument.
func ParseMihomoRuleIR(document MihomoRoutingDocument) (MihomoRuleIR, error) {
	ir := MihomoRuleIR{
		Rules: make([]MihomoRuleIRRule, 0, len(document.Rules)),
	}
	for _, rule := range document.Rules {
		parsed, err := parseMihomoRuleIRRule(rule)
		if err != nil {
			return MihomoRuleIR{}, err
		}
		ir.Rules = append(ir.Rules, parsed)
	}

	subRules, err := orderedMihomoSubRules(document)
	if err != nil {
		return MihomoRuleIR{}, err
	}
	ir.SubRules = make([]MihomoSubRuleIR, 0, len(subRules))
	seenNames := make(map[string]struct{}, len(subRules))
	for _, subRule := range subRules {
		if _, exists := seenNames[subRule.Name]; exists {
			return MihomoRuleIR{}, fmt.Errorf("parse Mihomo sub-rules: duplicate sub-rule %q", subRule.Name)
		}
		seenNames[subRule.Name] = struct{}{}
		parsedSubRule := MihomoSubRuleIR{
			Name:        subRule.Name,
			SourceIndex: subRule.SourceIndex,
			SourceLine:  subRule.SourceLine,
			Rules:       make([]MihomoRuleIRRule, 0, len(subRule.Rules)),
		}
		for _, rule := range subRule.Rules {
			parsed, err := parseMihomoRuleIRRule(rule)
			if err != nil {
				return MihomoRuleIR{}, err
			}
			parsedSubRule.Rules = append(parsedSubRule.Rules, parsed)
		}
		ir.SubRules = append(ir.SubRules, parsedSubRule)
	}
	return ir, nil
}

func orderedMihomoSubRules(document MihomoRoutingDocument) ([]MihomoSubRule, error) {
	if len(document.SubRuleValues) > 0 {
		return append([]MihomoSubRule(nil), document.SubRuleValues...), nil
	}
	if len(document.SubRules) == 0 {
		return nil, nil
	}
	names := append([]string(nil), document.SubRuleOrder...)
	if len(names) == 0 {
		// A hand-built document without the ordered view cannot carry source
		// order. Sort as a deterministic compatibility fallback; documents
		// from ParseMihomoRoutingDocument always use SubRuleValues above.
		for name := range document.SubRules {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	ordered := make([]MihomoSubRule, 0, len(names))
	for index, name := range names {
		rules, ok := document.SubRules[name]
		if !ok {
			return nil, fmt.Errorf("parse Mihomo sub-rules: ordered sub-rule %q is missing from map", name)
		}
		ordered = append(ordered, MihomoSubRule{
			Name:        name,
			Rules:       rules,
			SourceIndex: index,
		})
	}
	return ordered, nil
}

func parseMihomoRuleIRRule(rule MihomoRule) (MihomoRuleIRRule, error) {
	raw := rule.Raw
	if raw == "" {
		raw = rule.Value
	}
	source := MihomoRuleSource{SourceIndex: rule.SourceIndex, SourceLine: rule.SourceLine, Raw: raw}
	fields, err := splitMihomoRuleFields(raw)
	if err != nil {
		return MihomoRuleIRRule{}, &MihomoRuleParseError{Source: source, Reason: err.Error()}
	}
	if len(fields) == 0 {
		return MihomoRuleIRRule{}, &MihomoRuleParseError{Source: source, Reason: "empty rule"}
	}
	for i := range fields {
		fields[i] = normalizeMihomoRuleField(fields[i])
		if fields[i] == "" {
			return MihomoRuleIRRule{}, &MihomoRuleParseError{Source: source, Reason: "empty rule field"}
		}
	}

	expr, action, err := parseMihomoRuleFields(fields, source)
	if err != nil {
		var scriptErr *MihomoScriptUnsupportedError
		if errors.As(err, &scriptErr) {
			return MihomoRuleIRRule{}, err
		}
		return MihomoRuleIRRule{}, &MihomoRuleParseError{Source: source, Reason: err.Error()}
	}
	return MihomoRuleIRRule{MihomoRuleSource: source, Expr: expr, Action: action}, nil
}

func parseMihomoRuleFields(fields []string, source MihomoRuleSource) (MihomoExpr, MihomoAction, error) {
	typeName := strings.ToUpper(fields[0])
	switch typeName {
	case "SCRIPT":
		return MihomoExpr{}, MihomoAction{}, newMihomoScriptUnsupportedError(source, fields[1:])
	case "AND", "OR", "NOT":
		if len(fields) < 3 {
			return MihomoExpr{}, MihomoAction{}, fmt.Errorf("%s rule requires condition and action", typeName)
		}
		if len(fields) > 3 {
			// Logic syntax has one expression payload. Any following fields are
			// action options, not extra expression arguments.
			action, err := parseMihomoAction(fields[2], fields[3:])
			if err != nil {
				return MihomoExpr{}, MihomoAction{}, err
			}
			expr, err := parseMihomoLogicExpression(typeName, fields[1], source)
			return expr, action, err
		}
		expr, err := parseMihomoLogicExpression(typeName, fields[1], source)
		if err != nil {
			return MihomoExpr{}, MihomoAction{}, err
		}
		action, err := parseMihomoAction(fields[2], nil)
		return expr, action, err
	case "RULE-SET":
		if len(fields) < 3 {
			return MihomoExpr{}, MihomoAction{}, errors.New("RULE-SET rule requires provider and action")
		}
		if fields[1] == "" {
			return MihomoExpr{}, MihomoAction{}, errors.New("empty RULE-SET provider")
		}
		action, err := parseMihomoAction(fields[2], fields[3:])
		if err != nil {
			return MihomoExpr{}, MihomoAction{}, err
		}
		return MihomoExpr{
			Kind:        MihomoExprRuleSet,
			Raw:         strings.Join(fields, ","),
			ProviderRef: &MihomoRuleSetRef{Provider: fields[1]},
		}, action, nil
	case "SUB-RULE":
		if len(fields) < 3 {
			return MihomoExpr{}, MihomoAction{}, errors.New("SUB-RULE requires guard and sub-rule name")
		}
		if fields[2] == "" {
			return MihomoExpr{}, MihomoAction{}, errors.New("empty sub-rule name")
		}
		guard, err := parseMihomoExpression(fields[1], source)
		if err != nil {
			return MihomoExpr{}, MihomoAction{}, err
		}
		// SUB-RULE has no outbound action: its third field is the referenced
		// sub-rule name. Keep any extension fields as options instead of
		// silently discarding them.
		return MihomoExpr{
			Kind:       MihomoExprSubRule,
			Raw:        strings.Join(fields, ","),
			SubRuleRef: &MihomoSubRuleRef{Name: fields[2], Guard: guard},
		}, MihomoAction{Options: append([]string(nil), fields[3:]...)}, nil
	case "MATCH":
		if len(fields) < 2 {
			return MihomoExpr{}, MihomoAction{}, errors.New("MATCH rule requires action")
		}
		action, err := parseMihomoAction(fields[1], fields[2:])
		if err != nil {
			return MihomoExpr{}, MihomoAction{}, err
		}
		return makeMihomoAtomExpression("MATCH", nil, strings.Join(fields, ",")), action, nil
	default:
		if len(fields) < 3 {
			return MihomoExpr{}, MihomoAction{}, fmt.Errorf("%s rule requires condition and action", typeName)
		}
		action, err := parseMihomoAction(fields[2], fields[3:])
		if err != nil {
			return MihomoExpr{}, MihomoAction{}, err
		}
		return makeMihomoAtomExpression(typeName, fields[1:2], strings.Join(fields, ",")), action, nil
	}
}

func parseMihomoExpression(raw string, source MihomoRuleSource) (MihomoExpr, error) {
	fields, err := splitMihomoRuleFields(raw)
	if err != nil {
		return MihomoExpr{}, err
	}
	if len(fields) == 0 {
		return MihomoExpr{}, errors.New("empty condition expression")
	}
	for i := range fields {
		fields[i] = normalizeMihomoRuleField(fields[i])
		if fields[i] == "" {
			return MihomoExpr{}, errors.New("empty condition field")
		}
	}
	if len(fields) == 1 && isMihomoWrappedExpression(fields[0]) {
		return parseMihomoExpression(fields[0][1:len(fields[0])-1], source)
	}

	typeName := strings.ToUpper(fields[0])
	switch typeName {
	case "SCRIPT":
		return MihomoExpr{}, newMihomoScriptUnsupportedError(source, fields[1:])
	case "AND", "OR", "NOT":
		if len(fields) != 2 {
			return MihomoExpr{}, fmt.Errorf("nested %s condition requires one expression payload", typeName)
		}
		return parseMihomoLogicExpression(typeName, fields[1], source)
	case "RULE-SET":
		if len(fields) < 2 || fields[1] == "" {
			return MihomoExpr{}, errors.New("RULE-SET condition requires provider")
		}
		if len(fields) > 2 {
			return MihomoExpr{}, errors.New("RULE-SET condition parameters are unsupported in nested expressions")
		}
		return MihomoExpr{Kind: MihomoExprRuleSet, Raw: strings.Join(fields, ","), ProviderRef: &MihomoRuleSetRef{Provider: fields[1]}}, nil
	case "SUB-RULE":
		if len(fields) != 3 || fields[2] == "" {
			return MihomoExpr{}, errors.New("SUB-RULE condition requires guard and sub-rule name")
		}
		guard, err := parseMihomoExpression(fields[1], source)
		if err != nil {
			return MihomoExpr{}, err
		}
		return MihomoExpr{Kind: MihomoExprSubRule, Raw: strings.Join(fields, ","), SubRuleRef: &MihomoSubRuleRef{Name: fields[2], Guard: guard}}, nil
	default:
		if len(fields) < 2 {
			return MihomoExpr{}, fmt.Errorf("%s condition requires a value", typeName)
		}
		// Keep the complete payload. For known atoms the lowerer interprets
		// the first field as the value and the rest as condition parameters;
		// retaining them here is what prevents nested no-resolve/match-mac
		// fields from becoming extra match values or disappearing.
		return makeMihomoAtomExpression(typeName, fields[1:], strings.Join(fields, ",")), nil
	}
}

func parseMihomoLogicExpression(typeName, raw string, source MihomoRuleSource) (MihomoExpr, error) {
	payload := normalizeMihomoRuleField(raw)
	if !isMihomoWrappedExpression(payload) {
		return MihomoExpr{}, fmt.Errorf("%s condition payload must be parenthesized", typeName)
	}
	inner := payload[1 : len(payload)-1]
	parts, err := splitMihomoRuleFields(inner)
	if err != nil {
		return MihomoExpr{}, err
	}
	if len(parts) == 0 {
		return MihomoExpr{}, fmt.Errorf("%s condition has empty payload", typeName)
	}
	children := make([]MihomoExpr, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return MihomoExpr{}, fmt.Errorf("%s condition has empty child", typeName)
		}
		child, err := parseMihomoExpression(part, source)
		if err != nil {
			return MihomoExpr{}, err
		}
		children = append(children, child)
	}
	if typeName == "NOT" && len(children) != 1 {
		return MihomoExpr{}, errors.New("NOT condition requires exactly one child")
	}
	kind := MihomoExprAnd
	if typeName == "OR" {
		kind = MihomoExprOr
	} else if typeName == "NOT" {
		kind = MihomoExprNot
	}
	return MihomoExpr{Kind: kind, Raw: typeName + "," + payload, Children: children}, nil
}

func makeMihomoAtomExpression(typeName string, arguments []string, raw string) MihomoExpr {
	args := make([]string, len(arguments))
	for i, argument := range arguments {
		args[i] = normalizeMihomoRuleField(argument)
	}
	known := isKnownMihomoAtom(typeName)
	atom := &MihomoAtom{
		Type:      typeName,
		Arguments: args,
		Known:     known,
		Raw:       raw,
	}
	if len(args) > 0 {
		atom.Value = args[0]
	}
	return MihomoExpr{Kind: MihomoExprAtom, Raw: raw, Atom: atom}
}

func isKnownMihomoAtom(typeName string) bool {
	switch typeName {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
		"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "DST-PORT", "SRC-PORT",
		"IN-PORT", "NETWORK", "PROCESS-NAME", "MATCH":
		return true
	default:
		return false
	}
}

func parseMihomoAction(target string, options []string) (MihomoAction, error) {
	target = normalizeMihomoRuleField(target)
	if target == "" {
		return MihomoAction{}, errors.New("empty action target")
	}
	cleanOptions := make([]string, len(options))
	noResolve := false
	for i, option := range options {
		cleanOptions[i] = normalizeMihomoRuleField(option)
		if cleanOptions[i] == "" {
			return MihomoAction{}, errors.New("empty action option")
		}
		if strings.EqualFold(cleanOptions[i], "no-resolve") {
			noResolve = true
		}
	}
	return MihomoAction{Target: target, Options: cleanOptions, NoResolve: noResolve}, nil
}

func newMihomoScriptUnsupportedError(source MihomoRuleSource, fields []string) error {
	shortcut := ""
	if len(fields) > 0 {
		shortcut = normalizeMihomoRuleField(fields[0])
	}
	return &MihomoScriptUnsupportedError{Source: source, Shortcut: shortcut}
}

func splitMihomoRuleFields(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("empty rule field")
	}
	fields := make([]string, 0, 4)
	start := 0
	depth := 0
	var quote byte
	escaped := false
	for index := 0; index < len(raw); index++ {
		char := raw[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, errors.New("unexpected closing parenthesis")
			}
		case ',':
			if depth == 0 {
				field := strings.TrimSpace(raw[start:index])
				if field == "" {
					return nil, errors.New("empty rule field")
				}
				fields = append(fields, field)
				start = index + 1
			}
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote")
	}
	if depth != 0 {
		return nil, errors.New("unclosed parentheses")
	}
	field := strings.TrimSpace(raw[start:])
	if field == "" {
		return nil, errors.New("empty rule field")
	}
	fields = append(fields, field)
	return fields, nil
}

func normalizeMihomoRuleField(field string) string {
	field = strings.TrimSpace(field)
	if len(field) < 2 || (field[0] != '\'' && field[0] != '"') || field[len(field)-1] != field[0] {
		return field
	}
	quote := field[0]
	body := field[1 : len(field)-1]
	var out strings.Builder
	for index := 0; index < len(body); index++ {
		if body[index] == '\\' && index+1 < len(body) {
			next := body[index+1]
			if next == quote || next == '\\' {
				out.WriteByte(next)
				index++
				continue
			}
		}
		out.WriteByte(body[index])
	}
	return out.String()
}

func isMihomoWrappedExpression(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
		return false
	}
	depth := 0
	var quote byte
	escaped := false
	for index := 0; index < len(value); index++ {
		char := value[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && index != len(value)-1 {
				return false
			}
		}
	}
	return quote == 0 && depth == 0
}
