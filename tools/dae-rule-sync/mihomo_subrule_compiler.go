package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	// DefaultMihomoSubRuleMaxDepth bounds the number of nested SUB-RULE calls
	// from a top-level rule. A zero option selects this value.
	DefaultMihomoSubRuleMaxDepth = 32

	// DefaultMihomoSubRuleMaxExpandedRules bounds the complete compiled Rules
	// slice, including ordinary top-level rules that were not expanded.
	DefaultMihomoSubRuleMaxExpandedRules = 1024
)

var (
	ErrMihomoSubRuleCompile        = errors.New("Mihomo sub-rule compilation failed")
	ErrMihomoSubRuleDuplicate      = errors.New("duplicate Mihomo sub-rule")
	ErrMihomoSubRuleUndefined      = errors.New("undefined Mihomo sub-rule")
	ErrMihomoSubRuleCycle          = errors.New("Mihomo sub-rule cycle")
	ErrMihomoSubRuleEmpty          = errors.New("empty Mihomo sub-rule")
	ErrMihomoSubRuleDepth          = errors.New("Mihomo sub-rule expansion depth exceeded")
	ErrMihomoSubRuleExpansionLimit = errors.New("Mihomo sub-rule expansion limit exceeded")
	ErrMihomoSubRuleEmbedded       = errors.New("embedded Mihomo SUB-RULE is not representable")
)

// MihomoSubRuleCompilerOptions controls graph expansion. Zero values select
// the safe defaults above; negative values are invalid.
type MihomoSubRuleCompilerOptions struct {
	MaxDepth         int
	MaxExpandedRules int
}

// MihomoSubRulesCompilerOptions is a compatibility spelling for callers that
// use the plural feature name.
type MihomoSubRulesCompilerOptions = MihomoSubRuleCompilerOptions

// MihomoSubRuleCompileError retains the source location of the call or leaf
// rule that made compilation fail. Kind is exposed through errors.Is.
type MihomoSubRuleCompileError struct {
	Source  MihomoRuleSource
	SubRule string
	Reason  string
	Kind    error
}

func (e *MihomoSubRuleCompileError) Error() string {
	name := ""
	if e.SubRule != "" {
		name = fmt.Sprintf(" %q", e.SubRule)
	}
	return fmt.Sprintf("compile Mihomo sub-rule%s at index %d line %d: %s", name, e.Source.SourceIndex, e.Source.SourceLine, e.Reason)
}

func (e *MihomoSubRuleCompileError) Unwrap() error {
	if e.Kind == nil {
		return ErrMihomoSubRuleCompile
	}
	return e.Kind
}

func (e *MihomoSubRuleCompileError) Is(target error) bool {
	return target == ErrMihomoSubRuleCompile || target == e.Kind
}

// MihomoSubRuleCompiler expands only SUB-RULE calls reachable from ir.Rules.
// It is deliberately independent from the lowerer and does not create routes
// or runtime objects.
type MihomoSubRuleCompiler struct {
	maxDepth         int
	maxExpandedRules int
	definitions      map[string][]MihomoSubRuleIR
	emitted          int
}

// NewMihomoSubRuleCompiler constructs a compiler. Option validation is kept in
// Compile so construction remains convenient for configuration plumbing.
func NewMihomoSubRuleCompiler(options MihomoSubRuleCompilerOptions) *MihomoSubRuleCompiler {
	maxDepth := options.MaxDepth
	if maxDepth == 0 {
		maxDepth = DefaultMihomoSubRuleMaxDepth
	}
	maxExpandedRules := options.MaxExpandedRules
	if maxExpandedRules == 0 {
		maxExpandedRules = DefaultMihomoSubRuleMaxExpandedRules
	}
	return &MihomoSubRuleCompiler{
		maxDepth:         maxDepth,
		maxExpandedRules: maxExpandedRules,
	}
}

// CompileMihomoSubRules expands reachable SUB-RULE calls in top-level order.
// The returned IR has no sub-rule definitions because all reachable calls have
// been inlined and unreachable definitions are intentionally not carried into
// the compiled view.
func CompileMihomoSubRules(ir MihomoRuleIR, options MihomoSubRuleCompilerOptions) (MihomoRuleIR, error) {
	return NewMihomoSubRuleCompiler(options).Compile(ir)
}

// CompileMihomoRuleIR is the concise IR-oriented spelling of
// CompileMihomoSubRules.
func CompileMihomoRuleIR(ir MihomoRuleIR, options MihomoSubRuleCompilerOptions) (MihomoRuleIR, error) {
	return CompileMihomoSubRules(ir, options)
}

// CompileMihomoSubRuleIR is the singular spelling retained for callers that
// name the graph feature after one SUB-RULE expression.
func CompileMihomoSubRuleIR(ir MihomoRuleIR, options MihomoSubRuleCompilerOptions) (MihomoRuleIR, error) {
	return CompileMihomoSubRules(ir, options)
}

// Compile performs option validation, builds the name graph, and expands only
// definitions reached from top-level call sites.
func (c *MihomoSubRuleCompiler) Compile(ir MihomoRuleIR) (MihomoRuleIR, error) {
	if c.maxDepth == 0 {
		c.maxDepth = DefaultMihomoSubRuleMaxDepth
	}
	if c.maxExpandedRules == 0 {
		c.maxExpandedRules = DefaultMihomoSubRuleMaxExpandedRules
	}
	if c.maxDepth < 0 {
		return MihomoRuleIR{}, fmt.Errorf("MaxDepth must not be negative")
	}
	if c.maxExpandedRules < 0 {
		return MihomoRuleIR{}, fmt.Errorf("MaxExpandedRules must not be negative")
	}

	c.definitions = make(map[string][]MihomoSubRuleIR, len(ir.SubRules))
	for _, definition := range ir.SubRules {
		// Duplicate definitions are checked when the name is reached. This is
		// what permits a completely unreachable malformed graph to be ignored.
		c.definitions[definition.Name] = append(c.definitions[definition.Name], definition)
	}
	c.emitted = 0

	compiled := make([]MihomoRuleIRRule, 0, len(ir.Rules))
	for _, rule := range ir.Rules {
		if rule.Expr.Kind == MihomoExprSubRule {
			expanded, err := c.expandCall(rule, nil, 1, nil, nil)
			if err != nil {
				return MihomoRuleIR{}, err
			}
			compiled = append(compiled, expanded...)
			continue
		}
		if err := mihomoRejectEmbeddedSubRule(rule.Expr, rule.Source); err != nil {
			return MihomoRuleIR{}, err
		}
		copied := cloneMihomoRuleIRRule(rule)
		if err := c.emit(copied.Source); err != nil {
			return MihomoRuleIR{}, err
		}
		compiled = append(compiled, copied)
	}
	return MihomoRuleIR{Rules: compiled}, nil
}

func (c *MihomoSubRuleCompiler) expandCall(call MihomoRuleIRRule, inherited *MihomoExpr, depth int, path []string, trace []MihomoSubRuleCall) ([]MihomoRuleIRRule, error) {
	ref := call.Expr.SubRuleRef
	if ref == nil || strings.TrimSpace(ref.Name) == "" {
		return nil, c.error(call.Source, "", "SUB-RULE expression has no referenced name", ErrMihomoSubRuleUndefined)
	}
	if call.Action.Target != "" || len(call.Action.Options) != 0 || call.Action.NoResolve {
		return nil, c.error(call.Source, ref.Name, "SUB-RULE call cannot carry an action or options", ErrMihomoSubRuleCompile)
	}
	if ref.Guard.Kind == "" {
		return nil, c.error(call.Source, ref.Name, "SUB-RULE call has an empty guard", ErrMihomoSubRuleCompile)
	}
	if err := mihomoRejectEmbeddedSubRule(ref.Guard, call.Source); err != nil {
		return nil, err
	}

	effectiveGuard := mihomoCombineSubRuleGuards(inherited, ref.Guard)
	nextTrace := appendMihomoSubRuleTrace(trace, MihomoSubRuleCall{
		Name:   ref.Name,
		Source: call.Source,
		Guard:  cloneMihomoExpr(ref.Guard),
	})
	return c.expandNamed(ref.Name, effectiveGuard, depth, path, nextTrace, call.Source)
}

func (c *MihomoSubRuleCompiler) expandNamed(name string, guard *MihomoExpr, depth int, path []string, trace []MihomoSubRuleCall, callSource MihomoRuleSource) ([]MihomoRuleIRRule, error) {
	if depth > c.maxDepth {
		return nil, c.error(callSource, name, fmt.Sprintf("maximum depth %d exceeded", c.maxDepth), ErrMihomoSubRuleDepth)
	}
	for _, ancestor := range path {
		if ancestor == name {
			cycle := append(append([]string(nil), path...), name)
			return nil, c.error(callSource, name, "cycle detected: "+strings.Join(cycle, " -> "), ErrMihomoSubRuleCycle)
		}
	}

	definitions := c.definitions[name]
	if len(definitions) == 0 {
		return nil, c.error(callSource, name, "referenced sub-rule is not defined", ErrMihomoSubRuleUndefined)
	}
	if len(definitions) > 1 {
		return nil, c.error(callSource, name, fmt.Sprintf("sub-rule has %d definitions", len(definitions)), ErrMihomoSubRuleDuplicate)
	}
	definition := definitions[0]
	if len(definition.Rules) == 0 {
		source := MihomoRuleSource{SourceIndex: definition.SourceIndex, SourceLine: definition.SourceLine}
		return nil, c.error(source, name, "referenced sub-rule has no rules", ErrMihomoSubRuleEmpty)
	}

	nextPath := append(append([]string(nil), path...), name)
	compiled := make([]MihomoRuleIRRule, 0, len(definition.Rules))
	for _, child := range definition.Rules {
		if child.Expr.Kind == MihomoExprSubRule {
			expanded, err := c.expandCall(child, guard, depth+1, nextPath, trace)
			if err != nil {
				return nil, err
			}
			compiled = append(compiled, expanded...)
			continue
		}
		if err := mihomoRejectEmbeddedSubRule(child.Expr, child.Source); err != nil {
			return nil, err
		}
		leaf := cloneMihomoRuleIRRule(child)
		leaf.Expr = mihomoCombineSubRuleGuards(guard, leaf.Expr)
		leaf.CallTrace = appendMihomoSubRuleTrace(nil, trace...)
		if err := c.emit(leaf.Source); err != nil {
			return nil, err
		}
		compiled = append(compiled, leaf)
	}
	return compiled, nil
}

func (c *MihomoSubRuleCompiler) emit(source MihomoRuleSource) error {
	if c.emitted >= c.maxExpandedRules {
		return c.error(source, "", fmt.Sprintf("expanded rules exceed %d", c.maxExpandedRules), ErrMihomoSubRuleExpansionLimit)
	}
	c.emitted++
	return nil
}

func (c *MihomoSubRuleCompiler) error(source MihomoRuleSource, name, reason string, kind error) error {
	return &MihomoSubRuleCompileError{Source: source, SubRule: name, Reason: reason, Kind: kind}
}

func mihomoRejectEmbeddedSubRule(expr MihomoExpr, source MihomoRuleSource) error {
	if !mihomoExprContainsSubRule(expr) {
		return nil
	}
	return &MihomoSubRuleCompileError{
		Source: source,
		Reason: "SUB-RULE is nested inside an ordinary AND/OR/NOT expression and cannot be expanded without changing kdae semantics",
		Kind:   ErrMihomoSubRuleEmbedded,
	}
}

func mihomoExprContainsSubRule(expr MihomoExpr) bool {
	if expr.Kind == MihomoExprSubRule {
		return true
	}
	for _, child := range expr.Children {
		if mihomoExprContainsSubRule(child) {
			return true
		}
	}
	if expr.SubRuleRef != nil && mihomoExprContainsSubRule(expr.SubRuleRef.Guard) {
		return true
	}
	return false
}

func mihomoCombineSubRuleGuards(inherited *MihomoExpr, child MihomoExpr) MihomoExpr {
	child = cloneMihomoExpr(child)
	if inherited == nil {
		return child
	}
	left := cloneMihomoExpr(*inherited)
	right := child
	return MihomoExpr{
		Kind:     MihomoExprAnd,
		Raw:      "AND,(" + mihomoSubRuleExprRaw(left) + "),(" + mihomoSubRuleExprRaw(right) + ")",
		Children: []MihomoExpr{left, right},
	}
}

func mihomoSubRuleExprRaw(expr MihomoExpr) string {
	if expr.Raw != "" {
		return expr.Raw
	}
	switch expr.Kind {
	case MihomoExprAtom:
		if expr.Atom != nil {
			return expr.Atom.Raw
		}
	case MihomoExprAnd, MihomoExprOr, MihomoExprNot:
		parts := make([]string, 0, len(expr.Children))
		for _, child := range expr.Children {
			parts = append(parts, mihomoSubRuleExprRaw(child))
		}
		return strings.ToUpper(string(expr.Kind)) + ",(" + strings.Join(parts, ",") + ")"
	case MihomoExprRuleSet:
		if expr.ProviderRef != nil {
			return "RULE-SET," + expr.ProviderRef.Provider
		}
	}
	return string(expr.Kind)
}

func cloneMihomoRuleIRRule(rule MihomoRuleIRRule) MihomoRuleIRRule {
	cloned := rule
	cloned.Expr = cloneMihomoExpr(rule.Expr)
	cloned.Action.Options = append([]string(nil), rule.Action.Options...)
	cloned.CallTrace = appendMihomoSubRuleTrace(nil, rule.CallTrace...)
	return cloned
}

func cloneMihomoExpr(expr MihomoExpr) MihomoExpr {
	cloned := expr
	cloned.Children = make([]MihomoExpr, len(expr.Children))
	for index, child := range expr.Children {
		cloned.Children[index] = cloneMihomoExpr(child)
	}
	if expr.Atom != nil {
		atom := *expr.Atom
		atom.Arguments = append([]string(nil), expr.Atom.Arguments...)
		cloned.Atom = &atom
	}
	if expr.ProviderRef != nil {
		provider := *expr.ProviderRef
		cloned.ProviderRef = &provider
	}
	if expr.ProviderDataRef != nil {
		providerData := *expr.ProviderDataRef
		providerData.Domains = append([]DomainRule(nil), expr.ProviderDataRef.Domains...)
		providerData.Prefixes = append([]netip.Prefix(nil), expr.ProviderDataRef.Prefixes...)
		cloned.ProviderDataRef = &providerData
	}
	if expr.SubRuleRef != nil {
		ref := *expr.SubRuleRef
		ref.Guard = cloneMihomoExpr(expr.SubRuleRef.Guard)
		cloned.SubRuleRef = &ref
	}
	return cloned
}

func appendMihomoSubRuleTrace(dst []MihomoSubRuleCall, values ...MihomoSubRuleCall) []MihomoSubRuleCall {
	if len(values) == 0 {
		if dst == nil {
			return nil
		}
		return append([]MihomoSubRuleCall(nil), dst...)
	}
	result := make([]MihomoSubRuleCall, 0, len(dst)+len(values))
	for _, value := range append(append([]MihomoSubRuleCall(nil), dst...), values...) {
		cloned := value
		cloned.Guard = cloneMihomoExpr(value.Guard)
		result = append(result, cloned)
	}
	return result
}
