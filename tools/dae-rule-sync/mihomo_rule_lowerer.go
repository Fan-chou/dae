package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

// DefaultMihomoRuleMaxExpandedRules bounds the number of kdae rules emitted
// for one LowerRules call.  A zero MaxExpandedRules selects this value.
const DefaultMihomoRuleMaxExpandedRules = 1024

// MihomoRuleLowererOptions contains the names and provider capabilities needed
// to lower Mihomo routing rules without guessing runtime objects.
type MihomoRuleLowererOptions struct {
	// ProviderNameMap maps an original Mihomo RULE-SET name to its safe kdae
	// provider name.
	ProviderNameMap map[string]string

	// OutboundNameMap maps an original Mihomo node or group name to its safe
	// kdae outbound name. DIRECT and REJECT are mapped to the built-ins direct
	// and block and do not require entries here.
	OutboundNameMap map[string]string

	// ProviderBehaviors maps a provider name to its normalized behavior, such
	// as domain, ipcidr, or classical. It is used for no-resolve validation.
	ProviderBehaviors map[string]string

	// MaxExpandedRules is the maximum number of output rules for the complete
	// lowering operation. Zero selects DefaultMihomoRuleMaxExpandedRules.
	MaxExpandedRules int
}

// MihomoLowererOptions is kept as a concise alias for callers that do not
// need to distinguish this lowerer from the IR it consumes.
type MihomoLowererOptions = MihomoRuleLowererOptions

// MihomoLoweredRoutingRule carries source metadata alongside the kdae rule.
// Alternatives emitted from one source rule are contiguous in the result.
type MihomoLoweredRoutingRule struct {
	Source MihomoRuleSource
	Rule   *config_parser.RoutingRule

	AlternativeIndex int
	AlternativeCount int
}

// MihomoLoweredRule is a short alias for MihomoLoweredRoutingRule.
type MihomoLoweredRule = MihomoLoweredRoutingRule

// ErrMihomoRuleLoweringUnsupported identifies a source rule that cannot be
// represented by the current kdae routing rule model.
var ErrMihomoRuleLoweringUnsupported = errors.New("Mihomo rule lowering unsupported")

// MihomoRuleLoweringError retains the source location for unsupported or
// otherwise invalid lowering input.
type MihomoRuleLoweringError struct {
	Source MihomoRuleSource
	Reason string
}

func (e *MihomoRuleLoweringError) Error() string {
	return fmt.Sprintf("lower Mihomo rule at index %d line %d: %s", e.Source.SourceIndex, e.Source.SourceLine, e.Reason)
}

func (e *MihomoRuleLoweringError) Unwrap() error { return ErrMihomoRuleLoweringUnsupported }

// MihomoRuleLowerer converts typed Mihomo expressions into kdae routing
// rules. It does not load providers, compile sub-rule graphs, or publish any
// generated configuration.
type MihomoRuleLowerer struct {
	options MihomoRuleLowererOptions
}

// NewMihomoRuleLowerer constructs a lowerer. Invalid options are reported by
// LowerRule or LowerIR, keeping construction convenient for configuration
// plumbing.
func NewMihomoRuleLowerer(options MihomoRuleLowererOptions) *MihomoRuleLowerer {
	return &MihomoRuleLowerer{options: options}
}

// LowerMihomoRule lowers one source rule and returns its contiguous
// alternatives, preserving the source metadata on every result.
func LowerMihomoRule(rule MihomoRuleIRRule, options MihomoRuleLowererOptions) ([]MihomoLoweredRoutingRule, error) {
	return NewMihomoRuleLowerer(options).LowerRule(rule)
}

// LowerMihomoRuleIR lowers top-level rules in source order. Sub-rule
// definitions are intentionally not expanded here; a SUB-RULE expression is
// an explicit boundary for the later graph compiler.
func LowerMihomoRuleIR(ir MihomoRuleIR, options MihomoRuleLowererOptions) ([]MihomoLoweredRoutingRule, error) {
	return NewMihomoRuleLowerer(options).LowerIR(ir)
}

// LowerMihomoRules is the plural spelling of LowerMihomoRuleIR.
func LowerMihomoRules(ir MihomoRuleIR, options MihomoRuleLowererOptions) ([]MihomoLoweredRoutingRule, error) {
	return LowerMihomoRuleIR(ir, options)
}

// LowerRule lowers one Mihomo source rule.
func (l *MihomoRuleLowerer) LowerRule(rule MihomoRuleIRRule) ([]MihomoLoweredRoutingRule, error) {
	limit, err := l.expansionLimit()
	if err != nil {
		return nil, err
	}
	return l.lowerRule(rule, limit)
}

// LowerIR lowers top-level rules while enforcing the expansion bound across
// the complete result. Alternatives for each source rule remain adjacent.
func (l *MihomoRuleLowerer) LowerIR(ir MihomoRuleIR) ([]MihomoLoweredRoutingRule, error) {
	limit, err := l.expansionLimit()
	if err != nil {
		return nil, err
	}
	result := make([]MihomoLoweredRoutingRule, 0, len(ir.Rules))
	for _, rule := range ir.Rules {
		remaining := limit - len(result)
		if remaining <= 0 {
			return nil, mihomoLoweringError(rule.Source, fmt.Sprintf("expanded routing rules exceed %d", limit))
		}
		lowered, err := l.lowerRule(rule, remaining)
		if err != nil {
			return nil, err
		}
		result = append(result, lowered...)
	}
	return result, nil
}

// LowerRules is the method form of LowerIR.
func (l *MihomoRuleLowerer) LowerRules(ir MihomoRuleIR) ([]MihomoLoweredRoutingRule, error) {
	return l.LowerIR(ir)
}

func (l *MihomoRuleLowerer) lowerRule(rule MihomoRuleIRRule, limit int) ([]MihomoLoweredRoutingRule, error) {
	if err := l.validateActionOptions(rule.Action, rule.Source); err != nil {
		return nil, err
	}
	if rule.Action.NoResolve || mihomoActionHasNoResolve(rule.Action) {
		if err := l.validateNoResolve(rule.Expr, rule.Source); err != nil {
			return nil, err
		}
	}

	terms, err := l.lowerExpression(rule.Expr, false, rule.Source, limit)
	if err != nil {
		return nil, err
	}
	outbound, err := l.lowerAction(rule.Action, rule.Source)
	if err != nil {
		return nil, err
	}
	if len(terms) > limit {
		return nil, mihomoLoweringError(rule.Source, fmt.Sprintf("expanded routing rules exceed %d", limit))
	}

	result := make([]MihomoLoweredRoutingRule, 0, len(terms))
	for index, term := range terms {
		functions := make([]*config_parser.Function, len(term))
		for i := range term {
			functions[i] = term[i]
		}
		result = append(result, MihomoLoweredRoutingRule{
			Source:           rule.Source,
			Rule:             &config_parser.RoutingRule{AndFunctions: functions, Outbound: *outbound},
			AlternativeIndex: index,
			AlternativeCount: len(terms),
		})
	}
	return result, nil
}

type mihomoLoweredTerm []*config_parser.Function

func (l *MihomoRuleLowerer) lowerExpression(expr MihomoExpr, negated bool, source MihomoRuleSource, limit int) ([]mihomoLoweredTerm, error) {
	switch expr.Kind {
	case MihomoExprAtom:
		if expr.Atom == nil {
			return nil, mihomoLoweringError(source, "atom expression has no atom")
		}
		if strings.EqualFold(expr.Atom.Type, "MATCH") {
			if negated {
				return nil, mihomoLoweringError(source, "NOT MATCH has no exact kdae routing equivalent")
			}
			return []mihomoLoweredTerm{{}}, nil
		}
		function, err := lowerMihomoAtom(*expr.Atom, negated, source)
		if err != nil {
			return nil, err
		}
		return []mihomoLoweredTerm{{function}}, nil

	case MihomoExprRuleSet:
		if negated {
			return nil, mihomoLoweringError(source, "NOT RULE-SET cannot be represented exactly")
		}
		if expr.ProviderRef == nil || strings.TrimSpace(expr.ProviderRef.Provider) == "" {
			return nil, mihomoLoweringError(source, "RULE-SET expression has no provider")
		}
		safeName, ok := l.options.ProviderNameMap[expr.ProviderRef.Provider]
		if !ok || strings.TrimSpace(safeName) == "" {
			return nil, mihomoLoweringError(source, fmt.Sprintf("RULE-SET provider %q has no safe provider mapping", expr.ProviderRef.Provider))
		}
		return []mihomoLoweredTerm{{{
			Name:   "ruleset",
			Not:    false,
			Params: []*config_parser.Param{{Val: safeName}},
		}}}, nil

	case MihomoExprSubRule:
		return nil, mihomoLoweringError(source, "SUB-RULE expression is unsupported; graph compiler must lower it")

	case MihomoExprNot:
		if len(expr.Children) != 1 {
			return nil, mihomoLoweringError(source, "NOT expression requires exactly one child")
		}
		return l.lowerExpression(expr.Children[0], !negated, source, limit)

	case MihomoExprAnd:
		if len(expr.Children) == 0 {
			return nil, mihomoLoweringError(source, "AND expression has no children")
		}
		if negated {
			return l.lowerNegatedDisjunction(expr.Children, source, limit)
		}
		return l.lowerConjunction(expr.Children, source, limit)

	case MihomoExprOr:
		if len(expr.Children) == 0 {
			return nil, mihomoLoweringError(source, "OR expression has no children")
		}
		if negated {
			return l.lowerNegatedConjunction(expr.Children, source, limit)
		}
		result := make([]mihomoLoweredTerm, 0)
		for _, child := range expr.Children {
			terms, err := l.lowerExpression(child, false, source, limit-len(result))
			if err != nil {
				return nil, err
			}
			if len(terms) > limit-len(result) {
				return nil, mihomoLoweringError(source, fmt.Sprintf("expanded routing rules exceed %d", limit))
			}
			result = append(result, terms...)
		}
		return result, nil

	default:
		return nil, mihomoLoweringError(source, fmt.Sprintf("unknown Mihomo expression kind %q", expr.Kind))
	}
}

func (l *MihomoRuleLowerer) lowerConjunction(children []MihomoExpr, source MihomoRuleSource, limit int) ([]mihomoLoweredTerm, error) {
	result := []mihomoLoweredTerm{{}}
	for _, child := range children {
		terms, err := l.lowerExpression(child, false, source, limit)
		if err != nil {
			return nil, err
		}
		result, err = combineMihomoTerms(result, terms, limit)
		if err != nil {
			return nil, mihomoLoweringError(source, err.Error())
		}
	}
	return result, nil
}

func (l *MihomoRuleLowerer) lowerNegatedDisjunction(children []MihomoExpr, source MihomoRuleSource, limit int) ([]mihomoLoweredTerm, error) {
	result := make([]mihomoLoweredTerm, 0, len(children))
	for _, child := range children {
		terms, err := l.lowerExpression(child, true, source, limit-len(result))
		if err != nil {
			return nil, err
		}
		if len(terms) > limit-len(result) {
			return nil, mihomoLoweringError(source, fmt.Sprintf("expanded routing rules exceed %d", limit))
		}
		result = append(result, terms...)
	}
	return result, nil
}

func (l *MihomoRuleLowerer) lowerNegatedConjunction(children []MihomoExpr, source MihomoRuleSource, limit int) ([]mihomoLoweredTerm, error) {
	result := []mihomoLoweredTerm{{}}
	for _, child := range children {
		terms, err := l.lowerExpression(child, true, source, limit)
		if err != nil {
			return nil, err
		}
		result, err = combineMihomoTerms(result, terms, limit)
		if err != nil {
			return nil, mihomoLoweringError(source, err.Error())
		}
	}
	return result, nil
}

func combineMihomoTerms(left, right []mihomoLoweredTerm, limit int) ([]mihomoLoweredTerm, error) {
	if len(left) == 0 || len(right) == 0 {
		return nil, errors.New("expression produced no DNF alternatives")
	}
	if len(left) > limit/len(right) {
		return nil, fmt.Errorf("expanded routing rules exceed %d", limit)
	}
	result := make([]mihomoLoweredTerm, 0, len(left)*len(right))
	for _, leftTerm := range left {
		for _, rightTerm := range right {
			term := make(mihomoLoweredTerm, 0, len(leftTerm)+len(rightTerm))
			term = append(term, leftTerm...)
			term = append(term, rightTerm...)
			result = append(result, term)
		}
	}
	return result, nil
}

func lowerMihomoAtom(atom MihomoAtom, negated bool, source MihomoRuleSource) (*config_parser.Function, error) {
	arguments := atom.Arguments
	if len(arguments) == 0 && atom.Value != "" {
		arguments = []string{atom.Value}
	}
	if len(arguments) == 0 {
		return nil, mihomoLoweringError(source, fmt.Sprintf("Mihomo atom %q has no value", atom.Type))
	}
	params := make([]*config_parser.Param, 0, len(arguments))
	for _, argument := range arguments {
		if strings.TrimSpace(argument) == "" {
			return nil, mihomoLoweringError(source, fmt.Sprintf("Mihomo atom %q has an empty value", atom.Type))
		}
		params = append(params, &config_parser.Param{Val: argument})
	}

	functionName := ""
	key := ""
	switch strings.ToUpper(atom.Type) {
	case "DOMAIN":
		functionName, key = "domain", "full"
	case "DOMAIN-SUFFIX":
		functionName, key = "domain", "suffix"
	case "DOMAIN-KEYWORD":
		functionName, key = "domain", "keyword"
	case "DOMAIN-REGEX":
		functionName, key = "domain", "regex"
	case "IP-CIDR":
		functionName = "dip"
	case "IP-CIDR6":
		// ip is the canonical destination-IP matcher; dip is its routing
		// alias and is retained for the IPv4 spelling above.
		functionName = "ip"
	case "SRC-IP-CIDR":
		functionName = "sip"
	case "DST-PORT":
		functionName = "dport"
	case "SRC-PORT":
		functionName = "sport"
	case "NETWORK":
		functionName = "l4proto"
	case "PROCESS-NAME":
		functionName = "pname"
	case "IN-PORT", "IP-ASN", "DOMAIN-WILDCARD":
		return nil, mihomoLoweringError(source, fmt.Sprintf("unsupported Mihomo atom %q", atom.Type))
	default:
		if strings.HasPrefix(strings.ToUpper(atom.Type), "GEO") {
			return nil, mihomoLoweringError(source, fmt.Sprintf("unsupported Mihomo atom %q", atom.Type))
		}
		return nil, mihomoLoweringError(source, fmt.Sprintf("unsupported unknown Mihomo atom %q", atom.Type))
	}
	if key != "" {
		for _, param := range params {
			param.Key = key
		}
	}
	return &config_parser.Function{Name: functionName, Not: negated, Params: params}, nil
}

func (l *MihomoRuleLowerer) lowerAction(action MihomoAction, source MihomoRuleSource) (*config_parser.Function, error) {
	target := strings.TrimSpace(action.Target)
	if target == "" || strings.EqualFold(target, "MATCH") {
		return nil, mihomoLoweringError(source, "action target does not identify an outbound")
	}
	var outbound string
	switch strings.ToUpper(target) {
	case "DIRECT":
		outbound = "direct"
	case "REJECT":
		outbound = "block"
	case "REJECT-DROP":
		return nil, mihomoLoweringError(source, "REJECT-DROP has no exact kdae outbound equivalent")
	default:
		var ok bool
		outbound, ok = l.options.OutboundNameMap[target]
		if !ok || strings.TrimSpace(outbound) == "" {
			return nil, mihomoLoweringError(source, fmt.Sprintf("outbound %q has no safe outbound mapping", target))
		}
	}
	return &config_parser.Function{Name: outbound}, nil
}

func (l *MihomoRuleLowerer) validateActionOptions(action MihomoAction, source MihomoRuleSource) error {
	for _, option := range action.Options {
		if strings.EqualFold(strings.TrimSpace(option), "no-resolve") {
			continue
		}
		return mihomoLoweringError(source, fmt.Sprintf("unsupported Mihomo action option %q", option))
	}
	return nil
}

func mihomoActionHasNoResolve(action MihomoAction) bool {
	for _, option := range action.Options {
		if strings.EqualFold(strings.TrimSpace(option), "no-resolve") {
			return true
		}
	}
	return false
}

func (l *MihomoRuleLowerer) validateNoResolve(expr MihomoExpr, source MihomoRuleSource) error {
	switch expr.Kind {
	case MihomoExprAtom:
		if expr.Atom == nil {
			return mihomoLoweringError(source, "no-resolve is not valid for an empty atom")
		}
		switch strings.ToUpper(expr.Atom.Type) {
		case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
			return nil
		default:
			return mihomoLoweringError(source, fmt.Sprintf("no-resolve is only equivalent for IP-CIDR/SRC-IP-CIDR conditions, not %q", expr.Atom.Type))
		}
	case MihomoExprRuleSet:
		if expr.ProviderRef == nil || strings.TrimSpace(expr.ProviderRef.Provider) == "" {
			return mihomoLoweringError(source, "no-resolve RULE-SET has no provider")
		}
		provider := expr.ProviderRef.Provider
		behavior, ok := l.options.ProviderBehaviors[provider]
		if !ok {
			if safeName, mapped := l.options.ProviderNameMap[provider]; mapped {
				behavior, ok = l.options.ProviderBehaviors[safeName]
			}
		}
		if !ok || !strings.EqualFold(strings.TrimSpace(behavior), "ipcidr") {
			return mihomoLoweringError(source, fmt.Sprintf("no-resolve RULE-SET provider %q is not known to have ipcidr behavior", provider))
		}
		return nil
	case MihomoExprSubRule:
		return mihomoLoweringError(source, "SUB-RULE expression is unsupported; graph compiler must lower it")
	case MihomoExprNot, MihomoExprAnd, MihomoExprOr:
		if len(expr.Children) == 0 {
			return mihomoLoweringError(source, "no-resolve expression has no children")
		}
		for _, child := range expr.Children {
			if err := l.validateNoResolve(child, source); err != nil {
				return err
			}
		}
		return nil
	default:
		return mihomoLoweringError(source, fmt.Sprintf("no-resolve expression kind %q is unsupported", expr.Kind))
	}
}

func (l *MihomoRuleLowerer) expansionLimit() (int, error) {
	limit := l.options.MaxExpandedRules
	if limit == 0 {
		limit = DefaultMihomoRuleMaxExpandedRules
	}
	if limit < 0 {
		return 0, fmt.Errorf("MaxExpandedRules must not be negative")
	}
	return limit, nil
}

func mihomoLoweringError(source MihomoRuleSource, reason string) error {
	return &MihomoRuleLoweringError{Source: source, Reason: reason}
}
