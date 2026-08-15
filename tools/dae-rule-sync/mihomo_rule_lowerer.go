package main

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

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

	// SkipUnsupported omits rules that cannot be lowered instead of returning
	// an error. Logf receives the source location and reason for every omitted
	// rule or ignored condition.
	SkipUnsupported bool
	Logf            func(format string, args ...any)
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
	logged  map[string]struct{}
}

// NewMihomoRuleLowerer constructs a lowerer. Invalid options are reported by
// LowerRule or LowerIR, keeping construction convenient for configuration
// plumbing.
func NewMihomoRuleLowerer(options MihomoRuleLowererOptions) *MihomoRuleLowerer {
	return &MihomoRuleLowerer{options: options, logged: make(map[string]struct{})}
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
	lowered, err := l.lowerRule(rule, limit)
	if err != nil && l.options.SkipUnsupported && errors.Is(err, ErrMihomoRuleLoweringUnsupported) {
		l.logRuleSkip(rule.MihomoRuleSource, err)
		return nil, nil
	}
	return lowered, err
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
			err := mihomoLoweringError(rule.MihomoRuleSource, fmt.Sprintf("expanded routing rules exceed %d", limit))
			if l.options.SkipUnsupported {
				l.logRuleSkip(rule.MihomoRuleSource, err)
				break
			}
			return nil, err
		}
		lowered, err := l.lowerRule(rule, remaining)
		if err != nil {
			if l.options.SkipUnsupported && errors.Is(err, ErrMihomoRuleLoweringUnsupported) {
				l.logRuleSkip(rule.MihomoRuleSource, err)
				continue
			}
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
	if err := l.validateRuleOptions(rule.Expr, rule.Action, rule.MihomoRuleSource); err != nil {
		return nil, err
	}
	expr, err := l.applyRuleOptions(rule.Expr, rule.Action.Options, rule.MihomoRuleSource)
	if err != nil {
		return nil, err
	}
	if rule.Action.NoResolve || mihomoActionHasNoResolve(rule.Action) {
		if err := l.validateNoResolve(expr, rule.MihomoRuleSource); err != nil {
			return nil, err
		}
	}

	terms, err := l.lowerExpression(expr, false, rule.MihomoRuleSource, limit)
	if err != nil {
		return nil, err
	}
	outbound, err := l.lowerAction(rule.Action, rule.MihomoRuleSource)
	if err != nil {
		return nil, err
	}
	if len(terms) > limit {
		return nil, mihomoLoweringError(rule.MihomoRuleSource, fmt.Sprintf("expanded routing rules exceed %d", limit))
	}

	result := make([]MihomoLoweredRoutingRule, 0, len(terms))
	for index, term := range terms {
		functions := make([]*config_parser.Function, len(term))
		for i := range term {
			functions[i] = term[i]
		}
		result = append(result, MihomoLoweredRoutingRule{
			Source:           rule.MihomoRuleSource,
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
		l.logIgnoredAtomOptions(*expr.Atom, source)
		if ignoredMihomoAtom(expr.Atom.Type) {
			// IN-PORT and IP-ASN depend on runtime data that is intentionally not
			// modeled here. Treat either condition as an ignored branch:
			// conjunctions containing it are skipped and OR expressions may still
			// lower their representable branches.
			l.logOnce(fmt.Sprintf("condition:%d:%d:%s:%s", source.SourceIndex, source.SourceLine, source.Raw, expr.Atom.Type), "ignore Mihomo condition at index %d line %d (%q): atom %q", source.SourceIndex, source.SourceLine, source.Raw, expr.Atom.Type)
			return nil, nil
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

	case MihomoExprProviderData:
		function, err := lowerMihomoProviderData(expr.ProviderDataRef, negated, source)
		if err != nil {
			return nil, err
		}
		return []mihomoLoweredTerm{{function}}, nil

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
		return []mihomoLoweredTerm{}, nil
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

func ignoredMihomoAtom(typeName string) bool {
	switch strings.ToUpper(strings.TrimSpace(typeName)) {
	case "IN-PORT", "IP-ASN":
		return true
	default:
		return false
	}
}

func (l *MihomoRuleLowerer) logIgnoredAtomOptions(atom MihomoAtom, source MihomoRuleSource) {
	_, options := mihomoAtomArguments(atom)
	for _, option := range options {
		if strings.EqualFold(strings.TrimSpace(option), "match-mac") {
			l.logOnce(fmt.Sprintf("condition-option:%d:%d:%s:%s:%s", source.SourceIndex, source.SourceLine, source.Raw, atom.Type, option), "ignore Mihomo condition option at index %d line %d (%q): atom %q option %q", source.SourceIndex, source.SourceLine, source.Raw, atom.Type, option)
		}
	}
}

func (l *MihomoRuleLowerer) logRuleSkip(source MihomoRuleSource, err error) {
	l.logOnce(fmt.Sprintf("rule-skip:%d:%d:%s:%v", source.SourceIndex, source.SourceLine, source.Raw, err), "skip Mihomo rule at index %d line %d (%q): %v", source.SourceIndex, source.SourceLine, source.Raw, err)
}

func (l *MihomoRuleLowerer) logf(format string, args ...any) {
	if l.options.Logf != nil {
		l.options.Logf(format, args...)
	}
}

func (l *MihomoRuleLowerer) logOnce(key, format string, args ...any) {
	if l.options.Logf == nil {
		return
	}
	if _, ok := l.logged[key]; ok {
		return
	}
	l.logged[key] = struct{}{}
	l.logf(format, args...)
}

func lowerMihomoAtom(atom MihomoAtom, negated bool, source MihomoRuleSource) (*config_parser.Function, error) {
	arguments, options := mihomoAtomArguments(atom)
	if len(arguments) == 0 {
		return nil, mihomoLoweringError(source, fmt.Sprintf("Mihomo atom %q has no value", atom.Type))
	}
	if err := validateMihomoAtomOptions(atom.Type, options, source); err != nil {
		return nil, err
	}
	if strings.EqualFold(atom.Type, "DOMAIN-WILDCARD") {
		wildcardRegex, err := mihomoDomainWildcardRegex(arguments[0])
		if err != nil {
			return nil, mihomoLoweringError(source, err.Error())
		}
		arguments[0] = wildcardRegex
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
	case "DOMAIN-WILDCARD":
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
	case "IN-PORT", "IP-ASN":
		return nil, mihomoLoweringError(source, fmt.Sprintf("unsupported Mihomo atom %q", atom.Type))
	default:
		if strings.HasPrefix(strings.ToUpper(atom.Type), "GEO") {
			return nil, mihomoLoweringError(source, fmt.Sprintf("unsupported Mihomo atom %q", atom.Type))
		}
		return nil, mihomoLoweringError(source, fmt.Sprintf("unsupported unknown Mihomo atom %q", atom.Type))
	}
	if mihomoAtomHasOption(options, "src") {
		switch strings.ToUpper(atom.Type) {
		case "IP-CIDR", "IP-CIDR6":
			functionName = "sip"
		}
	}
	if key != "" {
		for _, param := range params {
			param.Key = key
			if key == "keyword" {
				param.Val = canonicalizeMihomoDomainKeyword(param.Val)
			}
		}
	}
	return &config_parser.Function{Name: functionName, Not: negated, Params: params}, nil
}

// mihomoAtomArguments separates the primary match value from condition
// parameters that are legal in nested AND/OR/NOT/SUB-RULE expressions. The
// parser intentionally keeps the original slice intact; this helper is the
// single place where a known atom's grammar is interpreted for lowering.
func mihomoAtomArguments(atom MihomoAtom) (arguments, options []string) {
	arguments = append([]string(nil), atom.Arguments...)
	if len(arguments) == 0 && atom.Value != "" {
		arguments = []string{atom.Value}
	}
	if isKnownMihomoAtom(atom.Type) && len(arguments) > 1 {
		options = append([]string(nil), arguments[1:]...)
		arguments = arguments[:1]
	}
	return arguments, options
}

func validateMihomoAtomOptions(typeName string, options []string, source MihomoRuleSource) error {
	if len(options) == 0 {
		return nil
	}
	upperType := strings.ToUpper(typeName)
	for _, option := range options {
		option = strings.TrimSpace(option)
		switch {
		case strings.EqualFold(option, "no-resolve"):
			switch upperType {
			case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
				// kdae's IP matchers do not perform the Mihomo hostname
				// resolution fallback, so this option is semantically inert
				// after the condition has been lowered to an IP matcher.
			default:
				return mihomoLoweringError(source, fmt.Sprintf("Mihomo atom %q option %q has no exact kdae equivalent", typeName, option))
			}
		case strings.EqualFold(option, "src"):
			if upperType != "IP-CIDR" && upperType != "IP-CIDR6" && upperType != "SRC-IP-CIDR" {
				return mihomoLoweringError(source, fmt.Sprintf("Mihomo atom %q option %q has no exact kdae equivalent", typeName, option))
			}
		case strings.EqualFold(option, "match-mac"):
			// Mihomo's match-mac qualification is intentionally ignored. The
			// remaining source-IP condition is still lowered to kdae's sip().
			continue
		default:
			return mihomoLoweringError(source, fmt.Sprintf("unsupported Mihomo atom %q option %q", typeName, option))
		}
	}
	return nil
}

func mihomoAtomHasOption(options []string, wanted string) bool {
	for _, option := range options {
		if strings.EqualFold(strings.TrimSpace(option), wanted) {
			return true
		}
	}
	return false
}

func lowerMihomoProviderData(ref *MihomoProviderDataRef, negated bool, source MihomoRuleSource) (*config_parser.Function, error) {
	if err := validateMihomoProviderDataRef(ref, source); err != nil {
		return nil, err
	}

	providerCode := strings.TrimSpace(ref.ProviderCode)
	if ref.UseDAT {
		return &config_parser.Function{
			Name: map[MihomoProviderDataKind]string{
				MihomoProviderDataDomain: "domain",
				MihomoProviderDataIPCIDR: "ip",
			}[ref.Kind],
			Not:    negated,
			Params: []*config_parser.Param{{Key: "ext", Val: strings.TrimSpace(ref.DATRelativePath) + ":" + providerCode}},
		}, nil
	}

	if ref.Kind == MihomoProviderDataDomain {
		params := make([]*config_parser.Param, 0, len(ref.Domains))
		for _, rule := range ref.Domains {
			key := string(rule.Kind)
			params = append(params, &config_parser.Param{Key: key, Val: rule.Value})
		}
		return &config_parser.Function{Name: "domain", Not: negated, Params: params}, nil
	}

	params := make([]*config_parser.Param, 0, len(ref.Prefixes))
	for _, prefix := range ref.Prefixes {
		params = append(params, &config_parser.Param{Val: prefix.String()})
	}
	return &config_parser.Function{Name: "ip", Not: negated, Params: params}, nil
}

func validateMihomoProviderDataRef(ref *MihomoProviderDataRef, source MihomoRuleSource) error {
	if ref == nil {
		return mihomoLoweringError(source, "provider-data expression has no provider data")
	}
	if !providerNamePattern.MatchString(ref.ProviderCode) {
		return mihomoLoweringError(source, fmt.Sprintf("provider-data provider code %q is not a safe identifier", ref.ProviderCode))
	}

	validateDATPath := func(directory string) error {
		path := ref.DATRelativePath
		if strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return mihomoLoweringError(source, "provider-data DAT binding path contains a control character")
		}
		if strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) {
			return mihomoLoweringError(source, "provider-data DAT binding path must be relative")
		}
		for _, component := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
			if component == ".." {
				return mihomoLoweringError(source, "provider-data DAT binding path must not contain a parent component")
			}
		}
		expected := directory + ref.ProviderCode + ".dat"
		if path != expected {
			return mihomoLoweringError(source, fmt.Sprintf("provider-data DAT binding path %q does not match %q", path, expected))
		}
		return nil
	}

	if ref.UseDAT {
		if strings.TrimSpace(ref.DATRelativePath) == "" {
			return mihomoLoweringError(source, "provider-data DAT binding has an empty relative path")
		}
		if len(ref.Domains) != 0 || len(ref.Prefixes) != 0 {
			return mihomoLoweringError(source, "provider-data DAT binding must not include inline data")
		}
	} else if strings.TrimSpace(ref.DATRelativePath) != "" {
		return mihomoLoweringError(source, "inline provider-data must not include a DAT path")
	}

	switch ref.Kind {
	case MihomoProviderDataDomain:
		if ref.UseDAT {
			if err := validateDATPath("generated/geosite/"); err != nil {
				return err
			}
		}
		if len(ref.Prefixes) != 0 {
			return mihomoLoweringError(source, "domain provider-data contains ipcidr data")
		}
		if !ref.UseDAT && len(ref.Domains) == 0 {
			return mihomoLoweringError(source, "domain provider-data has no inline rules")
		}
		for _, rule := range ref.Domains {
			if strings.TrimSpace(rule.Value) == "" {
				return mihomoLoweringError(source, "domain provider-data contains an empty inline value")
			}
			switch rule.Kind {
			case DomainFull, DomainSuffix, DomainKeyword, DomainRegex:
			default:
				return mihomoLoweringError(source, fmt.Sprintf("domain provider-data has unsupported rule kind %q", rule.Kind))
			}
		}
	case MihomoProviderDataIPCIDR:
		if ref.UseDAT {
			if err := validateDATPath("generated/geoip/"); err != nil {
				return err
			}
		}
		if len(ref.Domains) != 0 {
			return mihomoLoweringError(source, "ipcidr provider-data contains domain data")
		}
		if !ref.UseDAT && len(ref.Prefixes) == 0 {
			return mihomoLoweringError(source, "ipcidr provider-data has no inline rules")
		}
		for _, prefix := range ref.Prefixes {
			if !prefix.IsValid() {
				return mihomoLoweringError(source, "ipcidr provider-data contains an invalid inline prefix")
			}
		}
	default:
		return mihomoLoweringError(source, fmt.Sprintf("provider-data has unsupported kind %q", ref.Kind))
	}
	return nil
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
		// The requested compatibility policy treats Mihomo's silent-drop
		// action as kdae's block outbound.
		outbound = "block"
	default:
		var ok bool
		outbound, ok = l.options.OutboundNameMap[target]
		if !ok || strings.TrimSpace(outbound) == "" {
			return nil, mihomoLoweringError(source, fmt.Sprintf("outbound %q has no safe outbound mapping", target))
		}
	}
	return &config_parser.Function{Name: outbound}, nil
}

func (l *MihomoRuleLowerer) validateRuleOptions(expr MihomoExpr, action MihomoAction, source MihomoRuleSource) error {
	for _, option := range action.Options {
		option = strings.TrimSpace(option)
		switch {
		case strings.EqualFold(option, "no-resolve"):
			continue
		case strings.EqualFold(option, "src"):
			if !mihomoExprSupportsSourceIP(expr) {
				return mihomoLoweringError(source, fmt.Sprintf("Mihomo rule option %q has no exact kdae equivalent for expression %q", option, expr.Kind))
			}
			continue
		case strings.EqualFold(option, "match-mac"):
			l.logOnce(fmt.Sprintf("action-option:%d:%d:%s:%s", source.SourceIndex, source.SourceLine, source.Raw, option), "ignore Mihomo rule option at index %d line %d (%q): action option %q", source.SourceIndex, source.SourceLine, source.Raw, option)
			continue
		default:
			return mihomoLoweringError(source, fmt.Sprintf("unsupported Mihomo rule option %q", option))
		}
	}
	return nil
}

func mihomoExprSupportsSourceIP(expr MihomoExpr) bool {
	if expr.Kind != MihomoExprAtom || expr.Atom == nil {
		return false
	}
	switch strings.ToUpper(expr.Atom.Type) {
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
		return true
	default:
		return false
	}
}

func (l *MihomoRuleLowerer) applyRuleOptions(expr MihomoExpr, options []string, source MihomoRuleSource) (MihomoExpr, error) {
	for _, option := range options {
		if !strings.EqualFold(strings.TrimSpace(option), "src") {
			continue
		}
		if !mihomoExprSupportsSourceIP(expr) {
			return MihomoExpr{}, mihomoLoweringError(source, fmt.Sprintf("Mihomo rule option %q has no exact kdae equivalent for expression %q", option, expr.Kind))
		}
		cloned := expr
		atom := *expr.Atom
		atom.Arguments = append([]string(nil), expr.Atom.Arguments...)
		if len(atom.Arguments) == 0 && atom.Value != "" {
			atom.Arguments = []string{atom.Value}
		}
		if len(atom.Arguments) <= 1 || !mihomoAtomHasOption(atom.Arguments[1:], "src") {
			atom.Arguments = append(atom.Arguments, "src")
		}
		cloned.Atom = &atom
		expr = cloned
	}
	return expr, nil
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
		if ignoredMihomoAtom(expr.Atom.Type) {
			return nil
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
	case MihomoExprProviderData:
		if err := validateMihomoProviderDataRef(expr.ProviderDataRef, source); err != nil {
			return err
		}
		if expr.ProviderDataRef.Kind != MihomoProviderDataIPCIDR {
			return mihomoLoweringError(source, fmt.Sprintf("no-resolve is only equivalent for ipcidr provider-data, not %q", expr.ProviderDataRef.Kind))
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
