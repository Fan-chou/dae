package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// MihomoProviderBindingOptions controls provider-data binding. A zero DAT
// threshold selects generationDATRuleThreshold; a zero expansion limit
// selects DefaultMihomoRuleMaxExpandedRules. The limit counts bound data
// leaves, including both leaves produced for one classical provider.
type MihomoProviderBindingOptions struct {
	UseDAT                     bool
	GenerationDATRuleThreshold int
	MaxExpandedRules           int
}

// MihomoProviderBindingResult is the provider-bound view consumed by later
// lowerers. Actions, source order, and rule boundaries remain in IR; provider
// data is represented only by explicit provider-data expression nodes.
type MihomoProviderBindingResult struct {
	IR                 MihomoRuleIR
	GenerationDATSpecs []generationDATSpec
	UsedProviders      []string
}

// BindMihomoProviderData replaces every RULE-SET expression in ir, including
// expressions below sub-rule definitions, with typed provider-data nodes. It
// does not lower actions or create routing rules.
func BindMihomoProviderData(
	ir MihomoRuleIR,
	normalization MihomoProviderNormalization,
	sets map[string]ParsedRuleSet,
	options MihomoProviderBindingOptions,
) (MihomoProviderBindingResult, error) {
	binder, err := newMihomoProviderBinder(normalization, sets, options)
	if err != nil {
		return MihomoProviderBindingResult{}, err
	}
	bound := MihomoRuleIR{
		Rules:    make([]MihomoRuleIRRule, 0, len(ir.Rules)),
		SubRules: make([]MihomoSubRuleIR, 0, len(ir.SubRules)),
	}
	for _, rule := range ir.Rules {
		cloned, err := binder.bindRule(rule)
		if err != nil {
			return MihomoProviderBindingResult{}, err
		}
		bound.Rules = append(bound.Rules, cloned)
	}
	for _, subRule := range ir.SubRules {
		cloned := MihomoSubRuleIR{
			Name:        subRule.Name,
			SourceIndex: subRule.SourceIndex,
			SourceLine:  subRule.SourceLine,
			Rules:       make([]MihomoRuleIRRule, 0, len(subRule.Rules)),
		}
		for _, rule := range subRule.Rules {
			boundRule, err := binder.bindRule(rule)
			if err != nil {
				return MihomoProviderBindingResult{}, err
			}
			cloned.Rules = append(cloned.Rules, boundRule)
		}
		bound.SubRules = append(bound.SubRules, cloned)
	}
	return MihomoProviderBindingResult{
		IR:                 bound,
		GenerationDATSpecs: cloneGenerationDATSpecs(binder.datSpecs),
		UsedProviders:      append([]string(nil), binder.usedProviders...),
	}, nil
}

// BindMihomoRuleProviderData is the rule-oriented spelling retained for
// callers that name the source feature after RULE-SET providers.
func BindMihomoRuleProviderData(
	ir MihomoRuleIR,
	normalization MihomoProviderNormalization,
	sets map[string]ParsedRuleSet,
	options MihomoProviderBindingOptions,
) (MihomoProviderBindingResult, error) {
	return BindMihomoProviderData(ir, normalization, sets, options)
}

// BindMihomoRuleProviders is a concise compatibility spelling for the same
// data-only binding operation.
func BindMihomoRuleProviders(
	ir MihomoRuleIR,
	normalization MihomoProviderNormalization,
	sets map[string]ParsedRuleSet,
	options MihomoProviderBindingOptions,
) (MihomoProviderBindingResult, error) {
	return BindMihomoProviderData(ir, normalization, sets, options)
}

type mihomoProviderBinder struct {
	normalization MihomoProviderNormalization
	sets          map[string]ParsedRuleSet
	useDAT        bool
	datThreshold  int
	maxLeaves     int
	boundLeaves   int
	datSpecs      []generationDATSpec
	datSpecIndex  map[string]int
	usedProviders []string
	used          map[string]struct{}
}

func newMihomoProviderBinder(
	normalization MihomoProviderNormalization,
	sets map[string]ParsedRuleSet,
	options MihomoProviderBindingOptions,
) (*mihomoProviderBinder, error) {
	threshold := options.GenerationDATRuleThreshold
	if threshold == 0 {
		threshold = generationDATRuleThreshold
	}
	if threshold < 0 {
		return nil, fmt.Errorf("GenerationDATRuleThreshold must not be negative")
	}
	maxLeaves := options.MaxExpandedRules
	if maxLeaves == 0 {
		maxLeaves = DefaultMihomoRuleMaxExpandedRules
	}
	if maxLeaves < 0 {
		return nil, fmt.Errorf("MaxExpandedRules must not be negative")
	}
	return &mihomoProviderBinder{
		normalization: normalization,
		sets:          sets,
		useDAT:        options.UseDAT,
		datThreshold:  threshold,
		maxLeaves:     maxLeaves,
		datSpecIndex:  make(map[string]int),
		used:          make(map[string]struct{}),
	}, nil
}

func (b *mihomoProviderBinder) bindRule(rule MihomoRuleIRRule) (MihomoRuleIRRule, error) {
	cloned := cloneMihomoRuleIRRule(rule)
	expr, err := b.bindExpression(cloned.Expr, cloned.MihomoRuleSource)
	if err != nil {
		return MihomoRuleIRRule{}, err
	}
	cloned.Expr = expr
	return cloned, nil
}

func (b *mihomoProviderBinder) bindExpression(expr MihomoExpr, source MihomoRuleSource) (MihomoExpr, error) {
	if expr.Kind == MihomoExprRuleSet {
		return b.bindRuleSet(expr, source)
	}
	cloned := expr
	if len(expr.Children) != 0 {
		cloned.Children = make([]MihomoExpr, len(expr.Children))
		for index, child := range expr.Children {
			bound, err := b.bindExpression(child, source)
			if err != nil {
				return MihomoExpr{}, err
			}
			cloned.Children[index] = bound
		}
	}
	if expr.SubRuleRef != nil {
		guard, err := b.bindExpression(expr.SubRuleRef.Guard, source)
		if err != nil {
			return MihomoExpr{}, err
		}
		ref := *expr.SubRuleRef
		ref.Guard = guard
		cloned.SubRuleRef = &ref
	}
	return cloned, nil
}

func (b *mihomoProviderBinder) bindRuleSet(expr MihomoExpr, source MihomoRuleSource) (MihomoExpr, error) {
	if expr.ProviderRef == nil || strings.TrimSpace(expr.ProviderRef.Provider) == "" {
		return MihomoExpr{}, b.bindingError(source, "RULE-SET expression has an empty provider")
	}
	providerName := strings.TrimSpace(expr.ProviderRef.Provider)
	safeName, provider, err := b.resolveProvider(providerName)
	if err != nil {
		return MihomoExpr{}, b.bindingError(source, err.Error())
	}
	set, err := b.resolveRuleSet(providerName, safeName)
	if err != nil {
		return MihomoExpr{}, b.bindingError(source, err.Error())
	}
	if len(set.Unsupported) != 0 {
		return MihomoExpr{}, b.bindingError(source, fmt.Sprintf("provider %q contains %d unsupported rules; refusing to bind a convertible subset", providerName, len(set.Unsupported)))
	}
	behavior := strings.ToLower(strings.TrimSpace(provider.Behavior))
	switch behavior {
	case "domain":
		if len(set.Prefixes) != 0 {
			return MihomoExpr{}, b.bindingError(source, fmt.Sprintf("provider %q has ipcidr data but behavior is domain", providerName))
		}
		if len(set.Domains) == 0 {
			return MihomoExpr{}, b.bindingError(source, fmt.Sprintf("provider %q has no domain rules", providerName))
		}
		leaf, err := b.bindLeaf(safeName, MihomoProviderDataDomain, set)
		if err != nil {
			return MihomoExpr{}, b.bindingError(source, err.Error())
		}
		return leaf, nil
	case "ipcidr":
		if len(set.Domains) != 0 {
			return MihomoExpr{}, b.bindingError(source, fmt.Sprintf("provider %q has domain data but behavior is ipcidr", providerName))
		}
		if len(set.Prefixes) == 0 {
			return MihomoExpr{}, b.bindingError(source, fmt.Sprintf("provider %q has no ipcidr rules", providerName))
		}
		leaf, err := b.bindLeaf(safeName, MihomoProviderDataIPCIDR, set)
		if err != nil {
			return MihomoExpr{}, b.bindingError(source, err.Error())
		}
		return leaf, nil
	case "classical":
		if len(set.Domains) == 0 && len(set.Prefixes) == 0 {
			return MihomoExpr{}, b.bindingError(source, fmt.Sprintf("provider %q has no domain or ipcidr rules", providerName))
		}
		if len(set.Domains) == 0 {
			leaf, err := b.bindLeaf(safeName, MihomoProviderDataIPCIDR, set)
			if err != nil {
				return MihomoExpr{}, b.bindingError(source, err.Error())
			}
			return leaf, nil
		}
		if len(set.Prefixes) == 0 {
			leaf, err := b.bindLeaf(safeName, MihomoProviderDataDomain, set)
			if err != nil {
				return MihomoExpr{}, b.bindingError(source, err.Error())
			}
			return leaf, nil
		}
		domainLeaf, err := b.bindLeaf(safeName, MihomoProviderDataDomain, set)
		if err != nil {
			return MihomoExpr{}, b.bindingError(source, err.Error())
		}
		ipLeaf, err := b.bindLeaf(safeName, MihomoProviderDataIPCIDR, set)
		if err != nil {
			return MihomoExpr{}, b.bindingError(source, err.Error())
		}
		return MihomoExpr{
			Kind:     MihomoExprOr,
			Raw:      expr.Raw,
			Children: []MihomoExpr{domainLeaf, ipLeaf},
		}, nil
	default:
		return MihomoExpr{}, b.bindingError(source, fmt.Sprintf("provider %q has unsupported behavior %q", providerName, provider.Behavior))
	}
}

func (b *mihomoProviderBinder) bindLeaf(providerCode string, kind MihomoProviderDataKind, set ParsedRuleSet) (MihomoExpr, error) {
	var count int
	if kind == MihomoProviderDataDomain {
		count = len(set.Domains)
	} else {
		count = len(set.Prefixes)
	}
	if count == 0 {
		return MihomoExpr{}, fmt.Errorf("provider %q has no %s rules", providerCode, kind)
	}
	if b.maxLeaves-b.boundLeaves < 1 {
		return MihomoExpr{}, fmt.Errorf("bound provider-data leaves exceed %d", b.maxLeaves)
	}
	b.boundLeaves++
	b.recordProvider(providerCode)
	useDAT := b.useDAT && count > b.datThreshold
	ref := &MihomoProviderDataRef{ProviderCode: providerCode, Kind: kind, UseDAT: useDAT}
	if useDAT {
		ref.DATRelativePath = mihomoProviderDATPath(providerCode, kind)
		b.recordDATSpec(providerCode, kind, ref.DATRelativePath, set)
	} else if kind == MihomoProviderDataDomain {
		ref.Domains = append([]DomainRule(nil), set.Domains...)
	} else {
		ref.Prefixes = append(ref.Prefixes, set.Prefixes...)
	}
	return MihomoExpr{Kind: MihomoExprProviderData, ProviderDataRef: ref}, nil
}

func (b *mihomoProviderBinder) resolveProvider(name string) (string, ProviderSpec, error) {
	safeName := strings.TrimSpace(b.normalization.NameMap[name])
	if safeName == "" {
		if _, ok := b.normalization.ReverseNameMap[name]; ok {
			safeName = name
		}
	}
	if safeName == "" {
		return "", ProviderSpec{}, fmt.Errorf("RULE-SET provider %q has no safe provider mapping", name)
	}
	for _, provider := range b.normalization.Providers {
		if provider.Name == safeName {
			return safeName, provider, nil
		}
	}
	return "", ProviderSpec{}, fmt.Errorf("RULE-SET provider %q maps to undeclared safe provider %q", name, safeName)
}

func (b *mihomoProviderBinder) resolveRuleSet(name, safeName string) (ParsedRuleSet, error) {
	if set, ok := b.sets[name]; ok {
		return set, nil
	}
	if set, ok := b.sets[safeName]; ok {
		return set, nil
	}
	if original := b.normalization.ReverseNameMap[safeName]; original != "" {
		if set, ok := b.sets[original]; ok {
			return set, nil
		}
	}
	return ParsedRuleSet{}, fmt.Errorf("RULE-SET provider %q has missing rule-set data mapping", name)
}

func (b *mihomoProviderBinder) recordProvider(providerCode string) {
	if _, exists := b.used[providerCode]; exists {
		return
	}
	b.used[providerCode] = struct{}{}
	b.usedProviders = append(b.usedProviders, providerCode)
}

func (b *mihomoProviderBinder) recordDATSpec(providerCode string, kind MihomoProviderDataKind, path string, set ParsedRuleSet) {
	key := providerCode + "\x00" + string(kind)
	if _, exists := b.datSpecIndex[key]; exists {
		return
	}
	b.datSpecIndex[key] = len(b.datSpecs)
	spec := generationDATSpec{Provider: providerCode, Kind: string(kind), RelativePath: path}
	if kind == MihomoProviderDataDomain {
		spec.Domains = append([]DomainRule(nil), set.Domains...)
	} else {
		spec.Prefixes = append(spec.Prefixes, set.Prefixes...)
	}
	b.datSpecs = append(b.datSpecs, spec)
}

func (b *mihomoProviderBinder) bindingError(source MihomoRuleSource, reason string) error {
	return fmt.Errorf("bind Mihomo provider data at index %d line %d: %s", source.SourceIndex, source.SourceLine, reason)
}

func mihomoProviderDATPath(providerCode string, kind MihomoProviderDataKind) string {
	if kind == MihomoProviderDataDomain {
		return "generated/geosite/" + providerCode + ".dat"
	}
	return "generated/geoip/" + providerCode + ".dat"
}

func cloneGenerationDATSpecs(specs []generationDATSpec) []generationDATSpec {
	if len(specs) == 0 {
		return nil
	}
	result := make([]generationDATSpec, len(specs))
	for index, spec := range specs {
		result[index] = spec
		result[index].Domains = append([]DomainRule(nil), spec.Domains...)
		result[index].Prefixes = append([]netip.Prefix(nil), spec.Prefixes...)
	}
	return result
}
