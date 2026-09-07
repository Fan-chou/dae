package main

import (
	"fmt"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func hasMihomoNoResolve(e MihomoExpr) bool {
	if e.NoResolve || e.MemoID != 0 {
		return true
	}
	if e.Atom != nil {
		_, opts := mihomoAtomArguments(*e.Atom)
		if mihomoAtomHasOption(opts, "no-resolve") {
			return true
		}
	}
	for _, c := range e.Children {
		if hasMihomoNoResolve(c) {
			return true
		}
	}
	return false
}

// Preserve the original expression instead of distributing side-effectful
// predicates into DNF. The routing compiler emits its own kernel-only DNF.
func (l *MihomoRuleLowerer) orderedExpr(e MihomoExpr, source MihomoRuleSource, inhibit bool) (*routing.OrderedExpr, error) {
	return l.orderedExprNegated(e, source, inhibit, false)
}

func (l *MihomoRuleLowerer) orderedExprNegated(e MihomoExpr, source MihomoRuleSource, inhibit, negated bool) (*routing.OrderedExpr, error) {
	if e.MemoID != 0 {
		id := e.MemoID
		e.MemoID = 0
		result, err := l.orderedExpr(e, source, inhibit)
		if err == nil {
			result.MemoID = id
			if negated {
				result = &routing.OrderedExpr{Op: "not", Children: []*routing.OrderedExpr{result}}
			}
		}
		return result, err
	}
	inhibit = inhibit || e.NoResolve
	switch e.Kind {
	case MihomoExprNot:
		if len(e.Children) != 1 {
			return nil, mihomoLoweringError(source, "NOT requires one child")
		}
		return l.orderedExprNegated(e.Children[0], source, inhibit, !negated)
	case MihomoExprAnd, MihomoExprOr:
		op := "and"
		if (e.Kind == MihomoExprOr) != negated {
			op = "or"
		}
		result := &routing.OrderedExpr{Op: op}
		for _, c := range e.Children {
			x, err := l.orderedExprNegated(c, source, inhibit, negated)
			if err != nil {
				return nil, err
			}
			result.Children = append(result.Children, x)
		}
		return result, nil
	case MihomoExprAtom:
		if e.Atom == nil {
			return nil, fmt.Errorf("nil Mihomo atom")
		}
		// Keep MATCH and the existing unsupported-condition policy identical
		// to the legacy importer, including under NOT / De Morgan transforms.
		terms, err := l.lowerExpression(e, negated, source, 1)
		if err != nil {
			return nil, err
		}
		f := &config_parser.Function{Name: "port", Not: len(terms) == 0, Params: []*config_parser.Param{{Val: "0-65535"}}}
		if len(terms) != 0 && len(terms[0]) != 0 {
			f = terms[0][0]
		}
		if inhibit && (f.Name == "dip" || f.Name == "ip") {
			f.Name = "ip_no_resolve"
		}
		return &routing.OrderedExpr{Op: "atom", Atom: f}, nil
	case MihomoExprRuleSet:
		if e.ProviderRef == nil {
			return nil, fmt.Errorf("nil provider reference")
		}
		name, ok := l.options.ProviderNameMap[e.ProviderRef.Provider]
		if !ok {
			return nil, mihomoLoweringError(source, "unknown provider "+e.ProviderRef.Provider)
		}
		fn := "ruleset"
		if inhibit {
			fn = "ruleset_no_resolve"
		}
		return &routing.OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: fn, Not: negated, Params: []*config_parser.Param{{Val: name}}}}, nil
	case MihomoExprProviderData:
		f, err := lowerMihomoProviderData(e.ProviderDataRef, negated, source)
		if err != nil {
			return nil, err
		}
		if inhibit && (f.Name == "ip" || f.Name == "dip") {
			f.Name = "ip_no_resolve"
		}
		return &routing.OrderedExpr{Op: "atom", Atom: f}, nil
	default:
		return nil, mihomoLoweringError(source, "unsupported ordered expression "+string(e.Kind))
	}
}
