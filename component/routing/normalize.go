/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func NewNormalizedProgram(
	rules []*config_parser.RoutingRule,
	fallback config.FunctionOrString,
	optimizers ...RulesOptimizer,
) (*NormalizedProgram, error) {

	if HasOrderedRules(rules) {
		ordered := make([]OrderedRule, 0, len(rules))
		for _, r := range DeepCloneRules(rules) {
			root := &OrderedExpr{Op: "and"}
			for _, f := range r.AndFunctions {
				e, err := ExprFromFunction(f)
				if err != nil {
					return nil, err
				}
				root.Children = append(root.Children, e)
			}
			if len(root.Children) == 0 {
				root.Children = append(root.Children, &OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: "port", Params: []*config_parser.Param{{Val: "0-65535"}}}})
			}
			if err := root.Walk(func(*config_parser.Function) error { return nil }); err != nil {
				return nil, err
			}
			compactOrderedExpr(root)
			ordered = appendOrderedRule(ordered, OrderedRule{Expr: root, Outbound: r.Outbound})
		}
		var expanded []*config_parser.RoutingRule
		id := 0
		for _, r := range ordered {
			if err := r.Expr.Walk(func(f *config_parser.Function) error { id++; f.EvaluationID = id; return nil }); err != nil {
				return nil, err
			}
			terms, err := r.Expr.DNF(false, 100000)
			if err != nil {
				return nil, err
			}
			for _, term := range terms {
				expanded = append(expanded, &config_parser.RoutingRule{AndFunctions: term, Outbound: r.Outbound})
			}
		}
		// Safe set compaction is already done. Do not run the legacy optimizer,
		// which also reorders AND predicates and would invalidate identities.
		filtered := make([]RulesOptimizer, 0, len(optimizers))
		for _, o := range optimizers {
			if _, ok := o.(*MergeAndSortRulesOptimizer); !ok {
				filtered = append(filtered, o)
			}
		}
		normalized, err := ApplyRulesOptimizers(expanded, filtered...)
		if err != nil {
			return nil, err
		}
		return &NormalizedProgram{Rules: normalized, Fallback: fallback, Ordered: ordered}, nil
	}
	var (
		normalized []*config_parser.RoutingRule
		err        error
	)
	if len(optimizers) > 0 {
		normalized, err = ApplyRulesOptimizers(rules, optimizers...)
		if err != nil {
			return nil, err
		}
	} else {
		normalized = DeepCloneRules(rules)
	}
	return &NormalizedProgram{
		Rules:    normalized,
		Fallback: fallback,
	}, nil
}

func (p *NormalizedProgram) Lower(
	log *logrus.Logger,
	registerParsers func(*RulesBuilder),
	addFallback func(config.FunctionOrString) error,
) error {
	if p == nil {
		return nil
	}
	builder := NewRulesBuilder(log)
	if registerParsers != nil {
		registerParsers(builder)
	}
	if err := builder.Apply(p.Rules); err != nil {
		return err
	}
	if addFallback != nil {
		return addFallback(p.Fallback)
	}
	return nil
}
