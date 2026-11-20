/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

const (
	maxRuleSummaryParams = 3
	maxRuleSummaryLen    = 128
)

func truncateUTF8WithEllipsis(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 3 {
		i := maxBytes
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		return s[:i]
	}
	i := maxBytes - 3
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + "..."
}

// SummarizeRoutingRule builds a concise, URI-safe display summary of a routing rule.
func SummarizeRoutingRule(r *config_parser.RoutingRule) string {
	if r == nil {
		return ""
	}
	parts := make([]string, 0, len(r.AndFunctions))
	for _, f := range r.AndFunctions {
		if f == nil {
			continue
		}
		var b strings.Builder
		if f.Not {
			b.WriteByte('!')
		}
		b.WriteString(f.Name)
		b.WriteByte('(')
		limit := len(f.Params)
		if limit > maxRuleSummaryParams {
			limit = maxRuleSummaryParams
		}
		for i := 0; i < limit; i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			p := f.Params[i]
			if p == nil {
				continue
			}
			val := sanitizeSummaryToken(p.Val)
			if p.Key != "" {
				b.WriteString(sanitizeSummaryToken(p.Key))
				b.WriteByte(':')
			}
			if val != "" {
				b.WriteString(val)
			} else if len(p.AndFunctions) > 0 {
				b.WriteString("...")
			}
		}
		if len(f.Params) > maxRuleSummaryParams {
			b.WriteString(fmt.Sprintf(", +%d", len(f.Params)-maxRuleSummaryParams))
		}
		b.WriteByte(')')
		parts = append(parts, b.String())
	}
	left := strings.Join(parts, " && ")
	if left == "" {
		left = "*"
	}
	outStr := r.Outbound.Name
	if len(r.Outbound.Params) > 0 {
		outStr = r.Outbound.String(false, false, false)
	}
	out := sanitizeSummaryToken(outStr)
	summary := left + " -> " + out
	return truncateUTF8WithEllipsis(summary, maxRuleSummaryLen)
}

func sanitizeSummaryToken(s string) string {
	if strings.Contains(s, "://") {
		return "[redacted]"
	}
	return s
}

func stampMissingRuleMeta(rules []*config_parser.RoutingRule) {
	for i, r := range rules {
		if r == nil {
			continue
		}
		if r.SourceIndex == 0 {
			r.SourceIndex = i + 1
		}
		if r.SourceOrigin == "" {
			r.SourceOrigin = "config"
		}
		if r.SourceSummary == "" {
			r.SourceSummary = SummarizeRoutingRule(r)
		}
	}
}

type ruleSourceMeta struct {
	index   int
	summary string
	origin  string
}

func NewNormalizedProgram(
	rules []*config_parser.RoutingRule,
	fallback config.FunctionOrString,
	optimizers ...RulesOptimizer,
) (*NormalizedProgram, error) {

	if HasOrderedRules(rules) {
		cloned := DeepCloneRules(rules)
		stampMissingRuleMeta(cloned)
		ordered := make([]OrderedRule, 0, len(cloned))
		orderedMeta := make([]ruleSourceMeta, 0, len(cloned))
		for _, r := range cloned {
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
			prevLen := len(ordered)
			ordered = appendOrderedRule(ordered, OrderedRule{Expr: root, Outbound: r.Outbound})
			meta := ruleSourceMeta{index: r.SourceIndex, summary: r.SourceSummary, origin: r.SourceOrigin}
			for len(orderedMeta) < len(ordered) {
				orderedMeta = append(orderedMeta, meta)
			}
			_ = prevLen
		}
		var expanded []*config_parser.RoutingRule
		id := 0
		for idx, r := range ordered {
			if err := r.Expr.Walk(func(f *config_parser.Function) error { id++; f.EvaluationID = id; return nil }); err != nil {
				return nil, err
			}
			terms, err := r.Expr.DNF(false, 100000)
			if err != nil {
				return nil, err
			}
			meta := orderedMeta[idx]
			for _, term := range terms {
				expanded = append(expanded, &config_parser.RoutingRule{
					AndFunctions:  term,
					Outbound:      r.Outbound,
					SourceIndex:   meta.index,
					SourceSummary: meta.summary,
					SourceOrigin:  meta.origin,
				})
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
	stamped := DeepCloneRules(rules)
	stampMissingRuleMeta(stamped)
	var (
		normalized []*config_parser.RoutingRule
		err        error
	)
	if len(optimizers) > 0 {
		normalized, err = ApplyRulesOptimizers(stamped, optimizers...)
		if err != nil {
			return nil, err
		}
	} else {
		normalized = stamped
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
