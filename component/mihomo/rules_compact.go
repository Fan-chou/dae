/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// Rules are matched first-hit in order, so two adjacent rules with the same
// outbound are one rule whose condition is the OR of both. Merging them
// before counting matters twice: dae spends one match set per rule, and the
// rule cap is there to protect that budget, so counting unmerged rules fails
// configurations that are small once merged.
//
// Only merges that cannot change what matches are done:
//
//   - plain rules: adjacent, one positive set function each, same function
//     name, same outbound (the rule dae's own optimizer applies later);
//   - ordered rules from one SUB-RULE call: adjacent, same outbound, same
//     guard (same memo id); the leaves are ORed behind the shared guard, in
//     order, so the guard is still decided once and resolution order is kept.
//
// Nothing is moved across another rule, so evaluation order and which rule
// hits first are unchanged.

// mergeableSets are the functions whose parameters are alternatives of one
// another. ruleset and route_expr are deliberately absent: they are expanded
// later and cannot take extra parameters.
var mergeableSets = map[string]struct{}{
	"domain": {}, "ip": {}, "dip": {}, "sip": {}, "mac": {}, "dport": {}, "sport": {}, "pname": {}, "l4proto": {},
}

func mergeablePlain(r *config_parser.RoutingRule) (*config_parser.Function, bool) {
	if len(r.AndFunctions) != 1 {
		return nil, false
	}
	f := r.AndFunctions[0]
	if f.Not || len(f.Params) == 0 {
		return nil, false
	}
	_, ok := mergeableSets[f.Name]
	return f, ok
}

// appendCompact appends r, merging it into the previous rule when that is
// safe. It returns the new list.
func (l *lowerer) appendCompact(list []*outRule, r *outRule) []*outRule {
	if !l.noCompact && len(list) > 0 && mergeInto(list[len(list)-1], r) {
		return list
	}
	return append(list, r)
}

func mergeInto(prev, next *outRule) bool {
	if prev.rule.Outbound.Name != next.rule.Outbound.Name {
		return false
	}
	if prev.ordered == nil && next.ordered == nil {
		a, ok := mergeablePlain(prev.rule)
		if !ok {
			return false
		}
		b, ok := mergeablePlain(next.rule)
		if !ok || a.Name != b.Name {
			return false
		}
		// Copy on write: expansion can leave two rules sharing a function.
		merged := *a
		merged.Params = append(append([]*config_parser.Param(nil), a.Params...), b.Params...)
		prev.rule = &config_parser.RoutingRule{AndFunctions: []*config_parser.Function{&merged}, Outbound: prev.rule.Outbound}
		return true
	}
	if prev.ordered == nil || next.ordered == nil {
		return false
	}
	return mergeGuarded(prev.ordered, next.ordered)
}

// guardedParts splits and[guard, leaf] where guard carries a SUB-RULE memo id.
func guardedParts(e *routing.OrderedExpr) (guard, leaf *routing.OrderedExpr, ok bool) {
	if e.Op != "and" || e.MemoID != 0 || len(e.Children) != 2 || e.Children[0].MemoID == 0 {
		return nil, nil, false
	}
	return e.Children[0], e.Children[1], true
}

func mergeGuarded(prev, next *routing.OrderedExpr) bool {
	pg, pl, ok := guardedParts(prev)
	if !ok {
		return false
	}
	ng, nl, ok := guardedParts(next)
	if !ok || pg.MemoID != ng.MemoID {
		return false
	}
	var alternatives []*routing.OrderedExpr
	for _, leaf := range []*routing.OrderedExpr{pl, nl} {
		if leaf.Op == "or" && leaf.MemoID == 0 {
			alternatives = append(alternatives, leaf.Children...)
		} else {
			alternatives = append(alternatives, leaf)
		}
	}
	prev.Children[1] = &routing.OrderedExpr{Op: "or", Children: alternatives}
	return true
}

// appendTerm adds a term to the alternatives of one rule, merging it into the
// previous term under the same condition as mergeablePlain.
func (l *lowerer) appendTerm(list []term, t term) []term {
	if !l.noCompact && len(list) > 0 {
		last := list[len(list)-1]
		if len(last) == 1 && len(t) == 1 && !last[0].Not && !t[0].Not &&
			last[0].Name == t[0].Name && len(last[0].Params) > 0 && len(t[0].Params) > 0 {
			if _, ok := mergeableSets[last[0].Name]; ok {
				merged := *last[0]
				merged.Params = append(append([]*config_parser.Param(nil), last[0].Params...), t[0].Params...)
				list[len(list)-1] = term{&merged}
				return list
			}
		}
	}
	return append(list, t)
}
