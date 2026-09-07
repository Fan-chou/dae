package routing

import "github.com/daeuniverse/dae/pkg/config_parser"

// compactOrderedExpr combines adjacent positive sets in an OR, without
// distributing expressions or moving predicates across a resolution/call boundary.
// It runs on owned trees, before assigning evaluation identities.
func compactOrderedExpr(e *OrderedExpr) {
	for _, child := range e.Children {
		compactOrderedExpr(child)
	}
	if e.Op != "or" {
		return
	}
	children := e.Children[:0]
	for _, child := range e.Children {
		if len(children) != 0 && mergeOrderedSets(children[len(children)-1], child) {
			continue
		}
		children = append(children, child)
	}
	e.Children = children
}

func orderedSetAtom(e *OrderedExpr) *config_parser.Function {
	for e.MemoID == 0 {
		if e.Op == "atom" {
			if e.Atom.Not || len(e.Atom.Params) == 0 {
				return nil
			}
			return e.Atom
		}
		if (e.Op != "and" && e.Op != "or") || len(e.Children) != 1 {
			return nil
		}
		e = e.Children[0]
	}
	return nil
}

func orderedSetKind(name string) string {
	switch name {
	case "domain":
		return "domain"
	case "ip", "dip":
		return "ip"
	case "ip_no_resolve", "dip_no_resolve":
		return "ip_no_resolve"
	}
	return ""
}

func mergeOrderedSets(left, right *OrderedExpr) bool {
	a, b := orderedSetAtom(left), orderedSetAtom(right)
	if a == nil || b == nil {
		return false
	}
	kind := orderedSetKind(a.Name)
	if kind == "" || kind != orderedSetKind(b.Name) {
		return false
	}
	a.Params = append(a.Params, b.Params...)
	return true
}

func appendOrderedRule(rules []OrderedRule, rule OrderedRule) []OrderedRule {
	if len(rules) != 0 {
		last := &rules[len(rules)-1]
		if last.Outbound.String(true, true, false) == rule.Outbound.String(true, true, false) &&
			mergeOrderedSets(last.Expr, rule.Expr) {
			return rules
		}
	}
	return append(rules, rule)
}
