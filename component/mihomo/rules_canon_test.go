package mihomo

import (
	"fmt"
	"sort"
	"strings"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// canonProgram reduces an ordered rule list to a structure-independent form
// so two spellings of the same routing behavior compare equal:
//
//   - function aliases are unified with dae's own AliasOptimizer;
//   - a multi-value function becomes one atom per value (OR, or AND when the
//     function is negated);
//   - every rule, including route_expr, is flattened to a disjunction of
//     conjunctions in rule order;
//   - atoms inside a term are sorted, except in terms holding a no-resolve
//     predicate, where evaluation order is observable and kept.
//
// Rule order and outbounds are preserved exactly.
func canonProgram(rules []*config_parser.RoutingRule, fallback string) ([]string, error) {
	cloned := routing.DeepCloneRules(rules)
	if _, err := (&routing.AliasOptimizer{}).Optimize(cloned); err != nil {
		return nil, err
	}
	var out []string
	for _, rule := range cloned {
		root := &routing.OrderedExpr{Op: "and"}
		for _, f := range rule.AndFunctions {
			e, err := routing.ExprFromFunction(f)
			if err != nil {
				return nil, err
			}
			root.Children = append(root.Children, splitValues(e))
		}
		if len(root.Children) == 0 {
			out = append(out, "ALWAYS -> "+rule.Outbound.Name)
			continue
		}
		terms, err := root.DNF(false, 1_000_000)
		if err != nil {
			return nil, err
		}
		for _, t := range terms {
			out = append(out, canonTerm(t)+" -> "+rule.Outbound.Name)
		}
	}
	if fallback == "" {
		fallback = "direct"
	}
	return append(out, "FALLBACK "+fallback), nil
}

// splitValues rewrites every atom into single-value atoms.
func splitValues(e *routing.OrderedExpr) *routing.OrderedExpr {
	if e.Op != "atom" {
		c := &routing.OrderedExpr{Op: e.Op}
		for _, child := range e.Children {
			c.Children = append(c.Children, splitValues(child))
		}
		return c
	}
	f := e.Atom
	if len(f.Params) <= 1 {
		return e
	}
	op := "or"
	if f.Not {
		op = "and"
	}
	c := &routing.OrderedExpr{Op: op}
	for _, p := range f.Params {
		single := *f
		single.Params = []*config_parser.Param{p}
		c.Children = append(c.Children, &routing.OrderedExpr{Op: "atom", Atom: &single})
	}
	return c
}

// canonName unifies the aliases dae treats as the same function. dae's
// AliasOptimizer does this for plain rules only, so atoms decoded from a
// route_expr are normalized here.
func canonName(name string) string {
	switch name {
	case "dip":
		return "ip"
	case "dport":
		return "port"
	case "dip_no_resolve":
		return "ip_no_resolve"
	}
	return name
}

func canonTerm(term []*config_parser.Function) string {
	parts := make([]string, 0, len(term))
	ordered := false
	for _, f := range term {
		if strings.HasSuffix(f.Name, "_no_resolve") {
			ordered = true
		}
		s := canonName(f.Name) + "("
		for i, p := range f.Params {
			if i > 0 {
				s += ","
			}
			val := p.Val
			if f.Name == "domain" && (p.Key == "full" || p.Key == "suffix" || p.Key == "keyword" || p.Key == "") {
				// dae lower-cases domain patterns when it builds the matcher.
				val = strings.ToLower(val)
			}
			if p.Key != "" {
				s += p.Key + "="
			}
			s += val
		}
		s += ")"
		if f.Not {
			s = "!" + s
		}
		parts = append(parts, s)
	}
	if !ordered {
		sort.Strings(parts)
		parts = dedupe(parts)
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, " & "))
}

func dedupe(sorted []string) []string {
	out := sorted[:0:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}
