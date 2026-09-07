package ruleprovider

import (
	"fmt"
	"github.com/daeuniverse/dae/component/routing"
)

func expandOrderedExpr(e *routing.OrderedExpr, registry Registry, inhibit bool) (*routing.OrderedExpr, error) {
	if e.MemoID != 0 {
		id := e.MemoID
		e.MemoID = 0
		result, err := expandOrderedExpr(e, registry, inhibit)
		if err == nil {
			result.MemoID = id
		}
		return result, err
	}
	if e.Op != "atom" {
		for i, c := range e.Children {
			x, err := expandOrderedExpr(c, registry, inhibit)
			if err != nil {
				return nil, err
			}
			e.Children[i] = x
		}
		return e, nil
	}
	f := e.Atom
	if f.Name != "ruleset" && f.Name != "ruleset_no_resolve" {
		if inhibit && (f.Name == "dip" || f.Name == "ip") {
			f.Name = "ip_no_resolve"
		}
		return e, nil
	}
	if len(f.Params) != 1 || f.Params[0].Key != "" {
		return nil, fmt.Errorf("ruleset requires one provider name")
	}
	p, ok := registry[f.Params[0].Val]
	if !ok || len(p.Functions) == 0 {
		return nil, fmt.Errorf("unknown or empty provider %q", f.Params[0].Val)
	}
	inhibit = inhibit || f.Name == "ruleset_no_resolve"
	result := &routing.OrderedExpr{Op: "or"}
	for _, atom := range p.Functions {
		child := &routing.OrderedExpr{Op: "atom", Atom: cloneFunction(atom)}
		expanded, err := expandOrderedExpr(child, registry, inhibit)
		if err != nil {
			return nil, err
		}
		result.Children = append(result.Children, expanded)
	}
	if f.Not {
		return &routing.OrderedExpr{Op: "not", Children: []*routing.OrderedExpr{result}}, nil
	}
	return result, nil
}
