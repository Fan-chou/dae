package ruleprovider

import (
	"errors"
	"fmt"
	"github.com/daeuniverse/dae/component/routing"
)

var errDegradedProviderSkip = errors.New("rule provider is degraded and skipped")

func expandOrderedExpr(e *routing.OrderedExpr, registry Registry, inhibit bool) (*routing.OrderedExpr, error) {
	if e.MemoID != 0 {
		id := e.MemoID
		e.MemoID = 0
		result, err := expandOrderedExpr(e, registry, inhibit)
		if err == nil && result != nil {
			result.MemoID = id
		}
		return result, err
	}
	switch e.Op {
	case "atom":
		// handled below
	case "or":
		filtered := make([]*routing.OrderedExpr, 0, len(e.Children))
		for _, c := range e.Children {
			x, err := expandOrderedExpr(c, registry, inhibit)
			if err != nil {
				return nil, err
			}
			if x != nil {
				filtered = append(filtered, x)
			}
		}
		if len(filtered) == 0 {
			return nil, nil
		}
		if len(filtered) == 1 {
			return filtered[0], nil
		}
		e.Children = filtered
		return e, nil
	case "and":
		for i, c := range e.Children {
			x, err := expandOrderedExpr(c, registry, inhibit)
			if err != nil {
				return nil, err
			}
			if x == nil {
				return nil, nil
			}
			e.Children[i] = x
		}
		return e, nil
	case "not":
		for i, c := range e.Children {
			x, err := expandOrderedExpr(c, registry, inhibit)
			if err != nil {
				return nil, err
			}
			if x == nil {
				return nil, errDegradedProviderSkip
			}
			e.Children[i] = x
		}
		return e, nil
	default:
		for i, c := range e.Children {
			x, err := expandOrderedExpr(c, registry, inhibit)
			if err != nil {
				return nil, err
			}
			if x == nil {
				return nil, nil
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
	if !ok {
		return nil, fmt.Errorf("unknown or empty provider %q", f.Params[0].Val)
	}
	if len(p.Functions) == 0 {
		if p.Degraded {
			if f.Not {
				return nil, errDegradedProviderSkip
			}
			return nil, nil
		}
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
		if expanded != nil {
			result.Children = append(result.Children, expanded)
		}
	}
	if len(result.Children) == 0 {
		if f.Not {
			return nil, errDegradedProviderSkip
		}
		return nil, nil
	}
	if f.Not {
		return &routing.OrderedExpr{Op: "not", Children: []*routing.OrderedExpr{result}}, nil
	}
	return result, nil
}
