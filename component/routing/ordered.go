package routing

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

// OrderedExpr retains evaluation order where resolving an address is observable.
// route_expr is the serialized form used by imported logical/provider rules.
type OrderedExpr struct {
	MemoID   int                     `json:"memo_id,omitempty"`
	Op       string                  `json:"op"`
	Atom     *config_parser.Function `json:"atom,omitempty"`
	Children []*OrderedExpr          `json:"children,omitempty"`
}
type OrderedRule struct {
	Expr     *OrderedExpr
	Outbound config_parser.Function
}

func EncodeOrderedExpr(e *OrderedExpr) (*config_parser.Function, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return &config_parser.Function{Name: "route_expr", Params: []*config_parser.Param{{Val: base64.RawURLEncoding.EncodeToString(b)}}}, nil
}
func DecodeOrderedExpr(f *config_parser.Function) (*OrderedExpr, error) {
	if len(f.Params) != 1 || f.Params[0].Key != "" {
		return nil, fmt.Errorf("route_expr requires one expression")
	}
	var e OrderedExpr
	data, err := base64.RawURLEncoding.DecodeString(f.Params[0].Val)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	if err := e.Walk(func(*config_parser.Function) error { return nil }); err != nil {
		return nil, err
	}
	if f.Not {
		return &OrderedExpr{Op: "not", Children: []*OrderedExpr{&e}}, nil
	}
	return &e, nil
}
func (e *OrderedExpr) Walk(fn func(*config_parser.Function) error) error {
	if e == nil {
		return fmt.Errorf("nil routing expression")
	}
	switch e.Op {
	case "atom":
		if e.Atom == nil || e.Atom.Name == "route_expr" || len(e.Children) != 0 {
			return fmt.Errorf("invalid routing atom")
		}
		return fn(e.Atom)
	case "not":
		if len(e.Children) != 1 {
			return fmt.Errorf("not requires one child")
		}
	case "and", "or":
		if len(e.Children) == 0 {
			return fmt.Errorf("%s requires children", e.Op)
		}
	default:
		return fmt.Errorf("unknown routing expression %q", e.Op)
	}
	for _, c := range e.Children {
		if err := c.Walk(fn); err != nil {
			return err
		}
	}
	return nil
}
func ExprFromFunction(f *config_parser.Function) (*OrderedExpr, error) {
	if f.Name == "route_expr" {
		return DecodeOrderedExpr(f)
	}
	return &OrderedExpr{Op: "atom", Atom: f}, nil
}

// DNF is used only for the kernel, whose destination address is already known.
func (e *OrderedExpr) DNF(neg bool, limit int) ([][]*config_parser.Function, error) {
	if e.Op == "atom" {
		f := *e.Atom
		f.Not = f.Not != neg
		return [][]*config_parser.Function{{&f}}, nil
	}
	if e.Op == "not" {
		return e.Children[0].DNF(!neg, limit)
	}
	conjunction := (e.Op == "and") != neg
	var result [][]*config_parser.Function
	if conjunction {
		result = [][]*config_parser.Function{{}}
	}
	for _, child := range e.Children {
		terms, err := child.DNF(neg, limit)
		if err != nil {
			return nil, err
		}
		if !conjunction {
			result = append(result, terms...)
		} else {
			if len(terms) > 0 && len(result) > limit/len(terms) {
				return nil, fmt.Errorf("routing expression exceeds %d alternatives", limit)
			}
			var next [][]*config_parser.Function
			for _, a := range result {
				for _, b := range terms {
					t := append([]*config_parser.Function{}, a...)
					t = append(t, b...)
					next = append(next, t)
				}
			}
			result = next
		}
		if len(result) > limit {
			return nil, fmt.Errorf("routing expression exceeds %d alternatives", limit)
		}
	}
	return result, nil
}
func HasOrderedRules(rules []*config_parser.RoutingRule) bool {
	for _, r := range rules {
		for _, f := range r.AndFunctions {
			if f.Name == "route_expr" || f.Name == "ip_no_resolve" || f.Name == "dip_no_resolve" {
				return true
			}
		}
	}
	return false
}
