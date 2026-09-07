package routing

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestOrderedCompactionPreservesBoundaries(t *testing.T) {
	atom := func(name, value string) *OrderedExpr {
		return &OrderedExpr{Op: "atom", Atom: &config_parser.Function{Name: name, Params: []*config_parser.Param{{Val: value}}}}
	}
	for _, boundary := range []string{"resolve", "not", "call", "mark", "must"} {
		t.Run(boundary, func(t *testing.T) {
			a, b := atom("ip_no_resolve", "203.0.113.0/25"), atom("ip_no_resolve", "203.0.113.128/25")
			x, y := config_parser.Function{Name: "proxy"}, config_parser.Function{Name: "proxy"}
			switch boundary {
			case "resolve":
				b.Atom.Name = "ip"
			case "not":
				a.Atom.Not, b.Atom.Not = true, true
			case "call":
				a.MemoID, b.MemoID = 1, 2
			case "mark":
				y.Params = []*config_parser.Param{{Key: "mark", Val: "1"}}
			case "must":
				y.Params = []*config_parser.Param{{Val: "must"}}
			}
			rules := appendOrderedRule([]OrderedRule{{Expr: a, Outbound: x}}, OrderedRule{Expr: b, Outbound: y})
			if len(rules) != 2 {
				t.Fatal("merged across semantic boundary")
			}
		})
	}
}
