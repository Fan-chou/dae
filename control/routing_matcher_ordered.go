package control

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

type orderedRoutingExpr struct {
	memoID   int
	op       string
	indices  []int
	not      bool
	children []*orderedRoutingExpr
}
type orderedRoutingRule struct {
	expr   *orderedRoutingExpr
	action compiledRoutingMatch
}

func compileOrderedRouting(rules []routing.OrderedRule, spans map[int][]int, matches []compiledRoutingMatch) ([]orderedRoutingRule, error) {
	var result []orderedRoutingRule
	for _, r := range rules {
		last := -1
		var compile func(*routing.OrderedExpr) (*orderedRoutingExpr, error)
		compile = func(e *routing.OrderedExpr) (*orderedRoutingExpr, error) {
			c := &orderedRoutingExpr{op: e.Op, memoID: e.MemoID}
			if e.Op == "atom" {
				c.not = e.Atom.Not
				c.indices = spans[e.Atom.EvaluationID]
				if len(c.indices) == 0 {
					return nil, fmt.Errorf("missing compiled atom %s", e.Op)
				}
				for _, i := range c.indices {
					if i > last {
						last = i
					}
				}
				// DNF can duplicate the same atom. Its first complete occurrence is
				// enough to evaluate the positive predicate; retain all for action lookup above.
				for n, i := range c.indices {
					if matches[i].outbound != consts.OutboundLogicalOr {
						c.indices = c.indices[:n+1]
						break
					}
				}

			}
			for _, child := range e.Children {
				cc, err := compile(child)
				if err != nil {
					return nil, err
				}
				c.children = append(c.children, cc)
			}
			return c, nil
		}
		e, err := compile(r.Expr)
		if err != nil {
			return nil, err
		}
		if last < 0 {
			return nil, fmt.Errorf("missing compiled routing action")
		}
		result = append(result, orderedRoutingRule{expr: e, action: matches[last]})
	}
	return result, nil
}

// matchOrderedFakeIP keeps one address state for the entire walk. Resolving
// during a later predicate never retroactively activates an earlier rule.
func (m *RoutingMatcher) matchOrderedFakeIP(facts routingMatcherFacts, resolve func() (netip.Addr, error)) (consts.OutboundIndex, uint32, bool, netip.Addr, error) {
	var real netip.Addr
	attempted := false
	// A SUB-RULE entry is decided once per call, even when child rules
	// resolve an address. This state is local to this routing decision.
	var memo map[int]bool
	var eval func(*orderedRoutingExpr) (bool, error)
	var evaluate func(*orderedRoutingExpr) (bool, error)
	eval = func(e *orderedRoutingExpr) (bool, error) {
		if e.memoID == 0 {
			return evaluate(e)
		}
		if v, ok := memo[e.memoID]; ok {
			return v, nil
		}
		v, err := evaluate(e)
		if err == nil {
			if memo == nil {
				memo = make(map[int]bool)
			}
			memo[e.memoID] = v
		}
		return v, err
	}
	evaluate = func(e *orderedRoutingExpr) (bool, error) {
		switch e.op {
		case "not":
			v, err := eval(e.children[0])
			return !v, err
		case "and":
			for _, c := range e.children {
				v, err := eval(c)
				if err != nil || !v {
					return v, err
				}
			}
			return true, nil
		case "or":
			for _, c := range e.children {
				v, err := eval(c)
				if err != nil || v {
					return v, err
				}
			}
			return false, nil
		case "atom":
			indices := e.indices
			if len(indices) == 0 {
				return false, fmt.Errorf("missing compiled routing atom %s", e.op)
			}
			hit := false
			for _, i := range indices {
				match := m.compiledMatches[i]
				if destIPRoutingMatch(match.matchType) && !real.IsValid() {
					if !match.noResolve && !attempted {
						attempted = true
						ip, err := resolve()
						if err == nil && ip.IsValid() {
							real = ip
							facts.destAddr = ip.As16()
							facts.ipSetBin = fakeIPAddrBin(ip)
							facts.ipVersion = consts.IpVersion_6
							if ip.Is4() || ip.Is4In6() {
								facts.ipVersion = consts.IpVersion_4
							}
						}
					}
					if !real.IsValid() {
						continue
					}
				}
				v, err := m.matchCompiledMatch(i, match, &facts)
				if err != nil {
					return false, err
				}
				if v {
					hit = true
					break
				}
			}
			if e.not {
				hit = !hit
			}
			return hit, nil
		}
		return false, fmt.Errorf("invalid ordered routing operator %q", e.op)
	}
	must := false
	for _, r := range m.orderedRules {
		hit, err := eval(r.expr)
		if err != nil {
			return 0, 0, false, real, err
		}
		if !hit {
			continue
		}
		action := r.action
		if action.outbound == consts.OutboundMustRules {
			must = true
			continue
		}

		return action.outbound, action.mark, must || action.must, real, nil
	}
	action := m.compiledMatches[len(m.compiledMatches)-1]
	return action.outbound, action.mark, must || action.must, real, nil
}
