package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"net/netip"
)

// This evaluates the existing compiled predicates with partial facts. UDP/443
// is a hypothesis; future source port, DSCP, process and target IP are unknown.
func (m *RoutingMatcher) resolveDNSPrefetchRoute(domain string, v6 bool, src netip.Addr, mac [6]uint8, fakeDestination bool) (consts.OutboundIndex, uint32, bool, bool) {
	if m == nil || !src.IsValid() || len(m.compiledMatches) == 0 {
		return 0, 0, false, false
	}
	var mac16 [16]uint8
	copy(mac16[10:], mac[:])
	version := consts.IpVersion_4
	if v6 {
		version = consts.IpVersion_6
	}
	facts, err := m.newFacts(src.As16(), [16]uint8{}, 0, 443, version, consts.L4ProtoType_UDP, domain, [16]uint8{}, 0, mac16)
	if err != nil {
		return 0, 0, false, false
	}
	// Once a possible resolving predicate was encountered, a later no-resolve
	// predicate cannot assume the real address would still be absent.
	possibleResolve := false
	atom := func(i int) fakeIPKleene {
		match := m.compiledMatches[i]
		switch match.matchType {
		case consts.MatchType_IpSet:
			if fakeDestination && match.noResolve && !possibleResolve {
				return fakeIPKleeneFalse
			}
			possibleResolve = true
			return fakeIPKleeneUnknown
		case consts.MatchType_IpVersion:
			// A resolving FakeIP match may change the address family.
			if possibleResolve {
				return fakeIPKleeneUnknown
			}
		case consts.MatchType_SourcePort, consts.MatchType_Dscp, consts.MatchType_ProcessName:
			return fakeIPKleeneUnknown
		case consts.MatchType_Mac, consts.MatchType_SourceIpSetMatchMac:
			if mac == ([6]uint8{}) {
				return fakeIPKleeneUnknown
			}
		}
		hit, e := m.matchCompiledMatch(i, match, &facts)
		if e != nil {
			return fakeIPKleeneUnknown
		}
		if hit {
			return fakeIPKleeneTrue
		}
		return fakeIPKleeneFalse
	}
	must := false
	action := func(v fakeIPKleene, a compiledRoutingMatch) (bool, bool) {
		if v == fakeIPKleeneUnknown {
			return true, false
		}
		if v != fakeIPKleeneTrue {
			return false, false
		}
		if a.outbound == consts.OutboundControlPlaneRouting {
			return false, false
		}
		if a.outbound == consts.OutboundMustRules {
			must = true
			return false, false
		}
		return true, true
	}
	if len(m.orderedRules) > 0 {
		memo := make(map[int]fakeIPKleene)
		var eval func(*orderedRoutingExpr) fakeIPKleene
		eval = func(e *orderedRoutingExpr) fakeIPKleene {
			if e.memoID != 0 {
				if v, ok := memo[e.memoID]; ok {
					return v
				}
			}
			v := fakeIPKleeneUnknown
			switch e.op {
			case "atom":
				v = fakeIPKleeneFalse
				for _, i := range e.indices {
					v = fakeIPKleeneOr(v, atom(i))
					if v == fakeIPKleeneTrue {
						break
					}
				}
				if e.not {
					v = fakeIPKleeneNot(v)
				}
			case "not":
				v = fakeIPKleeneNot(eval(e.children[0]))
			case "and":
				v = fakeIPKleeneTrue
				for _, child := range e.children {
					v = fakeIPKleeneAnd(v, eval(child))
					if v == fakeIPKleeneFalse {
						break
					}
				}
			case "or":
				v = fakeIPKleeneFalse
				for _, child := range e.children {
					v = fakeIPKleeneOr(v, eval(child))
					if v == fakeIPKleeneTrue {
						break
					}
				}
			}
			if e.memoID != 0 {
				memo[e.memoID] = v
			}
			return v
		}
		for _, r := range m.orderedRules {
			if stop, ok := action(eval(r.expr), r.action); stop {
				return r.action.outbound, r.action.mark, must || r.action.must, ok
			}
		}
		a := m.compiledMatches[len(m.compiledMatches)-1]
		return a.outbound, a.mark, must || a.must, true
	}
	sub, rule := fakeIPKleeneFalse, fakeIPKleeneTrue
	for i, a := range m.compiledMatches {
		if rule != fakeIPKleeneFalse && sub != fakeIPKleeneTrue {
			sub = fakeIPKleeneOr(sub, atom(i))
		}
		if a.outbound != consts.OutboundLogicalOr {
			if a.not {
				sub = fakeIPKleeneNot(sub)
			}
			rule = fakeIPKleeneAnd(rule, sub)
			sub = fakeIPKleeneFalse
		}
		if a.outbound&consts.OutboundLogicalMask != consts.OutboundLogicalMask {
			if stop, ok := action(rule, a); stop {
				return a.outbound, a.mark, must || a.must, ok
			}
			rule = fakeIPKleeneTrue
		}
	}
	return 0, 0, false, false
}
