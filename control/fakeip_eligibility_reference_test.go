package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"net/netip"
)

func (m *RoutingMatcher) fakeIPEvalSipReference(match compiledRoutingMatch, src netip.Addr, mac [6]byte) fakeIPKleene {
	switch match.matchType {
	case consts.MatchType_SourceIpSet:
		if !src.IsValid() {
			return fakeIPKleeneUnknown
		}
		if m.fakeIPLpmHit(match.lpmIndex, fakeIPAddrBin(src)) {
			return fakeIPKleeneTrue
		}
		return fakeIPKleeneFalse
	case consts.MatchType_SourceIpSetMatchMac:
		// Same as userspace Route(): sip CIDR hits first, then learned MAC IPs.
		if src.IsValid() && m.fakeIPLpmHit(match.lpmIndex, fakeIPAddrBin(src)) {
			return fakeIPKleeneTrue
		}
		if !fakeIPMacIsZero(mac) && m.lookupMacAssoc != nil {
			for _, bin := range m.lookupMacAssoc(mac) {
				if m.fakeIPLpmHit(match.lpmIndex, bin) {
					return fakeIPKleeneTrue
				}
			}
		}
		if src.IsValid() || !fakeIPMacIsZero(mac) {
			return fakeIPKleeneFalse
		}
		return fakeIPKleeneUnknown
	case consts.MatchType_Mac:
		if fakeIPMacIsZero(mac) {
			return fakeIPKleeneUnknown
		}
		if m.fakeIPLpmHit(match.lpmIndex, fakeIPMacBin(mac)) {
			return fakeIPKleeneTrue
		}
		return fakeIPKleeneFalse
	default:
		return fakeIPKleeneUnknown
	}
}

func (m *RoutingMatcher) fakeIPEvalKnownReference(match compiledRoutingMatch, index int, domainBitmap []uint32, ipVersion *consts.IpVersionType, src, dest netip.Addr, mac [6]byte) (val fakeIPKleene, known bool) {
	switch match.matchType {
	case consts.MatchType_DomainSet:
		hit := domainBitmap != nil &&
			index/32 < len(domainBitmap) &&
			(domainBitmap[index/32]>>(index%32))&1 > 0
		if hit {
			return fakeIPKleeneTrue, true
		}
		return fakeIPKleeneFalse, true
	case consts.MatchType_IpVersion:
		if ipVersion == nil {
			return fakeIPKleeneUnknown, true
		}
		if *ipVersion&consts.IpVersionType(match.mask) > 0 {
			return fakeIPKleeneTrue, true
		}
		return fakeIPKleeneFalse, true
	case consts.MatchType_IpSet:
		if !dest.IsValid() {
			if match.noResolve {
				return fakeIPKleeneFalse, true
			}
			return fakeIPKleeneUnknown, true
		}
		if m.fakeIPLpmHit(match.lpmIndex, fakeIPAddrBin(dest)) {
			return fakeIPKleeneTrue, true
		}
		return fakeIPKleeneFalse, true
	case consts.MatchType_L4Proto, consts.MatchType_Port, consts.MatchType_SourcePort:
		// DNS has no dest 5-tuple. Treat transport predicates as FALSE so
		// QUIC-intercept rules (domain && udp && dport -> block) do not
		// stop the walk; the later domain-only proxy rule can still hit.
		// Do not treat them as TRUE: that would match the block rule.
		return fakeIPKleeneFalse, true
	case consts.MatchType_SourceIpSet, consts.MatchType_SourceIpSetMatchMac, consts.MatchType_Mac:
		return m.fakeIPEvalSipReference(match, src, mac), true
	case consts.MatchType_Fallback:
		return fakeIPKleeneTrue, true
	default:
		return fakeIPKleeneUnknown, true
	}
}

// FakeIPEligibility walks traffic routing with Kleene three-value first-match.
// Rules without domain() are skipped. l4proto/dport/sport are FALSE (continue).
// DNS sip/mac are evaluated from this query when present. dest ip() uses real
// A/AAAA answers when provided; missing dest stays UNKNOWN. Multiple dests:
// any PROXY wins, all DIRECT is DIRECT, Direct+Unknown stays UNKNOWN (ShouldFake
// only fakes PROXY). A hit user group follows the live selection leaf: direct/block
// is DIRECT, a node is PROXY. Do not call Select() here.

func (m *RoutingMatcher) FakeIPEligibilityForReference(domain string, ipVersion *consts.IpVersionType, src netip.Addr, mac [6]byte, dests []netip.Addr) FakeIPEligibility {
	var valid []netip.Addr
	for _, dest := range dests {
		if dest.IsValid() {
			valid = append(valid, dest)
		}
	}
	if len(valid) <= 1 {
		var dest netip.Addr
		if len(valid) == 1 {
			dest = valid[0]
		}
		return m.fakeIPEligibilityWalkReference(domain, ipVersion, src, mac, dest)
	}

	var anyProxy, sawDirect, sawUnknown bool
	for _, dest := range valid {
		switch m.fakeIPEligibilityWalkReference(domain, ipVersion, src, mac, dest) {
		case FakeIPEligibilityProxy:
			anyProxy = true
		case FakeIPEligibilityDirect:
			sawDirect = true
		default:
			sawUnknown = true
		}
	}
	if anyProxy {
		return FakeIPEligibilityProxy
	}
	if sawUnknown {
		return FakeIPEligibilityUnknown
	}
	if sawDirect {
		return FakeIPEligibilityDirect
	}
	return FakeIPEligibilityDirect
}

func (m *RoutingMatcher) fakeIPEligibilityWalkReference(domain string, ipVersion *consts.IpVersionType, src netip.Addr, mac [6]byte, dest netip.Addr) FakeIPEligibility {
	if m == nil || len(m.compiledMatches) == 0 {
		return FakeIPEligibilityDirect
	}
	var domainBitmap []uint32
	if domain != "" && m.domainMatcher != nil {
		domainBitmap = m.domainMatcher.MatchDomainBitmap(domain)
	}

	matches := m.compiledMatches
	ruleVal := fakeIPKleeneTrue
	subruleVal := fakeIPKleeneFalse
	hasDomain := false
	subruleHasDomain := false

	for i, match := range matches {
		raw, _ := m.fakeIPEvalKnownReference(match, i, domainBitmap, ipVersion, src, dest, mac)
		subruleVal = fakeIPKleeneOr(subruleVal, raw)
		if fakeIPMatchIsDomain(match.matchType) {
			subruleHasDomain = true
			hasDomain = true
		}

		outbound := match.outbound
		if outbound != consts.OutboundLogicalOr {
			if match.not {
				subruleVal = fakeIPKleeneNot(subruleVal)
			}
			ruleVal = fakeIPKleeneAnd(ruleVal, subruleVal)
			if subruleHasDomain {
				hasDomain = true
			}
			subruleVal = fakeIPKleeneFalse
			subruleHasDomain = false
		}
		if outbound&consts.OutboundLogicalMask != consts.OutboundLogicalMask {
			if outbound == consts.OutboundMustRules {
				return FakeIPEligibilityDirect
			}
			if match.matchType == consts.MatchType_Fallback {
				if m.fakeIPOutboundIsProxy(outbound) {
					return FakeIPEligibilityProxy
				}
				return FakeIPEligibilityDirect
			}
			if !hasDomain {
				ruleVal = fakeIPKleeneTrue
				hasDomain = false
				continue
			}
			switch ruleVal {
			case fakeIPKleeneUnknown:
				return FakeIPEligibilityUnknown
			case fakeIPKleeneTrue:
				if m.fakeIPOutboundIsProxy(outbound) {
					return FakeIPEligibilityProxy
				}
				return FakeIPEligibilityDirect
			}
			ruleVal = fakeIPKleeneTrue
			hasDomain = false
		}
	}
	return FakeIPEligibilityDirect
}
