/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/trie"
)

// FakeIPEligibility is the DNS-time Kleene result for selective FakeIP.
type FakeIPEligibility uint8

const (
	FakeIPEligibilityDirect FakeIPEligibility = iota
	FakeIPEligibilityProxy
	FakeIPEligibilityUnknown
)

type fakeIPKleene uint8

const (
	fakeIPKleeneFalse fakeIPKleene = iota
	fakeIPKleeneTrue
	fakeIPKleeneUnknown
)

func fakeIPKleeneAnd(a, b fakeIPKleene) fakeIPKleene {
	if a == fakeIPKleeneFalse || b == fakeIPKleeneFalse {
		return fakeIPKleeneFalse
	}
	if a == fakeIPKleeneUnknown || b == fakeIPKleeneUnknown {
		return fakeIPKleeneUnknown
	}
	return fakeIPKleeneTrue
}

func fakeIPKleeneOr(a, b fakeIPKleene) fakeIPKleene {
	if a == fakeIPKleeneTrue || b == fakeIPKleeneTrue {
		return fakeIPKleeneTrue
	}
	if a == fakeIPKleeneUnknown || b == fakeIPKleeneUnknown {
		return fakeIPKleeneUnknown
	}
	return fakeIPKleeneFalse
}

func fakeIPKleeneNot(a fakeIPKleene) fakeIPKleene {
	switch a {
	case fakeIPKleeneTrue:
		return fakeIPKleeneFalse
	case fakeIPKleeneFalse:
		return fakeIPKleeneTrue
	default:
		return fakeIPKleeneUnknown
	}
}

func fakeIPMatchIsDomain(matchType consts.MatchType) bool {
	return matchType == consts.MatchType_DomainSet
}

func fakeIPMacIsZero(mac [6]byte) bool {
	return mac == [6]byte{}
}

func fakeIPAddrBin(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(addr.As16()), 128))
}

func fakeIPMacBin(mac [6]byte) string {
	var mac16 [16]uint8
	copy(mac16[10:], mac[:])
	return trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(mac16), 128))
}

func (m *RoutingMatcher) fakeIPLpmHit(lpmIndex uint32, bin string) bool {
	if m == nil || bin == "" || int(lpmIndex) >= len(m.lpmMatcher) {
		return false
	}
	return m.lpmMatcher[lpmIndex].HasPrefix(bin)
}

func (m *RoutingMatcher) fakeIPEvalSip(match compiledRoutingMatch, src netip.Addr, mac [6]byte) fakeIPKleene {
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

func (m *RoutingMatcher) fakeIPEvalKnown(match compiledRoutingMatch, index int, domainBitmap []uint32, ipVersion *consts.IpVersionType, src netip.Addr, mac [6]byte) (val fakeIPKleene, known bool) {
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
	case consts.MatchType_L4Proto, consts.MatchType_Port, consts.MatchType_SourcePort:
		// DNS has no dest 5-tuple. Treat transport predicates as FALSE so
		// QUIC-intercept rules (domain && udp && dport -> block) do not
		// stop the walk; the later domain-only proxy rule can still hit.
		// Do not treat them as TRUE: that would match the block rule.
		return fakeIPKleeneFalse, true
	case consts.MatchType_SourceIpSet, consts.MatchType_SourceIpSetMatchMac, consts.MatchType_Mac:
		return m.fakeIPEvalSip(match, src, mac), true
	case consts.MatchType_Fallback:
		return fakeIPKleeneTrue, true
	default:
		return fakeIPKleeneUnknown, true
	}
}

// FakeIPEligibility walks traffic routing with Kleene three-value first-match.
// Rules without domain() are skipped. l4proto/dport/sport are FALSE (continue).
// DNS sip/mac are evaluated from this query when present; dest ip() stays
// UNKNOWN. A hit user group follows the live selection leaf: direct/block is
// DIRECT, a node is PROXY.
func (m *RoutingMatcher) FakeIPEligibility(domain string, ipVersion *consts.IpVersionType) FakeIPEligibility {
	return m.FakeIPEligibilityFor(domain, ipVersion, netip.Addr{}, [6]byte{})
}

func (m *RoutingMatcher) FakeIPEligibilityFor(domain string, ipVersion *consts.IpVersionType, src netip.Addr, mac [6]byte) FakeIPEligibility {
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
		raw, _ := m.fakeIPEvalKnown(match, i, domainBitmap, ipVersion, src, mac)
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

func (m *RoutingMatcher) fakeIPOutboundIsProxy(outbound consts.OutboundIndex) bool {
	if outbound.IsReserved() {
		return false
	}
	if outbound < consts.OutboundUserDefinedMin || outbound > consts.OutboundUserDefinedMax {
		return false
	}
	if m != nil && m.fakeIPLeafIsProxy != nil {
		return m.fakeIPLeafIsProxy(outbound)
	}
	return true
}
