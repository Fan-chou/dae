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

// fakeIPPortIsFullRange reports a port/sport range that every port satisfies.
func fakeIPPortIsFullRange(match compiledRoutingMatch) bool {
	return match.portStart == 0 && match.portEnd == 65535
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

// fakeIPRule contains only rules relevant to the existing DNS-time policy.
// The indices remain those of compiledMatches (and the domain bitmap).
type fakeIPRule struct{ start, end int }

func compileFakeIPRules(matches []compiledRoutingMatch) []fakeIPRule {
	rules := make([]fakeIPRule, 0)
	start, hasDomain := 0, false
	for i, match := range matches {
		hasDomain = hasDomain || fakeIPMatchIsDomain(match.matchType)
		if match.outbound&consts.OutboundLogicalMask == consts.OutboundLogicalMask {
			continue
		}
		if hasDomain || match.outbound == consts.OutboundMustRules || match.matchType == consts.MatchType_Fallback {
			rules = append(rules, fakeIPRule{start, i + 1})
		}
		start, hasDomain = i+1, false
	}
	return rules
}

// Facts live for one DNS query only. Group selections are still read live;
// reloads and later queries never reuse a previous eligibility decision.
type fakeIPEligibilityFacts struct {
	matcher        *RoutingMatcher
	domainBitmap   []uint32
	ipVersion      *consts.IpVersionType
	src            netip.Addr
	mac            [6]byte
	srcBin, macBin string
	macAssoc       []string
	macAssocLoaded bool
	sourceResults  map[uint64]fakeIPKleene
}

func (f *fakeIPEligibilityFacts) sourceBin() string {
	if f.srcBin == "" {
		f.srcBin = fakeIPAddrBin(f.src)
	}
	return f.srcBin
}
func (f *fakeIPEligibilityFacts) sourceMacBin() string {
	if f.macBin == "" {
		f.macBin = fakeIPMacBin(f.mac)
	}
	return f.macBin
}
func (f *fakeIPEligibilityFacts) associatedBins() []string {
	if !f.macAssocLoaded {
		f.macAssoc = f.matcher.lookupMacAssoc(f.mac)
		f.macAssocLoaded = true
	}
	return f.macAssoc
}

func (f *fakeIPEligibilityFacts) evalSip(match compiledRoutingMatch) fakeIPKleene {
	m, src, mac := f.matcher, f.src, f.mac
	switch match.matchType {
	case consts.MatchType_SourceIpSet:
		if !src.IsValid() {
			return fakeIPKleeneUnknown
		}
		if m.fakeIPLpmHit(match.lpmIndex, f.sourceBin()) {
			return fakeIPKleeneTrue
		}
		return fakeIPKleeneFalse
	case consts.MatchType_SourceIpSetMatchMac:
		// Same as userspace Route(): sip CIDR hits first, then learned MAC IPs.
		if src.IsValid() && m.fakeIPLpmHit(match.lpmIndex, f.sourceBin()) {
			return fakeIPKleeneTrue
		}
		if !fakeIPMacIsZero(mac) && m.lookupMacAssoc != nil {
			for _, bin := range f.associatedBins() {
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
		if m.fakeIPLpmHit(match.lpmIndex, f.sourceMacBin()) {
			return fakeIPKleeneTrue
		}
		return fakeIPKleeneFalse
	default:
		return fakeIPKleeneUnknown
	}
}

func (f *fakeIPEligibilityFacts) evalKnown(match compiledRoutingMatch, index int, dest netip.Addr) (val fakeIPKleene, known bool) {
	m, domainBitmap, ipVersion := f.matcher, f.domainBitmap, f.ipVersion
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
	case consts.MatchType_Port, consts.MatchType_SourcePort:
		// A range covering every port is a tautology, not a transport
		// predicate. Mihomo lowering uses port(0-65535) for an unconditional
		// MATCH (e.g. SUB-RULE,(RULE-SET,x),sub with a MATCH body), so
		// treating it as FALSE would disable every such domain rule.
		if fakeIPPortIsFullRange(match) {
			return fakeIPKleeneTrue, true
		}
		return fakeIPKleeneFalse, true
	case consts.MatchType_L4Proto:
		// DNS has no dest 5-tuple. Treat transport predicates as FALSE so
		// QUIC-intercept rules (domain && udp && dport -> block) do not
		// stop the walk; the later domain-only proxy rule can still hit.
		// Do not treat them as TRUE: that would match the block rule.
		return fakeIPKleeneFalse, true
	case consts.MatchType_SourceIpSet, consts.MatchType_SourceIpSetMatchMac, consts.MatchType_Mac:
		key := uint64(match.matchType)<<32 | uint64(match.lpmIndex)
		if v, ok := f.sourceResults[key]; ok {
			return v, true
		}
		v := f.evalSip(match)
		if f.sourceResults == nil {
			f.sourceResults = make(map[uint64]fakeIPKleene)
		}
		f.sourceResults[key] = v
		return v, true
	case consts.MatchType_Fallback:
		return fakeIPKleeneTrue, true
	default:
		return fakeIPKleeneUnknown, true
	}
}

// FakeIPEligibility walks traffic routing with Kleene three-value first-match.
// Rules without domain() are skipped. l4proto and dport/sport are FALSE
// (continue), except a port range covering 0-65535, which is TRUE.
// DNS sip/mac are evaluated from this query when present. dest ip() uses real
// A/AAAA answers when provided; missing dest stays UNKNOWN. Multiple dests:
// any PROXY wins, all DIRECT is DIRECT, Direct+Unknown stays UNKNOWN (ShouldFake
// only fakes PROXY). A hit user group follows the live selection leaf: direct/block
// is DIRECT, a node is PROXY. Do not call Select() here.
func (m *RoutingMatcher) FakeIPEligibility(domain string, ipVersion *consts.IpVersionType) FakeIPEligibility {
	return m.FakeIPEligibilityFor(domain, ipVersion, netip.Addr{}, [6]byte{}, nil)
}

func (m *RoutingMatcher) FakeIPEligibilityFor(domain string, ipVersion *consts.IpVersionType, src netip.Addr, mac [6]byte, dests []netip.Addr) FakeIPEligibility {
	if m == nil || len(m.compiledMatches) == 0 {
		return FakeIPEligibilityDirect
	}
	rules := m.fakeIPRules
	if rules == nil {
		rules = compileFakeIPRules(m.compiledMatches)
	}
	facts := fakeIPEligibilityFacts{matcher: m, ipVersion: ipVersion, src: src, mac: mac}
	if domain != "" && m.domainMatcher != nil {
		facts.domainBitmap = m.domainMatcher.MatchDomainBitmap(domain)
	}
	sawValid, sawUnknown := false, false
	for _, dest := range dests {
		if !dest.IsValid() {
			continue
		}
		sawValid = true
		switch facts.walk(rules, dest) {
		case FakeIPEligibilityProxy:
			return FakeIPEligibilityProxy
		case FakeIPEligibilityUnknown:
			sawUnknown = true
		}
	}
	if !sawValid {
		return facts.walk(rules, netip.Addr{})
	}
	if sawUnknown {
		return FakeIPEligibilityUnknown
	}
	return FakeIPEligibilityDirect
}

func (f *fakeIPEligibilityFacts) walk(rules []fakeIPRule, dest netip.Addr) FakeIPEligibility {
	m := f.matcher
	for _, rule := range rules {
		action := m.compiledMatches[rule.end-1]
		// These actions were unconditional in the original DNS-time evaluator.
		if action.outbound == consts.OutboundMustRules {
			return FakeIPEligibilityDirect
		}
		if action.matchType == consts.MatchType_Fallback {
			if m.fakeIPOutboundIsProxy(action.outbound) {
				return FakeIPEligibilityProxy
			}
			return FakeIPEligibilityDirect
		}
		ruleVal, subruleVal := fakeIPKleeneTrue, fakeIPKleeneFalse
		for i := rule.start; i < rule.end; i++ {
			match := m.compiledMatches[i]
			raw, _ := f.evalKnown(match, i, dest)
			subruleVal = fakeIPKleeneOr(subruleVal, raw)
			if match.outbound != consts.OutboundLogicalOr {
				if match.not {
					subruleVal = fakeIPKleeneNot(subruleVal)
				}
				ruleVal = fakeIPKleeneAnd(ruleVal, subruleVal)
				subruleVal = fakeIPKleeneFalse
			}
		}
		switch ruleVal {
		case fakeIPKleeneUnknown:
			return FakeIPEligibilityUnknown
		case fakeIPKleeneTrue:
			if m.fakeIPOutboundIsProxy(action.outbound) {
				return FakeIPEligibilityProxy
			}
			return FakeIPEligibilityDirect
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
