/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/trie"
)

type RoutingMatcher struct {
	lpmMatcher    []*trie.Trie
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.

	compiledMatches []compiledRoutingMatch
	predicateGroups []routingMatcherPredicateGroupSpan
	lookupMacAssoc  macAssocLookup
	// fakeIPLeafIsProxy reports whether a user-defined outbound currently
	// selects a proxy node. Nil treats every user group as PROXY (unit tests).
	fakeIPLeafIsProxy func(consts.OutboundIndex) bool

	// needs records which fact strings any compiled rule can consume, so the
	// hot path skips building 128-char binary keys nothing will ever read.
	needs routingMatcherNeeds
}

type routingMatcherNeeds struct {
	ipSetBin     bool
	sourceIPSetB bool
	macBin       bool
	domainBitmap bool
}

func computeRoutingMatcherNeeds(matches []compiledRoutingMatch) routingMatcherNeeds {
	var n routingMatcherNeeds
	for _, m := range matches {
		switch m.matchType {
		case consts.MatchType_IpSet:
			n.ipSetBin = true
		case consts.MatchType_SourceIpSet, consts.MatchType_SourceIpSetMatchMac:
			n.sourceIPSetB = true
		case consts.MatchType_Mac:
			n.macBin = true
		case consts.MatchType_DomainSet:
			n.domainBitmap = true
		}
	}
	return n
}

// routingMatcherPredicateGroupSpan maps one immutable policy predicate group
// to the compiled match operations emitted by the legacy lowerer.
//
// The span is recorded while RulesBuilder invokes the parser. It cannot be
// reconstructed from logical outbound markers because a non-final parameter
// key group can itself end with OutboundLogicalOr.
type routingMatcherPredicateGroupSpan struct {
	name  string
	key   string
	not   bool
	start int
	end   int
}

// routingMatcherFacts is the normalized userspace input shared by the legacy
// matcher loop and the PolicySnapshot predicate-group resolver.
type routingMatcherFacts struct {
	sourceAddr [16]uint8
	destAddr   [16]uint8
	sourcePort uint16
	destPort   uint16
	ipVersion  consts.IpVersionType
	l4proto    consts.L4ProtoType
	domain     string
	pname      [16]uint8
	dscp       uint8
	mac        [16]uint8

	ipSetBin       string
	sourceIPSetBin string
	macBin         string
	macAssocBins   []string
	domainBitmap   []uint32

	// identityDontCare compares dest-IP + domain (+ fallback / IP version)
	// without a connection 5-tuple. Identity matches are skipped so AND
	// `mac && domain` reduces to domain, while standalone sip/dscp/mac
	// rules miss instead of always hitting.
	identityDontCare bool
}

type compiledRoutingMatch struct {
	matchType consts.MatchType
	outbound  consts.OutboundIndex
	not       bool
	mark      uint32
	must      bool

	lpmIndex  uint32
	portStart uint16
	portEnd   uint16
	mask      uint8
	pname     [16]uint8
	dscp      uint8
}

func compileRoutingMatch(match bpfMatchSet) (compiledRoutingMatch, error) {
	compiled := compiledRoutingMatch{
		matchType: consts.MatchType(match.Type),
		outbound:  consts.OutboundIndex(match.Outbound),
		not:       match.Not != 0,
		mark:      match.Mark,
		must:      match.Must != 0,
	}

	switch compiled.matchType {
	case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_SourceIpSetMatchMac, consts.MatchType_Mac:
		compiled.lpmIndex = nativeBpfABI.uint32(match.Value[:4])
	case consts.MatchType_Port, consts.MatchType_SourcePort:
		compiled.portStart, compiled.portEnd = ParsePortRange(match.Value[:])
	case consts.MatchType_IpVersion, consts.MatchType_L4Proto:
		compiled.mask = match.Value[0]
	case consts.MatchType_ProcessName:
		compiled.pname = match.Value
	case consts.MatchType_Dscp:
		compiled.dscp = match.Value[0]
	case consts.MatchType_DomainSet, consts.MatchType_Fallback:
		// No extra decode fields.
	default:
		return compiledRoutingMatch{}, fmt.Errorf("unknown match type: %v", match.Type)
	}

	return compiled, nil
}

func compileRoutingMatches(matches []bpfMatchSet) ([]compiledRoutingMatch, error) {
	compiled := make([]compiledRoutingMatch, 0, len(matches))
	for _, match := range matches {
		c, err := compileRoutingMatch(match)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, c)
	}
	return compiled, nil
}

func (m *RoutingMatcher) newFacts(
	sourceAddr [16]uint8,
	destAddr [16]uint8,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	dscp uint8,
	mac [16]uint8,
) (routingMatcherFacts, error) {
	if len(sourceAddr) != net.IPv6len || len(destAddr) != net.IPv6len || len(mac) != net.IPv6len {
		return routingMatcherFacts{}, fmt.Errorf("bad address length")
	}

	facts := routingMatcherFacts{
		sourceAddr: sourceAddr,
		destAddr:   destAddr,
		sourcePort: sourcePort,
		destPort:   destPort,
		ipVersion:  ipVersion,
		l4proto:    l4proto,
		domain:     domain,
		pname:      processName,
		dscp:       dscp,
		mac:        mac,
	}
	if m.lookupMacAssoc != nil {
		mac6 := mac6FromRoutedMac(mac)
		if mac6[0]|mac6[1]|mac6[2]|mac6[3]|mac6[4]|mac6[5] != 0 {
			facts.macAssocBins = m.lookupMacAssoc(mac6)
		}
	}
	// Gated on the compiled rule inventory: Prefix2bin128 churns a 128-byte
	// string per call, so skip keys that no rule reads.
	if m.needs.ipSetBin {
		facts.ipSetBin = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(destAddr), 128))
	}
	if m.needs.sourceIPSetB {
		facts.sourceIPSetBin = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(sourceAddr), 128))
	}
	if m.needs.macBin {
		facts.macBin = trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(mac), 128))
	}
	if m.needs.domainBitmap && domain != "" && m.domainMatcher != nil {
		facts.domainBitmap = m.domainMatcher.MatchDomainBitmap(domain)
	}
	return facts, nil
}

// matchCompiledMatch evaluates one positive compiled match operation. Callers
// own group negation and logical composition so this stays identical for the
// legacy matcher loop and PolicySnapshot predicate-group evaluation.
func (m *RoutingMatcher) matchCompiledMatch(index int, match compiledRoutingMatch, facts *routingMatcherFacts) (bool, error) {
	if facts == nil {
		return false, fmt.Errorf("nil routing matcher facts")
	}

	switch match.matchType {
	case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_SourceIpSetMatchMac, consts.MatchType_Mac:
		lpmIndex := int(match.lpmIndex)
		if lpmIndex < 0 || lpmIndex >= len(m.lpmMatcher) {
			return false, fmt.Errorf("bad lpm index: %d", lpmIndex)
		}
		var targetBin string
		switch match.matchType {
		case consts.MatchType_IpSet:
			targetBin = facts.ipSetBin
		case consts.MatchType_SourceIpSet:
			targetBin = facts.sourceIPSetBin
		case consts.MatchType_SourceIpSetMatchMac:
			if m.lpmMatcher[lpmIndex].HasPrefix(facts.sourceIPSetBin) {
				return true, nil
			}
			for _, bin := range facts.macAssocBins {
				if m.lpmMatcher[lpmIndex].HasPrefix(bin) {
					return true, nil
				}
			}
			return false, nil
		case consts.MatchType_Mac:
			targetBin = facts.macBin
		}
		return m.lpmMatcher[lpmIndex].HasPrefix(targetBin), nil
	case consts.MatchType_DomainSet:
		return facts.domainBitmap != nil &&
			index/32 < len(facts.domainBitmap) &&
			(facts.domainBitmap[index/32]>>(index%32))&1 > 0, nil
	case consts.MatchType_Port:
		return facts.destPort >= match.portStart && facts.destPort <= match.portEnd, nil
	case consts.MatchType_SourcePort:
		return facts.sourcePort >= match.portStart && facts.sourcePort <= match.portEnd, nil
	case consts.MatchType_IpVersion:
		return facts.ipVersion&consts.IpVersionType(match.mask) > 0, nil
	case consts.MatchType_L4Proto:
		return facts.l4proto&consts.L4ProtoType(match.mask) > 0, nil
	case consts.MatchType_ProcessName:
		return facts.pname[0] != 0 && match.pname == facts.pname, nil
	case consts.MatchType_Dscp:
		return facts.dscp == match.dscp, nil
	case consts.MatchType_Fallback:
		return true, nil
	default:
		return false, fmt.Errorf("unknown match type: %v", match.matchType)
	}
}

// Match is modified from kern/tproxy.c; please keep sync.
func (m *RoutingMatcher) Match(
	sourceAddr [16]uint8,
	destAddr [16]uint8,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	dscp uint8,
	mac [16]uint8,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	facts, err := m.newFacts(
		sourceAddr,
		destAddr,
		sourcePort,
		destPort,
		ipVersion,
		l4proto,
		domain,
		processName,
		dscp,
		mac,
	)
	if err != nil {
		return 0, 0, false, err
	}
	outbound, mark, must, _, err := m.matchFacts(facts)
	return outbound, mark, must, err
}

// MatchDeferringDestIP is Match with dest ip()/geoip left UNKNOWN.
func (m *RoutingMatcher) MatchDeferringDestIP(
	sourceAddr [16]uint8,
	destAddr [16]uint8,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	dscp uint8,
	mac [16]uint8,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, needsDestIP bool, err error) {
	facts, err := m.newFacts(
		sourceAddr,
		destAddr,
		sourcePort,
		destPort,
		ipVersion,
		l4proto,
		domain,
		processName,
		dscp,
		mac,
	)
	if err != nil {
		return 0, 0, false, false, err
	}
	return m.matchFactsDeferringDestIP(facts)
}

// identityRoutingMatch is MAC / source / port / process / DSCP / L4: known only
// on a real connection, not at DNS time.
func identityRoutingMatch(matchType consts.MatchType) bool {
	switch matchType {
	case consts.MatchType_Mac, consts.MatchType_SourceIpSet, consts.MatchType_SourceIpSetMatchMac,
		consts.MatchType_Port, consts.MatchType_SourcePort, consts.MatchType_ProcessName,
		consts.MatchType_Dscp, consts.MatchType_L4Proto:
		return true
	default:
		return false
	}
}

// destRoutingMatch is dest-IP / domain / IP version / fallback: enough to
// fingerprint DNS owners on a shared address.
func destRoutingMatch(matchType consts.MatchType) bool {
	switch matchType {
	case consts.MatchType_IpSet, consts.MatchType_DomainSet, consts.MatchType_IpVersion, consts.MatchType_Fallback:
		return true
	default:
		return false
	}
}

func destIPRoutingMatch(matchType consts.MatchType) bool {
	switch matchType {
	case consts.MatchType_IpSet, consts.MatchType_IpVersion:
		return true
	default:
		return false
	}
}

// conflictFingerprint evaluates routing from dest IP and domain bits only.
// Identity conjuncts are skipped so `mac && domain` still fingerprints as
// domain, while standalone sip/dscp rules cannot collapse every owner onto
// must_direct. A hitting rule that skipped identity is marked
// identitySensitive so shared-IP owners that only agree dest-only still
// conflict.
func (m *RoutingMatcher) conflictFingerprint(dest netip.Addr, domainBitmap []uint32) domainRoutingFingerprint {
	if m == nil || !dest.IsValid() {
		return domainRoutingFingerprint{}
	}
	dest16 := dest.As16()
	ipVersion := consts.IpVersion_6
	if dest.Is4() || dest.Is4In6() {
		ipVersion = consts.IpVersion_4
	}
	outbound, mark, must, identitySensitive, err := m.matchFacts(routingMatcherFacts{
		destAddr:         dest16,
		ipVersion:        ipVersion,
		ipSetBin:         trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(dest16), 128)),
		domainBitmap:     domainBitmap,
		identityDontCare: true,
	})
	if err != nil {
		return domainRoutingFingerprint{}
	}
	return domainRoutingFingerprint{
		outbound:          outbound,
		mark:              mark,
		must:              must,
		identitySensitive: identitySensitive,
		valid:             true,
	}
}

func (m *RoutingMatcher) matchFacts(facts routingMatcherFacts) (outboundIndex consts.OutboundIndex, mark uint32, must bool, identitySensitive bool, err error) {
	if m == nil {
		return 0, 0, false, false, fmt.Errorf("nil routing matcher")
	}
	matches := m.compiledMatches
	if len(matches) == 0 {
		return 0, 0, false, false, fmt.Errorf("no compiled routing match set")
	}

	goodSubrule := false
	badRule := false
	ruleHasDest := false
	subruleHasDest := false
	ruleHasIdentitySkip := false
	for i, match := range matches {
		if destRoutingMatch(match.matchType) {
			subruleHasDest = true
			ruleHasDest = true
		}
		identitySkip := facts.identityDontCare && identityRoutingMatch(match.matchType)
		if identitySkip {
			ruleHasIdentitySkip = true
		}
		if !identitySkip && !badRule && !goodSubrule {
			matched, matchErr := m.matchCompiledMatch(i, match, &facts)
			if matchErr != nil {
				return 0, 0, false, false, matchErr
			}
			if matched {
				goodSubrule = true
			}
		}
		outbound := match.outbound
		if outbound != consts.OutboundLogicalOr {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			// A subrule of only skipped identity matches is vacuous: AND
			// `mac && domain` reduces to domain, OR `sip || domain` waits
			// for the dest side.
			if !(facts.identityDontCare && !subruleHasDest) && goodSubrule == match.not {
				// This subrule does not hit.
				badRule = true
			}

			// Reset goodSubrule.
			goodSubrule = false
			subruleHasDest = false
		}

		if outbound&consts.OutboundLogicalMask !=
			consts.OutboundLogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if facts.identityDontCare && !ruleHasDest {
				badRule = true
			}
			if !badRule {
				if outbound == consts.OutboundMustRules {
					must = true
					ruleHasDest = false
					ruleHasIdentitySkip = false
					continue
				}
				if outbound == consts.OutboundControlPlaneRouting {
					// Implicit sniff-punt lines exist only in the kernel-space
					// projection: once a connection has been punted and
					// sniffed, userspace must re-route over the remaining
					// rules as if this line did not exist.
					badRule = false
					continue
				}
				return outbound, match.mark, match.must || must, ruleHasIdentitySkip, nil
			}
			badRule = false
			ruleHasDest = false
			ruleHasIdentitySkip = false
		}
	}
	return 0, 0, false, false, fmt.Errorf("no match set hit")
}

func (m *RoutingMatcher) evalDeferringDestIP(index int, match compiledRoutingMatch, facts *routingMatcherFacts) (fakeIPKleene, error) {
	if destIPRoutingMatch(match.matchType) {
		return fakeIPKleeneUnknown, nil
	}
	hit, err := m.matchCompiledMatch(index, match, facts)
	if err != nil {
		return 0, err
	}
	if hit {
		return fakeIPKleeneTrue, nil
	}
	return fakeIPKleeneFalse, nil
}

// matchFactsDeferringDestIP is first-match routing with dest ip()/geoip/
// ipversion() UNKNOWN. Domain, sip, mac, port, l4proto, and fallback are evaluated.
// A TRUE hit is returned with needsDestIP=false. A rule that cannot be
// decided without dest IP returns needsDestIP=true so the caller can
// resolve and rematch.
//
// AND/OR short-circuit matches matchFacts: a FALSE conjunct or a TRUE
// disjunct stops evaluating the rest of that rule so a later ip() cannot
// turn a decided rule into UNKNOWN (and force a DNS lookup).
func (m *RoutingMatcher) matchFactsDeferringDestIP(facts routingMatcherFacts) (outboundIndex consts.OutboundIndex, mark uint32, must bool, needsDestIP bool, err error) {
	if m == nil {
		return 0, 0, false, false, fmt.Errorf("nil routing matcher")
	}
	matches := m.compiledMatches
	if len(matches) == 0 {
		return 0, 0, false, false, fmt.Errorf("no compiled routing match set")
	}

	subrule := fakeIPKleeneFalse
	rule := fakeIPKleeneTrue
	for i, match := range matches {
		// FALSE && x = FALSE; TRUE || x = TRUE. Skip x so an UNKNOWN
		// dest-IP term cannot poison a rule that is already decided.
		if rule != fakeIPKleeneFalse && subrule != fakeIPKleeneTrue {
			val, evalErr := m.evalDeferringDestIP(i, match, &facts)
			if evalErr != nil {
				return 0, 0, false, false, evalErr
			}
			subrule = fakeIPKleeneOr(subrule, val)
		}
		outbound := match.outbound
		if outbound != consts.OutboundLogicalOr {
			if match.not {
				subrule = fakeIPKleeneNot(subrule)
			}
			rule = fakeIPKleeneAnd(rule, subrule)
			subrule = fakeIPKleeneFalse
		}
		if outbound&consts.OutboundLogicalMask != consts.OutboundLogicalMask {
			if outbound == consts.OutboundMustRules {
				switch rule {
				case fakeIPKleeneUnknown:
					return 0, 0, false, true, nil
				case fakeIPKleeneTrue:
					must = true
				}
				rule = fakeIPKleeneTrue
				continue
			}
			switch rule {
			case fakeIPKleeneUnknown:
				return 0, 0, false, true, nil
			case fakeIPKleeneTrue:
				return outbound, match.mark, match.must || must, false, nil
			}
			rule = fakeIPKleeneTrue
		}
	}
	return 0, 0, false, false, fmt.Errorf("no match set hit")
}
