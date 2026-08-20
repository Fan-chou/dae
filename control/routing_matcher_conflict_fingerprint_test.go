/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestConflictFingerprintIgnoresMACAndUsesDomainBits(t *testing.T) {
	matcher := &RoutingMatcher{
		compiledMatches: []compiledRoutingMatch{
			{matchType: consts.MatchType_Mac, outbound: consts.OutboundLogicalAnd},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundDirect},
			{matchType: consts.MatchType_Fallback, outbound: consts.OutboundBlock},
		},
	}
	dest := netip.MustParseAddr("203.0.113.10")
	// DomainSet is match index 1, so it consults bit 1.
	direct := matcher.conflictFingerprint(dest, []uint32{0x2})
	if !direct.valid || direct.outbound != consts.OutboundDirect {
		t.Fatalf("domain bit hit = %+v, want valid direct", direct)
	}
	fallback := matcher.conflictFingerprint(dest, []uint32{0x1})
	if !fallback.valid || fallback.outbound != consts.OutboundBlock {
		t.Fatalf("domain bit miss = %+v, want valid block fallback", fallback)
	}
}

func TestConflictFingerprintSameOutboundDifferentDomainRules(t *testing.T) {
	matcher := &RoutingMatcher{
		compiledMatches: []compiledRoutingMatch{
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundDirect},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundDirect},
			{matchType: consts.MatchType_Fallback, outbound: consts.OutboundBlock},
		},
	}
	dest := netip.MustParseAddr("203.0.113.10")
	first := matcher.conflictFingerprint(dest, []uint32{0x1})
	second := matcher.conflictFingerprint(dest, []uint32{0x2})
	if !first.valid || !second.valid {
		t.Fatalf("fingerprints not valid: %+v %+v", first, second)
	}
	if first != second {
		t.Fatalf("same outbound fingerprints differ: %+v vs %+v", first, second)
	}
}

func TestConflictFingerprintDifferentOutbound(t *testing.T) {
	matcher := &RoutingMatcher{
		compiledMatches: []compiledRoutingMatch{
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundDirect},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundUserDefinedMin},
			{matchType: consts.MatchType_Fallback, outbound: consts.OutboundBlock},
		},
	}
	dest := netip.MustParseAddr("203.0.113.10")
	direct := matcher.conflictFingerprint(dest, []uint32{0x1})
	proxy := matcher.conflictFingerprint(dest, []uint32{0x2})
	if !direct.valid || !proxy.valid {
		t.Fatalf("fingerprints not valid: %+v %+v", direct, proxy)
	}
	if direct.outbound != consts.OutboundDirect {
		t.Fatalf("first outbound = %v, want direct", direct.outbound)
	}
	if proxy.outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("second outbound = %v, want user-defined", proxy.outbound)
	}
	if direct == proxy {
		t.Fatal("expected different fingerprints for direct vs proxy")
	}
}

func identityPrefixConflictMatcher() *RoutingMatcher {
	// 223-shaped prefix: sip / dscp / !sip(match_mac) must_direct, then two
	// domain rules. DomainSet bits follow compiled match indices 3 and 4.
	return &RoutingMatcher{
		compiledMatches: []compiledRoutingMatch{
			{matchType: consts.MatchType_SourceIpSet, outbound: consts.OutboundDirect, must: true},
			{matchType: consts.MatchType_Dscp, outbound: consts.OutboundDirect, must: true},
			{matchType: consts.MatchType_SourceIpSet, outbound: consts.OutboundDirect, must: true, not: true},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundDirect},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundUserDefinedMin},
			{matchType: consts.MatchType_Fallback, outbound: consts.OutboundBlock},
		},
	}
}

func TestConflictFingerprintSkipsStandaloneIdentityRules(t *testing.T) {
	matcher := identityPrefixConflictMatcher()
	dest := netip.MustParseAddr("203.0.113.10")
	direct := matcher.conflictFingerprint(dest, []uint32{1 << 3})
	proxy := matcher.conflictFingerprint(dest, []uint32{1 << 4})
	if !direct.valid || direct.outbound != consts.OutboundDirect || direct.must {
		t.Fatalf("domain bit 3 = %+v, want valid non-must direct", direct)
	}
	if direct.identitySensitive {
		t.Fatal("sip/dscp prefix must not mark the dest-only domain hit identity-sensitive")
	}
	if !proxy.valid || proxy.outbound != consts.OutboundUserDefinedMin || proxy.must {
		t.Fatalf("domain bit 4 = %+v, want valid non-must proxy", proxy)
	}
	if direct == proxy {
		t.Fatal("sip/dscp prefix must not collapse both owners onto must_direct")
	}
}

func TestConflictFingerprintOrIdentityReducesToDomain(t *testing.T) {
	matcher := &RoutingMatcher{
		compiledMatches: []compiledRoutingMatch{
			{matchType: consts.MatchType_SourceIpSet, outbound: consts.OutboundLogicalOr},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundUserDefinedMin},
			{matchType: consts.MatchType_Fallback, outbound: consts.OutboundDirect},
		},
	}
	dest := netip.MustParseAddr("203.0.113.10")
	hit := matcher.conflictFingerprint(dest, []uint32{0x2})
	miss := matcher.conflictFingerprint(dest, []uint32{0x1})
	if !hit.valid || hit.outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("sip || domain hit = %+v, want proxy", hit)
	}
	if !miss.valid || miss.outbound != consts.OutboundDirect {
		t.Fatalf("sip || domain miss = %+v, want fallback direct", miss)
	}
}

func TestAttachDomainRoutingFingerprints(t *testing.T) {
	matcher := &RoutingMatcher{
		compiledMatches: []compiledRoutingMatch{
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundDirect},
			{matchType: consts.MatchType_Fallback, outbound: consts.OutboundBlock},
		},
	}
	core := &controlPlaneCore{}
	core.bindDomainRoutingFingerprinter(matcher)
	cache := domainRoutingACache("cn.example.:1", "203.0.113.77", domainRoutingBitmap(0x1))
	snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	core.attachDomainRoutingFingerprints(cache, &snapshot)
	if len(snapshot.fingerprints) != 1 {
		t.Fatalf("fingerprint count = %d, want 1", len(snapshot.fingerprints))
	}
	for _, fp := range snapshot.fingerprints {
		if !fp.valid || fp.outbound != consts.OutboundDirect {
			t.Fatalf("fingerprint = %+v, want valid direct", fp)
		}
	}
}

func l4SplitConflictMatcher() *RoutingMatcher {
	// domain(a) && tcp -> common; domain(a) && udp -> proxy_a;
	// domain(b) && tcp -> common; domain(b) && udp -> proxy_b.
	// Dest-only evaluation skips l4proto, so both owners hit common.
	return &RoutingMatcher{
		compiledMatches: []compiledRoutingMatch{
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundLogicalAnd},
			{matchType: consts.MatchType_L4Proto, outbound: consts.OutboundDirect},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundLogicalAnd},
			{matchType: consts.MatchType_L4Proto, outbound: consts.OutboundUserDefinedMin},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundLogicalAnd},
			{matchType: consts.MatchType_L4Proto, outbound: consts.OutboundDirect},
			{matchType: consts.MatchType_DomainSet, outbound: consts.OutboundLogicalAnd},
			{matchType: consts.MatchType_L4Proto, outbound: consts.OutboundUserDefinedMin + 1},
			{matchType: consts.MatchType_Fallback, outbound: consts.OutboundBlock},
		},
	}
}

func TestConflictFingerprintDomainAndL4IsIdentitySensitive(t *testing.T) {
	matcher := l4SplitConflictMatcher()
	dest := netip.MustParseAddr("203.0.113.10")
	first := matcher.conflictFingerprint(dest, []uint32{1<<0 | 1<<2})
	second := matcher.conflictFingerprint(dest, []uint32{1<<4 | 1<<6})
	if !first.valid || first.outbound != consts.OutboundDirect || !first.identitySensitive {
		t.Fatalf("owner a = %+v, want valid identity-sensitive common/direct", first)
	}
	if !second.valid || second.outbound != consts.OutboundDirect || !second.identitySensitive {
		t.Fatalf("owner b = %+v, want valid identity-sensitive common/direct", second)
	}
}
