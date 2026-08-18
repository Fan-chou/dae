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
