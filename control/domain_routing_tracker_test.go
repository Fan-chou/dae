/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestDomainRoutingTrackerZeroFingerprintORsBitmaps(t *testing.T) {
	tracker := newDomainRoutingTracker()
	cacheA := domainRoutingACache("a.example.:1", "203.0.113.77", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("b.example.:1", "203.0.113.77", domainRoutingBitmap(0x2))

	if err := phase5ProjectCache(tracker, 0, cacheA); err != nil {
		t.Fatalf("project A: %v", err)
	}
	if err := phase5ProjectCache(tracker, 0, cacheB); err != nil {
		t.Fatalf("project B: %v", err)
	}
	merged := requireTrackerMerged(t, tracker, cacheA)
	if merged.Bitmap[0] != 0x3 {
		t.Fatalf("merged bitmap = %#x, want 0x3", merged.Bitmap[0])
	}
	if merged.Ambiguous != 0 {
		t.Fatalf("ambiguous = %d, want 0 for zero fingerprints", merged.Ambiguous)
	}
}

func TestDomainRoutingTrackerSameFingerprintKeepsKernelOR(t *testing.T) {
	tracker := newDomainRoutingTracker()
	same := domainRoutingFingerprint{outbound: consts.OutboundDirect, valid: true}
	cacheA := domainRoutingACache("a.example.:1", "203.0.113.77", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("b.example.:1", "203.0.113.77", domainRoutingBitmap(0x2))

	if err := projectDomainRoutingWithFingerprint(tracker, 0, cacheA, same); err != nil {
		t.Fatalf("project A: %v", err)
	}
	if err := projectDomainRoutingWithFingerprint(tracker, 0, cacheB, same); err != nil {
		t.Fatalf("project B: %v", err)
	}
	merged := requireTrackerMerged(t, tracker, cacheA)
	if merged.Bitmap[0] != 0x3 {
		t.Fatalf("merged bitmap = %#x, want 0x3", merged.Bitmap[0])
	}
	if merged.Ambiguous != 0 {
		t.Fatalf("ambiguous = %d, want 0 when fingerprints match", merged.Ambiguous)
	}
}

func TestDomainRoutingTrackerDifferentFingerprintMarksAmbiguous(t *testing.T) {
	tracker := newDomainRoutingTracker()
	cacheA := domainRoutingACache("a.example.:1", "203.0.113.77", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("b.example.:1", "203.0.113.77", domainRoutingBitmap(0x2))

	if err := projectDomainRoutingWithFingerprint(tracker, 0, cacheA, domainRoutingFingerprint{
		outbound: consts.OutboundDirect,
		valid:    true,
	}); err != nil {
		t.Fatalf("project A: %v", err)
	}
	if err := projectDomainRoutingWithFingerprint(tracker, 0, cacheB, domainRoutingFingerprint{
		outbound: consts.OutboundUserDefinedMin,
		valid:    true,
	}); err != nil {
		t.Fatalf("project B: %v", err)
	}
	merged := requireTrackerMerged(t, tracker, cacheA)
	if merged.Bitmap[0] != 0x3 {
		t.Fatalf("merged bitmap = %#x, want 0x3 (OR must be kept)", merged.Bitmap[0])
	}
	if merged.Ambiguous != 1 {
		t.Fatalf("ambiguous = %d, want 1", merged.Ambiguous)
	}
}

func TestDomainRoutingTrackerDropOwnerClearsAmbiguous(t *testing.T) {
	tracker := newDomainRoutingTracker()
	cacheA := domainRoutingACache("a.example.:1", "203.0.113.77", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("b.example.:1", "203.0.113.77", domainRoutingBitmap(0x2))

	if err := projectDomainRoutingWithFingerprint(tracker, 0, cacheA, domainRoutingFingerprint{
		outbound: consts.OutboundDirect,
		valid:    true,
	}); err != nil {
		t.Fatalf("project A: %v", err)
	}
	if err := projectDomainRoutingWithFingerprint(tracker, 0, cacheB, domainRoutingFingerprint{
		outbound: consts.OutboundUserDefinedMin,
		valid:    true,
	}); err != nil {
		t.Fatalf("project B: %v", err)
	}
	if err := phase5RemoveCache(tracker, 0, cacheB); err != nil {
		t.Fatalf("remove B: %v", err)
	}
	merged := requireTrackerMerged(t, tracker, cacheA)
	if merged.Bitmap[0] != 0x1 {
		t.Fatalf("merged bitmap = %#x, want 0x1 after dropping B", merged.Bitmap[0])
	}
	if merged.Ambiguous != 0 {
		t.Fatalf("ambiguous = %d, want 0 after a single owner remains", merged.Ambiguous)
	}
}

func TestDomainRoutingTrackerIdentityPrefixMarksAmbiguous(t *testing.T) {
	matcher := identityPrefixConflictMatcher()
	core := &controlPlaneCore{}
	core.bindDomainRoutingFingerprinter(matcher)
	tracker := newDomainRoutingTracker()
	cacheA := domainRoutingACache("a.example.:1", "203.0.113.77", domainRoutingBitmap(1<<3))
	cacheB := domainRoutingACache("b.example.:1", "203.0.113.77", domainRoutingBitmap(1<<4))
	for _, cache := range []*DnsCache{cacheA, cacheB} {
		snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
		if err != nil {
			t.Fatalf("snapshot %q: %v", cache.RouteOwnerKey, err)
		}
		core.attachDomainRoutingFingerprints(cache, &snapshot)
		if err := tracker.syncOwnerForSlot(nil, 0, cache.RouteOwnerKey, snapshot); err != nil {
			t.Fatalf("project %q: %v", cache.RouteOwnerKey, err)
		}
	}
	merged := requireTrackerMerged(t, tracker, cacheA)
	if merged.Bitmap[0] != (1<<3)|(1<<4) {
		t.Fatalf("merged bitmap = %#x, want bits 3 and 4", merged.Bitmap[0])
	}
	if merged.Ambiguous != 1 {
		t.Fatalf("ambiguous = %d, want 1 with sip/dscp prefix in front of domain rules", merged.Ambiguous)
	}
}

func TestDomainRoutingTrackerIdentitySensitiveMarksAmbiguous(t *testing.T) {
	tracker := newDomainRoutingTracker()
	cacheA := domainRoutingACache("a.example.:1", "203.0.113.77", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("b.example.:1", "203.0.113.77", domainRoutingBitmap(0x2))
	sameSensitive := domainRoutingFingerprint{
		outbound:          consts.OutboundDirect,
		identitySensitive: true,
		valid:             true,
	}

	if err := projectDomainRoutingWithFingerprint(tracker, 0, cacheA, sameSensitive); err != nil {
		t.Fatalf("project A: %v", err)
	}
	if err := projectDomainRoutingWithFingerprint(tracker, 0, cacheB, sameSensitive); err != nil {
		t.Fatalf("project B: %v", err)
	}
	merged := requireTrackerMerged(t, tracker, cacheA)
	if merged.Bitmap[0] != 0x3 {
		t.Fatalf("merged bitmap = %#x, want 0x3", merged.Bitmap[0])
	}
	if merged.Ambiguous != 1 {
		t.Fatalf("ambiguous = %d, want 1 when dest-only fingerprints match but identity can split", merged.Ambiguous)
	}
}

func TestDomainRoutingTrackerIdentitySensitiveAttachedFromMatcher(t *testing.T) {
	matcher := l4SplitConflictMatcher()
	core := &controlPlaneCore{}
	core.bindDomainRoutingFingerprinter(matcher)
	tracker := newDomainRoutingTracker()
	cacheA := domainRoutingACache("a.example.:1", "203.0.113.77", domainRoutingBitmap(1<<0|1<<2))
	cacheB := domainRoutingACache("b.example.:1", "203.0.113.77", domainRoutingBitmap(1<<4|1<<6))
	for _, cache := range []*DnsCache{cacheA, cacheB} {
		snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
		if err != nil {
			t.Fatalf("snapshot %q: %v", cache.RouteOwnerKey, err)
		}
		core.attachDomainRoutingFingerprints(cache, &snapshot)
		if err := tracker.syncOwnerForSlot(nil, 0, cache.RouteOwnerKey, snapshot); err != nil {
			t.Fatalf("project %q: %v", cache.RouteOwnerKey, err)
		}
	}
	merged := requireTrackerMerged(t, tracker, cacheA)
	if merged.Ambiguous != 1 {
		t.Fatalf("ambiguous = %d, want 1 for shared-IP domain+l4proto split", merged.Ambiguous)
	}
}

func projectDomainRoutingWithFingerprint(
	tracker *domainRoutingTracker,
	slot uint32,
	cache *DnsCache,
	fp domainRoutingFingerprint,
) error {
	snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
	if err != nil {
		return err
	}
	snapshot.fingerprints = make(map[[4]uint32]domainRoutingFingerprint, len(snapshot.ips))
	for key := range snapshot.ips {
		snapshot.fingerprints[key] = fp
	}
	return tracker.syncOwnerForSlot(nil, slot, cache.RouteOwnerKey, snapshot)
}

func requireTrackerMerged(t *testing.T, tracker *domainRoutingTracker, cache *DnsCache) bpfDomainRouting {
	t.Helper()
	snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if len(snapshot.ips) != 1 {
		t.Fatalf("ip count = %d, want 1", len(snapshot.ips))
	}
	for key := range snapshot.ips {
		tracker.mu.Lock()
		state := tracker.ips[key]
		tracker.mu.Unlock()
		if state == nil {
			t.Fatalf("domain routing state for %q is absent", cache.RouteOwnerKey)
		}
		return state.merged
	}
	t.Fatal("snapshot had no IP keys")
	return bpfDomainRouting{}
}
