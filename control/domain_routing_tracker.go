/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

// ErrBpfMapFull reports that a BPF map rejected an insertion because it is at
// max_entries. domain_routing_map is a plain hash so that userspace accounting
// stays authoritative, which means a full map surfaces here instead of being
// papered over by LRU eviction.
var ErrBpfMapFull = stderrors.New("bpf map is full")

func isBpfMapFullError(err error) bool {
	return stderrors.Is(err, syscall.E2BIG) || stderrors.Is(err, syscall.ENOSPC)
}

// domainRoutingFingerprint is the DNS-time routing outcome for one owner on one
// destination IP, ignoring connection identity (MAC/port/process). Zero value
// (valid=false) is ignored when detecting conflicts so tests without a matcher
// keep the historical OR-only merge.
type domainRoutingFingerprint struct {
	outbound consts.OutboundIndex
	mark     uint32
	must     bool
	valid    bool
}

type domainRoutingOwnerSnapshot struct {
	bitmap       bpfDomainRouting
	ips          map[[4]uint32]struct{}
	fingerprints map[[4]uint32]domainRoutingFingerprint
}

type domainRoutingIPOwner struct {
	bitmap      bpfDomainRouting
	fingerprint domainRoutingFingerprint
}

type domainRoutingIPState struct {
	owners map[string]domainRoutingIPOwner
	merged bpfDomainRouting
}

type domainRoutingTracker struct {
	mu     sync.Mutex
	owners map[string]domainRoutingOwnerSnapshot
	ips    map[[4]uint32]*domainRoutingIPState
}

func newDomainRoutingTracker() *domainRoutingTracker {
	return &domainRoutingTracker{
		owners: make(map[string]domainRoutingOwnerSnapshot),
		ips:    make(map[[4]uint32]*domainRoutingIPState),
	}
}

func cloneDomainRoutingIPSet(src map[[4]uint32]struct{}) map[[4]uint32]struct{} {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[[4]uint32]struct{}, len(src))
	for key := range src {
		dst[key] = struct{}{}
	}
	return dst
}

func cloneDomainRoutingFingerprints(src map[[4]uint32]domainRoutingFingerprint) map[[4]uint32]domainRoutingFingerprint {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[[4]uint32]domainRoutingFingerprint, len(src))
	for key, fp := range src {
		dst[key] = fp
	}
	return dst
}

func isZeroDomainRoutingBitmap(bitmap bpfDomainRouting) bool {
	for _, word := range bitmap.Bitmap {
		if word != 0 {
			return false
		}
	}
	return true
}

func orDomainRoutingBitmap(dst *bpfDomainRouting, src bpfDomainRouting) {
	for i := range dst.Bitmap {
		dst.Bitmap[i] |= src.Bitmap[i]
	}
}

func mergeDomainRoutingIPOwners(owners map[string]domainRoutingIPOwner) bpfDomainRouting {
	var merged bpfDomainRouting
	var seen domainRoutingFingerprint
	seenValid := false
	ambiguous := false
	for _, owner := range owners {
		orDomainRoutingBitmap(&merged, owner.bitmap)
		if !owner.fingerprint.valid {
			continue
		}
		if !seenValid {
			seen = owner.fingerprint
			seenValid = true
			continue
		}
		if owner.fingerprint != seen {
			ambiguous = true
		}
	}
	if ambiguous {
		merged.Ambiguous = 1
	}
	return merged
}

func buildDomainRoutingOwnerSnapshot(cache *DnsCache) (domainRoutingOwnerSnapshot, error) {
	if cache == nil {
		return domainRoutingOwnerSnapshot{}, nil
	}
	if len(cache.DomainBitmap) != len(bpfDomainRouting{}.Bitmap) {
		return domainRoutingOwnerSnapshot{}, fmt.Errorf("domain bitmap length not sync with kern program")
	}
	var snapshot domainRoutingOwnerSnapshot
	copy(snapshot.bitmap.Bitmap[:], cache.DomainBitmap)
	ips := extractIPsFromDnsCache(cache)
	if len(ips) == 0 {
		return snapshot, nil
	}
	snapshot.ips = make(map[[4]uint32]struct{}, len(ips))
	for _, ip := range ips {
		ip6 := ip.As16()
		snapshot.ips[common.Ipv6ByteSliceToUint32Array(ip6[:])] = struct{}{}
	}
	return snapshot, nil
}

func (t *domainRoutingTracker) desiredBitmapForKeyLocked(
	key [4]uint32,
	ownerKey string,
	snapshot domainRoutingOwnerSnapshot,
) (bitmap bpfDomainRouting, present bool) {
	owners := make(map[string]domainRoutingIPOwner)
	if state := t.ips[key]; state != nil {
		for existingOwnerKey, existing := range state.owners {
			if existingOwnerKey == ownerKey {
				continue
			}
			owners[existingOwnerKey] = existing
			present = true
		}
	}
	if len(snapshot.ips) > 0 && !isZeroDomainRoutingBitmap(snapshot.bitmap) {
		if _, ok := snapshot.ips[key]; ok {
			owners[ownerKey] = domainRoutingIPOwner{
				bitmap:      snapshot.bitmap,
				fingerprint: snapshot.fingerprints[key],
			}
			present = true
		}
	}
	if !present {
		return bpfDomainRouting{}, false
	}
	return mergeDomainRoutingIPOwners(owners), true
}

func (t *domainRoutingTracker) applyOwnerSnapshotLocked(ownerKey string, snapshot domainRoutingOwnerSnapshot) {
	if ownerKey == "" {
		return
	}
	if old, ok := t.owners[ownerKey]; ok {
		for key := range old.ips {
			state := t.ips[key]
			if state == nil {
				continue
			}
			delete(state.owners, ownerKey)
			if len(state.owners) == 0 {
				delete(t.ips, key)
				continue
			}
			state.merged = mergeDomainRoutingIPOwners(state.owners)
		}
		delete(t.owners, ownerKey)
	}
	if len(snapshot.ips) == 0 || isZeroDomainRoutingBitmap(snapshot.bitmap) {
		return
	}
	cloned := domainRoutingOwnerSnapshot{
		bitmap:       snapshot.bitmap,
		ips:          cloneDomainRoutingIPSet(snapshot.ips),
		fingerprints: cloneDomainRoutingFingerprints(snapshot.fingerprints),
	}
	t.owners[ownerKey] = cloned
	for key := range cloned.ips {
		state := t.ips[key]
		if state == nil {
			state = &domainRoutingIPState{
				owners: make(map[string]domainRoutingIPOwner),
			}
			t.ips[key] = state
		}
		state.owners[ownerKey] = domainRoutingIPOwner{
			bitmap:      cloned.bitmap,
			fingerprint: cloned.fingerprints[key],
		}
		state.merged = mergeDomainRoutingIPOwners(state.owners)
	}
}

func (t *domainRoutingTracker) syncOwnerForSlot(
	m *ebpf.Map,
	slot uint32,
	ownerKey string,
	snapshot domainRoutingOwnerSnapshot,
) error {
	if ownerKey == "" {
		return fmt.Errorf("empty domain routing owner key")
	}
	if !validRoutingEpochSlot(slot) {
		return fmt.Errorf("invalid domain routing epoch slot %d", slot)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	oldSnapshot := t.owners[ownerKey]
	affected := make(map[[4]uint32]struct{}, len(oldSnapshot.ips)+len(snapshot.ips))
	for key := range oldSnapshot.ips {
		affected[key] = struct{}{}
	}
	for key := range snapshot.ips {
		affected[key] = struct{}{}
	}

	keysToUpdate := make([]bpfRoutingEpochIp, 0, len(affected))
	valuesToUpdate := make([]bpfDomainRouting, 0, len(affected))
	keysToDelete := make([]bpfRoutingEpochIp, 0, len(affected))

	for key := range affected {
		desiredBitmap, present := t.desiredBitmapForKeyLocked(key, ownerKey, snapshot)
		current := t.ips[key]
		switch {
		case !present:
			if current != nil {
				keysToDelete = append(keysToDelete, bpfRoutingEpochIp{Slot: slot, Addr: key})
			}
		case current == nil || current.merged != desiredBitmap:
			keysToUpdate = append(keysToUpdate, bpfRoutingEpochIp{Slot: slot, Addr: key})
			valuesToUpdate = append(valuesToUpdate, desiredBitmap)
		}
	}

	if m != nil {
		// Delete before update: retiring stale entries frees room in a map that
		// is close to full, so the update below is more likely to fit.
		if len(keysToDelete) > 0 {
			if _, err := BpfMapBatchDelete(m, keysToDelete); err != nil {
				return fmt.Errorf("delete domain_routing_map: %w", err)
			}
		}
		if len(keysToUpdate) > 0 {
			if _, err := BpfMapBatchUpdate(m, keysToUpdate, valuesToUpdate, &ebpf.BatchOptions{
				ElemFlags: uint64(ebpf.UpdateAny),
			}); err != nil {
				if isBpfMapFullError(err) {
					// Leave the tracker untouched so the desired state is
					// recomputed and retried once DNS cache expiry frees
					// entries. Reporting a distinguishable error lets the
					// caller keep serving the answer instead of failing it.
					return fmt.Errorf("update domain_routing_map: %w: %w", ErrBpfMapFull, err)
				}
				return fmt.Errorf("update domain_routing_map: %w", err)
			}
		}
	}

	t.applyOwnerSnapshotLocked(ownerKey, snapshot)
	return nil
}
