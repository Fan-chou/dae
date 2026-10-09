// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	udpDNSPinCurrent uint32 = iota
	udpDNSPinPrepared
	udpDNSPinSuperseded
	udpDNSPinClosed
)

// Only scoped enforce flows allocate this identity. The original address is
// the client's NAT identity; peer is the immutable application destination.
type udpPinnedTargetIdentity struct {
	original, peer netip.AddrPort
	domain         string
	native         bool
	initial        PacketSnifferKey
	flow           *udpPinnedFlowIdentity
	// DNS FakeIP flows record the mapping name seen when the flow was created
	// and the process-owned store. Leases are per endpoint, never copied here.
	fakeName  string
	fakeStore *FakeIPStore
}

// No packet write takes this mutex. It serializes publication, connection
// identity changes, and retirement memory writes across transport successors.
type udpPinnedFlowIdentity struct {
	mu        sync.Mutex
	owner     *UdpEndpoint
	revision  atomic.Uint64
	revoked   atomic.Bool
	uncertain atomic.Bool
}

func newUDPPinnedTarget(ue *UdpEndpoint, option *DialOption) *udpPinnedTargetIdentity {
	peer, err := netip.ParseAddrPort(option.Target)
	if err != nil || !ue.poolKey.Dst.IsValid() {
		return nil
	}
	f := &udpPinnedFlowIdentity{owner: ue}
	f.revision.Store(1)
	t := &udpPinnedTargetIdentity{original: ue.poolKey.Dst, peer: netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()), domain: strings.ToLower(strings.TrimSuffix(option.SniffedDomain, ".")), native: option.ResolveDNSOriginalNative, initial: option.ResolveDNSInitial, flow: f}
	if !t.native {
		t.fakeName, t.fakeStore = canonicalizeFakeIPQname(option.FakeIPName), option.FakeIPStore
	}
	return t
}

// A read-only check for candidate selection. prepare's AcquireLease is the
// authoritative decision.
func (p *udpPinnedTargetIdentity) fakeIPExclusion() string {
	if p.fakeName == "" || p.fakeStore == nil || !p.fakeStore.Ready() {
		return "resolve_dns_fakeip_unleased"
	}
	if name, ok := p.fakeStore.LookBack(p.original.Addr()); !ok || canonicalizeFakeIPQname(name) != p.fakeName {
		return "resolve_dns_mapping_changed"
	}
	return ""
}

func (p *udpPinnedTargetIdentity) acquireFakeIPLease() (*fakeIPLease, error) {
	return p.fakeStore.AcquireLease(p.original.Addr(), p.fakeName)
}

func fakeIPLeaseReason(err error) string {
	switch {
	case errors.Is(err, errFakeIPLeaseMappingChanged):
		return "resolve_dns_mapping_changed"
	case errors.Is(err, errFakeIPLeaseFull):
		return "resolve_dns_fakeip_lease_full"
	default:
		return "resolve_dns_fakeip_unleased"
	}
}

func (ue *UdpEndpoint) releaseFakeIPLease() {
	if ue.resolveDNSState != nil {
		ue.resolveDNSState.fakeLease.Swap(nil).Release()
	}
}

func (ue *UdpEndpoint) pinnedDNSExclusion(peer netip.AddrPort) string {
	p := ue.pinnedTarget
	if p == nil || ue.resolveDNSState == nil || p.flow.revoked.Load() || p.flow.uncertain.Load() {
		return "resolve_dns_identity_uncertain"
	}
	if !p.native {
		if reason := p.fakeIPExclusion(); reason != "" {
			return reason
		}
	}
	target, err := netip.ParseAddrPort(ue.DialTarget)
	if err != nil {
		return "resolve_dns_target_unresolved"
	}
	if p.domain == "" || p.domain != strings.ToLower(strings.TrimSuffix(ue.SniffedDomain, ".")) || ue.resolveDNSState.initial != p.initial || (ue.identifiedQuic() && !p.initial.HasCacheableDcid()) {
		return "resolve_dns_identity_uncertain"
	}
	if ue.resolveDNSState.phase.Load() != udpDNSPinCurrent {
		return "resolve_dns_pin_owner_changed"
	}
	src := ue.poolKey.Src.Addr().Unmap()
	original := netip.AddrPortFrom(p.original.Addr().Unmap(), p.original.Port())
	// The visible reply address must be usable by the client. The immutable
	// application peer can use either family: canonicalReplyFrom and the
	// transport's UDP reply hint preserve original, while recovery evidence
	// still comes from the independently reported actual peer.
	if !src.IsValid() || p.original != ue.poolKey.Dst || peer != p.peer || netip.AddrPortFrom(target.Addr().Unmap(), target.Port()) != p.peer || !validDroughtPeer(original) || !validDroughtPeer(peer) || original.Port() != peer.Port() || src.Is4() != original.Addr().Is4() {
		return "resolve_dns_peer_mismatch"
	}
	if ue.crossFamily != nil {
		s := ue.crossFamily.store
		if s == nil || !s.Ready() || s.Contains(original.Addr()) || s.Contains(peer.Addr()) {
			return "peer_alias_unsupported"
		}
	}
	if slot := ue.rebuildPeer(peer); slot != nil && slot.original != p.original {
		return "resolve_dns_peer_mismatch"
	}
	return ""
}

func (ue *UdpEndpoint) rebuildOriginal(peer netip.AddrPort) netip.AddrPort {
	if p := ue.pinnedTarget; p != nil && p.peer == peer {
		return p.original
	}
	if A, _, ok := ue.aliasCandidate(peer); ok {
		return A
	}
	return peer
}

func (ue *UdpEndpoint) rebuildPeerForOriginal(original netip.AddrPort) *udpRebuildPeer {
	if ue == nil {
		return nil
	}
	if p := ue.pinnedTarget; p != nil && p.original == original {
		return ue.rebuildPeer(p.peer)
	}
	tables := ue.rebuildPeers.Load()
	if tables == nil {
		return nil
	}
	if s := tables.byPeer[original]; s != nil {
		return s
	}
	if tables.byOriginal == nil {
		return nil
	}
	if s := tables.byOriginal[original]; s != nil {
		return s
	}
	if mapped := unmapPort(original); mapped != original {
		return tables.byOriginal[mapped]
	}
	return nil
}

// Called before normal successor admission. A new target or business identity
// must not become a successor of a claim for the previous application peer.
func (ue *UdpEndpoint) inheritPinnedRebuildTarget(old *UdpEndpoint, option *DialOption) bool {
	if old.pinnedTarget == nil {
		return true
	}
	p, ds := old.pinnedTarget, ue.resolveDNSState
	peer, err := netip.ParseAddrPort(ue.DialTarget)
	if ds == nil || err != nil || netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()) != p.peer || ue.poolKey != old.poolKey || strings.ToLower(strings.TrimSuffix(ue.SniffedDomain, ".")) != p.domain || ds.initial != p.initial || old.resolveDNSState.phase.Load() != udpDNSPinCurrent || p.flow.revoked.Load() || option.Binding.Route != old.flowRouteBinding || option.ResolveDNSOriginalNative != p.native {
		return false
	}
	if !p.native {
		// Each owner holds its own lease; the ancestor's ends with it.
		if p.fakeStore == nil || option.FakeIPStore != p.fakeStore || canonicalizeFakeIPQname(option.FakeIPName) != p.fakeName {
			return false
		}
		lease, err := p.acquireFakeIPLease()
		if err != nil {
			return false
		}
		ds.fakeLease.Store(lease)
	}
	copy := *p
	ue.pinnedTarget = &copy
	ds.phase.Store(udpDNSPinPrepared)
	return true
}

// Ordinary successors of an alias claim must still resolve the same client
// address to the same real peer in the same inner table. A new read-only
// wrapper is the same table. A different table, a closed table, or a different
// peer starts a new flow and must not keep the old claim.
func (ue *UdpEndpoint) inheritAliasRebuild(slot *udpRebuildPeer) bool {
	if slot == nil || slot.aliasStore.Load() == nil {
		return true
	}
	snap := slot.aliasStore.Load()
	if ue == nil || ue.crossFamily == nil || ue.crossFamily.store != snap || !snap.Ready() {
		return false
	}
	A, P := unmapPort(slot.original), unmapPort(slot.peer)
	if ue.poolKey.Dst.IsValid() && ue.poolKey.Dst.Port() != 0 && unmapPort(ue.poolKey.Dst) != A {
		return false
	}
	target, err := netip.ParseAddrPort(ue.DialTarget)
	if err != nil || unmapPort(target) != P {
		return false
	}
	decoded, isAlias, err := ue.crossFamily.decode(A)
	if err != nil || !isAlias || unmapPort(decoded) != P {
		return false
	}
	return true
}

// Keep the boxed key and identity-validation temporaries out of the ordinary
// create frame. Most new flows have no recovery override.
func (p *UdpEndpointPool) prepareOrdinaryRebuildSuccessor(ue *UdpEndpoint, slot *udpRebuildPeer, option *DialOption) bool {
	ue.prepared.Store(true)
	old := slot.owner.Load().endpoint
	if ue.inheritPinnedRebuildTarget(old, option) && ue.inheritAliasRebuild(slot) {
		return true
	}
	// A closed pin/new target starts a new business flow.
	old.revokePinnedDNSIdentity()
	p.rebuildOverrides.CompareAndDelete(ue.poolKey, slot)
	ue.prepared.Store(false)
	return false
}

// store and ledger are acquired only with TryLock after pool publication locks.
// The caller validates its ticket before calling transferPinnedDNSLocked.
func lockPinnedDNSTransfer(old, next *UdpEndpoint) (func(), string) {
	if old.pinnedTarget == nil {
		return func() {}, ""
	}
	p := old.pinnedTarget
	if !p.flow.mu.TryLock() {
		return nil, "resolve_dns_pin_busy"
	}
	unlock := func() { p.flow.mu.Unlock() }
	if next.pinnedTarget == nil || next.pinnedTarget.flow != p.flow || p.flow.owner != old || p.flow.revoked.Load() || old.resolveDNSState.phase.Load() != udpDNSPinCurrent || next.resolveDNSState.phase.Load() != udpDNSPinPrepared {
		unlock()
		return nil, "resolve_dns_pin_owner_changed"
	}
	s := old.resolveDNSState.store
	if s == nil || next.resolveDNSState.store != s {
		unlock()
		return nil, "resolve_dns_pin_owner_changed"
	}
	if !s.mu.TryLock() {
		unlock()
		return nil, "resolve_dns_pin_busy"
	}
	// A concurrent Close/discard can change phase before we acquire store.mu.
	if old.resolveDNSState.phase.Load() != udpDNSPinCurrent || next.resolveDNSState.phase.Load() != udpDNSPinPrepared {
		s.mu.Unlock()
		unlock()
		return nil, "resolve_dns_pin_owner_changed"
	}
	return func() { s.mu.Unlock(); unlock() }, ""
}

func transferPinnedDNSLocked(old, next *UdpEndpoint) {
	if old.pinnedTarget == nil {
		return
	}
	// Never wait for Once while holding store.mu: save holds Once before mu.
	old.resolveDNSState.phase.Store(udpDNSPinSuperseded)
	next.resolveDNSState.phase.Store(udpDNSPinCurrent)
	s := old.resolveDNSState.store
	if r, ok := s.entries[old.poolKey]; ok && r.owner <= old.resolveDNSState.id {
		delete(s.entries, old.poolKey)
	}
	old.pinnedTarget.flow.owner = next
}

// A retired owner can still have delayed cache/memory callbacks. End its
// business identity before publishing an ordinary flow with a different pin.
func (ue *UdpEndpoint) revokePinnedDNSIdentity() {
	if ue == nil || ue.pinnedTarget == nil {
		return
	}
	ue.rebuildLifecycleMu.Lock()
	defer ue.rebuildLifecycleMu.Unlock()
	p := ue.pinnedTarget
	p.flow.mu.Lock()
	defer p.flow.mu.Unlock()
	if p.flow.owner == ue && !p.flow.revoked.Load() {
		ue.revokePinnedDNSIdentityLocked()
	}
}

func (ue *UdpEndpoint) revokePinnedDNSIdentityLocked() {
	i := ue.pinnedTarget
	i.flow.revoked.Store(true)
	i.flow.revision.Add(1)
	ue.resolveDNSState.store.discard(ue)
	flowKey := NewUdpFlowKey(ue.poolKey.Src, ue.poolKey.Dst)
	shard := defaultQuicRejectMemory.shard(flowKey)
	shard.mu.Lock()
	delete(shard.flows, flowKey)
	shard.mu.Unlock()
	DefaultPacketSnifferSessionMgr.RemoveFlowFamilySessions(i.initial)
}

func (ue *UdpEndpoint) fillPinnedRecoveryRow(row *UDPReplyDroughtPeer) {
	if p := ue.pinnedTarget; p != nil {
		row.OriginalTarget = p.original.String()
		row.OriginalFamily = udpPinnedAddrFamily(p.original.Addr())
		row.ActualPeerFamily = udpPinnedAddrFamily(p.peer.Addr())
		row.TargetKind = "resolve_dns_native"
		if !p.native {
			row.TargetKind = "resolve_dns_fakeip"
		}
		row.DNSPinOwnerID = ue.resolveDNSState.id
		row.FlowIdentityRevision = p.flow.revision.Load()
	}
}

func (ue *UdpEndpoint) fillPinnedRecoveryEvent(event *UDPRecoveryEvent) {
	var row UDPReplyDroughtPeer
	ue.fillPinnedRecoveryRow(&row)
	event.OriginalTarget, event.TargetKind = row.OriginalTarget, row.TargetKind
	event.OriginalFamily, event.ActualPeerFamily = row.OriginalFamily, row.ActualPeerFamily
	event.DNSPinOwnerID, event.FlowIdentityRevision = row.DNSPinOwnerID, row.FlowIdentityRevision
	event.PinInherited = ue.pinnedTarget != nil && ue.rebuildRevision > 1
}

// Alias claims keep the client-visible address on the slot. Fill it for the
// archive without consulting the mapping table.
func (ue *UdpEndpoint) fillAliasRecoveryRow(row *UDPReplyDroughtPeer, peer netip.AddrPort) {
	if ue == nil || row == nil || ue.pinnedTarget != nil || row.TargetKind != "" {
		return
	}
	slot := ue.rebuildPeer(unmapPort(peer))
	if slot == nil {
		return
	}
	original, actual := unmapPort(slot.original), unmapPort(slot.peer)
	if !original.IsValid() || original == actual || original.Addr().Is4() == actual.Addr().Is4() {
		return
	}
	row.OriginalTarget = original.String()
	row.OriginalFamily = udpPinnedAddrFamily(original.Addr())
	row.ActualPeerFamily = udpPinnedAddrFamily(actual.Addr())
	row.TargetKind = "peer_alias"
}

func (ue *UdpEndpoint) fillAliasRecoveryEvent(event *UDPRecoveryEvent, peer netip.AddrPort) {
	if event == nil || event.TargetKind != "" {
		return
	}
	var row UDPReplyDroughtPeer
	ue.fillAliasRecoveryRow(&row, peer)
	event.OriginalTarget, event.TargetKind = row.OriginalTarget, row.TargetKind
	event.OriginalFamily, event.ActualPeerFamily = row.OriginalFamily, row.ActualPeerFamily
}

func udpPinnedAddrFamily(addr netip.Addr) string {
	if addr.Unmap().Is4() {
		return "ipv4"
	}
	if addr.Is6() {
		return "ipv6"
	}
	return ""
}

// Keep the large key/decision copies out of the usual ingress stack frame.
// Cold off/observe callers skip these helpers before constructing the key.
func (c *ControlPlane) checkPinnedDNSInitial(result *bpfRoutingResult, decision *UdpFlowDecision) bool {
	scope := udpEndpointRouteScope{}
	if c.udpRouteScopeSensitive {
		scope = newUdpEndpointRouteScope(result)
	}
	return DefaultUdpEndpointPool.checkPinnedRebuildInitial(decision.SymmetricNatEndpointKeyWithScope(scope), *decision)
}

func (p *UdpEndpointPool) checkPinnedDNSInitialUnscoped(decision *UdpFlowDecision) bool {
	return p.checkPinnedRebuildInitial(decision.SymmetricNatEndpointKey(), *decision)
}

// Initial checks precede retained/override/prefetch selection. Unknown Initial
// identity disables automatic execution but never destroys the live endpoint.
func (p *UdpEndpointPool) checkPinnedRebuildInitial(key UdpEndpointKey, decision UdpFlowDecision) bool {
	if !decision.IsQuicInitial || !p.hasPinnedDNSRebuild.Load() {
		return false
	}
	var ue *UdpEndpoint
	if slot, ok := p.rebuildOverride(key); ok {
		if owner := slot.owner.Load(); owner != nil {
			ue = owner.endpoint
		}
	} else {
		s := p.shardFor(key)
		s.mu.RLock()
		ue = s.pool[key]
		s.mu.RUnlock()
	}
	if ue == nil || ue.pinnedTarget == nil {
		return false
	}
	i := ue.pinnedTarget
	initial := decision.PacketSnifferKey()
	if !initial.HasCacheableDcid() || !i.initial.HasCacheableDcid() {
		i.flow.mu.Lock()
		i.flow.uncertain.Store(true)
		i.flow.revision.Add(1)
		i.flow.mu.Unlock()
		return false
	}
	if initial == i.initial {
		return false
	}
	for {
		ue.rebuildLifecycleMu.Lock()
		i.flow.mu.Lock()
		if i.flow.owner == ue || i.flow.revoked.Load() {
			break
		}
		// Publication may have completed since the initial pool lookup.
		current := i.flow.owner
		i.flow.mu.Unlock()
		ue.rebuildLifecycleMu.Unlock()
		ue = current
	}
	if i.flow.revoked.Load() {
		i.flow.mu.Unlock()
		ue.rebuildLifecycleMu.Unlock()
		return true
	}
	ue.revokePinnedDNSIdentityLocked()
	ue.dead.Store(true)
	i.flow.mu.Unlock()
	ue.rebuildLifecycleMu.Unlock()
	if slot, ok := p.rebuildOverride(key); ok {
		if owner := slot.owner.Load(); owner != nil && owner.endpoint == ue {
			p.rebuildOverrides.CompareAndDelete(key, slot)
		}
	}
	ue.selfRemoveFromPool()
	go func() { _ = ue.Close() }()
	return true
}
