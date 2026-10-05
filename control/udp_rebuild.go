// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

const udpRebuildQueueLimit = 32

type udpRebuildCandidate struct {
	flow   *udpReplyDroughtFlow
	row    UDPReplyDroughtPeer
	queued time.Time
}
type udpRebuildCandidateKey struct {
	id   uint64
	peer string
}
type udpRebuildExecutor struct {
	plane    *ControlPlane
	observer *udpReplyDroughtObserver
	manager  *SessionManager
	ledger   *udpRebuildLedger
	ctx      context.Context
	cancel   context.CancelFunc
	closing  atomic.Bool
	once     sync.Once
	wg       sync.WaitGroup
	mu       sync.Mutex
	pending  map[udpRebuildCandidateKey]bool
	queue    chan udpRebuildCandidate
	now      func() time.Time
}

func (o *udpReplyDroughtObserver) bindExecution(c *ControlPlane, m *SessionManager) {
	if o == nil || !o.policy.Enforce {
		return
	}
	o.executionMu.Lock()
	defer o.executionMu.Unlock()
	if o.closed.Load() || m == nil || m.closed.Load() {
		return
	}
	if previous := o.execution.Load(); previous != nil && !previous.closing.Load() {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	x := &udpRebuildExecutor{plane: c, observer: o, manager: m, ledger: m.rebuildLedger(), ctx: ctx, cancel: cancel, queue: make(chan udpRebuildCandidate, udpRebuildQueueLimit), pending: make(map[udpRebuildCandidateKey]bool), now: time.Now}
	o.execution.Store(x)
	for i := 0; i < 2; i++ {
		x.wg.Add(1)
		go x.work()
	}
}
func (o *udpReplyDroughtObserver) stopExecution() {
	if o == nil {
		return
	}
	o.executionMu.Lock()
	defer o.executionMu.Unlock()
	x := o.execution.Load()
	if x != nil {
		x.Close()
	}
}
func (x *udpRebuildExecutor) Close() {
	x.once.Do(func() {
		x.closing.Store(true)
		x.cancel()
		x.wg.Wait()
		x.mu.Lock()
		defer x.mu.Unlock()
		x.pending = nil
		for {
			select {
			case <-x.queue:
				x.ledger.count("cancelled_queued")
			default:
				return
			}
		}
	})
}
func (x *udpRebuildExecutor) enqueue(f *udpReplyDroughtFlow, row UDPReplyDroughtPeer, now time.Time) {
	if x.closing.Load() || row.RuntimeID == 0 {
		return
	}
	key := udpRebuildCandidateKey{row.RuntimeID, row.Peer}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closing.Load() {
		return
	}
	if x.pending[key] {
		return
	}
	select {
	case x.queue <- udpRebuildCandidate{flow: f, row: row, queued: now}:
		x.pending[key] = true
	default:
		x.ledger.count("queue_full")
	}
}
func (x *udpRebuildExecutor) work() {
	defer x.wg.Done()
	for {
		select {
		case <-x.ctx.Done():
			return
		case candidate := <-x.queue:
			x.execute(candidate)
			x.mu.Lock()
			delete(x.pending, udpRebuildCandidateKey{candidate.row.RuntimeID, candidate.row.Peer})
			x.mu.Unlock()
		}
	}
}
func (x *udpRebuildExecutor) event(kind, reason string, row *UDPReplyDroughtPeer, successor ...*UdpEndpoint) {
	e := UDPRecoveryEvent{Kind: kind, Reason: reason, AtMS: x.now().UnixMilli(), Peer: row, RuntimeID: row.RuntimeID, LineageID: row.LineageID, Revision: row.Revision, ActualPeer: row.Peer}
	e.OriginalTarget, e.TargetKind = row.OriginalTarget, row.TargetKind
	e.DNSPinOwnerID, e.FlowIdentityRevision = row.DNSPinOwnerID, row.FlowIdentityRevision
	if len(successor) > 0 {
		e.SuccessorRuntimeID = successor[0].sessionRuntime.id
		e.Revision = successor[0].rebuildRevision
		successor[0].fillPinnedRecoveryEvent(&e)
	}
	x.observer.recordDiagnostic(e)
}
func (x *udpRebuildExecutor) exclusion(ue *UdpEndpoint, peer netip.AddrPort) string {
	if ue == nil || ue.dead.Load() || ue.prepared.Load() || ue.sessionRuntime == nil || ue.sessionRuntime.binding.Route.PolicyEpoch != x.plane.PolicyEpoch() {
		return "owner_changed"
	}
	if ue.replyDrought == nil || ue.replyDrought.observer != x.observer || ue.replyDrought.closed.Load() {
		return "observer_changed"
	}
	if !isProxyBackedDialer(ue.Dialer) || ue.endpointNetworkType.IsDns || ue.Outbound == nil {
		return "not_proxy_data"
	}
	if ue.resolveDNSState != nil {
		if reason := ue.pinnedDNSExclusion(peer); reason != "" {
			return reason
		}
	} else if ue.SniffedDomain != "" || udpRebuildPeerUsesAlias(ue, peer) {
		return "peer_alias_unsupported"
	}
	if _, err := netip.ParseAddrPort(ue.DialTarget); err != nil {
		return "target_unresolved"
	}
	if ue.writeBatch != nil {
		return "batch_fence_unsupported"
	}
	caps := netproxy.RecoveryCapabilities(ue.conn)
	if !caps.LocalWriteCompleted || !caps.IndependentAssociation || !caps.ApplicationPeer {
		return "transport_capability_missing"
	}
	if !ue.poolKey.Dst.IsValid() && !caps.AddressedWrites {
		return "shared_target_bound"
	}
	return ""
}

// A writable mapping store is attached to native flows too. Reject aliases
// for this peer without disabling recovery of an independent native peer on
// the same shared association.
func udpRebuildPeerUsesAlias(ue *UdpEndpoint, peer netip.AddrPort) bool {
	client := ue.poolKey.Src.Addr().Unmap()
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if !client.IsValid() || !validDroughtPeer(peer) || client.Is4() != peer.Addr().Is4() || (ue.poolKey.Dst.IsValid() && ue.poolKey.Dst != peer) {
		return true
	}
	if slot := ue.rebuildPeer(peer); slot != nil && netip.AddrPortFrom(slot.original.Addr().Unmap(), slot.original.Port()) != peer {
		return true
	}
	if ue.crossFamily == nil {
		return false
	}
	s := ue.crossFamily.store
	if s == nil || !s.Ready() || s.Contains(peer.Addr()) {
		return true
	}
	if target, err := netip.ParseAddrPort(ue.DialTarget); err == nil && s.Contains(target.Addr().Unmap()) {
		return true
	}
	return false
}
func (x *udpRebuildExecutor) evidenceLocked(q udpRebuildCandidate, peer netip.AddrPort) bool {
	f := q.flow
	if f.endpoint != nil {
		if target := f.endpoint.pinnedTarget; target != nil && (target.flow.revoked.Load() || target.flow.uncertain.Load() || q.row.FlowIdentityRevision != target.flow.revision.Load() || q.row.DNSPinOwnerID != f.endpoint.resolveDNSState.id) {
			return false
		}
	}
	p := f.peers[peer]
	identity := f.identity.Load()
	return !f.closed.Load() && !x.observer.closed.Load() && identity != nil && identity.RuntimeID == q.row.RuntimeID && p != nil && p.replies == q.row.Replies && p.invalidatedAt/int64(time.Millisecond) == q.row.InvalidatedAtMS && f.eligibility(p, x.observer.stamp(x.now())) == "candidate"
}
func (x *udpRebuildExecutor) execute(q udpRebuildCandidate) {
	if x.closing.Load() || x.ctx.Err() != nil {
		return
	}
	if activeControlPlanePublication.plane.Load() != x.plane {
		x.ledger.count("generation_unpublished")
		return
	}
	ue := q.flow.endpoint
	peer, err := netip.ParseAddrPort(q.row.Peer)
	if err != nil || x.now().Sub(q.queued) > udpRebuildTicketTTL {
		x.ledger.count("candidate_expired")
		return
	}
	if reason := x.exclusion(ue, peer); reason != "" {
		x.ledger.count(reason)
		x.event("excluded", reason, &q.row)
		return
	}
	q.flow.mu.Lock()
	valid := x.evidenceLocked(q, peer)
	q.flow.mu.Unlock()
	if !valid {
		x.ledger.count("evidence_changed")
		return
	}
	slot := ue.rebuildPeer(peer)
	if slot == nil || slot.owner.Load().endpoint != ue {
		x.ledger.count("owner_changed")
		return
	}
	key := udpRebuildKey{src: ue.poolKey.Src, original: slot.original, peer: peer, group: q.row.Group}
	ticket, reason := x.ledger.reserve(key, slot, ue, x.now())
	if ticket == nil {
		x.ledger.count(reason)
		x.event("deferred", reason, &q.row)
		return
	}
	defer func() { x.ledger.finish(ticket, "") }()
	x.event("reserved", "", &q.row)
	if x.closing.Load() || x.ctx.Err() != nil || !x.ledger.start(ticket, x.now()) {
		x.ledger.count("cancelled_before_dial")
		return
	}
	x.event("attempt_started", "", &q.row)
	ctx, cancel := context.WithTimeout(x.ctx, 2*time.Second)
	defer cancel()
	next, prepareErr := x.prepare(ctx, ue, peer)
	if prepareErr != nil {
		reason := "prepare_failed"
		if x.closing.Load() || x.ctx.Err() != nil {
			reason = "prepare_cancelled"
		}
		x.ledger.count(reason)
		x.event("cancelled", reason, &q.row)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = next.Close()
		}
	}()
	if !slot.fence(ctx, ue) {
		x.ledger.count("fence_cancelled")
		x.event("cancelled", "fence_cancelled", &q.row)
		return
	}
	defer slot.unfence()
	x.event("fencing", "", &q.row)
	if reason = x.commit(ctx, q, slot, ticket, ue, next); reason != "" {
		x.ledger.count(reason)
		x.event("cancelled", reason, &q.row)
		return
	}
	committed = true
	slot.unfence()
	x.event("committed", "", &q.row, next)
	ue.releaseRebuiltTuplePair(ue.poolKey.Src, slot.original)
	if ue.poolKey.Dst.IsValid() {
		ue.markDead()
		// Committed cleanup belongs to the established session lifecycle. A
		// slow old reply sender must not delay reload's speculative-work drain.
		go func() { _ = ue.Close() }()
	}
}

func (x *udpRebuildExecutor) prepare(ctx context.Context, old *UdpEndpoint, peer netip.AddrPort) (*UdpEndpoint, error) {
	binding := old.sessionRuntime.binding
	var runtime *egressRuntime
	if old.sessionRuntime.egressLease != nil {
		runtime = old.sessionRuntime.egressLease.runtime
	}
	lease, group, ok := runtime.acquireEgress(binding.Egress.Dialer, binding.Egress.Outbound, binding.Egress.SelectPath)
	if !ok {
		return nil, ErrSessionManagerClosed
	}
	defer lease.release()
	target := peer.String()
	original := old.rebuildOriginal(peer)
	conn, err := group.DialContextWithSelected(netproxy.ContextWithUDPReplyAddr(ctx, target, original), binding.Egress.Dialer, binding.Egress.Network, target)
	if err != nil {
		return nil, err
	}
	pc, ok := conn.(netproxy.PacketConn)
	if !ok {
		_ = conn.Close()
		return nil, errUdpEndpointAdmissionClosed
	}
	caps := netproxy.RecoveryCapabilities(pc)
	if !caps.LocalWriteCompleted || !caps.IndependentAssociation || !caps.ApplicationPeer {
		_ = conn.Close()
		return nil, errUdpEndpointAdmissionClosed
	}
	binding.Egress.Target = target
	key := old.poolKey
	key.Dst = original
	dialOption := &DialOption{Dialer: binding.Egress.Dialer, Outbound: group, Target: target, Network: binding.Egress.Network, NetworkType: &binding.Egress.NetworkType, Binding: binding, IsDialIp: true}
	if old.pinnedTarget != nil {
		dialOption.ResolveDNSPinned = true
		dialOption.ResolveDNSInitial = old.resolveDNSState.initial
		dialOption.ResolveDNSOriginalNative = old.pinnedTarget.native
		dialOption.SniffedDomain = old.SniffedDomain
		dialOption.StickySite = binding.Egress.StickySite
	}
	options := &UdpEndpointOptions{Handler: old.handler, NatTimeout: old.natTimeout(), Log: old.log, ConnStateOwner: old.udpConnStateOwner, replyDrought: x.observer, crossFamily: old.crossFamily}
	next := newUDPEndpointFromConn(old.poolRef, key, options, dialOption, pc)
	next.prepared.Store(true)
	if old.pinnedTarget != nil {
		copy := *old.pinnedTarget
		next.pinnedTarget = &copy
		next.resolveDNSState.phase.Store(udpDNSPinPrepared)
		next.resolveDNSState.store = old.resolveDNSState.store
		if old.identifiedQuic() {
			next.markIdentifiedQuic()
		}
	}
	next.rebuildLineage = old.rebuildLineage
	next.rebuildRevision = old.rebuildPeer(peer).owner.Load().revision + 1
	if next.writeBatch != nil {
		_ = next.Close()
		return nil, errUdpEndpointAdmissionClosed
	}
	if _, err = x.manager.adoptUDP(next, binding, runtime); err != nil {
		_ = next.Close()
		return nil, err
	}
	next.dialerGenerationRef = old.dialerGenerationRef
	next.dialerGeneration = old.dialerGeneration
	next.RefreshTtl()
	if !next.startTransportReceiver() {
		go next.startReadLoop()
	}
	return next, nil
}

func (x *udpRebuildExecutor) commit(ctx context.Context, q udpRebuildCandidate, slot *udpRebuildPeer, ticket *udpRebuildTicket, old, next *UdpEndpoint) string {
	// Acquire references before dropping the old pair. Cancellation closes next
	// and releases these references, never deleting the old owner's tuples.
	next.TrackUdpConnStateTuplePair(old.poolKey.Src, slot.original)
	if !activeControlPlanePublication.mu.TryRLock() {
		return "publication_busy"
	}
	defer activeControlPlanePublication.mu.RUnlock()
	if x.closing.Load() || x.manager.closed.Load() || ctx.Err() != nil || x.observer.closed.Load() || activeControlPlanePublication.plane.Load() != x.plane {
		return "generation_changed"
	}
	if !old.rebuildLifecycleMu.TryLock() {
		return "owner_busy"
	}
	defer old.rebuildLifecycleMu.Unlock()
	if !next.rebuildLifecycleMu.TryLock() {
		return "owner_busy"
	}
	defer next.rebuildLifecycleMu.Unlock()
	if !slot.mu.TryLock() {
		return "peer_busy"
	}
	defer slot.mu.Unlock()
	if old.dead.Load() || next.dead.Load() || !slot.fencing || slot.active != 0 || slot.owner.Load().endpoint != old {
		return "owner_changed"
	}
	if !q.flow.mu.TryLock() {
		return "evidence_busy"
	}
	defer q.flow.mu.Unlock()
	if !x.evidenceLocked(q, slot.peer) {
		return "evidence_changed"
	}
	p := old.poolRef
	a, b := p.shardFor(old.poolKey), p.shardFor(next.poolKey)
	// Ordered create locks are nonblocking; a normal dial must not extend the
	// fence or publication lease. Address order follows the pool shard index.
	i, j := hashUdpEndpointKey(old.poolKey)&uint64(udpEndpointCreateShardCount-1), hashUdpEndpointKey(next.poolKey)&uint64(udpEndpointCreateShardCount-1)
	first, second := a, b
	if i > j {
		first, second = b, a
	}
	if !first.createMu.TryLock() {
		return "pool_busy"
	}
	defer first.createMu.Unlock()
	if second != first {
		if !second.createMu.TryLock() {
			return "pool_busy"
		}
		defer second.createMu.Unlock()
	}
	if !first.mu.TryLock() {
		return "pool_busy"
	}
	defer first.mu.Unlock()
	if second != first {
		if !second.mu.TryLock() {
			return "pool_busy"
		}
		defer second.mu.Unlock()
	}
	if a.pool[old.poolKey] != old {
		return "owner_changed"
	}
	if existing := b.pool[next.poolKey]; existing != nil && existing != old {
		return "target_slot_occupied"
	}
	if !next.installRebuildPeer(slot.peer, slot) {
		return "peer_capacity"
	}
	if slot.fenceTimedOut || time.Since(slot.fenceStarted) >= udpRebuildFenceTimeout || ctx.Err() != nil {
		return "fence_expired"
	}
	unlockPin, reason := lockPinnedDNSTransfer(old, next)
	if reason != "" {
		return reason
	}
	defer unlockPin()
	if !x.ledger.mu.TryLock() {
		return "ledger_busy"
	}
	defer x.ledger.mu.Unlock()
	if old.pinnedTarget != nil && old.pinnedTarget.flow.uncertain.Load() {
		return "resolve_dns_identity_uncertain"
	}
	if slot.fenceTimedOut || time.Since(slot.fenceStarted) >= udpRebuildFenceTimeout || ctx.Err() != nil {
		return "fence_expired"
	}
	if !x.ledger.commitLocked(ticket, next, x.now()) {
		return "ticket_expired"
	}
	transferPinnedDNSLocked(old, next)
	slot.freshReplies = 0
	slot.successorIntent = false
	next.prepared.Store(false)
	slot.owner.Store(&udpRebuildOwnership{endpoint: next, revision: next.rebuildRevision})
	p.rebuildOverrides.Store(next.poolKey, slot)
	p.hasRebuildOverrides.Store(true)
	b.pool[next.poolKey] = next
	p.registerEndpoint(next)
	return ""
}
