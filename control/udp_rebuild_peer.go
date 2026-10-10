// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const udpRebuildFenceTimeout = 100 * time.Millisecond

type udpRebuildOwnership struct {
	endpoint *UdpEndpoint
	revision uint64
}
type udpRebuildPeerMap map[netip.AddrPort]*udpRebuildPeer

// One publication holds the real-peer table and, when the client-visible
// address differs, the alias table. A packet loads this pointer once.
type udpRebuildPeers struct {
	byPeer     udpRebuildPeerMap
	byOriginal udpRebuildPeerMap
}
type udpRebuildPeer struct {
	peer            netip.AddrPort
	original        netip.AddrPort
	lineageID       uint64
	manager         *SessionManager
	owner           atomic.Pointer[udpRebuildOwnership]
	record          atomic.Pointer[udpRebuildRecord]
	tombstoneUntil  atomic.Pointer[time.Time]
	mu              sync.Mutex
	fencing         bool
	fenceStarted    time.Time
	fenceTimedOut   bool
	active          int
	changed         chan struct{}
	freshReplies    uint64
	successorIntent bool
	// aliasStore is the inner mapping table captured before the successor is
	// dialed. It stays nil for native and resolve_dns claims. Commit and
	// ordinary inheritance compare this pointer; they do not read the cache.
	aliasStore atomic.Pointer[FakeIPStore]
}

func (s *udpRebuildPeer) signalLocked() {
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}
func (ue *UdpEndpoint) rebuildPeer(peer netip.AddrPort) *udpRebuildPeer {
	if ue == nil {
		return nil
	}
	tables := ue.rebuildPeers.Load()
	if tables == nil {
		return nil
	}
	return tables.byPeer[peer]
}

func (ue *UdpEndpoint) installRebuildPeer(peer netip.AddrPort, s *udpRebuildPeer) bool {
	original, index := rebuildOriginalKey(s)
	for {
		previous := ue.rebuildPeers.Load()
		var prevPeer, prevOriginal udpRebuildPeerMap
		if previous != nil {
			prevPeer, prevOriginal = previous.byPeer, previous.byOriginal
		}
		if prevPeer != nil {
			if existing := prevPeer[peer]; existing != nil && existing != s {
				return false
			}
			if prevPeer[peer] == nil && len(prevPeer) >= udpDroughtAssociationPeerLimit {
				return false
			}
		}
		if prevPeer != nil && prevPeer[peer] == s && originalIndexed(prevOriginal, original, index, s) {
			return true
		}
		nextPeer := make(udpRebuildPeerMap, len(prevPeer)+1)
		for k, v := range prevPeer {
			nextPeer[k] = v
		}
		nextPeer[peer] = s
		var nextOriginal udpRebuildPeerMap
		if index || len(prevOriginal) > 0 {
			nextOriginal = make(udpRebuildPeerMap, len(prevOriginal)+1)
			for k, v := range prevOriginal {
				if index && k == original && v != s {
					return false
				}
				nextOriginal[k] = v
			}
			if index {
				nextOriginal[original] = s
			}
		}
		if ue.rebuildPeers.CompareAndSwap(previous, &udpRebuildPeers{byPeer: nextPeer, byOriginal: nextOriginal}) {
			return true
		}
	}
}

func rebuildOriginalKey(s *udpRebuildPeer) (netip.AddrPort, bool) {
	if s == nil {
		return netip.AddrPort{}, false
	}
	original, peer := unmapPort(s.original), unmapPort(s.peer)
	if !original.IsValid() || original == peer {
		return netip.AddrPort{}, false
	}
	return original, true
}

func originalIndexed(tables udpRebuildPeerMap, original netip.AddrPort, index bool, s *udpRebuildPeer) bool {
	if !index {
		return true
	}
	return tables != nil && tables[original] == s
}

// A claim spans actual I/O. V1 deliberately excludes aggregators, whose
// Append completion does not release an actual-send claim.
func (s *udpRebuildPeer) claim(ctx context.Context, hasPayload bool) (*UdpEndpoint, error) {
	var deadline *time.Timer
	defer func() {
		if deadline != nil {
			deadline.Stop()
		}
	}()
	for {
		s.mu.Lock()
		if !s.fencing {
			owner := s.owner.Load()
			if owner == nil || owner.endpoint.dead.Load() {
				s.mu.Unlock()
				return nil, &udpEndpointWriteToleratedError{err: net.ErrClosed}
			}
			s.active++
			if hasPayload && owner.revision > 1 && !owner.endpoint.prepared.Load() {
				s.successorIntent = true
			}
			s.mu.Unlock()
			return owner.endpoint, nil
		}
		changed := s.changed
		s.mu.Unlock()
		if deadline == nil {
			deadline = time.NewTimer(udpRebuildFenceTimeout)
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, &udpEndpointWriteToleratedError{err: ctx.Err()}
		case <-deadline.C:
			s.mu.Lock()
			s.fenceTimedOut = true
			s.mu.Unlock()
			if l := s.manager.udpRebuild.Load(); l != nil {
				l.count("handoff_wait_timeout")
			}
			return nil, &udpEndpointWriteToleratedError{err: context.DeadlineExceeded}
		}
	}
}

func (s *udpRebuildPeer) release() {
	s.mu.Lock()
	s.active--
	if s.fencing {
		s.signalLocked()
	}
	s.mu.Unlock()
}

func (s *udpRebuildPeer) fence(ctx context.Context, old *UdpEndpoint) bool {
	timer := time.NewTimer(udpRebuildFenceTimeout)
	defer timer.Stop()
	s.mu.Lock()
	if s.fencing || s.owner.Load().endpoint != old {
		s.mu.Unlock()
		return false
	}
	s.fencing = true
	s.fenceStarted = time.Now()
	s.fenceTimedOut = false
	s.signalLocked()
	for s.active > 0 {
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			s.unfence()
			return false
		case <-timer.C:
			s.unfence()
			return false
		}
		s.mu.Lock()
	}
	s.mu.Unlock()
	return true
}
func (s *udpRebuildPeer) unfence() { s.mu.Lock(); s.fencing = false; s.signalLocked(); s.mu.Unlock() }

func (ue *UdpEndpoint) recordRebuildReply(peer netip.AddrPort) {
	s := ue.rebuildPeer(peer)
	if s == nil {
		return
	}
	s.mu.Lock()
	owner := s.owner.Load()
	if owner == nil || owner.endpoint != ue || ue.dead.Load() || ue.prepared.Load() || s.record.Load() == nil {
		late := s.record.Load() != nil && owner != nil && owner.endpoint != ue
		s.mu.Unlock()
		if late {
			if l := s.manager.udpRebuild.Load(); l != nil {
				l.count("late_reply")
			}
		}
		return
	}
	if owner.revision <= 1 || !s.successorIntent {
		s.mu.Unlock()
		return
	}
	if s.freshReplies >= udpRebuildRequiredReplies {
		s.mu.Unlock()
		return
	}
	s.freshReplies++
	recovered := s.manager.udpRebuild.Load().freshReply(s, s.freshReplies)
	s.mu.Unlock()
	if recovered && ue.sessionRuntime != nil {
		e := UDPRecoveryEvent{RuntimeID: ue.sessionRuntime.id, PolicyEpoch: uint64(ue.sessionRuntime.binding.Route.PolicyEpoch), LineageID: s.lineageID, Revision: owner.revision, ActualPeer: peer.String(), Kind: "recovered", Reason: "three_fresh_successor_replies", AtMS: time.Now().UnixMilli()}
		ue.fillPinnedRecoveryEvent(&e)
		ue.fillAliasRecoveryEvent(&e, peer)
		if ue.replyDrought != nil {
			e.Generation = ue.replyDrought.observer.generation
		}
		s.manager.udpRecoveryDiagnostics.Load().record(e)
	}
}

func (ue *UdpEndpoint) markDead() bool {
	ue.rebuildLifecycleMu.Lock()
	wasLive := !ue.dead.Swap(true)
	ue.rebuildLifecycleMu.Unlock()
	return wasLive
}
func (ue *UdpEndpoint) endRebuildOwnership() {
	peers := ue.rebuildPeers.Load()
	if peers == nil {
		return
	}
	for _, s := range peers.byPeer {
		s.mu.Lock()
		if owner := s.owner.Load(); owner != nil && owner.endpoint == ue {
			s.signalLocked()
		}
		s.mu.Unlock()
		if l := s.manager.udpRebuild.Load(); l != nil {
			l.endpointEnded(s, ue, time.Now())
		}
	}
}

func (ue *UdpEndpoint) detachedRebuildPeer(original netip.AddrPort) bool {
	s := ue.rebuildPeerForOriginal(original)
	return s != nil && s.record.Load() != nil && s.owner.Load().endpoint != ue
}

func (p *UdpEndpointPool) rebuildOverride(key UdpEndpointKey) (*udpRebuildPeer, bool) {
	if !p.hasRebuildOverrides.Load() {
		return nil, false
	}
	value, ok := p.rebuildOverrides.Load(key)
	if !ok {
		return nil, false
	}
	s := value.(*udpRebuildPeer)
	if expiry := s.tombstoneUntil.Load(); expiry != nil && !time.Now().Before(*expiry) {
		p.rebuildOverrides.CompareAndDelete(key, s)
		return nil, false
	}
	return s, true
}
func (p *UdpEndpointPool) rebuildLookup(key UdpEndpointKey) (*UdpEndpoint, bool) {
	s, ok := p.rebuildOverride(key)
	if !ok {
		return nil, false
	}
	owner := s.owner.Load()
	if owner == nil || owner.endpoint.IsDead() || owner.endpoint.prepared.Load() {
		return nil, true
	}
	return owner.endpoint, true
}

// Called under the target create lock on an ordinary error/NAT replacement.
// Keep the dedicated key and reply restriction, never fall back to the shared
// ancestor or reuse that ancestor's observation history.
func (p *UdpEndpointPool) rebindNormalRebuildOwner(key UdpEndpointKey, s *udpRebuildPeer, next *UdpEndpoint) bool {
	next.rebuildLifecycleMu.Lock()
	defer next.rebuildLifecycleMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.owner.Load()
	if s.fencing || s.active != 0 || next.dead.Load() || previous == nil || !previous.endpoint.dead.Load() {
		return false
	}
	if next.sessionRuntime == nil || next.Outbound == nil {
		return false
	}
	l := s.manager.udpRebuild.Load()
	r := s.record.Load()
	if l == nil || r == nil || next.Outbound.Name != r.key.group {
		return false
	}
	shard := p.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if existing := shard.pool[key]; existing != nil && existing != previous.endpoint {
		return false
	}
	unlockPin, reason := lockPinnedDNSTransfer(previous.endpoint, next)
	if reason != "" {
		return false
	}
	defer unlockPin()
	if !l.mu.TryLock() {
		return false
	}
	r.owners[next] = struct{}{}
	s.tombstoneUntil.Store(nil)
	r.endedAt = time.Time{}
	r.replies = 0
	r.state = "awaiting_replies"
	l.counts["ordinary_successor"]++
	transferPinnedDNSLocked(previous.endpoint, next)
	l.mu.Unlock()
	s.freshReplies = 0
	s.successorIntent = false
	next.prepared.Store(false)
	s.owner.Store(&udpRebuildOwnership{endpoint: next, revision: next.rebuildRevision})
	shard.poolLocked()[key] = next
	p.registerEndpoint(next)
	return true
}

func (ue *UdpEndpoint) releaseRebuiltTuplePair(src, dst netip.AddrPort) {
	forward := bpfTuplesKeyFromAddrPorts(src, dst, syscall.IPPROTO_UDP)
	reverse := bpfTuplesKeyFromAddrPorts(dst, src, syscall.IPPROTO_UDP)
	ue.udpConnStateMu.Lock()
	keys := make([]bpfTuplesKey, 0, 2)
	for _, key := range []bpfTuplesKey{forward, reverse} {
		if _, ok := ue.udpConnStateTuples[key]; ok {
			delete(ue.udpConnStateTuples, key)
			keys = append(keys, key)
		}
	}
	if last := ue.udpConnStateLastPair.Load(); last.matches(src, dst) {
		ue.udpConnStateLastPair.CompareAndSwap(last, nil)
	}
	owner := ue.udpConnStateOwner
	ue.udpConnStateMu.Unlock()
	if owner != nil && len(keys) > 0 {
		_ = owner.ReleaseUdpConnStateTuples(keys)
	}
	ue.routingMu.Lock()
	if ue.routingCacheDst == dst {
		ue.hasRoutingCache = false
	}
	ue.routingMu.Unlock()
}
