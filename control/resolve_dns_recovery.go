package control

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const resolveDNSRecoveryLimit = 4096
const resolveDNSRecoveryTTL = 30 * time.Second

var resolveDNSRecoverySequence atomic.Uint64

type udpResolveDNSState struct {
	initial PacketSnifferKey
	store   *resolveDNSRecoveryStore
	once    sync.Once
	id      uint64
	phase   atomic.Uint32
	// fakeLease protects a DNS FakeIP original for this endpoint's lifetime.
	fakeLease atomic.Pointer[fakeIPLease]
}

type resolveDNSRecovery struct {
	target  netip.AddrPort
	domain  string
	route   UdpRouteBinding
	initial PacketSnifferKey
	expires time.Time
	owner   uint64
}

// Only retired flows occupy this bounded process-owned map. Live endpoints
// hold their immutable target directly; DNS cache eviction cannot alter it.
type resolveDNSRecoveryStore struct {
	mu      sync.Mutex
	entries map[UdpEndpointKey]resolveDNSRecovery
}

func (s *resolveDNSRecoveryStore) lookup(key UdpEndpointKey, initial PacketSnifferKey, isInitial bool) (resolveDNSRecovery, bool) {
	if s == nil {
		return resolveDNSRecovery{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.entries[key]
	if !ok {
		return r, false
	}
	if time.Now().After(r.expires) || (isInitial && (!initial.HasCacheableDcid() || !r.initial.HasCacheableDcid() || initial != r.initial)) {
		delete(s.entries, key)
		return resolveDNSRecovery{}, false
	}
	return r, true
}
func (s *resolveDNSRecoveryStore) save(ue *UdpEndpoint) {
	if s == nil || ue == nil || ue.resolveDNSState == nil || !ue.poolKey.Dst.IsValid() || !isProxyBackedDialer(ue.Dialer) || (!ue.hasSent.Load() && !ue.hasReply.Load()) {
		return
	}
	target, err := netip.ParseAddrPort(ue.DialTarget)
	if err != nil {
		return
	}
	ue.resolveDNSState.once.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if ue.resolveDNSState.phase.Load() != udpDNSPinCurrent {
			return
		}
		if old, ok := s.entries[ue.poolKey]; ok && old.owner > ue.resolveDNSState.id {
			return
		}
		if s.entries == nil {
			s.entries = make(map[UdpEndpointKey]resolveDNSRecovery)
		}
		if len(s.entries) >= resolveDNSRecoveryLimit {
			var oldestKey UdpEndpointKey
			var oldest time.Time
			for k, r := range s.entries {
				if time.Now().After(r.expires) {
					delete(s.entries, k)
					continue
				}
				if oldest.IsZero() || r.expires.Before(oldest) {
					oldestKey, oldest = k, r.expires
				}
			}
			if len(s.entries) >= resolveDNSRecoveryLimit {
				delete(s.entries, oldestKey)
			}
		}
		s.entries[ue.poolKey] = resolveDNSRecovery{target: target, domain: strings.ToLower(strings.TrimSuffix(ue.SniffedDomain, ".")), route: ue.flowRouteBinding, initial: ue.resolveDNSState.initial, expires: time.Now().Add(resolveDNSRecoveryTTL), owner: ue.resolveDNSState.id}
	})
}
func (s *resolveDNSRecoveryStore) discard(ue *UdpEndpoint) {
	if ue == nil || ue.resolveDNSState == nil {
		return
	}
	// Prepared owners have no cache authority. Their Close first marks them
	// dead under the lifecycle mutex, so they cannot race successful publication.
	if ue.resolveDNSState.phase.CompareAndSwap(udpDNSPinPrepared, udpDNSPinClosed) {
		return
	}
	if ue.resolveDNSState.phase.Load() != udpDNSPinCurrent {
		return
	}
	if s == nil {
		ue.resolveDNSState.phase.CompareAndSwap(udpDNSPinCurrent, udpDNSPinClosed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ue.resolveDNSState.phase.CompareAndSwap(udpDNSPinCurrent, udpDNSPinClosed) {
		return
	}
	if r, ok := s.entries[ue.poolKey]; ok && r.owner <= ue.resolveDNSState.id {
		delete(s.entries, ue.poolKey)
	}
}
func (c *ControlPlane) inheritResolveDNSTarget(p *proxyDialParam, res *proxyDialResult) bool {
	r := p.ResolveDNSRecovery
	if r == nil || !r.target.IsValid() || p.Network != "udp" || res.Dialer == nil || !isProxyBackedDialer(res.Dialer) {
		return false
	}
	if time.Now().After(r.expires) || r.route.PolicyEpoch != c.PolicyEpoch() || r.route.Outbound != res.OutboundIndex || r.route.Mark != res.Mark || r.route.Must != res.Must || r.domain != strings.ToLower(strings.TrimSuffix(res.SniffedDomain, ".")) {
		return false
	}
	c.pinProxyResolveDNSTarget(res, r.target.Addr(), r.target.Port())
	res.ResolveDNSPinned = true
	res.ResolveDNSRestored = true
	return true
}

// Immediate retries carry the target directly, independently of bounded store
// admission. This snapshot never keeps the old connection alive.
func (ue *UdpEndpoint) resolveDNSTargetForRetry(decision ...UdpFlowDecision) *resolveDNSRecovery {
	if ue == nil || ue.resolveDNSState == nil || ue.resolveDNSState.phase.Load() != udpDNSPinCurrent || !ue.poolKey.Dst.IsValid() || !isProxyBackedDialer(ue.Dialer) || (!ue.hasSent.Load() && !ue.hasReply.Load()) {
		return nil
	}
	if len(decision) > 0 && decision[0].IsQuicInitial {
		initial := decision[0].PacketSnifferKey()
		if !initial.HasCacheableDcid() || !ue.resolveDNSState.initial.HasCacheableDcid() || initial != ue.resolveDNSState.initial {
			return nil
		}
	}
	target, err := netip.ParseAddrPort(ue.DialTarget)
	if err != nil {
		return nil
	}
	return &resolveDNSRecovery{target: target, domain: strings.ToLower(strings.TrimSuffix(ue.SniffedDomain, ".")), route: ue.flowRouteBinding, initial: ue.resolveDNSState.initial, expires: time.Now().Add(resolveDNSRecoveryTTL), owner: ue.resolveDNSState.id}
}
