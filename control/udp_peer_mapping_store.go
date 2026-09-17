package control

import (
	"fmt"
	"net/netip"
	"time"
)

// peerMapping allocates only the address family the client can use. Unlike DNS
// leases, peer identities remain usable after a pool expansion or replacement.
// Never recycle an alias: clients may still have it cached after a UDP timeout.
func (s *FakeIPStore) peerMapping(peer netip.Addr, allocate bool) (netip.Addr, error) {
	peer = peer.Unmap()
	name := canonicalizeFakeIPQname(peer.String())
	s.mu.Lock()
	if !s.stableAliases || !s.ready || s.closed || s.active == nil {
		s.mu.Unlock()
		return netip.Addr{}, errFakeIPNotReady
	}
	if id, ok := s.names[name]; ok && int(id) < len(s.records) {
		rec := s.records[id]
		alias := rec.ipv4
		if peer.Is4() {
			alias = rec.ipv6
		}
		if alias.IsValid() {
			seq := rec.seq
			s.mu.Unlock()
			if err := s.WaitDurable(seq); err != nil {
				return netip.Addr{}, err
			}
			return alias, nil
		}
	}
	if !allocate {
		s.mu.Unlock()
		return netip.Addr{}, fmt.Errorf("new UDP cross-family peer mappings are disabled")
	}
	if _, err := s.evictIfNeededLocked(); err != nil {
		s.mu.Unlock()
		return netip.Addr{}, err
	}
	alias, err := s.allocateLocked(name, !peer.Is4())
	if err != nil {
		s.mu.Unlock()
		return netip.Addr{}, fmt.Errorf("UDP peer mapping capacity exhausted; expand the mapping pool without deleting existing mappings: %w", err)
	}
	rec := fakeIPRecord{qname: name, origin4: s.active.inet4, origin6: s.active.inet6, updatedUnix: time.Now().Unix(), seq: s.seq + 1}
	if peer.Is4() {
		rec.ipv6 = alias
	} else {
		rec.ipv4 = alias
	}
	if err := s.appendWalLocked(rec); err != nil {
		s.mu.Unlock()
		return netip.Addr{}, err
	}
	s.seq = rec.seq
	id := s.internLocked(name)
	s.records[id] = rec
	s.active.forward[name] = id
	s.indexReverseLocked(id, rec)
	s.markUsedLocked(s.active, id, rec)
	s.mu.Unlock()
	if err := s.WaitDurable(rec.seq); err != nil {
		return netip.Addr{}, err
	}
	return alias, nil
}
