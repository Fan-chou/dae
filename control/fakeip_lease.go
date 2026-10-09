// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"sync/atomic"
)

// A rebuilt DNS FakeIP association may outlive the DNS activity that keeps its
// mapping fresh. Leases pin the tombstone in memory only: retirement still
// happens, but a leased address is never released and therefore never handed
// to another name. Leases are not persisted; a restart ends every flow.
const fakeIPLeaseHardLimit = 1024

var (
	errFakeIPLeaseMappingChanged = errors.New("fakeip mapping changed")
	errFakeIPLeaseFull           = errors.New("fakeip lease table full")
)

type fakeIPLease struct {
	store    *FakeIPStore
	epoch    uint64
	id       fakeIPInternID
	released atomic.Bool
}

func (s *FakeIPStore) leaseLimitLocked() int {
	return min(s.maxLive, fakeIPLeaseHardLimit)
}

// AcquireLease confirms that addr still belongs to name and protects that
// record from tombstone release. A retired record is acceptable: its
// tombstone still maps addr back to name.
func (s *FakeIPStore) AcquireLease(addr netip.Addr, name string) (*fakeIPLease, error) {
	name = canonicalizeFakeIPQname(name)
	if s == nil || s.stableAliases || !addr.IsValid() || name == "" {
		return nil, errFakeIPNotReady
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready || s.closed {
		return nil, errFakeIPNotReady
	}
	id, ok := s.lookBackLocked(addr)
	if !ok || int(id) >= len(s.records) || s.records[id].qname != name {
		return nil, errFakeIPLeaseMappingChanged
	}
	if s.leaseCount >= s.leaseLimitLocked() {
		return nil, errFakeIPLeaseFull
	}
	if s.leases == nil {
		s.leases = make(map[fakeIPInternID]int)
	}
	s.leases[id]++
	s.leaseCount++
	return &fakeIPLease{store: s, epoch: s.epoch, id: id}, nil
}

// Valid reports whether the lease still protects the same in-memory table.
func (l *fakeIPLease) Valid() bool {
	if l == nil || l.released.Load() {
		return false
	}
	s := l.store
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready && !s.closed && s.epoch == l.epoch
}

// Release is idempotent. A lease from before a reset never touches the new
// table. A record whose count drops to zero follows the normal expiry rules.
func (l *fakeIPLease) Release() {
	if l == nil || !l.released.CompareAndSwap(false, true) {
		return
	}
	s := l.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch != l.epoch {
		return
	}
	if n := s.leases[l.id]; n > 1 {
		s.leases[l.id] = n - 1
	} else if n == 1 {
		delete(s.leases, l.id)
	}
	if s.leaseCount > 0 {
		s.leaseCount--
	}
}

func (s *FakeIPStore) leasedLocked(i int) bool {
	return s.leases[fakeIPInternID(i)] > 0
}

// LeaseStats reports active lease handles, tombstones retained only because
// they are leased, and the lease limit.
func (s *FakeIPStore) LeaseStats() (leases, retainedTombstones, limit int) {
	if s == nil {
		return 0, 0, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id := range s.leases {
		if int(id) < len(s.records) && s.records[id].retired {
			retainedTombstones++
		}
	}
	return s.leaseCount, retainedTombstones, s.leaseLimitLocked()
}
