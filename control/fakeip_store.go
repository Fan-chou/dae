/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daeuniverse/dae/config"
	"golang.org/x/sys/unix"
)

const (
	fakeIPSnapshotMagic      = "KDAEFAK1"
	fakeIPStoreVersionV1     = 1
	fakeIPStoreVersionV2     = 2
	fakeIPStoreVersion       = 3
	fakeIPWalAlloc           = uint8(1)
	fakeIPWalAllocV2         = uint8(2)
	fakeIPRecordRetired      = uint8(1)
	fakeIPFileMode           = 0o600
	fakeIPDirMode            = 0o700
	fakeIPSnapshotName       = "mapping.bin"
	fakeIPWalName            = "mapping.wal"
	fakeIPWalCompactMinBytes = 64 << 10
)

var (
	fakeIPDefaultInet4   = netip.MustParsePrefix("198.18.0.0/15")
	fakeIPDefaultInet6   = netip.MustParsePrefix("fd00:daee::/96")
	fakeIPTombstoneGrace = 24 * time.Hour
	fakeIPFdatasync      = unix.Fdatasync
	fakeIPWalWriteHook   func([]byte) error
	errFakeIPNotDurable  = errors.New("fakeip wal sync failed")
)

var (
	errFakeIPStoreClosed = errors.New("fakeip store is closed")
	errFakeIPNotReady    = errors.New("fakeip store is not ready")
)

type fakeIPInternID uint32

type fakeIPRecord struct {
	qname       string
	ipv4        netip.Addr
	ipv6        netip.Addr
	origin4     netip.Prefix
	origin6     netip.Prefix
	updatedUnix int64
	retiredUnix int64
	seq         uint64
	retired     bool
}

type fakeIPGeneration struct {
	inet4   netip.Prefix
	inet6   netip.Prefix
	forward map[string]fakeIPInternID
	v4      map[uint32]fakeIPInternID
	v6      map[uint32]fakeIPInternID
	usedV4  map[uint32]struct{}
	usedV6  map[uint32]struct{}
}

func newFakeIPGeneration(inet4, inet6 netip.Prefix) *fakeIPGeneration {
	return &fakeIPGeneration{
		inet4:   inet4,
		inet6:   inet6,
		forward: make(map[string]fakeIPInternID),
		v4:      make(map[uint32]fakeIPInternID),
		v6:      make(map[uint32]fakeIPInternID),
		usedV4:  make(map[uint32]struct{}),
		usedV6:  make(map[uint32]struct{}),
	}
}

// FakeIPStore is process-owned mapping state. ControlPlane generations share
// one store and only swap FakeIPPolicy.
type FakeIPStore struct {
	dir string

	mu       sync.RWMutex
	ready    bool
	closed   bool
	active   *fakeIPGeneration
	retired  []*fakeIPGeneration
	records  []fakeIPRecord
	intern   []string
	names    map[string]fakeIPInternID
	rev4     map[uint32]fakeIPInternID
	rev6     map[[16]byte]fakeIPInternID
	seq      uint64
	durable  uint64
	syncErr  error
	wal      *os.File
	waiters  map[uint64][]chan struct{}
	maxLive  int
	maxBytes int
	diskOK   bool
	loadWarn error
}

func NewFakeIPStore(dir string, maxEntries int) *FakeIPStore {
	if maxEntries <= 0 {
		maxEntries = config.FakeIPDefaultMaxEntries
	}
	if maxEntries > config.FakeIPHardMaxEntries {
		maxEntries = config.FakeIPHardMaxEntries
	}
	return &FakeIPStore{
		dir:      dir,
		names:    make(map[string]fakeIPInternID),
		rev4:     make(map[uint32]fakeIPInternID),
		rev6:     make(map[[16]byte]fakeIPInternID),
		waiters:  make(map[uint64][]chan struct{}),
		maxLive:  maxEntries,
		maxBytes: max(2<<20, 64+maxEntries*256),
	}
}

func FakeIPStorePath(configDir, configured string) string {
	rel := configured
	if rel == "" {
		rel = config.FakeIPDefaultPath
	}
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(configDir, rel)
}

func (s *FakeIPStore) Open(inet4, inet6 netip.Prefix) error {
	if s == nil {
		return errFakeIPStoreClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errFakeIPStoreClosed
	}
	if err := os.MkdirAll(s.dir, fakeIPDirMode); err != nil {
		return fmt.Errorf("create fakeip dir: %w", err)
	}
	if err := os.Chmod(s.dir, fakeIPDirMode); err != nil {
		return fmt.Errorf("protect fakeip dir: %w", err)
	}
	s.resetMemoryLocked(inet4, inet6)
	loadErr := s.loadLocked()
	s.loadWarn = nil
	if loadErr != nil {
		s.quarantineDiskLocked()
		s.resetMemoryLocked(inet4, inet6)
		s.loadWarn = fmt.Errorf("fakeip store load failed; quarantined as *.corrupt-* under %s and reset: %w", s.dir, loadErr)
	}
	if err := s.openWalLocked(); err != nil {
		return err
	}
	_, snapErr := os.Stat(filepath.Join(s.dir, fakeIPSnapshotName))
	s.diskOK = loadErr == nil || os.IsNotExist(snapErr)
	s.ready = true
	return nil
}

func (s *FakeIPStore) resetMemoryLocked(inet4, inet6 netip.Prefix) {
	s.active = newFakeIPGeneration(inet4, inet6)
	s.retired = nil
	s.records = nil
	s.intern = nil
	s.names = make(map[string]fakeIPInternID)
	s.rev4 = make(map[uint32]fakeIPInternID)
	s.rev6 = make(map[[16]byte]fakeIPInternID)
	s.seq = 0
	s.durable = 0
	s.syncErr = nil
}

func (s *FakeIPStore) quarantineDiskLocked() {
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	for _, name := range []string{fakeIPSnapshotName, fakeIPWalName} {
		src := filepath.Join(s.dir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		_ = os.Rename(src, src+".corrupt-"+ts)
	}
}

func (s *FakeIPStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.ready = false
	if s.wal != nil {
		_ = s.flushSnapshotLocked()
		err := s.wal.Close()
		s.wal = nil
		return err
	}
	return nil
}

func (s *FakeIPStore) Ready() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready && !s.closed
}

func (s *FakeIPStore) LoadWarning() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadWarn
}

func (s *FakeIPStore) Prefixes() (active []netip.Prefix, retired []netip.Prefix) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active != nil {
		active = []netip.Prefix{s.active.inet4, s.active.inet6}
	}
	for _, gen := range s.retired {
		if len(gen.usedV4)+len(gen.usedV6) == 0 && len(gen.forward) == 0 {
			continue
		}
		retired = append(retired, gen.inet4, gen.inet6)
	}
	return active, retired
}

func (s *FakeIPStore) Contains(addr netip.Addr) bool {
	return s.prefixContains(addr)
}

func (s *FakeIPStore) prefixContains(addr netip.Addr) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.prefixContainsLocked(addr)
}

func (s *FakeIPStore) prefixContainsLocked(addr netip.Addr) bool {
	if _, ok := s.lookBackLocked(addr); ok {
		return true
	}
	if s.active != nil && (s.active.inet4.Contains(addr) || s.active.inet6.Contains(addr)) {
		return true
	}
	for _, gen := range s.retired {
		if gen.inet4.Contains(addr) || gen.inet6.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *FakeIPStore) LookBack(addr netip.Addr) (string, bool) {
	if s == nil || !addr.IsValid() {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.ready {
		return "", false
	}
	id, ok := s.lookBackLocked(addr)
	if !ok || int(id) >= len(s.intern) {
		return "", false
	}
	return s.intern[id], true
}

// Touch records DNS-time activity so eviction prefers idle names over popular
// ones that were assigned first. Packet LookBack stays read-only.
func (s *FakeIPStore) Touch(qname string) {
	qname = canonicalizeFakeIPQname(qname)
	if s == nil || qname == "" {
		return
	}
	now := time.Now().Unix()
	s.mu.Lock()
	s.touchLocked(qname, now)
	s.mu.Unlock()
}

func (s *FakeIPStore) touchLocked(qname string, now int64) {
	if s.active == nil {
		return
	}
	id, hit := s.active.forward[qname]
	if !hit || int(id) >= len(s.records) {
		return
	}
	rec := s.records[id]
	if rec.retired || rec.qname != qname {
		return
	}
	if rec.updatedUnix >= now {
		return
	}
	rec.updatedUnix = now
	s.records[id] = rec
}

func (s *FakeIPStore) Lookup(qname string) (v4, v6 netip.Addr, ok bool) {
	qname = canonicalizeFakeIPQname(qname)
	if s == nil || qname == "" {
		return netip.Addr{}, netip.Addr{}, false
	}
	s.mu.RLock()
	if !s.ready || s.active == nil {
		s.mu.RUnlock()
		return netip.Addr{}, netip.Addr{}, false
	}
	id, hit := s.active.forward[qname]
	if !hit || int(id) >= len(s.records) {
		s.mu.RUnlock()
		return netip.Addr{}, netip.Addr{}, false
	}
	rec := s.records[id]
	if rec.retired || rec.seq > s.durable {
		s.mu.RUnlock()
		return netip.Addr{}, netip.Addr{}, false
	}
	v4, v6 = s.liveAddrsLocked(rec)
	ok = v4.IsValid() || v6.IsValid()
	s.mu.RUnlock()
	if ok {
		s.Touch(qname)
	}
	return v4, v6, ok
}

func (s *FakeIPStore) Assign(qname string) (v4, v6 netip.Addr, seq uint64, err error) {
	qname = canonicalizeFakeIPQname(qname)
	if s == nil {
		return netip.Addr{}, netip.Addr{}, 0, errFakeIPStoreClosed
	}
	if qname == "" {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("empty qname")
	}
	s.mu.Lock()
	if !s.ready || s.closed || s.active == nil {
		s.mu.Unlock()
		return netip.Addr{}, netip.Addr{}, 0, errFakeIPNotReady
	}
	s.expireTombstonesLocked(time.Now())
	now := time.Now().Unix()
	if id, hit := s.active.forward[qname]; hit && int(id) < len(s.records) && !s.records[id].retired {
		if err := s.ensureActiveV6Locked(id); err != nil {
			s.mu.Unlock()
			return netip.Addr{}, netip.Addr{}, 0, err
		}
		s.touchLocked(qname, now)
		return s.waitPublishedLocked(s.records[id])
	}
	if rec, _, ok := s.reviveSamePoolLocked(qname); ok {
		return s.waitPublishedLocked(rec)
	}
	restoreEvict, err := s.evictIfNeededLocked()
	if err != nil {
		s.mu.Unlock()
		return netip.Addr{}, netip.Addr{}, 0, err
	}
	v4, err = s.allocateLocked(qname, true)
	if err != nil {
		restoreEvict()
		s.mu.Unlock()
		return netip.Addr{}, netip.Addr{}, 0, err
	}
	if s.active.inet6.IsValid() {
		v6, err = s.allocateLocked(qname, false)
		if err != nil {
			restoreEvict()
			s.mu.Unlock()
			return netip.Addr{}, netip.Addr{}, 0, err
		}
	}
	seq = s.seq + 1
	rec := fakeIPRecord{qname: qname, ipv4: v4, ipv6: v6, origin4: s.active.inet4, origin6: s.active.inet6, updatedUnix: now, seq: seq}
	if err := s.appendWalLocked(rec); err != nil {
		restoreEvict()
		s.mu.Unlock()
		return netip.Addr{}, netip.Addr{}, 0, err
	}
	s.seq = seq
	id := s.internLocked(qname)
	if int(id) < len(s.records) && s.records[id].qname == qname &&
		(s.records[id].retired || s.records[id].ipv4 != v4 || s.records[id].ipv6 != v6) &&
		(s.records[id].ipv4.IsValid() || s.records[id].ipv6.IsValid()) {
		id = s.internNewLocked(qname)
	}
	if int(id) < len(s.records) {
		s.records[id] = rec
	} else {
		s.records = append(s.records, rec)
	}
	s.active.forward[qname] = id
	s.indexReverseLocked(id, rec)
	if off, ok := fakeIPOffset(s.active.inet4, v4); ok {
		s.active.v4[off] = id
		s.active.usedV4[off] = struct{}{}
	}
	if off, ok := fakeIPOffset(s.active.inet6, v6); ok {
		s.active.v6[off] = id
		s.active.usedV6[off] = struct{}{}
	}
	ch := s.waiterLocked(seq)
	s.mu.Unlock()
	<-ch
	return s.publishedAfterWait(v4, v6, seq)
}

func (s *FakeIPStore) reviveSamePoolLocked(qname string) (fakeIPRecord, fakeIPInternID, bool) {
	id, ok := s.names[qname]
	if !ok || int(id) >= len(s.records) || s.active == nil {
		return fakeIPRecord{}, 0, false
	}
	rec := s.records[id]
	if rec.qname != qname || !rec.ipv4.IsValid() {
		return fakeIPRecord{}, 0, false
	}
	if rec.origin4 != s.active.inet4 || !s.active.inet4.Contains(rec.ipv4) {
		return fakeIPRecord{}, 0, false
	}
	rec.retired = false
	rec.retiredUnix = 0
	rec.updatedUnix = time.Now().Unix()
	s.records[id] = rec
	s.active.forward[qname] = id
	s.markUsedLocked(s.active, id, rec)
	return rec, id, true
}

func (s *FakeIPStore) liveAddrsLocked(rec fakeIPRecord) (v4, v6 netip.Addr) {
	if s.active != nil && s.active.inet4.Contains(rec.ipv4) {
		v4 = rec.ipv4
	}
	if s.active != nil && s.active.inet6.IsValid() && s.active.inet6.Contains(rec.ipv6) {
		v6 = rec.ipv6
	}
	return v4, v6
}

func (s *FakeIPStore) waitPublishedLocked(rec fakeIPRecord) (netip.Addr, netip.Addr, uint64, error) {
	v4, v6 := s.liveAddrsLocked(rec)
	if rec.seq == 0 || rec.seq <= s.durable {
		s.mu.Unlock()
		return v4, v6, 0, nil
	}
	ch := s.waiterLocked(rec.seq)
	s.mu.Unlock()
	<-ch
	return s.publishedAfterWait(v4, v6, rec.seq)
}

func (s *FakeIPStore) publishedAfterWait(v4, v6 netip.Addr, seq uint64) (netip.Addr, netip.Addr, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.durable >= seq {
		return v4, v6, seq, nil
	}
	err := s.syncErr
	if err == nil {
		err = errFakeIPNotDurable
	}
	return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("fakeip mapping not durable: %w", err)
}

func (s *FakeIPStore) WaitDurable(seq uint64) error {
	if seq == 0 {
		return nil
	}
	s.mu.Lock()
	if s.durable >= seq {
		s.mu.Unlock()
		return nil
	}
	ch := s.waiterLocked(seq)
	s.mu.Unlock()
	<-ch
	return nil
}

func (s *FakeIPStore) ApplyRanges(inet4, inet6 netip.Prefix) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyRangesLocked(inet4, inet6, false)
}

func (s *FakeIPStore) RetireActive(next4, next6 netip.Prefix) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyRangesLocked(next4, next6, true)
}

func (s *FakeIPStore) applyRangesLocked(inet4, inet6 netip.Prefix, force bool) {
	if s.active == nil {
		s.active = newFakeIPGeneration(inet4, inet6)
		s.restoreMatchingRetiredLocked(inet4, inet6)
		return
	}
	if force {
		s.retireActiveGenerationLocked()
		s.active = newFakeIPGeneration(inet4, inet6)
		return
	}
	if s.active.inet4 == inet4 && s.active.inet6 == inet6 {
		if len(s.active.forward) == 0 {
			s.restoreMatchingRetiredLocked(inet4, inet6)
		}
		return
	}
	if s.active.inet4 == inet4 {
		// IPv4 pool did not move: keep live A mappings. Only the IPv6 pool
		// is parked so old fake AAAA still LookBack, and new AAAA is not
		// advertised until inet6 matches again.
		s.replaceActiveInet6Locked(inet6)
		return
	}
	s.retireActiveGenerationLocked()
	s.active = newFakeIPGeneration(inet4, inet6)
	s.restoreMatchingRetiredLocked(inet4, inet6)
}

func (s *FakeIPStore) retireActiveGenerationLocked() {
	if s.active == nil {
		return
	}
	now := time.Now().Unix()
	s.retired = append(s.retired, s.active)
	for i := range s.records {
		if _, ok := s.active.forward[s.records[i].qname]; ok {
			s.records[i].retired = true
			s.records[i].retiredUnix = now
		}
	}
}

func (s *FakeIPStore) replaceActiveInet6Locked(inet6 netip.Prefix) {
	old6 := s.active.inet6
	if old6 == inet6 {
		return
	}
	if old6.IsValid() {
		s.parkInet6Locked(old6)
	}
	s.active.inet6 = inet6
	if inet6.IsValid() {
		s.adoptParkedInet6Locked(inet6)
	}
}

func (s *FakeIPStore) parkInet6Locked(old6 netip.Prefix) {
	if s.active == nil || !old6.IsValid() {
		return
	}
	parked := newFakeIPGeneration(netip.Prefix{}, old6)
	parked.usedV6 = s.active.usedV6
	parked.v6 = s.active.v6
	s.retired = append(s.retired, parked)
	s.active.usedV6 = make(map[uint32]struct{})
	s.active.v6 = make(map[uint32]fakeIPInternID)
}

func (s *FakeIPStore) adoptParkedInet6Locked(inet6 netip.Prefix) {
	if s.active == nil || !inet6.IsValid() {
		return
	}
	for i := len(s.retired) - 1; i >= 0; i-- {
		gen := s.retired[i]
		if gen == nil || gen.inet6 != inet6 || gen.inet4.IsValid() {
			continue
		}
		s.active.usedV6 = gen.usedV6
		s.active.v6 = gen.v6
		s.retired = append(s.retired[:i], s.retired[i+1:]...)
		break
	}
	if s.active.usedV6 == nil {
		s.active.usedV6 = make(map[uint32]struct{})
	}
	if s.active.v6 == nil {
		s.active.v6 = make(map[uint32]fakeIPInternID)
	}
	for id, rec := range s.records {
		if rec.qname == "" || rec.retired {
			continue
		}
		if _, ok := s.active.forward[rec.qname]; !ok {
			continue
		}
		if off, ok := fakeIPOffset(s.active.inet6, rec.ipv6); ok {
			s.active.v6[off] = fakeIPInternID(id)
			s.active.usedV6[off] = struct{}{}
		}
	}
}

func (s *FakeIPStore) ensureParkedInet6Locked(origin6 netip.Prefix, id fakeIPInternID, rec fakeIPRecord) {
	if !rec.ipv6.IsValid() {
		return
	}
	p6 := origin6
	if !p6.IsValid() || !p6.Contains(rec.ipv6) {
		if fakeIPDefaultInet6.Contains(rec.ipv6) {
			p6 = fakeIPDefaultInet6
		} else {
			p6, _ = rec.ipv6.Prefix(96)
		}
	}
	if !p6.IsValid() {
		return
	}
	var parked *fakeIPGeneration
	for _, gen := range s.retired {
		if gen != nil && gen.inet6 == p6 && !gen.inet4.IsValid() {
			parked = gen
			break
		}
	}
	if parked == nil {
		parked = newFakeIPGeneration(netip.Prefix{}, p6)
		s.retired = append(s.retired, parked)
	}
	s.markUsedLocked(parked, id, rec)
}

func (s *FakeIPStore) ensureActiveV6Locked(id fakeIPInternID) error {
	if s.active == nil || !s.active.inet6.IsValid() || int(id) >= len(s.records) {
		return nil
	}
	rec := s.records[id]
	if s.active.inet6.Contains(rec.ipv6) {
		return nil
	}
	v6, err := s.allocateLocked(rec.qname, false)
	if err != nil {
		return err
	}
	next := rec
	next.ipv6 = v6
	next.origin6 = s.active.inet6
	next.seq = s.seq + 1
	if err := s.appendWalLocked(next); err != nil {
		return err
	}
	s.seq = next.seq
	s.records[id] = next
	s.indexReverseLocked(id, next)
	s.markUsedLocked(s.active, id, next)
	return nil
}

func (s *FakeIPStore) restoreMatchingRetiredLocked(inet4, inet6 netip.Prefix) {
	for i := len(s.retired) - 1; i >= 0; i-- {
		gen := s.retired[i]
		if gen == nil || gen.inet4 != inet4 || gen.inet6 != inet6 {
			continue
		}
		s.active = gen
		s.retired = append(s.retired[:i], s.retired[i+1:]...)
		for idx, rec := range s.records {
			if rec.qname == "" {
				continue
			}
			if _, ok := gen.forward[rec.qname]; !ok {
				continue
			}
			s.records[idx].retired = false
			s.records[idx].retiredUnix = 0
		}
		return
	}
}

func (s *FakeIPStore) internLocked(qname string) fakeIPInternID {
	if id, ok := s.names[qname]; ok {
		return id
	}
	return s.internNewLocked(qname)
}

func (s *FakeIPStore) internNewLocked(qname string) fakeIPInternID {
	id := fakeIPInternID(len(s.intern))
	s.intern = append(s.intern, qname)
	s.names[qname] = id
	for int(id) >= len(s.records) {
		s.records = append(s.records, fakeIPRecord{})
	}
	return id
}

func (s *FakeIPStore) lookBackLocked(addr netip.Addr) (fakeIPInternID, bool) {
	if addr.Is4() || addr.Is4In6() {
		id, ok := s.rev4[fakeIPv4Key(addr)]
		return id, ok
	}
	id, ok := s.rev6[addr.As16()]
	return id, ok
}

func (s *FakeIPStore) allocateLocked(qname string, ipv4 bool) (netip.Addr, error) {
	gen := s.active
	var prefix netip.Prefix
	var used map[uint32]struct{}
	if ipv4 {
		prefix = gen.inet4
		used = unionUsed(gen.usedV4, s.retired, true)
	} else {
		prefix = gen.inet6
		used = unionUsed(gen.usedV6, s.retired, false)
	}
	size := fakeIPPoolSize(prefix)
	if size == 0 {
		return netip.Addr{}, fmt.Errorf("empty fakeip pool %s", prefix)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(qname))
	if ipv4 {
		_, _ = h.Write([]byte{4})
	} else {
		_, _ = h.Write([]byte{6})
	}
	start := uint32(h.Sum64() % uint64(size))
	for i := uint32(0); i < size; i++ {
		off := (start + i) % size
		if off == 0 {
			continue
		}
		if _, taken := used[off]; taken {
			continue
		}
		addr, err := fakeIPFromOffset(prefix, off)
		if err != nil {
			return netip.Addr{}, err
		}
		if _, hit := s.lookBackLocked(addr); hit {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("fakeip pool exhausted")
}

func unionUsed(active map[uint32]struct{}, retired []*fakeIPGeneration, ipv4 bool) map[uint32]struct{} {
	out := make(map[uint32]struct{}, len(active))
	for off := range active {
		out[off] = struct{}{}
	}
	for _, gen := range retired {
		src := gen.usedV4
		if !ipv4 {
			src = gen.usedV6
		}
		for off := range src {
			out[off] = struct{}{}
		}
	}
	return out
}

func (s *FakeIPStore) evictIfNeededLocked() (restore func(), err error) {
	restore = func() {}
	live := 0
	oldestIdx := -1
	oldestUnix := int64(1<<63 - 1)
	for i, rec := range s.records {
		if rec.qname == "" || rec.retired {
			continue
		}
		if _, ok := s.active.forward[rec.qname]; !ok {
			continue
		}
		live++
		if rec.updatedUnix <= oldestUnix {
			oldestUnix = rec.updatedUnix
			oldestIdx = i
		}
	}
	if live < s.maxLive {
		return restore, nil
	}
	if oldestIdx < 0 {
		return restore, fmt.Errorf("fakeip table full")
	}
	// Evict the idle ACTIVE (smallest updatedUnix = last DNS assign/lookup),
	// not the first-allocated name. Popular names stay if they keep resolving.
	rec := s.records[oldestIdx]
	id := fakeIPInternID(oldestIdx)
	s.records[oldestIdx].retired = true
	s.records[oldestIdx].retiredUnix = time.Now().Unix()
	delete(s.active.forward, rec.qname)
	restore = func() {
		s.records[oldestIdx] = rec
		if s.active != nil {
			s.active.forward[rec.qname] = id
		}
	}
	return restore, nil
}

func (s *FakeIPStore) expireTombstonesLocked(now time.Time) {
	graceSec := int64(fakeIPTombstoneGrace / time.Second)
	nowUnix := now.Unix()
	var live []int
	for i, rec := range s.records {
		if rec.qname == "" || !rec.retired {
			continue
		}
		at := rec.retiredUnix
		if at > 0 && (graceSec <= 0 || nowUnix-at >= graceSec) {
			s.releaseTombstoneLocked(i)
			continue
		}
		live = append(live, i)
	}
	extra := len(live) - s.maxLive
	for n := 0; n < extra; n++ {
		oldest := -1
		oldestAt := int64(1<<63 - 1)
		for _, i := range live {
			rec := s.records[i]
			if rec.qname == "" || !rec.retired {
				continue
			}
			at := rec.retiredUnix
			if at == 0 {
				at = rec.updatedUnix
			}
			if at < oldestAt {
				oldestAt = at
				oldest = i
			}
		}
		if oldest < 0 {
			return
		}
		s.releaseTombstoneLocked(oldest)
	}
}

func (s *FakeIPStore) releaseTombstoneLocked(i int) {
	if i < 0 || i >= len(s.records) {
		return
	}
	rec := s.records[i]
	if rec.ipv4.IsValid() {
		delete(s.rev4, fakeIPv4Key(rec.ipv4))
	}
	if rec.ipv6.IsValid() {
		delete(s.rev6, rec.ipv6.As16())
	}
	gens := make([]*fakeIPGeneration, 0, 1+len(s.retired))
	if s.active != nil {
		gens = append(gens, s.active)
	}
	gens = append(gens, s.retired...)
	for _, gen := range gens {
		if off, ok := fakeIPOffset(gen.inet4, rec.ipv4); ok {
			delete(gen.v4, off)
			delete(gen.usedV4, off)
		}
		if off, ok := fakeIPOffset(gen.inet6, rec.ipv6); ok {
			delete(gen.v6, off)
			delete(gen.usedV6, off)
		}
		delete(gen.forward, rec.qname)
	}
	if id, ok := s.names[rec.qname]; ok && int(id) == i {
		delete(s.names, rec.qname)
	}
	s.records[i] = fakeIPRecord{}
	if i < len(s.intern) {
		s.intern[i] = ""
	}
}

func (s *FakeIPStore) waiterLocked(seq uint64) chan struct{} {
	if s.durable >= seq {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	ch := make(chan struct{})
	s.waiters[seq] = append(s.waiters[seq], ch)
	go s.syncWal(seq)
	return ch
}

func (s *FakeIPStore) syncWal(seq uint64) {
	s.mu.Lock()
	if s.wal == nil {
		s.failUndurableWaitersLocked()
		s.mu.Unlock()
		return
	}
	if s.durable >= seq {
		s.broadcastLocked()
		s.mu.Unlock()
		return
	}
	toSync := s.seq
	fd := int(s.wal.Fd())
	s.mu.Unlock()

	err := fakeIPFdatasync(fd)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.syncErr = err
		s.failUndurableWaitersLocked()
		return
	}
	if s.durable < toSync {
		s.durable = toSync
		s.syncErr = nil
		if err := s.maybeCompactLocked(); err != nil {
			// Mapping is already durable; snapshot retry happens on Close.
			_ = err
		}
	}
	s.broadcastLocked()
}

func (s *FakeIPStore) failUndurableWaitersLocked() {
	for seq, waiters := range s.waiters {
		if s.durable >= seq {
			continue
		}
		for _, ch := range waiters {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
		delete(s.waiters, seq)
	}
}

func (s *FakeIPStore) broadcastLocked() {
	for seq, waiters := range s.waiters {
		if s.durable < seq {
			continue
		}
		for _, ch := range waiters {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
		delete(s.waiters, seq)
	}
}

func canonicalizeFakeIPQname(qname string) string {
	qname = stringsToLowerASCII(qname)
	if qname == "" {
		return ""
	}
	if !stringsHasSuffixByte(qname, '.') {
		qname += "."
	}
	return qname
}

func stringsToLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func stringsHasSuffixByte(s string, c byte) bool {
	return len(s) > 0 && s[len(s)-1] == c
}

func fakeIPPoolSize(prefix netip.Prefix) uint32 {
	bits := prefix.Bits()
	host := prefix.Addr().BitLen() - bits
	if host <= 0 {
		return 0
	}
	if host >= 32 {
		return ^uint32(0)
	}
	return uint32(1) << host
}

func fakeIPOffset(prefix netip.Prefix, addr netip.Addr) (uint32, bool) {
	if !prefix.Contains(addr) {
		return 0, false
	}
	base := prefix.Addr()
	if addr.Is4() || addr.Is4In6() {
		a := addr.As4()
		b := base.As4()
		off := binary.BigEndian.Uint32(a[:]) - binary.BigEndian.Uint32(b[:])
		return off, true
	}
	aa := addr.As16()
	bb := base.As16()
	off := binary.BigEndian.Uint32(aa[12:]) - binary.BigEndian.Uint32(bb[12:])
	return off, true
}

func fakeIPFromOffset(prefix netip.Prefix, off uint32) (netip.Addr, error) {
	addr := prefix.Addr()
	if addr.Is4() {
		raw4 := addr.As4()
		base := binary.BigEndian.Uint32(raw4[:])
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], base+off)
		return netip.AddrFrom4(raw), nil
	}
	raw := addr.As16()
	base := binary.BigEndian.Uint32(raw[12:])
	binary.BigEndian.PutUint32(raw[12:], base+off)
	return netip.AddrFrom16(raw), nil
}

func (s *FakeIPStore) openWalLocked() error {
	path := filepath.Join(s.dir, fakeIPWalName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, fakeIPFileMode)
	if err != nil {
		return fmt.Errorf("open fakeip wal: %w", err)
	}
	if err := os.Chmod(path, fakeIPFileMode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return err
	}
	s.wal = f
	return nil
}

func fakeIPv4Key(addr netip.Addr) uint32 {
	a := addr.Unmap().As4()
	return binary.BigEndian.Uint32(a[:])
}

func fakeIPAddrFrom16(raw [16]byte) netip.Addr {
	var zero [16]byte
	if raw == zero {
		return netip.Addr{}
	}
	return netip.AddrFrom16(raw)
}

func (s *FakeIPStore) indexReverseLocked(id fakeIPInternID, rec fakeIPRecord) {
	if rec.ipv4.IsValid() {
		s.rev4[fakeIPv4Key(rec.ipv4)] = id
	}
	if rec.ipv6.IsValid() {
		s.rev6[rec.ipv6.As16()] = id
	}
}

func (s *FakeIPStore) appendWalLocked(rec fakeIPRecord) error {
	if s.wal == nil {
		return fmt.Errorf("fakeip wal is not open")
	}
	off, err := s.wal.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	var buf [512]byte
	n := encodeFakeIPWalRecord(buf[:], rec)
	if fakeIPWalWriteHook != nil {
		if hookErr := fakeIPWalWriteHook(buf[:n]); hookErr != nil {
			return hookErr
		}
	}
	nw, err := s.wal.Write(buf[:n])
	if err != nil || nw != n {
		_ = s.wal.Truncate(off)
		_, _ = s.wal.Seek(off, io.SeekStart)
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	return nil
}

func encodeFakeIPWalRecord(dst []byte, rec fakeIPRecord) int {
	q := []byte(rec.qname)
	need := 1 + 8 + 2 + len(q) + 4 + 16 + 8 + 17 + 17
	if len(dst) < need {
		panic("wal buffer too small")
	}
	dst[0] = fakeIPWalAllocV2
	binary.LittleEndian.PutUint64(dst[1:9], rec.seq)
	binary.LittleEndian.PutUint16(dst[9:11], uint16(len(q)))
	copy(dst[11:], q)
	off := 11 + len(q)
	var v4 [4]byte
	if rec.ipv4.IsValid() {
		v4 = rec.ipv4.As4()
	}
	copy(dst[off:], v4[:])
	off += 4
	var v6 [16]byte
	if rec.ipv6.IsValid() {
		v6 = rec.ipv6.As16()
	}
	copy(dst[off:], v6[:])
	off += 16
	binary.LittleEndian.PutUint64(dst[off:], uint64(rec.updatedUnix))
	off += 8
	off += encodePrefixTo(dst[off:], rec.origin4)
	off += encodePrefixTo(dst[off:], rec.origin6)
	return off
}

func encodePrefixTo(dst []byte, p netip.Prefix) int {
	if !p.IsValid() {
		dst[0] = 0xff
		return 17
	}
	if p.Addr().Is4() || p.Addr().Is4In6() {
		dst[0] = byte(p.Bits())
		raw := p.Addr().Unmap().As4()
		copy(dst[1:], raw[:])
		return 5
	}
	dst[0] = byte(p.Bits())
	raw := p.Addr().As16()
	copy(dst[1:], raw[:])
	return 17
}

func (s *FakeIPStore) loadLocked() error {
	snap := filepath.Join(s.dir, fakeIPSnapshotName)
	body, err := os.ReadFile(snap)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(body) > s.maxBytes {
		return fmt.Errorf("fakeip snapshot too large")
	}
	if len(body) > 0 {
		if err := s.decodeSnapshotLocked(body); err != nil {
			return err
		}
	}
	walPath := filepath.Join(s.dir, fakeIPWalName)
	walBody, err := os.ReadFile(walPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(walBody) > s.maxBytes {
		return fmt.Errorf("fakeip wal too large")
	}
	if len(walBody) > 0 {
		if err := s.replayWalLocked(walBody); err != nil {
			return err
		}
	}
	s.expireTombstonesLocked(time.Now())
	return nil
}

func (s *FakeIPStore) decodeSnapshotLocked(body []byte) error {
	if len(body) < 8+4+5+17+4 {
		return io.ErrUnexpectedEOF
	}
	if string(body[:8]) != fakeIPSnapshotMagic {
		return fmt.Errorf("bad fakeip magic")
	}
	off := 8
	ver := binary.LittleEndian.Uint32(body[off:])
	off += 4
	if ver != fakeIPStoreVersion && ver != fakeIPStoreVersionV2 && ver != fakeIPStoreVersionV1 {
		return fmt.Errorf("unsupported fakeip version %d", ver)
	}
	inet4, n, err := decodePrefix(body[off:])
	if err != nil {
		return err
	}
	off += n
	inet6, n, err := decodePrefix(body[off:])
	if err != nil {
		return err
	}
	off += n

	wanted4, wanted6 := netip.Prefix{}, netip.Prefix{}
	if s.active != nil {
		wanted4, wanted6 = s.active.inet4, s.active.inet6
	}
	fileActive := newFakeIPGeneration(inet4, inet6)
	inet4Changed := s.active != nil && wanted4 != inet4

	if ver >= fakeIPStoreVersionV2 {
		if off+4 > len(body) {
			return io.ErrUnexpectedEOF
		}
		retiredN := binary.LittleEndian.Uint32(body[off:])
		off += 4
		for i := uint32(0); i < retiredN; i++ {
			r4, n, err := decodePrefix(body[off:])
			if err != nil {
				return err
			}
			off += n
			r6, n, err := decodePrefix(body[off:])
			if err != nil {
				return err
			}
			off += n
			s.retired = append(s.retired, newFakeIPGeneration(r4, r6))
		}
	}

	if off+4 > len(body) {
		return io.ErrUnexpectedEOF
	}
	count := binary.LittleEndian.Uint32(body[off:])
	off += 4
	if inet4Changed {
		s.retired = append(s.retired, fileActive)
	} else {
		s.active = fileActive
	}
	for i := uint32(0); i < count; i++ {
		rec, n, err := decodeFakeIPRecord(body[off:], ver)
		if err != nil {
			return err
		}
		off += n
		if !rec.origin4.IsValid() {
			rec.origin4 = inet4
		}
		if !rec.origin6.IsValid() {
			rec.origin6 = inet6
		}
		if rec.ipv4.IsValid() && rec.origin4.IsValid() && !rec.origin4.Contains(rec.ipv4) {
			rec.origin4, rec.origin6 = inferOrphanFakeIPPrefixes(rec)
		}
		s.placeRecordLocked(rec)
	}
	s.applyRangesLocked(wanted4, wanted6, false)
	s.durable = s.seq
	return nil
}

func (s *FakeIPStore) markUsedLocked(gen *fakeIPGeneration, id fakeIPInternID, rec fakeIPRecord) {
	if gen == nil {
		return
	}
	if v4off, ok := fakeIPOffset(gen.inet4, rec.ipv4); ok {
		gen.v4[v4off] = id
		gen.usedV4[v4off] = struct{}{}
	}
	if v6off, ok := fakeIPOffset(gen.inet6, rec.ipv6); ok {
		gen.v6[v6off] = id
		gen.usedV6[v6off] = struct{}{}
	}
}

func inferOrphanFakeIPPrefixes(rec fakeIPRecord) (netip.Prefix, netip.Prefix) {
	var p4, p6 netip.Prefix
	if rec.ipv4.IsValid() {
		a := rec.ipv4.Unmap()
		if fakeIPDefaultInet4.Contains(a) {
			p4 = fakeIPDefaultInet4
		} else {
			p4, _ = a.Prefix(16)
		}
	}
	if rec.ipv6.IsValid() {
		if fakeIPDefaultInet6.Contains(rec.ipv6) {
			p6 = fakeIPDefaultInet6
		} else {
			p6, _ = rec.ipv6.Prefix(96)
		}
	}
	return p4, p6
}

func (s *FakeIPStore) genMatchingOriginLocked(p4, p6 netip.Prefix) *fakeIPGeneration {
	if s.active != nil && s.active.inet4 == p4 && s.active.inet6 == p6 {
		return s.active
	}
	for _, gen := range s.retired {
		if gen.inet4 == p4 && gen.inet6 == p6 {
			return gen
		}
	}
	return nil
}

func (s *FakeIPStore) placeRecordLocked(rec fakeIPRecord) {
	if rec.qname == "" {
		return
	}
	rec.qname = canonicalizeFakeIPQname(rec.qname)
	if !rec.origin4.IsValid() && !rec.origin6.IsValid() {
		rec.origin4, rec.origin6 = inferOrphanFakeIPPrefixes(rec)
	}
	id := s.internLocked(rec.qname)
	if int(id) < len(s.records) {
		old := s.records[id]
		if old.qname == rec.qname && old.ipv4.IsValid() && (old.ipv4 != rec.ipv4 || old.ipv6 != rec.ipv6) {
			id = s.internNewLocked(rec.qname)
		}
	}
	if rec.seq > s.seq {
		s.seq = rec.seq
	}
	s.records[id] = rec
	s.indexReverseLocked(id, rec)
	if s.active != nil && !rec.retired && rec.origin4 == s.active.inet4 && s.active.inet4.Contains(rec.ipv4) {
		s.active.forward[rec.qname] = id
		s.markUsedLocked(s.active, id, rec)
		if rec.ipv6.IsValid() && (!s.active.inet6.IsValid() || !s.active.inet6.Contains(rec.ipv6)) {
			s.ensureParkedInet6Locked(rec.origin6, id, rec)
		}
		return
	}
	gen := s.genMatchingOriginLocked(rec.origin4, rec.origin6)
	if gen == nil {
		gen = newFakeIPGeneration(rec.origin4, rec.origin6)
		if s.active != nil && rec.origin4 == s.active.inet4 && rec.origin6 == s.active.inet6 {
			gen = s.active
		} else {
			s.retired = append(s.retired, gen)
		}
	}
	s.records[id].retired = true
	s.markUsedLocked(gen, id, rec)
}

func (s *FakeIPStore) replayWalLocked(body []byte) error {
	off := 0
	for off < len(body) {
		if off+11 > len(body) {
			// Truncated tail after a crash: keep complete records.
			return nil
		}
		if body[off] != fakeIPWalAlloc && body[off] != fakeIPWalAllocV2 {
			return fmt.Errorf("unknown fakeip wal type %d", body[off])
		}
		walV2 := body[off] == fakeIPWalAllocV2
		seq := binary.LittleEndian.Uint64(body[off+1 : off+9])
		qlen := int(binary.LittleEndian.Uint16(body[off+9 : off+11]))
		need := 11 + qlen + 4 + 16 + 8
		if walV2 {
			need += 5 + 5
		}
		if off+need > len(body) {
			return nil
		}
		off += 11
		qname := string(body[off : off+qlen])
		off += qlen
		var v4raw [4]byte
		copy(v4raw[:], body[off:off+4])
		off += 4
		var v6raw [16]byte
		copy(v6raw[:], body[off:off+16])
		off += 16
		updated := int64(binary.LittleEndian.Uint64(body[off : off+8]))
		off += 8
		rec := fakeIPRecord{
			qname:       canonicalizeFakeIPQname(qname),
			ipv4:        netip.AddrFrom4(v4raw),
			ipv6:        fakeIPAddrFrom16(v6raw),
			updatedUnix: updated,
			seq:         seq,
		}
		if walV2 {
			origin4, n, err := decodePrefix(body[off:])
			if err != nil {
				return nil
			}
			off += n
			origin6, n, err := decodePrefix(body[off:])
			if err != nil {
				return nil
			}
			off += n
			rec.origin4 = origin4
			rec.origin6 = origin6
		}
		s.placeRecordLocked(rec)
	}
	s.durable = s.seq
	return nil
}

func decodePrefix(b []byte) (netip.Prefix, int, error) {
	if len(b) < 1 {
		return netip.Prefix{}, 0, io.ErrUnexpectedEOF
	}
	bits := int(b[0])
	if bits > 128 {
		if len(b) < 17 {
			return netip.Prefix{}, 0, io.ErrUnexpectedEOF
		}
		return netip.Prefix{}, 17, nil
	}
	if bits <= 32 {
		if len(b) < 5 {
			return netip.Prefix{}, 0, io.ErrUnexpectedEOF
		}
		var raw [4]byte
		copy(raw[:], b[1:5])
		addr := netip.AddrFrom4(raw)
		p, err := addr.Prefix(bits)
		return p, 5, err
	}
	if len(b) < 17 {
		return netip.Prefix{}, 0, io.ErrUnexpectedEOF
	}
	var raw [16]byte
	copy(raw[:], b[1:17])
	addr := netip.AddrFrom16(raw)
	p, err := addr.Prefix(bits)
	return p, 17, err
}

func decodeFakeIPRecord(b []byte, ver uint32) (fakeIPRecord, int, error) {
	if len(b) < 2 {
		return fakeIPRecord{}, 0, io.ErrUnexpectedEOF
	}
	qlen := int(binary.LittleEndian.Uint16(b[:2]))
	need := 2 + qlen + 4 + 16 + 8
	if ver >= fakeIPStoreVersionV2 {
		need += 1 + 8 + 5 + 5
	}
	if ver >= fakeIPStoreVersion {
		need += 8
	}
	if len(b) < need {
		return fakeIPRecord{}, 0, io.ErrUnexpectedEOF
	}
	qname := canonicalizeFakeIPQname(string(b[2 : 2+qlen]))
	off := 2 + qlen
	var v4raw [4]byte
	copy(v4raw[:], b[off:off+4])
	off += 4
	var v6raw [16]byte
	copy(v6raw[:], b[off:off+16])
	off += 16
	updated := int64(binary.LittleEndian.Uint64(b[off : off+8]))
	off += 8
	rec := fakeIPRecord{
		qname:       qname,
		ipv4:        netip.AddrFrom4(v4raw),
		ipv6:        fakeIPAddrFrom16(v6raw),
		updatedUnix: updated,
	}
	if ver >= fakeIPStoreVersionV2 {
		flags := b[off]
		off++
		rec.retired = flags&fakeIPRecordRetired != 0
		rec.seq = binary.LittleEndian.Uint64(b[off : off+8])
		off += 8
		origin4, n, err := decodePrefix(b[off:])
		if err != nil {
			return fakeIPRecord{}, 0, err
		}
		off += n
		origin6, n, err := decodePrefix(b[off:])
		if err != nil {
			return fakeIPRecord{}, 0, err
		}
		off += n
		rec.origin4 = origin4
		rec.origin6 = origin6
		if ver >= fakeIPStoreVersion {
			if off+8 > len(b) {
				return fakeIPRecord{}, 0, io.ErrUnexpectedEOF
			}
			rec.retiredUnix = int64(binary.LittleEndian.Uint64(b[off : off+8]))
			off += 8
		} else if rec.retired {
			rec.retiredUnix = rec.updatedUnix
		}
	}
	return rec, off, nil
}

func (s *FakeIPStore) flushSnapshotLocked() error {
	if s.active == nil || !s.diskOK {
		return nil
	}
	tmp := filepath.Join(s.dir, fakeIPSnapshotName+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fakeIPFileMode)
	if err != nil {
		return err
	}
	if err := writeFakeIPSnapshot(f, s); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, fakeIPSnapshotName)); err != nil {
		return err
	}
	if err := fsyncDir(s.dir); err != nil {
		return err
	}
	if s.wal != nil {
		if err := s.wal.Truncate(0); err != nil {
			return err
		}
		if _, err := s.wal.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	return nil
}

func (s *FakeIPStore) maybeCompactLocked() error {
	if s.wal == nil {
		return nil
	}
	info, err := s.wal.Stat()
	if err != nil {
		return err
	}
	if info.Size() < int64(fakeIPWalCompactMinBytes) && (s.maxBytes == 0 || info.Size()*2 < int64(s.maxBytes)) {
		return nil
	}
	return s.flushSnapshotLocked()
}

func writeFakeIPSnapshot(w io.Writer, s *FakeIPStore) error {
	var hdr [8 + 4]byte
	copy(hdr[:8], fakeIPSnapshotMagic)
	binary.LittleEndian.PutUint32(hdr[8:], fakeIPStoreVersion)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if err := writePrefix(w, s.active.inet4); err != nil {
		return err
	}
	if err := writePrefix(w, s.active.inet6); err != nil {
		return err
	}
	var retiredN [4]byte
	binary.LittleEndian.PutUint32(retiredN[:], uint32(len(s.retired)))
	if _, err := w.Write(retiredN[:]); err != nil {
		return err
	}
	for _, gen := range s.retired {
		if err := writePrefix(w, gen.inet4); err != nil {
			return err
		}
		if err := writePrefix(w, gen.inet6); err != nil {
			return err
		}
	}
	live := make([]fakeIPRecord, 0, len(s.records))
	for _, rec := range s.records {
		if rec.qname == "" {
			continue
		}
		live = append(live, rec)
	}
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(live)))
	if _, err := w.Write(count[:]); err != nil {
		return err
	}
	for _, rec := range live {
		var buf [512]byte
		n := encodeFakeIPSnapshotRecord(buf[:], rec)
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
	}
	return nil
}

func encodeFakeIPSnapshotRecord(dst []byte, rec fakeIPRecord) int {
	q := []byte(rec.qname)
	binary.LittleEndian.PutUint16(dst[:2], uint16(len(q)))
	copy(dst[2:], q)
	off := 2 + len(q)
	var v4 [4]byte
	if rec.ipv4.IsValid() {
		v4 = rec.ipv4.As4()
	}
	copy(dst[off:], v4[:])
	off += 4
	var v6 [16]byte
	if rec.ipv6.IsValid() {
		v6 = rec.ipv6.As16()
	}
	copy(dst[off:], v6[:])
	off += 16
	binary.LittleEndian.PutUint64(dst[off:], uint64(rec.updatedUnix))
	off += 8
	flags := uint8(0)
	if rec.retired {
		flags |= fakeIPRecordRetired
	}
	dst[off] = flags
	off++
	binary.LittleEndian.PutUint64(dst[off:], rec.seq)
	off += 8
	off += encodePrefixTo(dst[off:], rec.origin4)
	off += encodePrefixTo(dst[off:], rec.origin6)
	binary.LittleEndian.PutUint64(dst[off:], uint64(rec.retiredUnix))
	return off + 8
}

func writePrefix(w io.Writer, p netip.Prefix) error {
	if !p.IsValid() {
		var b [17]byte
		b[0] = 0xff
		_, err := w.Write(b[:])
		return err
	}
	if p.Addr().Is4() {
		var b [5]byte
		b[0] = byte(p.Bits())
		raw := p.Addr().As4()
		copy(b[1:], raw[:])
		_, err := w.Write(b[:])
		return err
	}
	var b [17]byte
	b[0] = byte(p.Bits())
	raw := p.Addr().As16()
	copy(b[1:], raw[:])
	_, err := w.Write(b[:])
	return err
}

func fsyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return unix.Fsync(int(f.Fd()))
}
