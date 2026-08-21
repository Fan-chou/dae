/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

const fakeIPScaleN = 100_000

func TestFakeIPStore100kScale(t *testing.T) {
	prevSync := fakeIPFdatasync
	fakeIPFdatasync = func(int) error { return nil }
	defer func() { fakeIPFdatasync = prevSync }()

	dir := t.TempDir()
	store := NewFakeIPStore(dir, 1)
	store.maxLive = fakeIPScaleN
	store.maxBytes = max(2<<20, 64+fakeIPScaleN*256)
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	fillStart := time.Now()
	probe := store.fillSequentialLocked(t, fakeIPScaleN)
	fill := time.Since(fillStart)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	heap := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if heap < 0 {
		heap = int64(after.HeapAlloc)
	}

	t.Logf("fill %d sequential (no WAL) in %s", fakeIPScaleN, fill)
	t.Logf("heap delta ≈ %s (HeapAlloc after=%s Sys=%s)", humanBytes(heap), humanBytes(int64(after.HeapAlloc)), humanBytes(int64(after.Sys)))
	t.Logf("VmRSS %s", readVmRSS())

	const samples = 50_000
	look := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		off := uint32(1 + i%(fakeIPScaleN))
		addr, err := fakeIPFromOffset(v4, off)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		name, ok := store.LookBack(addr)
		look[i] = time.Since(start)
		if !ok || name == "" {
			t.Fatalf("lookback miss at offset %d", off)
		}
	}
	t.Logf("LookBack @%d  p50=%s p99=%s p999=%s max=%s",
		fakeIPScaleN, durationPct(look, 50), durationPct(look, 99), durationPct(look, 999), durationMax(look))

	lookups := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		q := canonicalizeFakeIPQname(scaleQname(1 + i%fakeIPScaleN))
		start := time.Now()
		got, _, ok := store.Lookup(q)
		lookups[i] = time.Since(start)
		if !ok || !got.IsValid() {
			t.Fatalf("lookup miss %s", q)
		}
	}
	t.Logf("Lookup  @%d  p50=%s p99=%s p999=%s",
		fakeIPScaleN, durationPct(lookups, 50), durationPct(lookups, 99), durationPct(lookups, 999))

	var wg sync.WaitGroup
	conc := make([]time.Duration, 8*samples/8)
	startConc := time.Now()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < samples/8; i++ {
				off := uint32(1 + (g*samples/8+i)%fakeIPScaleN)
				addr, _ := fakeIPFromOffset(v4, off)
				t0 := time.Now()
				_, ok := store.LookBack(addr)
				conc[g*samples/8+i] = time.Since(t0)
				if !ok {
					t.Errorf("concurrent lookback miss")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	t.Logf("LookBack 8-way @%d wall=%s p99=%s", fakeIPScaleN, time.Since(startConc), durationPct(conc, 99))

	oneStart := time.Now()
	extra4, _, _, err := store.Assign("extra-100k.example.com")
	one := time.Since(oneStart)
	if err != nil {
		t.Fatalf("Assign one more at %d: %v", fakeIPScaleN, err)
	}
	if extra4 == probe {
		t.Fatal("new assignment reused an existing address")
	}
	t.Logf("Assign 1 more at %d (fsync stubbed) %s → %s", fakeIPScaleN, one, extra4)

	var snap bytes.Buffer
	snapStart := time.Now()
	store.mu.Lock()
	if err := writeFakeIPSnapshot(&snap, store); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	snapWrite := time.Since(snapStart)
	t.Logf("snapshot encode %s size=%s (cap maxBytes=%s)", snapWrite, humanBytes(int64(snap.Len())), humanBytes(int64(store.maxBytes)))

	loadStore := NewFakeIPStore(t.TempDir(), 1)
	loadStore.maxLive = fakeIPScaleN
	loadStore.maxBytes = store.maxBytes
	if err := loadStore.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer loadStore.Close()
	loadStart := time.Now()
	loadStore.mu.Lock()
	err = loadStore.decodeSnapshotLocked(snap.Bytes())
	loadStore.mu.Unlock()
	load := time.Since(loadStart)
	if err != nil {
		t.Fatal(err)
	}
	loadStore.mu.RLock()
	live := 0
	if loadStore.active != nil {
		live = len(loadStore.active.forward)
	}
	loadStore.mu.RUnlock()
	first, _, firstOK := loadStore.Lookup(scaleQname(1))
	last, _, lastOK := loadStore.Lookup(scaleQname(fakeIPScaleN))
	t.Logf("snapshot decode %d entries in %s (forward=%d first=%v lastOK=%v last=%v)", fakeIPScaleN, load, live, firstOK, lastOK, last)
	if !firstOK || !first.IsValid() {
		t.Fatal("reload lost first mapping")
	}
	if live < fakeIPScaleN/2 {
		t.Fatalf("reload forward too small: %d", live)
	}
}

func TestFakeIPStoreEvictLatency32768(t *testing.T) {
	prevSync := fakeIPFdatasync
	fakeIPFdatasync = func(int) error { return nil }
	defer func() { fakeIPFdatasync = prevSync }()

	const n = 32768
	const samples = 80
	dir := t.TempDir()
	store := NewFakeIPStore(dir, 1)
	store.maxLive = n + samples + 8
	store.maxBytes = max(2<<20, 64+store.maxLive*256)
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	v6 := netip.MustParsePrefix("fd00:daee::/96")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.fillSequentialLocked(t, n)

	hit := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		if _, _, _, err := store.Assign(scaleQname(1 + i%n)); err != nil {
			t.Fatal(err)
		}
		hit[i] = time.Since(start)
	}

	noEvict := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		if _, _, _, err := store.Assign("new-under-cap-" + strconv.Itoa(i) + ".example.com"); err != nil {
			t.Fatal(err)
		}
		noEvict[i] = time.Since(start)
	}

	store.mu.Lock()
	store.maxLive = n
	evictOnly := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		if err := store.evictIfNeededLocked(); err != nil {
			store.mu.Unlock()
			t.Fatal(err)
		}
		evictOnly[i] = time.Since(start)
		// put a dummy live slot back so the next sample still sees a full table
		for idx := range store.records {
			rec := store.records[idx]
			if rec.qname == "" || !rec.retired {
				continue
			}
			if rec.origin4 != store.active.inet4 {
				continue
			}
			store.records[idx].retired = false
			store.records[idx].retiredUnix = 0
			store.active.forward[rec.qname] = fakeIPInternID(idx)
			break
		}
	}
	store.mu.Unlock()

	withEvict := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		if _, _, _, err := store.Assign("new-at-cap-" + strconv.Itoa(i) + ".example.com"); err != nil {
			t.Fatal(err)
		}
		withEvict[i] = time.Since(start)
	}

	t.Logf("32768 existing-name Assign (no evict)     p50=%s p99=%s max=%s", durationPct(hit, 50), durationPct(hit, 99), durationMax(hit))
	t.Logf("32768 new-name Assign under cap            p50=%s p99=%s max=%s", durationPct(noEvict, 50), durationPct(noEvict, 99), durationMax(noEvict))
	t.Logf("32768 evictIfNeeded only                   p50=%s p99=%s max=%s", durationPct(evictOnly, 50), durationPct(evictOnly, 99), durationMax(evictOnly))
	t.Logf("32768 new-name Assign at cap (kick+alloc)  p50=%s p99=%s max=%s", durationPct(withEvict, 50), durationPct(withEvict, 99), durationMax(withEvict))
}

func TestFakeIPStoreAssignCostGrowsWithTable(t *testing.T) {
	prevSync := fakeIPFdatasync
	fakeIPFdatasync = func(int) error { return nil }
	defer func() { fakeIPFdatasync = prevSync }()

	for _, n := range []int{1_000, 5_000, 10_000} {
		n := n
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			dir := t.TempDir()
			s := NewFakeIPStore(dir, 1)
			s.maxLive = n + 8
			s.maxBytes = max(2<<20, 64+(n+8)*256)
			v4 := netip.MustParsePrefix("198.18.0.0/15")
			v6 := netip.MustParsePrefix("fd00:daee::/96")
			if err := s.Open(v4, v6); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			start := time.Now()
			for i := 1; i <= n; i++ {
				if _, _, _, err := s.Assign(scaleQname(i)); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("Assign %d from empty (fsync stubbed) %s (%.0f names/s)", n, time.Since(start), float64(n)/time.Since(start).Seconds())
		})
	}
}

func (s *FakeIPStore) fillSequentialLocked(t *testing.T, n int) netip.Addr {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	var first netip.Addr
	for i := 1; i <= n; i++ {
		qname := canonicalizeFakeIPQname(scaleQname(i))
		v4, err := fakeIPFromOffset(s.active.inet4, uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		v6, err := fakeIPFromOffset(s.active.inet6, uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			first = v4
		}
		id := s.internLocked(qname)
		s.seq++
		rec := fakeIPRecord{
			qname:       qname,
			ipv4:        v4,
			ipv6:        v6,
			origin4:     s.active.inet4,
			origin6:     s.active.inet6,
			updatedUnix: now,
			seq:         s.seq,
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
	}
	s.durable = s.seq
	return first
}

func scaleQname(i int) string {
	return "h" + strconv.Itoa(i) + ".example.com"
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1fKiB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1fMiB", float64(n)/(1024*1024))
}

func readVmRSS() string {
	body, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "n/a"
	}
	for _, line := range splitLines(body) {
		if len(line) >= 6 && string(line[:6]) == "VmRSS:" {
			return string(line)
		}
	}
	return "n/a"
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func durationPct(samples []time.Duration, pct int) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), samples...)
	// insertion-ish via durationP99's sort in persist test; keep local to avoid import cycles
	return percentileDuration(cp, pct)
}

func percentileDuration(cp []time.Duration, permilleOrPct int) time.Duration {
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	var idx int
	if permilleOrPct > 100 {
		idx = len(cp) * permilleOrPct / 1000
	} else {
		idx = len(cp) * permilleOrPct / 100
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	if idx < 0 {
		idx = 0
	}
	return cp[idx]
}

func durationMax(samples []time.Duration) time.Duration {
	var m time.Duration
	for _, d := range samples {
		if d > m {
			m = d
		}
	}
	return m
}
