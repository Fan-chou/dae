//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Steady LAN numbers are taken from 222/223: a handful of parallel DNS
// answers (page load / app refresh), not a synthetic 500-domain burst.
// Failures here mean the main path would feel it. Burst subtests only log.
const (
	hotpathDatapathP99 = 5 * time.Millisecond
	hotpathReloadSlack = 200 * time.Millisecond
)

func TestDomainRoutingProjectionSteadyLAN(t *testing.T) {
	m := newHotpathDomainRoutingMap(t, 4096)
	tracker := newDomainRoutingTracker()

	const (
		owners  = 32
		workers = 8
	)
	caches := make([]*DnsCache, owners)
	for i := range caches {
		caches[i] = domainRoutingACache(
			fmt.Sprintf("lan-%d.example.:1", i),
			fmt.Sprintf("203.0.113.%d", i+1),
			domainRoutingBitmap(0x1),
		)
	}

	latencies := make([]time.Duration, owners)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(worker int) {
			defer wg.Done()
			for i := worker; i < owners; i += workers {
				start := time.Now()
				if err := projectDomainRoutingToMap(tracker, m, 0, caches[i]); err != nil {
					t.Errorf("project %s: %v", caches[i].RouteOwnerKey, err)
					return
				}
				latencies[i] = time.Since(start)
			}
		}(w)
	}
	wg.Wait()

	p50, p99, max := durationPercentiles(latencies)
	t.Logf("steady LAN 32 owners / 8 workers: p50=%s p99=%s max=%s", p50, p99, max)
	if p99 > hotpathDatapathP99 {
		t.Fatalf("p99 %s exceeds %s; DNS projection would stall the main path", p99, hotpathDatapathP99)
	}
}

func TestDomainRoutingProjectionBurstOnlyLogs(t *testing.T) {
	m := newHotpathDomainRoutingMap(t, 4096)
	tracker := newDomainRoutingTracker()

	const owners = 64
	latencies := make([]time.Duration, owners)
	var wg sync.WaitGroup
	wg.Add(owners)
	for i := 0; i < owners; i++ {
		go func(i int) {
			defer wg.Done()
			cache := domainRoutingACache(
				fmt.Sprintf("burst-%d.example.:1", i),
				fmt.Sprintf("198.51.100.%d", i+1),
				domainRoutingBitmap(0x2),
			)
			start := time.Now()
			if err := projectDomainRoutingToMap(tracker, m, 0, cache); err != nil {
				t.Errorf("burst project: %v", err)
				return
			}
			latencies[i] = time.Since(start)
		}(i)
	}
	wg.Wait()

	p50, p99, max := durationPercentiles(latencies)
	t.Logf("synthetic 64-way burst (not LAN-normal): p50=%s p99=%s max=%s", p50, p99, max)
	if p99 > hotpathDatapathP99 {
		t.Logf("burst p99 %s > %s: lock-across-syscall can serialize under a storm, but this is not the steady path",
			p99, hotpathDatapathP99)
	}
}

func TestBpfBatchUpdateTinyVsCoalesced(t *testing.T) {
	m := newHotpathDomainRoutingMap(t, 4096)

	const n = 32
	keys := make([]bpfRoutingEpochIp, n)
	values := make([]bpfDomainRouting, n)
	for i := range keys {
		keys[i] = bpfRoutingEpochIp{Slot: 0, Addr: [4]uint32{uint32(i + 1), 0, 0, 0}}
		values[i].Bitmap[0] = 1
	}

	oneKeys := keys[:2:2]
	oneVals := values[:2:2]
	start := time.Now()
	if _, err := BpfMapBatchUpdate(m, oneKeys, oneVals, &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}); err != nil {
		t.Fatalf("tiny batch: %v", err)
	}
	tiny := time.Since(start)

	start = time.Now()
	for i := 0; i < n; i += 2 {
		if _, err := BpfMapBatchUpdate(m, keys[i:i+2], values[i:i+2], &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}); err != nil {
			t.Fatalf("sequential tiny batch %d: %v", i, err)
		}
	}
	sequential := time.Since(start)

	start = time.Now()
	if _, err := BpfMapBatchUpdate(m, keys, values, &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}); err != nil {
		t.Fatalf("coalesced batch: %v", err)
	}
	coalesced := time.Since(start)

	t.Logf("2-IP BatchUpdate=%s; 32 sequential 2-IP=%s; one 32-IP=%s", tiny, sequential, coalesced)
	// A page-load of 32 DNS answers is still well under a DNS RTT. Fail only
	// if the sequential path itself would be user-visible.
	if sequential > hotpathDatapathP99*2 {
		t.Fatalf("32 sequential tiny BatchUpdates took %s; coalescing would matter on the main path", sequential)
	}
	if coalesced > sequential && sequential > tiny*8 {
		t.Logf("coalescing was not cheaper (%s vs %s); do not change the 1-4 IP DNS path for this",
			coalesced, sequential)
	}
}

func TestLpmMapCreateMaxEntriesCost(t *testing.T) {
	requireMemlock(t)

	const cidrs = 64
	keys := make([]_bpfLpmKey, cidrs)
	values := make([]uint32, cidrs)
	for i := range keys {
		prefix := netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i))
		keys[i] = cidrToBpfLpmKey(prefix)
		values[i] = 1
	}

	fitted, err := createAndFillLpm(uint32(cidrs), keys, values)
	if err != nil {
		t.Fatalf("fitted LPM: %v", err)
	}
	defer func() { _ = fitted.Close() }()

	start := time.Now()
	fitted2, err := createAndFillLpm(uint32(cidrs), keys, values)
	if err != nil {
		t.Fatalf("fitted LPM recreate: %v", err)
	}
	_ = fitted2.Close()
	fittedCost := time.Since(start)

	start = time.Now()
	oversized, err := createAndFillLpm(2048000, keys, values)
	if err != nil {
		t.Skipf("oversized LPM MaxEntries=2048000 not creatable here: %v", err)
	}
	_ = oversized.Close()
	oversizedCost := time.Since(start)

	delta := oversizedCost - fittedCost
	if delta < 0 {
		delta = 0
	}
	const typicalTries = 16
	t.Logf("LPM 64 CIDRs: MaxEntries=%d create+fill=%s; MaxEntries=2048000 create+fill=%s (delta=%s, x%d tries≈%s)",
		cidrs, fittedCost, oversizedCost, delta, typicalTries, delta*typicalTries)

	if delta*typicalTries > hotpathReloadSlack {
		t.Fatalf("16 oversized LPM creates add %s (> %s); this would dominate reload",
			delta*typicalTries, hotpathReloadSlack)
	}
}

func TestConnStateJanitorScanSteadyOccupancy(t *testing.T) {
	m := newHotpathConnStateMap(t, 8192)
	const occupied = 2048
	populateConnStateMapForScan(t, m, occupied)

	keysOut := make([]bpfTuplesKey, janitorBatchLookupSize)
	valuesOut := make([]bpfConnState, janitorBatchLookupSize)

	start := time.Now()
	var cursor ebpf.MapBatchCursor
	seen := 0
	for {
		count, err := m.BatchLookup(&cursor, keysOut, valuesOut, nil)
		seen += count
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)
	t.Logf("janitor BatchLookup %d entries (batch=%d): %s", seen, janitorBatchLookupSize, elapsed)
	if seen < occupied {
		t.Fatalf("scanned %d, want at least %d", seen, occupied)
	}
	// Janitor runs every 5s in steady state. A 2k-entry scan that takes tens
	// of milliseconds is background noise, not a datapath stall.
	if elapsed > 50*time.Millisecond {
		t.Fatalf("steady occupancy scan took %s; janitor would contend with the main path", elapsed)
	}
}

func projectDomainRoutingToMap(
	tracker *domainRoutingTracker,
	m *ebpf.Map,
	slot uint32,
	cache *DnsCache,
) error {
	snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
	if err != nil {
		return err
	}
	return tracker.syncOwnerForSlot(m, slot, cache.RouteOwnerKey, snapshot)
}

func newHotpathDomainRoutingMap(t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()
	requireMemlock(t)
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kdae_hot_dr",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(bpfRoutingEpochIp{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfDomainRouting{})),
		MaxEntries: maxEntries,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		t.Skipf("creating domain routing hash requires BPF: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func newHotpathConnStateMap(t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()
	requireMemlock(t)
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kdae_hot_cs",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(bpfTuplesKey{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfConnState{})),
		MaxEntries: maxEntries,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		t.Skipf("creating conn_state hash requires BPF: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func populateConnStateMapForScan(t *testing.T, m *ebpf.Map, n int) {
	t.Helper()
	var value bpfConnState
	for i := 0; i < n; i++ {
		var key bpfTuplesKey
		key.Sip.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, byte(i)}
		key.Dip.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 203, 0, 113, 1}
		key.Sport = uint16(10000 + i)
		key.Dport = 443
		key.L4proto = unix.IPPROTO_TCP
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate conn_state %d: %v", i, err)
		}
	}
}

func createAndFillLpm(maxEntries uint32, keys []_bpfLpmKey, values []uint32) (*ebpf.Map, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kdae_hot_lpm",
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(_bpfLpmKey{})),
		ValueSize:  4,
		MaxEntries: maxEntries,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		return nil, err
	}
	if _, err = BpfMapBatchUpdate(m, keys, values, &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

func requireMemlock(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
}

func durationPercentiles(samples []time.Duration) (p50, p99, max time.Duration) {
	if len(samples) == 0 {
		return 0, 0, 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p50 = sorted[len(sorted)*50/100]
	p99idx := len(sorted)*99/100
	if p99idx >= len(sorted) {
		p99idx = len(sorted) - 1
	}
	p99 = sorted[p99idx]
	max = sorted[len(sorted)-1]
	return p50, p99, max
}
