//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	hotpathCrossing = 5 * time.Millisecond
	workerQueue     = 1024
)

func TestHotpathScaleFindCrossing(t *testing.T) {
	t.Run("simultaneous_projection", func(t *testing.T) {
		for _, n := range []int{32, 128, 512, 1024, 2048, 4096} {
			p50, p99, max := measureSimultaneousProjection(t, n)
			t.Logf("simultaneous n=%-4d p50=%8s p99=%8s max=%8s  cross5ms=%v",
				n, p50, p99, max, max >= hotpathCrossing)
			if max >= hotpathCrossing {
				t.Logf("first 5ms crossing: %d simultaneous unique domain projections", n)
				break
			}
		}
	})

	t.Run("sequential_tiny_batch", func(t *testing.T) {
		for _, n := range []int{32, 256, 1024, 4096, 8192, 16384} {
			elapsed := measureSequentialTinyBatches(t, n)
			per := elapsed / time.Duration(n)
			t.Logf("sequential 2-IP x%-5d total=%8s per=%8s  cross5ms=%v",
				n, elapsed, per, elapsed >= hotpathCrossing)
			if elapsed >= hotpathCrossing {
				t.Logf("first 5ms crossing: %d sequential 2-IP BatchUpdates (~DNS answers)", n)
				break
			}
		}
	})

	t.Run("janitor_occupancy", func(t *testing.T) {
		for _, n := range []int{2048, 8192, 16384, 32768, 65536} {
			if memAvailableKB() < 80*1024 && n >= 32768 {
				t.Logf("skip janitor n=%d: MemAvailable too low", n)
				break
			}
			elapsed, scanned := measureJanitorScan(t, n)
			t.Logf("janitor occupied=%-5d scanned=%-5d elapsed=%8s  cross50ms=%v",
				n, scanned, elapsed, elapsed >= 50*time.Millisecond)
			if elapsed >= 50*time.Millisecond {
				t.Logf("janitor scan reaches 50ms around %d entries", n)
				break
			}
		}
	})

	t.Run("sixty_second_force_queue", func(t *testing.T) {
		for _, hot := range []int{50, 200, 1024, 2048, 8192, 16384} {
			overflow := 0
			if hot > workerQueue {
				overflow = hot - workerQueue
			}
			t.Logf("hot names=%-5d force/min=%-5d queue=1024 overflow=%-5d",
				hot, hot, overflow)
		}
	})
}

func TestHotpathMapMemlockScale(t *testing.T) {
	requireMemlock(t)
	avail := memAvailableKB()
	t.Logf("MemAvailable=%d kB; maps are private test objects, not Clash TUN", avail)

	sizes := []uint32{1024, 4096, 16384, 65536}
	if avail > 400*1024 {
		sizes = append(sizes, 262144)
	}

	t.Run("conn_state", func(t *testing.T) {
		for _, max := range sizes {
			emptyNo, filledNo := measureHashMemlock(t, max, unix.BPF_F_NO_PREALLOC, true)
			emptyPre, _ := measureHashMemlock(t, max, 0, false)
			t.Logf("conn_state max=%-6d  no_prealloc empty=%s fill10%%=%s  prealloc empty=%s",
				max, formatBytes(emptyNo), formatBytes(filledNo), formatBytes(emptyPre))
		}
	})

	t.Run("domain_routing", func(t *testing.T) {
		for _, max := range []uint32{1024, 4096, 16384, 65536, 131072} {
			if memAvailableKB() < 120*1024 && max >= 65536 {
				t.Logf("skip domain_routing max=%d: MemAvailable too low", max)
				break
			}
			emptyNo, filledNo := measureDomainRoutingMemlock(t, max, unix.BPF_F_NO_PREALLOC, true)
			emptyPre, _ := measureDomainRoutingMemlock(t, max, 0, false)
			t.Logf("domain_routing max=%-6d  no_prealloc empty=%s fill10%%=%s  prealloc empty=%s",
				max, formatBytes(emptyNo), formatBytes(filledNo), formatBytes(emptyPre))
		}
	})

	t.Run("tracker_userspace", func(t *testing.T) {
		for _, n := range []int{1024, 4096, 16384, 32768} {
			if memAvailableKB() < 100*1024 && n >= 16384 {
				t.Logf("skip tracker n=%d: MemAvailable too low", n)
				break
			}
			delta := measureTrackerHeap(t, n)
			t.Logf("tracker owners=%-5d heap_delta=%s  x2 slots≈%s",
				n, formatBytes(delta), formatBytes(delta*2))
		}
	})
}

func measureSimultaneousProjection(t *testing.T, n int) (p50, p99, max time.Duration) {
	t.Helper()
	maxEntries := uint32(n * 2)
	if maxEntries < 64 {
		maxEntries = 64
	}
	m := newHotpathDomainRoutingMap(t, maxEntries)
	tracker := newDomainRoutingTracker()
	caches := make([]*DnsCache, n)
	for i := range caches {
		caches[i] = domainRoutingACache(
			fmt.Sprintf("scale-%d.example.:1", i),
			fmt.Sprintf("198.51.%d.%d", (i/254)%256, i%254+1),
			domainRoutingBitmap(0x1),
		)
	}
	latencies := make([]time.Duration, n)
	var ready, start, done sync.WaitGroup
	ready.Add(n)
	start.Add(1)
	done.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			start.Wait()
			begin := time.Now()
			if err := projectDomainRoutingToMap(tracker, m, 0, caches[i]); err != nil {
				t.Errorf("n=%d i=%d: %v", n, i, err)
			}
			latencies[i] = time.Since(begin)
		}(i)
	}
	ready.Wait()
	start.Done()
	done.Wait()
	return durationPercentiles(latencies)
}

func measureSequentialTinyBatches(t *testing.T, n int) time.Duration {
	t.Helper()
	m := newHotpathDomainRoutingMap(t, uint32(n+8))
	keys := make([]bpfRoutingEpochIp, n)
	values := make([]bpfDomainRouting, n)
	for i := range keys {
		keys[i] = bpfRoutingEpochIp{Slot: 0, Addr: [4]uint32{uint32(i + 1), uint32(i/65536 + 1), 0, 0}}
		values[i].Bitmap[0] = 1
	}
	start := time.Now()
	for i := 0; i < n; i += 2 {
		end := i + 2
		if end > n {
			end = n
		}
		if _, err := BpfMapBatchUpdate(m, keys[i:end], values[i:end], &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}); err != nil {
			t.Fatalf("sequential n=%d i=%d: %v", n, i, err)
		}
	}
	return time.Since(start)
}

func measureJanitorScan(t *testing.T, occupied int) (time.Duration, int) {
	t.Helper()
	m := newHotpathConnStateMap(t, uint32(occupied*2))
	fillConnStateMapBatch(t, m, occupied)
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
	return time.Since(start), seen
}

func fillConnStateMapBatch(t *testing.T, m *ebpf.Map, n int) {
	t.Helper()
	const chunk = 256
	keys := make([]bpfTuplesKey, chunk)
	vals := make([]bpfConnState, chunk)
	for off := 0; off < n; off += chunk {
		batch := chunk
		if off+batch > n {
			batch = n - off
		}
		for i := 0; i < batch; i++ {
			idx := off + i
			keys[i] = bpfTuplesKey{}
			keys[i].Sip.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, byte(idx >> 16), byte(idx >> 8), byte(idx)}
			keys[i].Dip.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 203, 0, 113, 1}
			keys[i].Sport = uint16(10000 + idx%50000)
			keys[i].Dport = 443
			keys[i].L4proto = unix.IPPROTO_TCP
		}
		if _, err := BpfMapBatchUpdate(m, keys[:batch], vals[:batch], &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}); err != nil {
			t.Fatalf("fill conn_state %d: %v", off, err)
		}
	}
}

func measureHashMemlock(t *testing.T, maxEntries uint32, flags uint32, fill bool) (empty, filled uint64) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kdae_ml_cs",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(bpfTuplesKey{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfConnState{})),
		MaxEntries: maxEntries,
		Flags:      flags,
	})
	if err != nil {
		t.Logf("NewMap conn_state max=%d flags=%d: %v", maxEntries, flags, err)
		return 0, 0
	}
	defer func() { _ = m.Close() }()
	empty = readMapMemlock(t, m)
	if fill {
		n := int(maxEntries / 10)
		if n < 1 {
			n = 1
		}
		if n > 4096 {
			n = 4096
		}
		fillConnStateMapBatch(t, m, n)
		filled = readMapMemlock(t, m)
	}
	return empty, filled
}

func measureDomainRoutingMemlock(t *testing.T, maxEntries uint32, flags uint32, fill bool) (empty, filled uint64) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kdae_ml_dr",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(bpfRoutingEpochIp{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfDomainRouting{})),
		MaxEntries: maxEntries,
		Flags:      flags,
	})
	if err != nil {
		t.Logf("NewMap domain_routing max=%d flags=%d: %v", maxEntries, flags, err)
		return 0, 0
	}
	defer func() { _ = m.Close() }()
	empty = readMapMemlock(t, m)
	if fill {
		n := int(maxEntries / 10)
		if n > 2048 {
			n = 2048
		}
		keys := make([]bpfRoutingEpochIp, n)
		vals := make([]bpfDomainRouting, n)
		for i := 0; i < n; i++ {
			keys[i] = bpfRoutingEpochIp{Slot: 0, Addr: [4]uint32{uint32(i + 1), 1, 0, 0}}
			vals[i].Bitmap[0] = 1
		}
		if _, err := BpfMapBatchUpdate(m, keys, vals, &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)}); err != nil {
			t.Logf("fill domain_routing: %v", err)
		}
		filled = readMapMemlock(t, m)
	}
	return empty, filled
}

func measureTrackerHeap(t *testing.T, n int) uint64 {
	t.Helper()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	tracker := newDomainRoutingTracker()
	for i := 0; i < n; i++ {
		cache := domainRoutingACache(
			fmt.Sprintf("heap-%d.example.:1", i),
			fmt.Sprintf("203.0.%d.%d", (i/254)%256, i%254+1),
			domainRoutingBitmap(0x1),
		)
		if err := projectDomainRoutingToMap(tracker, nil, 0, cache); err != nil {
			t.Fatalf("tracker heap n=%d i=%d: %v", n, i, err)
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

func readMapMemlock(t *testing.T, m *ebpf.Map) uint64 {
	t.Helper()
	info, err := m.Info()
	if err != nil {
		t.Fatalf("map info: %v", err)
	}
	n, ok := info.Memlock()
	if !ok {
		return 0
	}
	return n
}

func memAvailableKB() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		return v
	}
	return 0
}

func formatBytes(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/float64(1<<10))
	case n == 0:
		return "n/a"
	default:
		return fmt.Sprintf("%dB", n)
	}
}
