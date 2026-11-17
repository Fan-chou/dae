/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

type fakeConnStateStore struct {
	mu      sync.Mutex
	entries map[bpfTuplesKey]bpfConnState
}

func newFakeConnStateStore() *fakeConnStateStore {
	return &fakeConnStateStore{entries: make(map[bpfTuplesKey]bpfConnState)}
}

func (f *fakeConnStateStore) LookupConnState(key *bpfTuplesKey, out *bpfConnState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	val, ok := f.entries[*key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*out = val
	return nil
}

func (f *fakeConnStateStore) UpdateConnState(key *bpfTuplesKey, val *bpfConnState, flags ebpf.MapUpdateFlags) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, exists := f.entries[*key]
	if flags == ebpf.UpdateExist && !exists {
		return ebpf.ErrKeyNotExist
	}
	f.entries[*key] = *val
	return nil
}

func (f *fakeConnStateStore) BatchDeleteConnState(keys []bpfTuplesKey) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	deleted := 0
	for _, k := range keys {
		if _, ok := f.entries[k]; ok {
			delete(f.entries, k)
			deleted++
		}
	}
	return deleted, nil
}

func (f *fakeConnStateStore) get(key bpfTuplesKey) (bpfConnState, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.entries[key]
	return v, ok
}

func TestReleaseFlowMarksProxiedConnStateClosingAndDeletesDirect(t *testing.T) {
	const nowNs uint64 = 50_000_000_000
	primaryMap := &ebpf.Map{}
	primaryStore := newFakeConnStateStore()

	manager := NewSessionManager(context.Background())
	defer manager.Close()
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: primaryMap}})
	manager.testConnStateOps = func(m *ebpf.Map) bpfConnStateStore {
		if m == primaryMap {
			return primaryStore
		}
		return nil
	}
	manager.testMonotonicNow = func() (uint64, error) {
		return nowNs, nil
	}

	runtime := newEgressRuntime(nil, nil)
	defer runtime.releaseOwner()

	src := netip.MustParseAddrPort("192.0.2.10:41001")
	dst := netip.MustParseAddrPort("198.51.100.10:443")
	proxiedKey := bpfTuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_TCP)
	unusedReverseKey := bpfTuplesKeyFromAddrPorts(dst, src, unix.IPPROTO_TCP)
	directKey := bpfTuplesKeyFromAddrPorts(netip.MustParseAddrPort("192.0.2.10:41002"), dst, unix.IPPROTO_TCP)
	unroutedKey := bpfTuplesKeyFromAddrPorts(netip.MustParseAddrPort("192.0.2.10:41003"), dst, unix.IPPROTO_TCP)

	var proxiedVal bpfConnState
	proxiedVal.LastSeenNs = 1_000_000_000
	proxiedVal.SeenNonSyn = 1
	proxiedVal.Meta.Data.HasRouting = 1
	proxiedVal.Meta.Data.Outbound = uint8(consts.OutboundUserDefinedMin)
	primaryStore.entries[proxiedKey] = proxiedVal

	var directVal bpfConnState
	directVal.LastSeenNs = 1_000_000_000
	directVal.SeenNonSyn = 1
	directVal.Meta.Data.HasRouting = 1
	directVal.Meta.Data.Outbound = uint8(consts.OutboundDirect)
	primaryStore.entries[directKey] = directVal

	var unroutedVal bpfConnState
	unroutedVal.LastSeenNs = 1_000_000_000
	unroutedVal.Meta.Data.HasRouting = 0
	unroutedVal.Meta.Data.Outbound = uint8(consts.OutboundUserDefinedMin)
	primaryStore.entries[unroutedKey] = unroutedVal

	proxiedFlow, err := manager.adoptTCP(
		&memoryLayoutConn{id: 101},
		nil,
		TcpFlowBinding{},
		runtime,
		[]bpfTuplesKey{proxiedKey, unusedReverseKey},
		src,
		dst,
	)
	if err != nil {
		t.Fatalf("adopt proxied flow: %v", err)
	}
	directFlow, err := manager.adoptTCP(
		&memoryLayoutConn{id: 102},
		nil,
		TcpFlowBinding{},
		runtime,
		[]bpfTuplesKey{directKey, unroutedKey},
		netip.MustParseAddrPort("192.0.2.10:41002"),
		dst,
	)
	if err != nil {
		t.Fatalf("adopt direct flow: %v", err)
	}

	proxiedFlow.finish()
	directFlow.finish()

	gotProxied, ok := primaryStore.get(proxiedKey)
	if !ok {
		t.Fatal("proxied conn_state entry was deleted on releaseFlow; want TCP_STATE_CLOSING cooldown")
	}
	if gotProxied.State != tcpConnStateClosing {
		t.Fatalf("proxied state = %d, want %d (tcpConnStateClosing)", gotProxied.State, tcpConnStateClosing)
	}
	if gotProxied.LastSeenNs != nowNs {
		t.Fatalf("proxied LastSeenNs = %d, want refreshed monotonic %d", gotProxied.LastSeenNs, nowNs)
	}
	if _, ok := primaryStore.get(unusedReverseKey); ok {
		t.Fatal("unused reverse key should not be created in conn_state_map")
	}
	if _, ok := primaryStore.get(directKey); ok {
		t.Fatal("OUTBOUND_DIRECT conn_state entry should be deleted immediately on releaseFlow")
	}
	if _, ok := primaryStore.get(unroutedKey); ok {
		t.Fatal("unrouted conn_state entry should be deleted immediately on releaseFlow")
	}
	if got := tcpConnStateExpireTimeoutNs(gotProxied.State, gotProxied.SeenNonSyn, 0, 0, false); got != tcpConnStateTimeoutClosing.Nanoseconds() {
		t.Fatalf("closing timeout = %d, want %d", got, tcpConnStateTimeoutClosing.Nanoseconds())
	}
}

func TestReleaseFlowRespectsSharedPinAndMigratedMaps(t *testing.T) {
	const nowNs uint64 = 75_000_000_000
	primaryMap := &ebpf.Map{}
	distinctMigratedMap := &ebpf.Map{}
	primaryStore := newFakeConnStateStore()
	migratedStore := newFakeConnStateStore()

	manager := NewSessionManager(context.Background())
	defer manager.Close()
	primaryBPF := &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: primaryMap}}
	migratedBPF := &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: distinctMigratedMap}}
	manager.udpBPF.Store(primaryBPF)
	manager.testConnStateOps = func(m *ebpf.Map) bpfConnStateStore {
		switch m {
		case primaryMap:
			return primaryStore
		case distinctMigratedMap:
			return migratedStore
		default:
			return nil
		}
	}
	manager.testMonotonicNow = func() (uint64, error) {
		return nowNs, nil
	}

	runtime := newEgressRuntime(nil, nil)
	defer runtime.releaseOwner()

	src := netip.MustParseAddrPort("192.0.2.11:42001")
	dst := netip.MustParseAddrPort("198.51.100.11:443")
	sharedKey := bpfTuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_TCP)
	uniqueKey := bpfTuplesKeyFromAddrPorts(netip.MustParseAddrPort("192.0.2.11:42002"), dst, unix.IPPROTO_TCP)

	var proxiedVal bpfConnState
	proxiedVal.LastSeenNs = 2_000_000_000
	proxiedVal.SeenNonSyn = 1
	proxiedVal.Meta.Data.HasRouting = 1
	proxiedVal.Meta.Data.Outbound = uint8(consts.OutboundUserDefinedMin)
	primaryStore.entries[sharedKey] = proxiedVal
	primaryStore.entries[uniqueKey] = proxiedVal
	migratedStore.entries[sharedKey] = proxiedVal
	migratedStore.entries[uniqueKey] = proxiedVal

	flowA, err := manager.adoptTCP(
		&memoryLayoutConn{id: 201},
		nil,
		TcpFlowBinding{},
		runtime,
		[]bpfTuplesKey{sharedKey, uniqueKey},
		src,
		dst,
	)
	if err != nil {
		t.Fatalf("adopt flowA: %v", err)
	}
	flowB, err := manager.adoptTCP(
		&memoryLayoutConn{id: 202},
		nil,
		TcpFlowBinding{},
		runtime,
		[]bpfTuplesKey{sharedKey},
		src,
		dst,
	)
	if err != nil {
		t.Fatalf("adopt flowB: %v", err)
	}

	// Simulate migration into both an alias of primaryBPF and a distinct map.
	flowA.repinConnStateMapsForRollback(primaryBPF)
	flowA.repinConnStateMapsForRollback(migratedBPF)

	// Releasing flowA leaves sharedKey pinned by flowB, while uniqueKey transitions
	// to TCP_STATE_CLOSING on both primaryMap and distinctMigratedMap without
	// being clobbered by the primaryBPF alias entry in flowA.migratedBpf.
	flowA.finish()

	gotShared, ok := primaryStore.get(sharedKey)
	if !ok || gotShared.State != 0 {
		t.Fatalf("sharedKey state while flowB still alive = %+v (exists=%v), want State=0 untouched", gotShared, ok)
	}
	if migShared, ok := migratedStore.get(sharedKey); !ok || migShared.State != 0 {
		t.Fatalf("migrated sharedKey state while flowB still alive = %+v (exists=%v), want State=0 untouched", migShared, ok)
	}

	for name, store := range map[string]*fakeConnStateStore{
		"primary":  primaryStore,
		"migrated": migratedStore,
	} {
		gotUnique, ok := store.get(uniqueKey)
		if !ok {
			t.Fatalf("%s store deleted uniqueKey instead of marking TCP_STATE_CLOSING", name)
		}
		if gotUnique.State != tcpConnStateClosing || gotUnique.LastSeenNs != nowNs {
			t.Fatalf("%s uniqueKey = %+v, want State=%d LastSeenNs=%d", name, gotUnique, tcpConnStateClosing, nowNs)
		}
	}

	flowB.finish()
	gotShared, ok = primaryStore.get(sharedKey)
	if !ok || gotShared.State != tcpConnStateClosing || gotShared.LastSeenNs != nowNs {
		t.Fatalf("sharedKey after flowB finish = %+v (exists=%v), want TCP_STATE_CLOSING at %d", gotShared, ok, nowNs)
	}
}

func TestReleaseFlowRealConnStateClosingAndJanitorExpire(t *testing.T) {
	f := newReloadRetirementCleanupFixture(t)
	f.manager.udpBPF.Store(f.plane.core.bpf.Load())

	nowNs, err := monotonicNowNano()
	if err != nil {
		t.Fatalf("monotonicNowNano: %v", err)
	}

	dst := netip.MustParseAddrPort("198.51.100.30:443")
	proxiedSrc := netip.MustParseAddrPort("192.0.2.30:43001")
	directSrc := netip.MustParseAddrPort("192.0.2.30:43002")
	proxiedKey := bpfTuplesKeyFromAddrPorts(proxiedSrc, dst, unix.IPPROTO_TCP)
	directKey := bpfTuplesKeyFromAddrPorts(directSrc, dst, unix.IPPROTO_TCP)

	var proxiedVal bpfConnState
	proxiedVal.LastSeenNs = nowNs - uint64(30*time.Second)
	proxiedVal.SeenNonSyn = 1
	proxiedVal.Meta.Data.HasRouting = 1
	proxiedVal.Meta.Data.Outbound = uint8(consts.OutboundUserDefinedMin)
	if err := f.connState.Update(&proxiedKey, &proxiedVal, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed proxied conn_state: %v", err)
	}

	var directVal bpfConnState
	directVal.LastSeenNs = nowNs - uint64(30*time.Second)
	directVal.SeenNonSyn = 1
	directVal.Meta.Data.HasRouting = 1
	directVal.Meta.Data.Outbound = uint8(consts.OutboundDirect)
	if err := f.connState.Update(&directKey, &directVal, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed direct conn_state: %v", err)
	}

	runtime := newEgressRuntime(nil, nil)
	defer runtime.releaseOwner()

	proxiedFlow, err := f.manager.adoptTCP(&memoryLayoutConn{id: 301}, nil, TcpFlowBinding{}, runtime, []bpfTuplesKey{proxiedKey}, proxiedSrc, dst)
	if err != nil {
		t.Fatalf("adopt proxied: %v", err)
	}
	directFlow, err := f.manager.adoptTCP(&memoryLayoutConn{id: 302}, nil, TcpFlowBinding{}, runtime, []bpfTuplesKey{directKey}, directSrc, dst)
	if err != nil {
		t.Fatalf("adopt direct: %v", err)
	}

	proxiedFlow.finish()
	directFlow.finish()

	if connStateExists(f.connState, directKey) {
		t.Fatal("direct TCP entry must be deleted immediately on finish")
	}
	var got bpfConnState
	if err := f.connState.Lookup(&proxiedKey, &got); err != nil {
		t.Fatalf("proxied entry missing after finish: %v", err)
	}
	if got.State != tcpConnStateClosing {
		t.Fatalf("proxied state = %d, want %d", got.State, tcpConnStateClosing)
	}
	if got.LastSeenNs < nowNs {
		t.Fatalf("proxied LastSeenNs = %d, want >= %d", got.LastSeenNs, nowNs)
	}

	// Janitor cleanup while within closing cooldown must keep the entry.
	f.plane.cleanupConnStateMapBeforeLocked(false, 0)
	if !connStateExists(f.connState, proxiedKey) {
		t.Fatal("fresh TCP_STATE_CLOSING entry must survive janitor before 10s timeout")
	}

	// Simulate expiration past tcpConnStateTimeoutClosing; janitor must reclaim it.
	got.LastSeenNs = nowNs - uint64(tcpConnStateTimeoutClosing+time.Second)
	if err := f.connState.Update(&proxiedKey, &got, ebpf.UpdateExist); err != nil {
		t.Fatalf("age closing entry: %v", err)
	}
	f.plane.cleanupConnStateMapBeforeLocked(false, 0)
	var lookupAfter bpfConnState
	if err := f.connState.Lookup(&proxiedKey, &lookupAfter); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("expired closing entry lookup err = %v, want ErrKeyNotExist", err)
	}
}
