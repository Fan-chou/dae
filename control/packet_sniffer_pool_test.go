/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPacketSnifferFlowFamilyReleaseRemovesLastEntry(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.10:40000"),
		mustParseAddrPort("198.51.100.20:443"),
		makeLikelyQuicInitialPayload(0x51),
	)

	pool.retainFlowFamily(key)
	if !pool.HasFlowFamilySession(key) {
		t.Fatal("expected retained flow family session to be visible")
	}

	pool.releaseFlowFamily(key)
	if pool.HasFlowFamilySession(key) {
		t.Fatal("expected released flow family session to disappear")
	}
	if _, ok := pool.flowFamilies.Load(key.FlowFamilyKey()); ok {
		t.Fatal("expected last flow family entry to be removed from the map")
	}
}

func TestPacketSnifferFlowFamilyReleaseKeepsEntryWhileRefsRemain(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.12:40002"),
		mustParseAddrPort("198.51.100.22:443"),
		makeLikelyQuicInitialPayload(0x71),
	)

	pool.retainFlowFamily(key)
	pool.retainFlowFamily(key)
	pool.releaseFlowFamily(key)

	if !pool.HasFlowFamilySession(key) {
		t.Fatal("expected flow family session to remain after releasing one of two refs")
	}
	value, ok := pool.flowFamilies.Load(key.FlowFamilyKey())
	if !ok {
		t.Fatal("expected flow family entry to stay in the map while refs remain")
	}
	if got := value.(*packetSnifferFlowFamilyRef).refs.Load(); got != 1 {
		t.Fatalf("refs = %d, want 1", got)
	}
}

func TestPacketSnifferFlowFamilyRetainReplacesDrainingEntry(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.11:40001"),
		mustParseAddrPort("198.51.100.21:443"),
		makeLikelyQuicInitialPayload(0x61),
	)

	draining := &packetSnifferFlowFamilyRef{}
	draining.refs.Store(packetSnifferFlowFamilyRefDraining)
	pool.flowFamilies.Store(key.FlowFamilyKey(), draining)

	pool.retainFlowFamily(key)

	value, ok := pool.flowFamilies.Load(key.FlowFamilyKey())
	if !ok {
		t.Fatal("expected retainFlowFamily to restore the flow family entry")
	}
	ref := value.(*packetSnifferFlowFamilyRef)
	if ref == draining {
		t.Fatal("expected retainFlowFamily to replace the draining entry")
	}
	if got := ref.refs.Load(); got != 1 {
		t.Fatalf("refs = %d, want 1", got)
	}
}

func TestPacketSnifferPool_GetOrCreateRegistersFlowFamilyMembers(t *testing.T) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	src := mustParseAddrPort("192.0.2.31:41001")
	dst := mustParseAddrPort("198.51.100.31:443")
	key1 := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(0x21))
	key2 := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(0x41))

	sniffer1, isNew := pool.GetOrCreate(key1, nil)
	if !isNew || sniffer1 == nil {
		t.Fatal("expected first GetOrCreate to create a sniffer")
	}
	sniffer2, isNew := pool.GetOrCreate(key2, nil)
	if !isNew || sniffer2 == nil {
		t.Fatal("expected second GetOrCreate to create a second sniffer")
	}

	family := pool.loadFlowFamily(key1)
	if family == nil {
		t.Fatal("expected flow family index to exist")
	}
	entries := family.snapshotMembers()
	if len(entries) != 2 {
		t.Fatalf("flow family member count = %d, want 2", len(entries))
	}

	got := map[PacketSnifferKey]*PacketSniffer{}
	for _, entry := range entries {
		got[entry.key] = entry.sniffer
	}
	if got[key1] != sniffer1 {
		t.Fatal("expected flow family index to include first sniffer")
	}
	if got[key2] != sniffer2 {
		t.Fatal("expected flow family index to include second sniffer")
	}
}

func TestPacketSnifferPool_RemoveFlowFamilySessionsRemovesOnlyMatchingFamily(t *testing.T) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	src := mustParseAddrPort("192.0.2.41:42001")
	dst := mustParseAddrPort("198.51.100.41:443")
	otherSrc := mustParseAddrPort("192.0.2.42:42002")
	otherDst := mustParseAddrPort("198.51.100.42:443")

	key1 := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(0x51))
	key2 := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(0x61))
	keyOther := NewPacketSnifferKey(otherSrc, otherDst, makeLikelyQuicInitialPayload(0x71))

	if _, isNew := pool.GetOrCreate(key1, nil); !isNew {
		t.Fatal("expected first family member to be created")
	}
	if _, isNew := pool.GetOrCreate(key2, nil); !isNew {
		t.Fatal("expected second family member to be created")
	}
	if _, isNew := pool.GetOrCreate(keyOther, nil); !isNew {
		t.Fatal("expected other-family member to be created")
	}

	removed := pool.RemoveFlowFamilySessions(key1)
	if removed != 2 {
		t.Fatalf("RemoveFlowFamilySessions() removed %d entries, want 2", removed)
	}
	if got := pool.Get(key1); got != nil {
		t.Fatal("expected first same-family sniffer to be removed")
	}
	if got := pool.Get(key2); got != nil {
		t.Fatal("expected second same-family sniffer to be removed")
	}
	if got := pool.Get(keyOther); got == nil {
		t.Fatal("expected other-family sniffer to remain")
	}
	if pool.HasFlowFamilySession(key1) {
		t.Fatal("expected removed flow family session to disappear")
	}
	if !pool.HasFlowFamilySession(keyOther) {
		t.Fatal("expected unrelated flow family session to remain")
	}
	if _, ok := pool.flowFamilies.Load(key1.FlowFamilyKey()); ok {
		t.Fatal("expected removed flow family entry to be deleted")
	}
	if _, ok := pool.flowFamilies.Load(keyOther.FlowFamilyKey()); !ok {
		t.Fatal("expected unrelated flow family entry to remain")
	}
}

func TestPacketSnifferInitialPacketBudget(t *testing.T) {
	ps := &PacketSniffer{}
	for i := 1; i <= maxInitialSniffPackets; i++ {
		if !ps.RecordQuicInitialPacket() {
			t.Fatalf("packet %d should still be sniffed", i)
		}
	}
	if ps.RecordQuicInitialPacket() {
		t.Fatal("packet after budget must not keep holding")
	}
	if ps.quicInitialPackets != maxInitialSniffPackets+1 {
		t.Fatalf("counted %d, want %d", ps.quicInitialPackets, maxInitialSniffPackets+1)
	}
}

func BenchmarkPacketSnifferPool_ObserveFlowFamilyQuicInitial(b *testing.B) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	targetSrc := mustParseAddrPort("192.0.2.51:43001")
	targetDst := mustParseAddrPort("198.51.100.51:443")
	targetPayload := makeLikelyQuicInitialPayload(0x81)
	targetKey := NewPacketSnifferKey(targetSrc, targetDst, targetPayload)

	if _, isNew := pool.GetOrCreate(targetKey, nil); !isNew {
		b.Fatal("expected target sniffer to be created")
	}

	for i := 0; i < 2048; i++ {
		src := mustParseAddrPort(fmt.Sprintf("192.0.2.60:%d", 44000+i))
		dst := mustParseAddrPort(fmt.Sprintf("198.51.100.60:%d", 45000+i))
		key := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(byte(i%200+1)))
		if _, isNew := pool.GetOrCreate(key, nil); !isNew {
			b.Fatalf("expected unrelated sniffer %d to be created", i)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		observed, changed := pool.ObserveFlowFamilyQuicInitial(targetKey, targetPayload)
		if !observed || changed {
			b.Fatalf("ObserveFlowFamilyQuicInitial() = (%v, %v), want (true, false)", observed, changed)
		}
	}
}

func BenchmarkPacketSnifferPool_RemoveFlowFamilySessions(b *testing.B) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	targetSrc := mustParseAddrPort("192.0.2.71:46001")
	targetDst := mustParseAddrPort("198.51.100.71:443")

	for i := 0; i < 2048; i++ {
		src := mustParseAddrPort(fmt.Sprintf("192.0.2.80:%d", 47000+i))
		dst := mustParseAddrPort(fmt.Sprintf("198.51.100.80:%d", 48000+i))
		key := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(byte(i%200+1)))
		if _, isNew := pool.GetOrCreate(key, nil); !isNew {
			b.Fatalf("expected unrelated sniffer %d to be created", i)
		}
	}

	repopulate := func() PacketSnifferKey {
		var firstKey PacketSnifferKey
		for i := 0; i < 4; i++ {
			key := NewPacketSnifferKey(targetSrc, targetDst, makeLikelyQuicInitialPayload(byte(0xa0+i)))
			if i > 0 {
				key.DCID[0] += byte(i)
			}
			if _, isNew := pool.GetOrCreate(key, nil); !isNew {
				b.Fatalf("expected target sniffer %d to be created", i)
			}
			if i == 0 {
				firstKey = key
			}
		}
		return firstKey
	}

	key := repopulate()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		removed := pool.RemoveFlowFamilySessions(key)
		if removed != 4 {
			b.Fatalf("RemoveFlowFamilySessions() removed %d entries, want 4", removed)
		}

		b.StopTimer()
		key = repopulate()
		b.StartTimer()
	}
}

func TestPacketSnifferCloseDetachesInnerSniffer(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.10:40000"),
		mustParseAddrPort("198.51.100.20:443"),
		makeLikelyQuicInitialPayload(0x61),
	)
	ps, _ := pool.GetOrCreate(key, nil)
	ps.AppendData(makeLikelyQuicInitialPayload(0x61))
	if err := ps.Close(); err != nil {
		t.Fatal(err)
	}
	if ps.Sniffer != nil {
		t.Fatal("Close must detach the inner sniffer before the struct is recycled")
	}
	ps.AppendData(makeLikelyQuicInitialPayload(0x62))
	_, _ = ps.SniffUdp()
}

func TestRetireExpiredPacketSnifferSkipsBusyAndRefreshed(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.10:40010"),
		mustParseAddrPort("198.51.100.20:443"),
		makeLikelyQuicInitialPayload(0x71),
	)
	ps, _ := pool.GetOrCreate(key, nil)
	ps.expiresAtNano.Store(1)
	ps.Mu.Lock()
	if pool.retireExpiredPacketSniffer(key, ps, time.Now().UnixNano()) {
		t.Fatal("busy sniffer must not be retired")
	}
	ps.Mu.Unlock()
	if got := pool.Get(key); got != ps {
		t.Fatal("busy sniffer must stay in the pool")
	}

	ps.RefreshTtl()
	if pool.retireExpiredPacketSniffer(key, ps, time.Now().UnixNano()) {
		t.Fatal("refreshed sniffer must not be retired")
	}

	ps.expiresAtNano.Store(1)
	if !pool.retireExpiredPacketSniffer(key, ps, time.Now().UnixNano()) {
		t.Fatal("expired idle sniffer must retire")
	}
	if pool.Get(key) != nil {
		t.Fatal("retired sniffer must leave the pool")
	}
	if ps.Sniffer != nil {
		t.Fatal("retire must detach the inner sniffer")
	}
}

func TestGetOrCreateDoesNotReturnSnifferClosedByJanitor(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.10:40011"),
		mustParseAddrPort("198.51.100.20:443"),
		makeLikelyQuicInitialPayload(0x81),
	)
	ps, isNew := pool.GetOrCreate(key, nil)
	if !isNew || ps == nil || ps.Sniffer == nil {
		t.Fatal("expected a live sniffer")
	}
	ps.expiresAtNano.Store(1)
	ps.Mu.Lock()
	started := make(chan struct{})
	done := make(chan *PacketSniffer, 1)
	go func() {
		close(started)
		got, _ := pool.GetOrCreate(key, nil)
		done <- got
	}()
	<-started
	time.Sleep(20 * time.Millisecond)

	if !pool.pool.CompareAndDelete(key, ps) {
		ps.Mu.Unlock()
		t.Fatal("expected to delete the expired sniffer under Mu")
	}
	_ = ps.closeLocked()
	ps.Mu.Unlock()

	select {
	case got := <-done:
		if got == ps {
			t.Fatal("GetOrCreate must not return the sniffer the janitor just closed")
		}
		if got == nil || got.Sniffer == nil {
			t.Fatal("replacement sniffer must still be live")
		}
		if pool.Get(key) != got {
			t.Fatal("GetOrCreate must return the pooled member, not a detached sniffer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetOrCreate blocked after janitor released Mu")
	}
}

func TestGetOrCreateReplacesClosedPooledSniffer(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.10:40012"),
		mustParseAddrPort("198.51.100.20:443"),
		makeLikelyQuicInitialPayload(0x91),
	)
	ps, isNew := pool.GetOrCreate(key, nil)
	if !isNew || ps == nil || ps.Sniffer == nil {
		t.Fatal("expected a live sniffer")
	}
	if err := ps.Close(); err != nil {
		t.Fatal(err)
	}
	if pool.Get(key) != ps {
		t.Fatal("Close must not itself remove the pooled sniffer")
	}
	got, _ := pool.GetOrCreate(key, nil)
	if got == ps {
		t.Fatal("GetOrCreate must not return a closed pooled sniffer")
	}
	if pool.Get(key) != got {
		t.Fatal("GetOrCreate must return the pooled member, not a detached sniffer")
	}
	if got == nil || got.Sniffer == nil {
		t.Fatal("replacement sniffer must be live")
	}
}

func TestGetOrCreateReturnsPooledMemberAfterRepeatedReplaces(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.10:40013"),
		mustParseAddrPort("198.51.100.20:443"),
		makeLikelyQuicInitialPayload(0xa1),
	)
	for i := 0; i < 32; i++ {
		got, _ := pool.GetOrCreate(key, nil)
		if pool.Get(key) != got {
			t.Fatalf("iteration %d: GetOrCreate returned a sniffer that is not the pool member", i)
		}
		if got == nil || got.Sniffer == nil {
			t.Fatalf("iteration %d: replacement sniffer must be live", i)
		}
		if err := got.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGetOrCreateConcurrentReturnsSamePooledMember(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.10:40014"),
		mustParseAddrPort("198.51.100.20:443"),
		makeLikelyQuicInitialPayload(0xb1),
	)
	const n = 32
	got := make([]*PacketSniffer, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			qs, _ := pool.GetOrCreate(key, nil)
			got[i] = qs
		}(i)
	}
	wg.Wait()
	first := pool.Get(key)
	if first == nil || first.Sniffer == nil {
		t.Fatal("pool must hold a live sniffer")
	}
	for i, qs := range got {
		if qs != first {
			t.Fatalf("goroutine %d got %p, want pooled %p", i, qs, first)
		}
	}
}
