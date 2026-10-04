// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testRebuildSlot(m *SessionManager, id uint64) (*UdpEndpoint, *udpRebuildPeer, udpRebuildKey) {
	ue := &UdpEndpoint{rebuildLineage: id, rebuildRevision: 1}
	peer := netip.MustParseAddrPort("192.0.2.1:1234")
	s := &udpRebuildPeer{peer: peer, original: peer, lineageID: id, manager: m, changed: make(chan struct{})}
	s.owner.Store(&udpRebuildOwnership{endpoint: ue, revision: 1})
	return ue, s, udpRebuildKey{src: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(1000+id)), peer: peer, original: peer, group: "game"}
}

func TestUDPRebuildLedgerSingleTicketAndRefund(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	l := m.rebuildLedger()
	now := time.Now()
	old, slot, key := testRebuildSlot(m, 1)
	var accepted atomic.Int32
	var ticket *udpRebuildTicket
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if t, reason := l.reserve(key, slot, old, now); reason == "" {
				ticket = t
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("duplicate concurrent tickets")
	}
	l.finish(ticket, "cancelled_before_dial")
	if s := l.snapshot(now); s.AttemptsInWindow != 0 || s.Reserved != 0 {
		t.Fatalf("pre-dial cancellation spent budget: %+v", s)
	}
	ticket, _ = l.reserve(key, slot, old, now)
	if !l.start(ticket, now) || l.start(ticket, now) {
		t.Fatal("attempt not exactly once")
	}
	l.finish(ticket, "cancelled_after_dial")
	if _, reason := l.reserve(key, slot, old, now.Add(time.Second)); reason != "peer_budget" {
		t.Fatalf("dial cancellation refunded quota: %s", reason)
	}
}

func TestUDPRebuildLedgerRegistrationRacesClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		m := NewSessionManager(nil)
		l := m.rebuildLedger()
		old, slot, key := testRebuildSlot(m, uint64(i+1))
		old.installRebuildPeer(slot.peer, slot)
		var wg sync.WaitGroup
		var ticket *udpRebuildTicket
		wg.Add(2)
		go func() { defer wg.Done(); ticket, _ = l.reserve(key, slot, old, time.Now()) }()
		go func() { defer wg.Done(); _ = old.Close() }()
		wg.Wait()
		if ticket != nil {
			l.finish(ticket, "")
		}
		for _, row := range l.snapshot(time.Now()).Records {
			if row.LiveOwners != 0 || row.State != "tombstone" {
				t.Fatalf("closed owner pinned: %+v", row)
			}
		}
		if tkt, reason := l.reserve(key, slot, old, time.Now()); tkt != nil || reason != "owner_changed" {
			t.Fatalf("registered ended owner: %s", reason)
		}
		_ = m.Close()
	}
}

func TestUDPRebuildLedgerLiveReplyGateAndLateCommit(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	l := m.rebuildLedger()
	now := time.Now()
	old, slot, key := testRebuildSlot(m, 1)
	ticket, _ := l.reserve(key, slot, old, now)
	l.start(ticket, now)
	next := &UdpEndpoint{}
	if !l.commit(ticket, next, now) || l.commit(ticket, next, now) {
		t.Fatal("commit not exactly once")
	}
	l.finish(ticket, "")
	if l.commit(ticket, next, now) {
		t.Fatal("late completion committed twice")
	}
	if _, reason := l.reserve(key, slot, next, now.Add(2*time.Hour)); reason != "awaiting_replies" {
		t.Fatalf("live reply gate expired: %s", reason)
	}
	l.freshReply(slot, 2)
	if _, reason := l.reserve(key, slot, next, now.Add(2*time.Hour)); reason != "awaiting_replies" {
		t.Fatalf("two replies bypassed gate: %s", reason)
	}
	l.freshReply(slot, 3)
	ticket, reason := l.reserve(key, slot, next, now.Add(2*time.Hour))
	if reason != "" {
		t.Fatal(reason)
	}
	l.finish(ticket, "")
	l.endpointEnded(slot, old, now.Add(3*time.Hour))
	l.endpointEnded(slot, next, now.Add(3*time.Hour))
	if expiry := slot.tombstoneUntil.Load(); expiry == nil || !expiry.Equal(now.Add(3*time.Hour+time.Minute)) {
		t.Fatal("missing post-owner tombstone")
	}
}

func TestUDPRebuildLedgerCapacityGroupProcessAndExpiry(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	l := m.rebuildLedger()
	now := time.Now()
	for i := uint64(1); i <= 8; i++ {
		old, slot, key := testRebuildSlot(m, i)
		key.group = fmt.Sprintf("g%d", (i-1)/2)
		ticket, reason := l.reserve(key, slot, old, now)
		if reason != "" {
			t.Fatal(reason)
		}
		l.start(ticket, now)
		l.finish(ticket, "")
	}
	old, slot, key := testRebuildSlot(m, 9)
	key.group = "other"
	if _, reason := l.reserve(key, slot, old, now); reason != "process_budget" {
		t.Fatal(reason)
	}
	key.group = "g0"
	// Group reservation limit is also checked before starting any dial.
	l2 := (&SessionManager{}).rebuildLedger()
	for i := uint64(1); i <= 2; i++ {
		old, s, k := testRebuildSlot(m, i)
		_, reason := l2.reserve(k, s, old, now)
		if reason != "" {
			t.Fatal(reason)
		}
	}
	key.group = "game"
	if _, reason := l2.reserve(key, slot, old, now); reason != "group_budget" {
		t.Fatal(reason)
	}
	l3 := (&SessionManager{}).rebuildLedger()
	for i := uint64(1); i <= udpRebuildLedgerLimit; i++ {
		old, s, k := testRebuildSlot(m, i)
		k.group = fmt.Sprintf("g%d", i)
		ticket, reason := l3.reserve(k, s, old, now)
		if reason != "" {
			t.Fatal(reason)
		}
		l3.finish(ticket, "")
	}
	if _, reason := l3.reserve(key, slot, old, now.Add(2*time.Hour)); reason != "ledger_full" {
		t.Fatalf("live records evicted: %s", reason)
	}
	for _, r := range l3.records {
		for ue := range r.owners {
			l3.endpointEnded(r.slot, ue, now)
		}
	}
	ticket, reason := l3.reserve(key, slot, old, now.Add(udpRebuildWindow+time.Second))
	if reason != "" {
		t.Fatal(reason)
	}
	if l3.start(ticket, now.Add(2*udpRebuildWindow)) {
		t.Fatal("expired ticket started dial")
	}
	l3.finish(ticket, "")
}
