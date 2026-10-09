// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func newFakeIPPinnedFixture(t *testing.T, kind string, maxLive int) *pinnedRebuildFixture {
	t.Helper()
	store := NewFakeIPStore(t.TempDir(), maxLive)
	if err := store.Open(netip.MustParsePrefix("198.18.0.0/24"), netip.MustParsePrefix("fd00:daee::/112")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f := newPinnedRebuildFixtureWith(t, kind, false, false, nil, store)
	if p := f.pin.pinnedTarget; p.native || p.fakeName != canonicalizeFakeIPQname("pinned.example") || p.fakeStore != store {
		t.Fatalf("FakeIP identity not recorded: %+v", p)
	}
	if f.pin.resolveDNSState.fakeLease.Load() != nil {
		t.Fatal("an original flow took a lease before entering recovery")
	}
	return f
}

func fakeIPLeases(f *pinnedRebuildFixture) int {
	active, _, _ := f.fake.LeaseStats()
	return active
}

func TestUDPRebuildResolveDNSFakeIPRealProxy(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			// The shared run covers DNS change, stale senders, three fresh
			// replies, observer off and an ordinary successor.
			f := newFakeIPPinnedFixture(t, kind, 8)
			runUDPRebuildResolveDNSRealProxy(t, f)
			slot := f.pin.rebuildPeer(f.b)
			owner := slot.owner.Load().endpoint
			if owner.resolveDNSState.fakeLease.Load() == nil {
				t.Fatal("ordinary successor did not take its own lease")
			}
			_ = owner.Close()
			waitRebuild(t, func() bool { return fakeIPLeases(f) == 0 })
		})
	}
}

func TestUDPRebuildResolveDNSFakeIPLeaseLifecycle(t *testing.T) {
	zeroFakeIPTombstoneGrace(t)
	f := newFakeIPPinnedFixture(t, "shadowsocks", 1)
	f.o.scan(f.qualifyPin(t))
	slot := f.pin.rebuildPeer(f.b)
	waitRebuild(t, func() bool { return slot.owner.Load().endpoint != f.pin })
	next := slot.owner.Load().endpoint
	if next.poolKey.Dst != f.original || next.DialTarget != f.b.String() || next.resolveDNSState.fakeLease.Load() == nil {
		t.Fatalf("successor key=%v dial=%s", next.poolKey.Dst, next.DialTarget)
	}
	if n := fakeIPLeases(f); n != 1 {
		t.Fatalf("leases=%d after commit", n)
	}
	f.relay.drop.Store(false)
	f.sendPin(t, f.pin, "pin/after-commit", true)
	// One live record: every Assign evicts and, with zero grace, would
	// release the old tombstone. The leased FakeIP must stay with its name.
	for i := 0; i < 16; i++ {
		got, _, _, err := f.fake.Assign(fmt.Sprintf("other-%d.example", i))
		if err != nil {
			t.Fatal(err)
		}
		if got == f.original.Addr() {
			t.Fatalf("FakeIP %v reassigned while the successor runs", got)
		}
	}
	if name, ok := f.fake.LookBack(f.original.Addr()); !ok || canonicalizeFakeIPQname(name) != canonicalizeFakeIPQname("pinned.example") {
		t.Fatalf("leased FakeIP lost its name: %q %v", name, ok)
	}
	// The reply source stays the FakeIP for new and late replies.
	f.sendPin(t, f.pin, "pin/after-retire", true)
	_ = next.Close()
	waitRebuild(t, func() bool { return fakeIPLeases(f) == 0 })
	if _, _, _, err := f.fake.Assign("after-close.example"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.fake.LookBack(f.original.Addr()); ok {
		t.Fatal("released FakeIP tombstone outlived its expiry")
	}
}

func TestUDPRebuildResolveDNSFakeIPMappingChanged(t *testing.T) {
	zeroFakeIPTombstoneGrace(t)
	f := newFakeIPPinnedFixture(t, "socks5", 1)
	now := f.qualifyPin(t)
	// Without a lease the mapping is released and the address is free for
	// another name before the candidate is executed.
	if _, _, _, err := f.fake.Assign("other.example"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.fake.Assign("third.example"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.fake.LookBack(f.original.Addr()); ok {
		if name, _ := f.fake.LookBack(f.original.Addr()); canonicalizeFakeIPQname(name) == canonicalizeFakeIPQname("pinned.example") {
			t.Fatal("setup did not change the FakeIP mapping")
		}
	}
	f.o.scan(now)
	waitRebuild(t, func() bool {
		return f.m.udpRebuild.Load().snapshot(time.Now()).Counts["resolve_dns_mapping_changed"] == 1
	})
	if f.pin.rebuildPeer(f.b).owner.Load().endpoint != f.pin || fakeIPLeases(f) != 0 {
		t.Fatal("changed mapping published a successor or kept a lease")
	}
	f.relay.drop.Store(false)
	f.sendPin(t, f.pin, "pin/after-mapping-change", true)
}

func TestUDPRebuildResolveDNSFakeIPLeaseFull(t *testing.T) {
	f := newFakeIPPinnedFixture(t, "shadowsocks", 1)
	now := f.qualifyPin(t)
	held, err := f.fake.AcquireLease(f.original.Addr(), "pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	dials := f.dial.dials.Load()
	f.o.scan(now)
	waitRebuild(t, func() bool {
		return f.m.udpRebuild.Load().snapshot(time.Now()).Counts["resolve_dns_fakeip_lease_full"] == 1
	})
	if f.pin.rebuildPeer(f.b).owner.Load().endpoint != f.pin || fakeIPLeases(f) != 1 {
		t.Fatal("full lease table published a successor or leaked a lease")
	}
	if f.dial.dials.Load() != dials {
		t.Fatal("dialed a successor without a lease")
	}
	held.Release()
	f.relay.drop.Store(false)
	f.sendPin(t, f.pin, "pin/after-full", true)
}

func TestUDPRebuildResolveDNSFakeIPCancelReleases(t *testing.T) {
	for _, reason := range []string{"reply", "reload", "new_initial"} {
		t.Run(reason, func(t *testing.T) {
			f := newFakeIPPinnedFixture(t, "shadowsocks", 8)
			runUDPRebuildResolveDNSCancelDuringPrepare(t, f, reason)
			waitRebuild(t, func() bool { return fakeIPLeases(f) == 0 })
		})
	}
}

func TestUDPRebuildResolveDNSFakeIPStoreReset(t *testing.T) {
	f := newFakeIPPinnedFixture(t, "shadowsocks", 8)
	now := f.qualifyPin(t)
	f.dial.onExtraDial = func() {
		// A reset after prepare's lease must cancel before the fence.
		f.fake.mu.Lock()
		f.fake.resetMemoryLocked(netip.MustParsePrefix("198.18.0.0/24"), netip.MustParsePrefix("fd00:daee::/112"))
		f.fake.mu.Unlock()
	}
	f.o.scan(now)
	waitRebuild(t, func() bool {
		return f.m.udpRebuild.Load().snapshot(time.Now()).Counts["resolve_dns_mapping_changed"] == 1
	})
	if f.pin.rebuildPeer(f.b).owner.Load().endpoint != f.pin || fakeIPLeases(f) != 0 {
		t.Fatal("reset store published a successor or left a lease")
	}
	f.relay.drop.Store(false)
	f.sendPin(t, f.pin, "pin/after-reset", true)
}
