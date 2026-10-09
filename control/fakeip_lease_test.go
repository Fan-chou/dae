// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

func newLeaseTestStore(t *testing.T, maxLive int) *FakeIPStore {
	t.Helper()
	store := NewFakeIPStore(t.TempDir(), maxLive)
	if err := store.Open(netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func zeroFakeIPTombstoneGrace(t *testing.T) {
	prev := fakeIPTombstoneGrace
	fakeIPTombstoneGrace = 0
	t.Cleanup(func() { fakeIPTombstoneGrace = prev })
}

func TestFakeIPLeaseKeepsTombstone(t *testing.T) {
	zeroFakeIPTombstoneGrace(t)
	// One live record: every Assign evicts the previous name, and zero grace
	// plus the tombstone overflow would normally release it immediately.
	store := newLeaseTestStore(t, 1)
	x, _, _, err := store.Assign("pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireLease(x, "pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		got, _, _, err := store.Assign(fmt.Sprintf("other-%d.example", i))
		if err != nil {
			t.Fatal(err)
		}
		if got == x {
			t.Fatalf("leased address %v was handed to another name", x)
		}
	}
	if name, ok := store.LookBack(x); !ok || canonicalizeFakeIPQname(name) != canonicalizeFakeIPQname("pinned.example") {
		t.Fatalf("leased tombstone lost: %q %v", name, ok)
	}
	if active, retained, limit := store.LeaseStats(); active != 1 || retained != 1 || limit != 1 {
		t.Fatalf("lease stats active=%d retained=%d limit=%d", active, retained, limit)
	}
	lease.Release()
	lease.Release()
	if _, _, _, err := store.Assign("after-release.example"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.LookBack(x); ok {
		t.Fatal("released lease kept the tombstone past its expiry")
	}
	if active, retained, _ := store.LeaseStats(); active != 0 || retained != 0 {
		t.Fatalf("lease stats after release active=%d retained=%d", active, retained)
	}
}

func TestFakeIPLeaseRetiredPoolKeepsMapping(t *testing.T) {
	zeroFakeIPTombstoneGrace(t)
	store := newLeaseTestStore(t, 1)
	x, _, _, err := store.Assign("pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireLease(x, "pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	// Moving the pool retires the whole generation. Returning to the old
	// prefix must still skip the leased address for other names.
	store.ApplyRanges(netip.MustParsePrefix("198.18.1.0/29"), netip.Prefix{})
	store.ApplyRanges(netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{})
	for i := 0; i < 32; i++ {
		got, _, _, err := store.Assign(fmt.Sprintf("other-%d.example", i))
		if err != nil {
			t.Fatal(err)
		}
		if got == x {
			t.Fatalf("leased address %v was reassigned after a pool move", x)
		}
	}
	if !lease.Valid() {
		t.Fatal("pool move invalidated a lease on a retained record")
	}
	if name, ok := store.LookBack(x); !ok || canonicalizeFakeIPQname(name) != canonicalizeFakeIPQname("pinned.example") {
		t.Fatalf("leased mapping changed after a pool move: %q %v", name, ok)
	}
}

func TestFakeIPLeaseRejectsChangedMappingAndLimit(t *testing.T) {
	store := newLeaseTestStore(t, 1)
	x, _, _, err := store.Assign("pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(x, "other.example"); !errors.Is(err, errFakeIPLeaseMappingChanged) {
		t.Fatalf("wrong name: %v", err)
	}
	if _, err := store.AcquireLease(netip.MustParseAddr("198.18.1.1"), "pinned.example"); !errors.Is(err, errFakeIPLeaseMappingChanged) {
		t.Fatalf("unassigned address: %v", err)
	}
	first, err := store.AcquireLease(x, "pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(x, "pinned.example"); !errors.Is(err, errFakeIPLeaseFull) {
		t.Fatalf("limit min(maxLive, %d)=1 was not enforced: %v", fakeIPLeaseHardLimit, err)
	}
	first.Release()
	again, err := store.AcquireLease(x, "pinned.example")
	if err != nil {
		t.Fatalf("released handle did not free its slot: %v", err)
	}
	again.Release()
}

func TestFakeIPLeaseResetAndClose(t *testing.T) {
	store := newLeaseTestStore(t, 4)
	x, _, _, err := store.Assign("pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	old, err := store.AcquireLease(x, "pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	// A corrupt-store reset rebuilds memory. The old handle neither protects
	// nor releases anything in the new table.
	store.mu.Lock()
	store.resetMemoryLocked(netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{})
	store.mu.Unlock()
	if old.Valid() {
		t.Fatal("lease survived a memory reset")
	}
	y, _, _, err := store.Assign("pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.AcquireLease(y, "pinned.example")
	if err != nil {
		t.Fatal(err)
	}
	old.Release()
	if active, _, _ := store.LeaseStats(); active != 1 {
		t.Fatalf("stale release changed the new table: active=%d", active)
	}
	_ = store.Close()
	if current.Valid() {
		t.Fatal("lease valid on a closed store")
	}
	if _, err := store.AcquireLease(y, "pinned.example"); !errors.Is(err, errFakeIPNotReady) {
		t.Fatalf("closed store issued a lease: %v", err)
	}
	current.Release()
}
