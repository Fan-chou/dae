/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestUnnamedFakeIPErrorSentinel(t *testing.T) {
	addr := netip.MustParseAddr("198.18.0.1")
	err := unnamedFakeIPError(addr)
	if !errors.Is(err, ErrUnnamedFakeIP) {
		t.Fatalf("unnamedFakeIPError() = %v, want ErrUnnamedFakeIP", err)
	}
}

func TestUnnamedFakeIPLogGateRateLimitsSameAddr(t *testing.T) {
	var g unnamedFakeIPLogGate
	addr := netip.MustParseAddr("198.18.0.7")
	now := time.Unix(1_700_000_000, 0)
	hits, ok := g.allow(addr, now)
	if !ok || hits != 1 {
		t.Fatalf("first allow = (%d, %v), want (1, true)", hits, ok)
	}
	hits, ok = g.allow(addr, now.Add(time.Second))
	if ok || hits != 2 {
		t.Fatalf("second allow within window = (%d, %v), want (2, false)", hits, ok)
	}
	hits, ok = g.allow(addr, now.Add(unnamedFakeIPLogInterval+time.Second))
	if !ok || hits != 1 {
		t.Fatalf("allow after window = (%d, %v), want (1, true)", hits, ok)
	}
}

func TestUnnamedFakeIPLogGateRateLimitsCollidingAddrs(t *testing.T) {
	var g unnamedFakeIPLogGate
	first := netip.MustParseAddr("198.18.0.1")
	second, ok := collidingUnnamedFakeIP(first)
	if !ok {
		t.Fatal("could not find a second FakeIP in the same log bucket")
	}
	now := time.Unix(1_700_000_000, 0)
	hits, allowed := g.allow(first, now)
	if !allowed || hits != 1 {
		t.Fatalf("first allow = (%d, %v), want (1, true)", hits, allowed)
	}
	hits, allowed = g.allow(second, now.Add(time.Second))
	if allowed || hits != 2 {
		t.Fatalf("colliding addr within window = (%d, %v), want (2, false)", hits, allowed)
	}
}

func collidingUnnamedFakeIP(first netip.Addr) (netip.Addr, bool) {
	want := unnamedFakeIPLogBucket(first)
	for i := 2; i < 1<<16; i++ {
		candidate := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		if candidate != first && unnamedFakeIPLogBucket(candidate) == want {
			return candidate, true
		}
	}
	return netip.Addr{}, false
}
