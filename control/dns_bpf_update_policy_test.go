/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// TestNeedsBpfUpdateUnchangedHashSkipsUntilMaxInterval is the contract the
// cache-hit path relies on: a packed-response hit must not enqueue a BPF write
// every second just because MinBpfUpdateInterval elapsed.
func TestNeedsBpfUpdateUnchangedHashSkipsUntilMaxInterval(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	cache := domainRoutingACache("hot.example.:1", "203.0.113.10", domainRoutingBitmap(0x1))
	cache.MarkBpfUpdated(t0)

	if cache.NeedsBpfUpdate(t0.Add(MinBpfUpdateInterval + time.Millisecond)) {
		t.Fatal("unchanged hash must not request a BPF update before MaxBpfUpdateInterval")
	}
	if !cache.NeedsBpfUpdate(t0.Add(MaxBpfUpdateInterval)) {
		t.Fatal("MaxBpfUpdateInterval must still force a refresh")
	}
}

func TestNeedsBpfUpdateHashChangeAfterMinInterval(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	cache := domainRoutingACache("hot.example.:1", "203.0.113.10", domainRoutingBitmap(0x1))
	cache.MarkBpfUpdated(t0)
	cache.Answer = domainRoutingACache("hot.example.:1", "203.0.113.11", domainRoutingBitmap(0x1)).Answer

	if cache.NeedsBpfUpdate(t0.Add(MinBpfUpdateInterval / 2)) {
		t.Fatal("hash change must still respect MinBpfUpdateInterval")
	}
	if !cache.NeedsBpfUpdate(t0.Add(MinBpfUpdateInterval + time.Millisecond)) {
		t.Fatal("hash change after MinBpfUpdateInterval must request an update")
	}
}

// TestNeedsBpfUpdateSteadyLANHitRate stays below a datapath-relevant write
// rate. Profile is 222-like: ~10 cache hits/s across 50 hot names whose A
// records do not change (SmartDNS hit, kdae cache hit). A result that needed
// hundreds of writes per second would be a main-path problem; one write per
// hot name per minute is not.
func TestNeedsBpfUpdateSteadyLANHitRate(t *testing.T) {
	const (
		hotNames   = 50
		hitQPS     = 10
		window     = 90 * time.Second
		warmup     = MaxBpfUpdateInterval
		maxWritePS = 2.0
	)
	t0 := time.Unix(1_700_000_000, 0)
	caches := make([]*DnsCache, hotNames)
	for i := range caches {
		caches[i] = domainRoutingACache(
			"lan-hot.example.:1",
			"203.0.113.10",
			domainRoutingBitmap(0x1),
		)
		caches[i].RouteOwnerKey = caches[i].RouteOwnerKey + string(rune('A'+i%26)) + string(rune('0'+i/26))
		caches[i].MarkBpfUpdated(t0)
	}

	hits := 0
	writes := 0
	postWarmWrites := 0
	steps := int(window / time.Second * hitQPS)
	for i := 0; i < steps; i++ {
		now := t0.Add(time.Duration(i) * time.Second / hitQPS)
		cache := caches[i%hotNames]
		hits++
		if !cache.NeedsBpfUpdate(now) {
			continue
		}
		writes++
		if now.Sub(t0) >= warmup {
			postWarmWrites++
		}
		cache.MarkBpfUpdated(now)
	}

	postWarm := window - warmup
	writePS := float64(postWarmWrites) / postWarm.Seconds()
	t.Logf("LAN cache-hit profile: hits=%d writes=%d post-warmup writes=%d (%.2f/s over %s)",
		hits, writes, postWarmWrites, writePS, postWarm)

	if hits != steps {
		t.Fatalf("hits = %d, want %d", hits, steps)
	}
	// After warmup the 60s hammer can fire once per hot name, then hash
	// equality suppresses further writes. That is ~50 writes / 30s ≈ 1.7/s
	// in the worst 30s slice of this 90s window, still well under a rate
	// that would stall DNS or the BPF worker.
	if writePS > maxWritePS {
		t.Fatalf("post-warmup BPF write rate %.2f/s exceeds %.1f/s; this would be a datapath problem",
			writePS, maxWritePS)
	}
	if writes == 0 {
		t.Fatal("expected the 60s force to fire at least once in a 90s window")
	}
}

func TestLookupDnsRespCacheInPlaceHitTriggersBpfUpdate(t *testing.T) {
	updated := make(chan *DnsCache, 1)
	ctrl := setTestDnsControllerRuntime(nil, func(rt *dnsControllerRuntimeState) {
		rt.cacheAccessCallback = func(cache *DnsCache) error {
			select {
			case updated <- cache:
			default:
			}
			return nil
		}
	})
	defer ctrl.Close()

	now := time.Now()
	cache := domainRoutingACache("inplace.example.:1", "203.0.113.20", domainRoutingBitmap(0x1))
	cache.Deadline = now.Add(time.Minute)
	cache.OriginalDeadline = cache.Deadline
	cache.MarkBpfUpdated(now.Add(-2 * MaxBpfUpdateInterval))
	ctrl.dnsCache.Store(cache.RouteOwnerKey, cache)

	req := new(dnsmessage.Msg)
	req.SetQuestion("inplace.example.", dnsmessage.TypeA)
	resp, needRefresh := ctrl.LookupDnsRespCache_(req, cache.RouteOwnerKey, false)
	if resp == nil {
		t.Fatal("expected non-nil response on in-place cache hit")
	}
	if needRefresh {
		t.Fatal("expected needRefresh=false on fresh in-place cache hit")
	}
	select {
	case got := <-updated:
		if got != cache {
			t.Fatalf("unexpected cache passed to BPF callback: got %v, want %v", got, cache)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected BPF update trigger on fillIntoWithTTLInPlace hit")
	}
}

func TestLookupDnsRespCacheStaleHitTriggersBpfUpdate(t *testing.T) {
	updated := make(chan *DnsCache, 1)
	ctrl := setTestDnsControllerRuntime(nil, func(rt *dnsControllerRuntimeState) {
		rt.optimisticCacheEnabled = true
		rt.optimisticCacheTtl = 60
		rt.cacheAccessCallback = func(cache *DnsCache) error {
			select {
			case updated <- cache:
			default:
			}
			return nil
		}
	})
	defer ctrl.Close()

	now := time.Now()
	cache := domainRoutingACache("stale.example.:1", "203.0.113.21", domainRoutingBitmap(0x1))
	if err := cache.prepackResponseWithTTL("stale.example.", dnsmessage.TypeA, 30, now.Add(-35*time.Second)); err != nil {
		t.Fatalf("prepackResponseWithTTL: %v", err)
	}
	expired := now.Add(-5 * time.Second)
	cache.Deadline = expired
	cache.OriginalDeadline = expired
	cache.deadlineNano.Store(expired.UnixNano())
	cache.MarkBpfUpdated(expired.Add(-2 * MaxBpfUpdateInterval))
	ctrl.dnsCache.Store(cache.RouteOwnerKey, cache)

	req := new(dnsmessage.Msg)
	req.SetQuestion("stale.example.", dnsmessage.TypeA)
	resp, needRefresh := ctrl.LookupDnsRespCache_(req, cache.RouteOwnerKey, false)
	if resp == nil {
		t.Fatal("expected non-nil response on RFC 8767 stale cache hit")
	}
	if !needRefresh {
		t.Fatal("expected needRefresh=true on first stale cache hit")
	}
	select {
	case got := <-updated:
		if got != cache {
			t.Fatalf("unexpected cache passed to BPF callback: got %v, want %v", got, cache)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected BPF update trigger on RFC 8767 GetStaleResponse hit")
	}
}
