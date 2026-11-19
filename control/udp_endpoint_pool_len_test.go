/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
)

func actualShardMapCount(p *UdpEndpointPool) int {
	total := 0
	for i := range p.shards {
		shard := &p.shards[i]
		shard.mu.RLock()
		total += len(shard.pool)
		shard.mu.RUnlock()
	}
	return total
}

func TestUdpEndpointPoolLenMatchesShardCounts(t *testing.T) {
	t.Parallel()
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)

	k1 := UdpEndpointKey{Src: netip.MustParseAddrPort("192.168.1.10:1001"), Dst: netip.MustParseAddrPort("1.1.1.1:443")}
	k2 := UdpEndpointKey{Src: netip.MustParseAddrPort("192.168.1.10:1002"), Dst: netip.MustParseAddrPort("1.1.1.1:443")}
	k3 := UdpEndpointKey{Src: netip.MustParseAddrPort("192.168.1.10:1003"), Dst: netip.MustParseAddrPort("8.8.8.8:443")}

	ue1 := &UdpEndpoint{poolRef: pool, poolKey: k1}
	ue1Replacement := &UdpEndpoint{poolRef: pool, poolKey: k1}
	ue2 := &UdpEndpoint{poolRef: pool, poolKey: k2}
	ue3 := &UdpEndpoint{poolRef: pool, poolKey: k3}

	insert := func(k UdpEndpointKey, ue *UdpEndpoint) {
		shard := pool.shardFor(k)
		shard.mu.Lock()
		pool.setShardEntryLocked(shard, k, ue)
		shard.mu.Unlock()
	}

	insert(k1, ue1)
	insert(k2, ue2)
	insert(k3, ue3)
	if got, want := pool.Len(), actualShardMapCount(pool); got != 3 || got != want {
		t.Fatalf("after 3 inserts: Len()=%d actual=%d, want 3", got, want)
	}

	// Overwriting the same key must not double-count.
	insert(k1, ue1Replacement)
	if got, want := pool.Len(), actualShardMapCount(pool); got != 3 || got != want {
		t.Fatalf("after overwrite: Len()=%d actual=%d, want 3", got, want)
	}

	// selfRemoveFromPool for stale pointer must leave entry and count intact.
	ue1.selfRemoveFromPool()
	if got, want := pool.Len(), actualShardMapCount(pool); got != 3 || got != want {
		t.Fatalf("after stale selfRemove: Len()=%d actual=%d, want 3", got, want)
	}

	// selfRemoveFromPool for active pointer decrements count.
	ue1Replacement.selfRemoveFromPool()
	if got, want := pool.Len(), actualShardMapCount(pool); got != 2 || got != want {
		t.Fatalf("after active selfRemove: Len()=%d actual=%d, want 2", got, want)
	}

	// Remove decrements count.
	if err := pool.Remove(k2, ue2); err != nil {
		t.Fatalf("Remove(k2): %v", err)
	}
	if got, want := pool.Len(), actualShardMapCount(pool); got != 1 || got != want {
		t.Fatalf("after Remove: Len()=%d actual=%d, want 1", got, want)
	}

	// Reset clears all entries and resets count to 0.
	pool.Reset()
	if got, want := pool.Len(), actualShardMapCount(pool); got != 0 || got != want {
		t.Fatalf("after Reset: Len()=%d actual=%d, want 0", got, want)
	}
}
