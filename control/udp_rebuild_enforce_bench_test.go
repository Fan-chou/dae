// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
)

func udpRebuildEnforceBenchmarkEndpoint() (*UdpEndpoint, func()) {
	ue, close := udpRebuildBenchmarkEndpoint("off")
	m := NewSessionManager(nil)
	m.rebuildLedger()
	o := newUDPReplyDroughtObserver(config.UDPReplyDroughtPolicy{Observe: true, Enforce: true, RequestReply: true, Group: "game", Peers: []netip.AddrPort{droughtTestPeer}})
	ue.replyDrought = o.newFlow("192.0.2.201:32000", "game", "bench", true)
	slot := &udpRebuildPeer{manager: m, peer: droughtTestPeer, original: droughtTestPeer, changed: make(chan struct{})}
	slot.owner.Store(&udpRebuildOwnership{endpoint: ue, revision: 1})
	ue.installRebuildPeer(droughtTestPeer, slot)
	return ue, func() { _ = o.Close(); _ = m.Close(); close() }
}
func BenchmarkUDPRebuildScopedEnforceWrite(b *testing.B) {
	ue, close := udpRebuildEnforceBenchmarkEndpoint()
	defer close()
	payload := make([]byte, 256)
	addr := droughtTestPeer.String()
	udpRebuildBenchmarkWrite(ue, payload, addr)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		udpRebuildBenchmarkWrite(ue, payload, addr)
	}
}
func TestUDPRebuildScopedEnforceLatency(t *testing.T) {
	ue, close := udpRebuildEnforceBenchmarkEndpoint()
	defer close()
	payload := make([]byte, 256)
	addr := droughtTestPeer.String()
	for i := 0; i < 10000; i++ {
		udpRebuildBenchmarkWrite(ue, payload, addr)
	}
	samples := make([]int64, 100000)
	for i := range samples {
		start := time.Now()
		udpRebuildBenchmarkWrite(ue, payload, addr)
		samples[i] = time.Since(start).Nanoseconds()
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("mode=enforce n=%d p50_ns=%d p95_ns=%d p99_ns=%d", len(samples), samples[50000], samples[95000], samples[99000])
}

func BenchmarkUDPRebuildPinnedEnforceWrite(b *testing.B) {
	ue, close := udpRebuildEnforceBenchmarkEndpoint()
	defer close()
	ue.poolKey = UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.201:32000"), Dst: netip.MustParseAddrPort("198.51.100.10:27015")}
	ue.DialTarget = droughtTestPeer.String()
	ue.SniffedDomain = "pinned.example"
	ue.resolveDNSState = &udpResolveDNSState{id: 1}
	ue.pinnedTarget = newUDPPinnedTarget(ue, &DialOption{Target: ue.DialTarget, SniffedDomain: ue.SniffedDomain, ResolveDNSOriginalNative: true})
	ue.rebuildPeer(droughtTestPeer).original = ue.poolKey.Dst
	payload := make([]byte, 256)
	addr := ue.dialTargetForWrite(ue.poolKey.Dst)
	udpRebuildBenchmarkWrite(ue, payload, addr)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		udpRebuildBenchmarkWrite(ue, payload, addr)
	}
}
