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
	return udpRebuildEnforceBenchmarkPeer(droughtTestPeer)
}

func udpRebuildEnforceBenchmarkPeer(peer netip.AddrPort) (*UdpEndpoint, func()) {
	ue, close := udpRebuildBenchmarkEndpoint("off")
	m := NewSessionManager(nil)
	m.rebuildLedger()
	o := newUDPReplyDroughtObserver(config.UDPReplyDroughtPolicy{Observe: true, Enforce: true, RequestReply: true, Group: "game", Peers: []netip.AddrPort{peer}})
	ue.replyDrought = o.newFlow("192.0.2.201:32000", "game", "bench", true)
	slot := &udpRebuildPeer{manager: m, peer: peer, original: peer, changed: make(chan struct{})}
	slot.owner.Store(&udpRebuildOwnership{endpoint: ue, revision: 1})
	ue.installRebuildPeer(peer, slot)
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
	ue, close := udpRebuildPinnedBenchmarkEndpoint(netip.MustParseAddrPort("198.51.100.10:27015"), droughtTestPeer)
	defer close()
	payload := make([]byte, 256)
	addr := ue.dialTargetForWrite(ue.poolKey.Dst)
	udpRebuildBenchmarkWrite(ue, payload, addr)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		udpRebuildBenchmarkWrite(ue, payload, addr)
	}
}

func udpRebuildPinnedBenchmarkEndpoint(original, peer netip.AddrPort) (*UdpEndpoint, func()) {
	ue, close := udpRebuildEnforceBenchmarkPeer(peer)
	src := netip.MustParseAddr("192.0.2.201")
	if original.Addr().Is6() {
		src = netip.MustParseAddr("2001:db8::201")
	}
	ue.poolKey = UdpEndpointKey{Src: netip.AddrPortFrom(src, 32000), Dst: original}
	ue.DialTarget = peer.String()
	ue.SniffedDomain = "pinned.example"
	ue.resolveDNSState = &udpResolveDNSState{id: 1}
	ue.pinnedTarget = newUDPPinnedTarget(ue, &DialOption{Target: ue.DialTarget, SniffedDomain: ue.SniffedDomain, ResolveDNSOriginalNative: true})
	ue.rebuildPeer(peer).original = original
	return ue, close
}

func BenchmarkUDPRebuildPinnedSameFamilyV6Write(b *testing.B) {
	ue, close := udpRebuildPinnedBenchmarkEndpoint(netip.MustParseAddrPort("[2001:db8::10]:27015"), netip.MustParseAddrPort("[2001:db8::20]:27015"))
	defer close()
	payload := make([]byte, 256)
	addr := ue.dialTargetForWrite(ue.poolKey.Dst)
	udpRebuildBenchmarkWrite(ue, payload, addr)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		udpRebuildBenchmarkWrite(ue, payload, addr)
	}
}

func BenchmarkUDPRebuildAliasFullConeWrite(b *testing.B) {
	store := openCrossFamilyTestStore(b, b.TempDir())
	client := netip.MustParseAddrPort("192.0.2.201:32000")
	peer := netip.MustParseAddrPort("[2001:db8::20]:27015")
	alias, err := store.reply(peer, client)
	if err != nil {
		b.Fatal(err)
	}
	ue, close := udpRebuildEnforceBenchmarkPeer(peer)
	defer close()
	ue.poolKey = UdpEndpointKey{Src: client}
	ue.crossFamily = store
	ue.DialTarget = ""
	slot := ue.rebuildPeer(peer)
	slot.original = alias
	if !ue.installRebuildPeer(peer, slot) {
		b.Fatal("alias index")
	}
	payload := make([]byte, 256)
	visible := alias
	ue.TrackUdpConnStateTuplePair(client, visible)
	dialed := ue.dialTargetForWrite(visible)
	_, _ = ue.writeObserved(payload, dialed, visible)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ue.TrackUdpConnStateTuplePair(client, visible)
		_, _ = ue.writeObserved(payload, dialed, visible)
	}
}

func BenchmarkUDPRebuildPinnedCrossFamilyWrite(b *testing.B) {
	for _, tc := range []struct{ name, original, peer string }{
		{"v4_to_v6", "198.51.100.10:27015", "[2001:db8::20]:27015"},
		{"v6_to_v4", "[2001:db8::10]:27015", "192.0.2.1:27015"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			ue, close := udpRebuildPinnedBenchmarkEndpoint(netip.MustParseAddrPort(tc.original), netip.MustParseAddrPort(tc.peer))
			defer close()
			payload := make([]byte, 256)
			addr := ue.dialTargetForWrite(ue.poolKey.Dst)
			udpRebuildBenchmarkWrite(ue, payload, addr)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				udpRebuildBenchmarkWrite(ue, payload, addr)
			}
		})
	}
}
