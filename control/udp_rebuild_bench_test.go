// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
)

// Set through -ldflags only on the archived baseline: before this change,
// upload accounting was done by the ingress caller after WriteTo.
var udpRebuildBaselineAccounting string

func udpRebuildBenchmarkEndpoint(mode string) (*UdpEndpoint, func()) {
	d := newNamedTestEndpointDialer("bench")
	ue := &UdpEndpoint{conn: &mockPacketConn{}, Dialer: d}
	ue.hasSent.Store(true)
	ue.hasReply.Store(true)
	ue.sessionRuntime = &UDPFlowRuntime{binding: UdpFlowBinding{Egress: UdpEgressBinding{Dialer: d, NetworkType: dialer.NetworkType{}}}}
	var o *udpReplyDroughtObserver
	if mode == "observe" {
		o = newUDPReplyDroughtObserver(config.UDPReplyDroughtPolicy{Observe: true, RequestReply: true, Group: "game", Peers: []netip.AddrPort{droughtTestPeer}})
		ue.replyDrought = o.newFlow("192.0.2.201:32000", "game", "bench", true)
	}
	return ue, func() {
		if o != nil {
			_ = o.Close()
		}
		_ = d.Close()
	}
}
func udpRebuildBenchmarkWrite(ue *UdpEndpoint, b []byte, addr string) {
	_, _ = ue.WriteTo(b, addr)
	if udpRebuildBaselineAccounting == "true" {
		addUDPFlowUpload(ue, len(b))
	}
}
func BenchmarkUDPRebuildSteadyWrite(b *testing.B) {
	for _, mode := range []string{"off", "observe"} {
		b.Run(mode, func(b *testing.B) {
			ue, close := udpRebuildBenchmarkEndpoint(mode)
			defer close()
			payload := make([]byte, 256)
			addr := droughtTestPeer.String()
			udpRebuildBenchmarkWrite(ue, payload, addr)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				udpRebuildBenchmarkWrite(ue, payload, addr)
			}
		})
	}
}

// A distribution as well as ns/op makes changes in rare waits visible. The
// same clock calls and sample count run on the baseline and current tree.
func TestUDPRebuildSteadyWriteLatency(t *testing.T) {
	for _, mode := range []string{"off", "observe"} {
		t.Run(mode, func(t *testing.T) {
			ue, close := udpRebuildBenchmarkEndpoint(mode)
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
			t.Logf("mode=%s n=%d p50_ns=%d p95_ns=%d p99_ns=%d", mode, len(samples), samples[50000], samples[95000], samples[99000])
		})
	}
}
