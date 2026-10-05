// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"sort"
	"testing"
	"time"
)

// Real cipher/framing and local UDP syscalls, with reply waits outside the
// measured write interval. This complements the allocation microbenchmark.
func TestUDPRebuildRealProxyWriteLatency(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "socks5"} {
		for _, mode := range []string{"off", "observe", "enforce"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newRebuildFixture(t, kind, mode)
				payload := make([]byte, 256)
				addr := f.b.String()
				samples := make([]int64, 2000)
				for i := 0; i < 2100; i++ {
					start := time.Now()
					n, err := f.old.WriteTo(payload, addr)
					if udpRebuildBaselineAccounting == "true" {
						addUDPFlowUpload(f.old, len(payload))
					}
					elapsed := time.Since(start).Nanoseconds()
					if err != nil || n < len(payload) {
						t.Fatalf("write: %d/%v", n, err)
					}
					select {
					case <-f.replies:
					case <-time.After(time.Second):
						t.Fatal("real latency reply missing")
					}
					if i >= 100 {
						samples[i-100] = elapsed
					}
				}
				sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
				t.Logf("proxy=%s mode=%s n=%d p50_ns=%d p95_ns=%d p99_ns=%d", kind, mode, len(samples), samples[1000], samples[1900], samples[1980])
			})
		}
	}
}

func TestUDPRebuildPinnedProxyWriteLatency(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			f := newPinnedRebuildFixture(t, kind)
			payload := make([]byte, 256)
			addr := f.pin.dialTargetForWrite(f.original)
			samples := make([]int64, 2000)
			for i := 0; i < 2100; i++ {
				start := time.Now()
				n, err := f.pin.WriteTo(payload, addr)
				elapsed := time.Since(start).Nanoseconds()
				if err != nil || n < len(payload) {
					t.Fatalf("pinned write: %d/%v", n, err)
				}
				select {
				case r := <-f.replies:
					if r.peer != f.original {
						t.Fatal("reply address changed")
					}
				case <-time.After(time.Second):
					t.Fatal("pinned latency reply missing")
				}
				if i >= 100 {
					samples[i-100] = elapsed
				}
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			t.Logf("proxy=%s mode=pinned_enforce n=%d p50_ns=%d p95_ns=%d p99_ns=%d", kind, len(samples), samples[1000], samples[1900], samples[1980])
		})
	}
}
