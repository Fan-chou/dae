package control

import (
	"sort"
	"sync"
	"testing"
	"time"
)

// Queue handoff only: excludes sniffing, socket I/O and network RTT. Bounded
// in-flight work avoids conflating processing cost with overload/drop policy.
func BenchmarkUdpFIFOProcessing(b *testing.B) {
	p := NewUdpTaskPool()
	defer p.Close()
	key := udpTaskPoolTestKey()
	slots := make(chan struct{}, 32)
	samples := make([]int64, 0, min(b.N, 10000))
	var done sync.WaitGroup
	done.Add(b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		slots <- struct{}{}
		start := time.Now()
		if !p.EmitTask(key, udpTaskFunc(func() {
			if len(samples) < cap(samples) {
				samples = append(samples, time.Since(start).Nanoseconds())
			}
			<-slots
			done.Done()
		})) {
			b.Fatal("queue rejected bounded work")
		}
	}
	done.Wait()
	b.StopTimer()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	if len(samples) > 0 {
		b.ReportMetric(float64(samples[(len(samples)-1)*99/100])/1000, "p99-us")
	}
}
