package ciphers

import (
	"math/rand/v2"
	"testing"
)

// In-order packet IDs: the dominant UDP case.
func BenchmarkSlidingWindowInOrder(b *testing.B) {
	f := NewSlidingWindowFilter(8192)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f.CheckAndUpdate(uint64(i) + 1)
	}
}

// Mild reordering around the latest ID, as seen on a real network path.
func BenchmarkSlidingWindowReordered(b *testing.B) {
	f := NewSlidingWindowFilter(8192)
	r := rand.New(rand.NewPCG(1, 2))
	ids := make([]uint64, 1<<16)
	for i := range ids {
		d := int64(r.IntN(33)) - 16
		v := int64(i) + 64 + d
		ids[i] = uint64(v)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.CheckAndUpdate(ids[i&(len(ids)-1)] + uint64(i>>16)<<16)
	}
}

// Large forward jumps force the multi-word shift path.
func BenchmarkSlidingWindowJumps(b *testing.B) {
	f := NewSlidingWindowFilter(8192)
	var id uint64
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id += uint64(1 + i%97)
		f.CheckAndUpdate(id)
	}
}
