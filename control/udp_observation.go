package control

import (
	"expvar"
	"sync/atomic"
	"time"
)

// udpWaitObservation samples one operation in 64. Buckets are disjoint and
// describe local waiting, not end-to-end latency or successful delivery.
// The snapshot is served by the existing localhost diagnostics listener.
type udpWaitObservation struct {
	operations atomic.Uint64
	buckets    [7]atomic.Uint64
}

func (o *udpWaitObservation) start() time.Time {
	if o.operations.Add(1)%64 != 0 {
		return time.Time{}
	}
	return time.Now()
}

func (o *udpWaitObservation) finish(start time.Time) {
	if start.IsZero() {
		return
	}
	elapsed := time.Since(start)
	limits := [...]time.Duration{time.Millisecond, 5 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, time.Second}
	i := 0
	for i < len(limits) && elapsed > limits[i] {
		i++
	}
	o.buckets[i].Add(1)
}

func (o *udpWaitObservation) snapshot() map[string]any {
	counts := make([]uint64, len(o.buckets))
	for i := range counts {
		counts[i] = o.buckets[i].Load()
	}
	return map[string]any{"operations": o.operations.Load(), "sample_every": 64, "bucket_upper_ms": []string{"1", "5", "20", "50", "100", "1000", "+Inf"}, "samples": counts}
}

var udpIngressWait, udpWriteWait, udpReplyWait, udpSniffWait udpWaitObservation
var udpReplyQueueDrops atomic.Uint64
var udpSniffBudgetFlushes, udpSniffBudgetRejected atomic.Uint64

func init() {
	expvar.Publish("dae_udp", expvar.Func(func() any {
		return map[string]any{
			"ingress_wait":           udpIngressWait.snapshot(),
			"synchronous_write_wait": udpWriteWait.snapshot(),
			"reply_wait":             udpReplyWait.snapshot(),
			"sniff_hold":             udpSniffWait.snapshot(),
			"sniff_budget_flushes":   udpSniffBudgetFlushes.Load(),
			"sniff_budget_rejected":  udpSniffBudgetRejected.Load(),
			"reply_queue_drops":      udpReplyQueueDrops.Load(),
			"ingress_drop_oldest":    udpIngressDropOldest.Load(),
		}
	}))
}
