package control

import (
	"expvar"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// udpWaitObservation samples one operation in 64. Buckets are disjoint and
// describe local waiting, not end-to-end latency or successful delivery.
// The snapshot is served by the existing localhost diagnostics listener.
type udpSlowSample struct {
	At           string  `json:"at"`
	Milliseconds float64 `json:"milliseconds"`
}

type udpWaitObservation struct {
	operations atomic.Uint64
	lastSlow   atomic.Pointer[udpSlowSample]
	buckets    [9]atomic.Uint64
}

func (o *udpWaitObservation) start() time.Time {
	if o.operations.Add(1)%64 != 0 {
		return time.Time{}
	}
	return time.Now()
}

func (o *udpWaitObservation) finish(start time.Time) time.Duration {
	if start.IsZero() {
		return 0
	}
	elapsed := time.Since(start)
	limits := [...]time.Duration{time.Millisecond, 5 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 500 * time.Millisecond, time.Second}
	i := 0
	for i < len(limits) && elapsed > limits[i] {
		i++
	}
	o.buckets[i].Add(1)
	if elapsed >= 100*time.Millisecond {
		o.lastSlow.Store(&udpSlowSample{At: time.Now().UTC().Format(time.RFC3339Nano), Milliseconds: float64(elapsed) / float64(time.Millisecond)})
	}
	return elapsed
}

func (o *udpWaitObservation) snapshot() map[string]any {
	counts := make([]uint64, len(o.buckets))
	for i := range counts {
		counts[i] = o.buckets[i].Load()
	}
	return map[string]any{"last_slow_sample": o.lastSlow.Load(), "operations": o.operations.Load(), "sample_every": 64, "bucket_upper_ms": []string{"1", "5", "20", "50", "100", "200", "500", "1000", "+Inf"}, "samples": counts}
}

var udpIngressWait, udpWriteWait, udpReplyWait, udpSniffWait udpWaitObservation
var udpDiscardWait, udpCreateWait, udpSelectWait, udpDialWait, udpBatchFlushWait, udpBatchQueueWait udpWaitObservation
var udpWriteByCarrier [4]udpWaitObservation
var udpOverloadPackets, udpOverloadBytes atomic.Uint64
var udpLastOverload atomic.Pointer[udpOverloadEvent]
var udpLastOverloadAt atomic.Int64
var udpLastSlowWrite atomic.Pointer[udpSlowWriteEvent]

type udpSlowWriteEvent struct {
	At           string  `json:"at"`
	Milliseconds float64 `json:"milliseconds"`
	Src          string  `json:"src"`
	Dst          string  `json:"dst"`
	Dialer       string  `json:"dialer"`
	Failed       bool    `json:"failed"`
}

func recordUDPSlowWrite(ue *UdpEndpoint, addr string, elapsed time.Duration, err error) {
	if elapsed < 100*time.Millisecond {
		return
	}
	name := ""
	if ue.Dialer != nil && ue.Dialer.Property() != nil {
		name = ue.Dialer.Property().Name
	}
	udpLastSlowWrite.Store(&udpSlowWriteEvent{At: time.Now().UTC().Format(time.RFC3339Nano), Milliseconds: float64(elapsed) / float64(time.Millisecond), Src: ue.lAddr.String(), Dst: addr, Dialer: name, Failed: err != nil})
}

type udpOverloadEvent struct {
	ActiveStage int32  `json:"active_stage"` // 0 idle, 1 routing/sniff, 2 create/select/dial, 3 write
	At          string `json:"at"`
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	Reason      string `json:"reason"`
	Pending     int    `json:"pending"`
	Bytes       int64  `json:"bytes"`
}

func recordUDPOverload(q *UdpTaskQueue, reason string) {
	if reason == "byte_limit" {
		udpOverloadBytes.Add(1)
	} else {
		udpOverloadPackets.Add(1)
	}
	now := time.Now()
	old := udpLastOverloadAt.Load()
	if now.UnixNano()-old < int64(time.Second) || !udpLastOverloadAt.CompareAndSwap(old, now.UnixNano()) {
		return
	}
	udpLastOverload.Store(&udpOverloadEvent{ActiveStage: q.activeStage.Load(), At: now.UTC().Format(time.RFC3339Nano), Src: q.key.Src.String(), Dst: q.key.Dst.String(), Reason: reason, Pending: len(q.ch) + len(q.overflow), Bytes: q.flowBytes.Load()})
}

func udpCarrierIndex(ue *UdpEndpoint) int {
	if ue.Dialer == nil {
		return 3
	}
	if !isProxyBackedDialer(ue.Dialer) {
		return 0
	}
	switch ue.Dialer.UdpForwardMode() {
	case dialer.UdpForwardDatagram:
		return 1
	case dialer.UdpForwardReliableOrdered:
		return 2
	default:
		return 3
	}
}

var udpReplyQueueDrops atomic.Uint64
var udpSniffBudgetFlushes, udpSniffBudgetRejected atomic.Uint64

func init() {
	expvar.Publish("dae_udp", expvar.Func(func() any {
		discard := udpDiscardWait.snapshot()
		discard["sampling_basis"] = "ingress_operations"
		return map[string]any{
			"ingress_wait":           udpIngressWait.snapshot(),
			"discard_wait":           discard,
			"endpoint_create_wait":   udpCreateWait.snapshot(),
			"select_resolve_wait":    udpSelectWait.snapshot(),
			"dial_wait":              udpDialWait.snapshot(),
			"batch_flush_wait":       udpBatchFlushWait.snapshot(),
			"batch_queue_wait":       udpBatchQueueWait.snapshot(),
			"write_by_carrier":       map[string]any{"direct": udpWriteByCarrier[0].snapshot(), "datagram": udpWriteByCarrier[1].snapshot(), "stream": udpWriteByCarrier[2].snapshot(), "other": udpWriteByCarrier[3].snapshot()},
			"overload_packet_limit":  udpOverloadPackets.Load(),
			"overload_byte_limit":    udpOverloadBytes.Load(),
			"last_overload":          udpLastOverload.Load(),
			"last_slow_write":        udpLastSlowWrite.Load(),
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
