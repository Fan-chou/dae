/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"math"
	"strings"
	"sync"
	"time"
)

// AdmissionState is the userspace selection gate. It must never be published
// into BPF outbound_connectivity_map: Degraded stays kernel-alive so new
// connections can still reach userspace selection.
type AdmissionState uint8

const (
	AdmissionAlive AdmissionState = iota
	AdmissionDegraded
	AdmissionDead
)

func (s AdmissionState) String() string {
	switch s {
	case AdmissionDegraded:
		return "degraded"
	case AdmissionDead:
		return "dead"
	default:
		return "alive"
	}
}

const (
	nodeHealthMaxTestResults   = 20
	nodeHealthBaselineMinN     = 3
	nodeHealthReseedHighStreak = 5
	nodeHealthRecoverSuccesses = 2
	nodeHealthBaselineAlpha    = 0.20
	nodeHealthSpikeIgnore      = 3.0
	nodeHealthDegradeFactor    = 1.50
	nodeHealthRecoverFactor    = 1.20
	// UDP-based outbounds (Hysteria/TUIC/Juicity) carry inner TCP over QUIC.
	// Brutal CC still has a heavy RTT tail, so the TCP-slot bar is 2× / 3
	// consecutive failures instead of 1.5× / single-fail, and congestion is
	// skipped. Data-UDP slots stay on the strict path.
	nodeHealthUDPTransportDegradeFactor = 2.0
	nodeHealthUDPTransportRecoverFactor = 1.5
	nodeHealthUDPTransportFailStreak    = 3
	// Inner TCP handshake on UDP/QUIC outbounds is local stream-open, often
	// ~1ms. Ignore those samples so the TCP-slot baseline tracks probe RTT.
	nodeHealthUDPTransportMinBaseline = 10 * time.Millisecond
	nodeHealthMaxStepUp               = 1.25
	nodeHealthLossPenaltyScale        = 2000 * time.Millisecond
	nodeHealthDegradePenalty          = 500 * time.Millisecond
	nodeHealthPenaltyUnit             = 200 * time.Millisecond
	nodeHealthPenaltyHalfLife         = 30 * time.Second
	nodeHealthCongestionWindow        = 15 * time.Second
	nodeHealthSpeedStale              = 30 * time.Second
	nodeHealthSpeedDecayLambda        = 0.001
	nodeHealthMinSpeedBytes           = 256 << 10
	nodeHealthMinSpeedElapsed         = time.Second
	nodeHealthSilentFail              = 3 * time.Second
	nodeHealthCongestionRatio         = 0.85
	nodeHealthRecentDelaysN           = 10
)

type nodeHealthSlot struct {
	baseline            time.Duration
	baselineSamples     int
	highLatencyStreak   int
	recentSuccessDelays []time.Duration
	reseedDelays        []time.Duration
	degraded            bool
	recoverStreak       int
	testResults         []bool
	penaltyLevel        int
	lastPenaltyAt       time.Time
	penaltyGoodStreak   int
	peakSpeed           uint64
	peakAt              time.Time
	currentSpeed        uint64
	currentAt           time.Time
	congested           bool
	congestedSince      time.Time
	lastSampleRTT       time.Duration
	failStreak          int
	// failDegraded is set only by unsuccessful probes/handshakes/traffic.
	// RTT-only slowdown still sets degraded (url_test + kernel DIRECT), but
	// fallback must not skip a working first member just because it got slower.
	failDegraded bool
}

type loggedAdmission struct {
	inited   bool
	alive    bool
	state    AdmissionState
	fallback AdmissionState
	reason   string
}

type admissionChange struct {
	from, to                 AdmissionState
	fromFallback, toFallback AdmissionState
	fromReason, toReason     string
	rtt, baseline            time.Duration
	failStreak               int
	congested                bool
}

type nodeHealth struct {
	mu           sync.Mutex
	udpTransport bool
	slots        [8]nodeHealthSlot
	logged       [8]loggedAdmission
}

func tcpHealthIndex(idx int) bool {
	return idx == IdxTcp4 || idx == IdxTcp6
}

func (h *nodeHealth) relaxedTCP(idx int) bool {
	return h != nil && h.udpTransport && tcpHealthIndex(idx)
}

func (h *nodeHealth) admission(idx int, alive bool) AdmissionState {
	return h.admissionAt(idx, alive, time.Now())
}

func (h *nodeHealth) admissionAt(idx int, alive bool, now time.Time) AdmissionState {
	if !alive {
		return AdmissionDead
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if idx < 0 || idx >= len(h.slots) {
		return AdmissionAlive
	}
	slot := &h.slots[idx]
	h.maybeUpdateCongestion(idx, slot, now)
	if slot.degraded || slot.congested {
		return AdmissionDegraded
	}
	return AdmissionAlive
}

func (h *nodeHealth) fallbackAdmission(idx int, alive bool) AdmissionState {
	return h.fallbackAdmissionAt(idx, alive, time.Now())
}

func (h *nodeHealth) fallbackAdmissionAt(idx int, alive bool, now time.Time) AdmissionState {
	if !alive {
		return AdmissionDead
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if idx < 0 || idx >= len(h.slots) {
		return AdmissionAlive
	}
	slot := &h.slots[idx]
	h.maybeUpdateCongestion(idx, slot, now)
	if slot.failDegraded {
		return AdmissionDegraded
	}
	return AdmissionAlive
}

func admissionReasonLocked(slot *nodeHealthSlot, alive bool) string {
	if !alive {
		return "not_alive"
	}
	var parts []string
	if slot.failDegraded {
		parts = append(parts, "fail")
	}
	if slot.degraded && !slot.failDegraded {
		parts = append(parts, "rtt")
	}
	if slot.failDegraded && slot.baseline > 0 && slot.lastSampleRTT > time.Duration(float64(slot.baseline)*nodeHealthDegradeFactor) {
		parts = append(parts, "rtt")
	}
	if slot.congested {
		parts = append(parts, "congestion")
	}
	if len(parts) == 0 {
		return "ok"
	}
	return strings.Join(parts, ",")
}

func (h *nodeHealth) admissionReason(idx int, alive bool) string {
	if h == nil || idx < 0 || idx >= len(h.slots) {
		if !alive {
			return "not_alive"
		}
		return "ok"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return admissionReasonLocked(&h.slots[idx], alive)
}

func (h *nodeHealth) consumeAdmissionChange(idx int, alive bool, now time.Time) (admissionChange, bool) {
	var change admissionChange
	if h == nil || idx < 0 || idx >= len(h.slots) {
		return change, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := &h.slots[idx]
	h.maybeUpdateCongestion(idx, slot, now)
	next := loggedAdmission{
		inited:   true,
		alive:    alive,
		state:    AdmissionAlive,
		fallback: AdmissionAlive,
		reason:   admissionReasonLocked(slot, alive),
	}
	if !alive {
		next.state = AdmissionDead
		next.fallback = AdmissionDead
	} else {
		if slot.degraded || slot.congested {
			next.state = AdmissionDegraded
		}
		if slot.failDegraded {
			next.fallback = AdmissionDegraded
		}
	}
	prev := h.logged[idx]
	if prev.inited && prev.alive == next.alive && prev.state == next.state && prev.fallback == next.fallback && prev.reason == next.reason {
		return change, false
	}
	h.logged[idx] = next
	if !prev.inited {
		// First observation is the baseline, not a promotion/demotion.
		return change, false
	}
	change = admissionChange{
		from:         prev.state,
		to:           next.state,
		fromFallback: prev.fallback,
		toFallback:   next.fallback,
		fromReason:   prev.reason,
		toReason:     next.reason,
		rtt:          slot.lastSampleRTT,
		baseline:     slot.baseline,
		failStreak:   slot.failStreak,
		congested:    slot.congested,
	}
	return change, true
}

func admissionSelectionBehavior(state, fallback AdmissionState) string {
	switch state {
	case AdmissionDead:
		return "skip in fallback and url_test; existing connections stay up"
	case AdmissionDegraded:
		if fallback == AdmissionDegraded {
			return "fallback skips if another alive member exists; url_test applies quality penalty; do not write kernel DIRECT"
		}
		return "fallback keeps declaration order; url_test applies quality penalty; do not write kernel DIRECT"
	default:
		return "eligible for fallback first-member and url_test ranking"
	}
}

func (h *nodeHealth) quality(idx int, base time.Duration, hasBase bool, now time.Time) (time.Duration, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if idx < 0 || idx >= len(h.slots) {
		return base, hasBase
	}
	slot := &h.slots[idx]
	h.maybeUpdateCongestion(idx, slot, now)
	if !hasBase {
		if slot.lastSampleRTT <= 0 {
			return 0, false
		}
		base = slot.lastSampleRTT
		hasBase = true
	}
	q := base
	q += slot.lossPenaltyLocked()
	if slot.degraded || slot.congested {
		q += nodeHealthDegradePenalty
	}
	q += slot.timeDecayPenaltyLocked(now)
	return q, true
}

func (h *nodeHealth) observeProbe(idx int, success bool, latency time.Duration, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return
	}
	slot.pushTestResult(success)
	if success {
		slot.lastSampleRTT = latency
		// Classify against the pre-sample baseline so a 1.5×~1.71× jump
		// cannot raise the bar before Degraded is decided. Tiny UDP-transport
		// leftovers are replaced first so a real probe is not a 100× "spike".
		skipUpdate := h.prepareUDPBaseline(idx, slot, latency)
		h.updateSlotDegraded(idx, slot, true, latency)
		if !skipUpdate {
			slot.updateBaseline(latency)
		}
		slot.reducePenalty(now)
		h.maybeUpdateCongestion(idx, slot, now)
		return
	}
	h.updateSlotDegraded(idx, slot, false, 0)
	slot.raisePenalty(now)
	h.maybeUpdateCongestion(idx, slot, now)
}

func (h *nodeHealth) observeSample(idx int, sample time.Duration, now time.Time) (slow bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return false
	}
	slot.lastSampleRTT = sample
	skipUpdate := h.prepareUDPBaseline(idx, slot, sample)
	slow = slot.baselineSamples >= nodeHealthBaselineMinN &&
		slot.baseline > 0 &&
		sample > time.Duration(float64(slot.baseline)*h.tcpSlowFactor(idx))
	h.updateSlotDegraded(idx, slot, true, sample)
	if !skipUpdate {
		slot.updateBaseline(sample)
	}
	if slow {
		slot.raisePenalty(now)
	} else {
		slot.reducePenalty(now)
	}
	return slow
}

func (h *nodeHealth) ttfbSlow(idx int, ttfb time.Duration) bool {
	if ttfb <= 0 {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return false
	}
	return slot.baselineSamples >= nodeHealthBaselineMinN &&
		slot.baseline > 0 &&
		ttfb > time.Duration(float64(slot.baseline)*h.tcpSlowFactor(idx))
}

func (h *nodeHealth) tcpSlowFactor(idx int) float64 {
	if h.relaxedTCP(idx) {
		return nodeHealthUDPTransportDegradeFactor
	}
	return nodeHealthDegradeFactor
}

// prepareUDPBaseline ignores local QUIC stream-open samples and unsticks a
// leftover sub-10ms TCP-slot baseline. Returns true when updateBaseline
// must not run (sample ignored or already replaced).
func (h *nodeHealth) prepareUDPBaseline(idx int, slot *nodeHealthSlot, latency time.Duration) bool {
	if slot == nil || !h.relaxedTCP(idx) {
		return false
	}
	if latency < nodeHealthUDPTransportMinBaseline {
		return true
	}
	if slot.baseline < nodeHealthUDPTransportMinBaseline {
		slot.baseline = latency
		if slot.baselineSamples < nodeHealthBaselineMinN {
			slot.baselineSamples = nodeHealthBaselineMinN
		}
		slot.highLatencyStreak = 0
		slot.rememberSuccessDelay(latency)
		return true
	}
	return false
}

func (h *nodeHealth) observeTrafficSuccess(idx int, now time.Time) (changed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return false
	}
	beforeLoss := slot.lossPenaltyLocked()
	beforeDegraded := slot.degraded
	beforePenalty := slot.penaltyLevel
	// Real data-UDP replies have no RTT sample. Count them toward Degraded
	// recovery and penalty decay without moving the latency baseline.
	// Also record a success in the loss window: data-UDP has no periodic
	// probe, so failures would otherwise pin lossPenalty forever.
	slot.pushTestResult(true)
	h.updateSlotDegraded(idx, slot, true, 0)
	slot.reducePenalty(now)
	return beforeLoss != slot.lossPenaltyLocked() ||
		beforeDegraded != slot.degraded ||
		beforePenalty != slot.penaltyLevel
}

func (h *nodeHealth) observeFailure(idx int, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return
	}
	slot.pushTestResult(false)
	h.updateSlotDegraded(idx, slot, false, 0)
	slot.raisePenalty(now)
}

func (h *nodeHealth) pushSpeed(idx int, bps uint64, now time.Time) {
	if bps == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return
	}
	slot.currentSpeed = bps
	slot.currentAt = now
	decayed := slot.decayedPeak(now)
	if slot.peakSpeed == 0 || bps >= decayed {
		slot.peakSpeed = bps
		slot.peakAt = now
	}
	h.maybeUpdateCongestion(idx, slot, now)
}

func (h *nodeHealth) observeConnFinished(idx int, elapsed time.Duration, upload, download uint64, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return
	}
	// Idle close, browser preconnect, AbortAll, and reload all finish with
	// zero bytes. That is not an outbound failure; only explicit I/O errors
	// and ObserveSilentFailure may record a negative sample.
	total := upload + download
	if elapsed < nodeHealthMinSpeedElapsed || total < nodeHealthMinSpeedBytes {
		return
	}
	bps := uint64(float64(total) / elapsed.Seconds())
	if bps == 0 {
		return
	}
	slot.currentSpeed = bps
	slot.currentAt = now
	decayed := slot.decayedPeak(now)
	if slot.peakSpeed == 0 || bps >= decayed {
		slot.peakSpeed = bps
		slot.peakAt = now
	}
	h.maybeUpdateCongestion(idx, slot, now)
}

func (h *nodeHealth) setDegradedForTest(idx int, degraded bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return
	}
	slot.degraded = degraded
	if !degraded {
		slot.congested = false
		slot.failDegraded = false
		slot.recoverStreak = 0
		slot.failStreak = 0
	}
}

func (h *nodeHealth) setFailDegradedForTest(idx int, failDegraded bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.slotLocked(idx)
	if slot == nil {
		return
	}
	slot.failDegraded = failDegraded
	if failDegraded {
		slot.degraded = true
		return
	}
	slot.failStreak = 0
}

func (h *nodeHealth) slotLocked(idx int) *nodeHealthSlot {
	if idx < 0 || idx >= len(h.slots) {
		return nil
	}
	return &h.slots[idx]
}

func (s *nodeHealthSlot) pushTestResult(success bool) {
	s.testResults = append(s.testResults, success)
	if len(s.testResults) > nodeHealthMaxTestResults {
		s.testResults = s.testResults[len(s.testResults)-nodeHealthMaxTestResults:]
	}
}

func (s *nodeHealthSlot) lossPenaltyLocked() time.Duration {
	n := len(s.testResults)
	if n < nodeHealthBaselineMinN {
		return 0
	}
	fails := 0
	for _, ok := range s.testResults {
		if !ok {
			fails++
		}
	}
	rate := float64(fails) / float64(n)
	if n < 5 {
		rate *= float64(n-2) / 3
	}
	if rate <= 0 {
		return 0
	}
	if rate > 1 {
		rate = 1
	}
	return time.Duration(rate * float64(nodeHealthLossPenaltyScale))
}

func (s *nodeHealthSlot) timeDecayPenaltyLocked(now time.Time) time.Duration {
	if s.penaltyLevel <= 0 {
		return 0
	}
	elapsed := now.Sub(s.lastPenaltyAt)
	if elapsed < 0 {
		elapsed = 0
	}
	factor := math.Exp(-elapsed.Seconds() / nodeHealthPenaltyHalfLife.Seconds() * math.Ln2)
	return time.Duration(float64(s.penaltyLevel) * float64(nodeHealthPenaltyUnit) * factor)
}

func (s *nodeHealthSlot) raisePenalty(now time.Time) {
	s.penaltyLevel++
	if s.penaltyLevel > 8 {
		s.penaltyLevel = 8
	}
	s.lastPenaltyAt = now
	s.penaltyGoodStreak = 0
}

func (s *nodeHealthSlot) reducePenalty(_ time.Time) {
	if s.penaltyLevel <= 0 {
		s.penaltyGoodStreak = 0
		return
	}
	s.penaltyGoodStreak++
	// One isolated success after failures is treated as flap, not recovery.
	// Match the Degraded exit bar: two consecutive good samples. Then drop
	// one level at a time so a jittery node stays expensive to re-elect.
	// lastPenaltyAt stays on the last raise so remaining debt keeps decaying
	// instead of a success re-arming the full remaining level.
	if s.penaltyGoodStreak < nodeHealthRecoverSuccesses {
		return
	}
	s.penaltyLevel--
	if s.penaltyLevel < 0 {
		s.penaltyLevel = 0
	}
}

func (s *nodeHealthSlot) updateBaseline(latency time.Duration) {
	if latency <= 0 {
		return
	}
	if s.baselineSamples < nodeHealthBaselineMinN {
		total := s.baseline * time.Duration(s.baselineSamples)
		s.baselineSamples++
		s.baseline = (total + latency) / time.Duration(s.baselineSamples)
		s.rememberSuccessDelay(latency)
		return
	}
	if s.baseline > 0 && latency > time.Duration(float64(s.baseline)*nodeHealthSpikeIgnore) {
		s.highLatencyStreak++
		s.rememberReseedDelay(latency)
		if s.highLatencyStreak >= nodeHealthReseedHighStreak {
			s.reseedFromMedian(s.reseedDelays)
			s.recentSuccessDelays = append([]time.Duration(nil), s.reseedDelays...)
			s.reseedDelays = s.reseedDelays[:0]
			s.highLatencyStreak = 0
		}
		return
	}
	s.highLatencyStreak = 0
	s.reseedDelays = s.reseedDelays[:0]
	next := time.Duration(float64(s.baseline)*(1-nodeHealthBaselineAlpha) + float64(latency)*nodeHealthBaselineAlpha)
	maxUp := time.Duration(float64(s.baseline) * nodeHealthMaxStepUp)
	if next > maxUp && maxUp > 0 {
		next = maxUp
	}
	s.baseline = next
	s.rememberSuccessDelay(latency)
}

func (s *nodeHealthSlot) rememberSuccessDelay(latency time.Duration) {
	s.recentSuccessDelays = append(s.recentSuccessDelays, latency)
	if len(s.recentSuccessDelays) > nodeHealthRecentDelaysN {
		s.recentSuccessDelays = s.recentSuccessDelays[len(s.recentSuccessDelays)-nodeHealthRecentDelaysN:]
	}
}

func (s *nodeHealthSlot) rememberReseedDelay(latency time.Duration) {
	s.reseedDelays = append(s.reseedDelays, latency)
	if len(s.reseedDelays) > nodeHealthRecentDelaysN {
		s.reseedDelays = s.reseedDelays[len(s.reseedDelays)-nodeHealthRecentDelaysN:]
	}
}

func (s *nodeHealthSlot) reseedFromMedian(samples []time.Duration) {
	n := len(samples)
	if n == 0 {
		return
	}
	cp := append([]time.Duration(nil), samples...)
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j] < cp[j-1]; j-- {
			cp[j], cp[j-1] = cp[j-1], cp[j]
		}
	}
	s.baseline = cp[len(cp)/2]
	s.baselineSamples = n
}

func (h *nodeHealth) updateSlotDegraded(idx int, slot *nodeHealthSlot, success bool, latency time.Duration) {
	degradeFactor := nodeHealthDegradeFactor
	recoverFactor := nodeHealthRecoverFactor
	failNeed := 1
	if h.relaxedTCP(idx) {
		degradeFactor = nodeHealthUDPTransportDegradeFactor
		recoverFactor = nodeHealthUDPTransportRecoverFactor
		failNeed = nodeHealthUDPTransportFailStreak
	}
	slot.updateDegraded(success, latency, degradeFactor, recoverFactor, failNeed)
}

func (h *nodeHealth) maybeUpdateCongestion(idx int, slot *nodeHealthSlot, now time.Time) {
	if h.relaxedTCP(idx) {
		slot.congested = false
		slot.congestedSince = time.Time{}
		return
	}
	slot.updateCongestion(now)
}

func (s *nodeHealthSlot) updateDegraded(success bool, latency time.Duration, degradeFactor, recoverFactor float64, failNeed int) {
	if failNeed < 1 {
		failNeed = 1
	}
	if !success {
		s.failStreak++
		s.recoverStreak = 0
		if s.failStreak >= failNeed {
			s.degraded = true
			s.failDegraded = true
		}
		return
	}
	s.failStreak = 0
	s.failDegraded = false
	if s.baselineSamples < nodeHealthBaselineMinN {
		s.recoverStreak++
		if s.recoverStreak >= nodeHealthRecoverSuccesses {
			s.degraded = false
			s.recoverStreak = 0
		}
		return
	}
	if s.baseline > 0 && latency > time.Duration(float64(s.baseline)*degradeFactor) {
		s.degraded = true
		s.recoverStreak = 0
		return
	}
	if s.degraded && (s.baseline == 0 || latency <= time.Duration(float64(s.baseline)*recoverFactor)) {
		s.recoverStreak++
		if s.recoverStreak >= nodeHealthRecoverSuccesses {
			s.degraded = false
			s.failDegraded = false
			s.recoverStreak = 0
		}
		return
	}
	s.recoverStreak = 0
}

func (s *nodeHealthSlot) decayedPeak(now time.Time) uint64 {
	if s.peakSpeed == 0 || s.peakAt.IsZero() {
		return 0
	}
	elapsed := now.Sub(s.peakAt).Seconds()
	if elapsed <= 0 {
		return s.peakSpeed
	}
	return uint64(float64(s.peakSpeed) * math.Exp(-nodeHealthSpeedDecayLambda*elapsed))
}

func (s *nodeHealthSlot) updateCongestion(now time.Time) {
	if now.Sub(s.currentAt) > nodeHealthSpeedStale {
		s.currentSpeed = 0
	}
	effective := s.decayedPeak(now)
	if s.currentSpeed > effective {
		effective = s.currentSpeed
	}
	rttDegraded := s.baselineSamples >= nodeHealthBaselineMinN &&
		s.baseline > 0 &&
		s.lastSampleRTT > time.Duration(float64(s.baseline)*nodeHealthDegradeFactor)
	saturated := effective > 0 && s.currentSpeed >= uint64(float64(effective)*nodeHealthCongestionRatio)
	if saturated && rttDegraded {
		if s.congestedSince.IsZero() {
			s.congestedSince = now
		}
		if now.Sub(s.congestedSince) >= nodeHealthCongestionWindow {
			s.congested = true
		}
		return
	}
	s.congestedSince = time.Time{}
	if s.congested && (!rttDegraded || s.currentSpeed == 0) {
		s.congested = false
	}
}

func (h *nodeHealth) snapshot() [8]NodeHealthSlotSnapshot {
	var out [8]NodeHealthSlotSnapshot
	if h == nil {
		return out
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.slots {
		slot := &h.slots[i]
		out[i] = NodeHealthSlotSnapshot{
			Baseline:            slot.baseline,
			BaselineSamples:     slot.baselineSamples,
			RecentSuccessDelays: append([]time.Duration(nil), slot.recentSuccessDelays...),
			LastSampleRTT:       slot.lastSampleRTT,
			Degraded:            slot.degraded,
		}
	}
	return out
}

func (h *nodeHealth) restore(slots [8]NodeHealthSlotSnapshot) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.slots {
		slot := &h.slots[i]
		src := slots[i]
		slot.baseline = src.Baseline
		slot.baselineSamples = src.BaselineSamples
		slot.recentSuccessDelays = append([]time.Duration(nil), src.RecentSuccessDelays...)
		slot.lastSampleRTT = src.LastSampleRTT
		slot.degraded = src.Degraded
		slot.failDegraded = false
		slot.penaltyLevel = 0
		slot.lastPenaltyAt = time.Time{}
		slot.penaltyGoodStreak = 0
		slot.recoverStreak = 0
		slot.failStreak = 0
		slot.highLatencyStreak = 0
		slot.reseedDelays = nil
		slot.testResults = nil
		slot.congested = false
		slot.congestedSince = time.Time{}
		slot.peakSpeed = 0
		slot.currentSpeed = 0
	}
}
