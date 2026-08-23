/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func TestNodeHealthProbeDegradeAndRecover(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4

	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 50*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	if got := h.admission(idx, true); got != AdmissionAlive {
		t.Fatalf("admission after baseline = %v, want Alive", got)
	}

	h.observeProbe(idx, true, 200*time.Millisecond, now)
	if got := h.admission(idx, true); got != AdmissionDegraded {
		t.Fatalf("admission after 4x RTT = %v, want Degraded", got)
	}

	now = now.Add(time.Second)
	h.observeProbe(idx, true, 50*time.Millisecond, now)
	now = now.Add(time.Second)
	h.observeProbe(idx, true, 50*time.Millisecond, now)
	if got := h.admission(idx, true); got != AdmissionAlive {
		t.Fatalf("admission after recover successes = %v, want Alive", got)
	}
}

func TestNodeHealthFallbackAdmissionIgnoresRTTButHonorsFailure(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 50*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	h.observeProbe(idx, true, 200*time.Millisecond, now)
	if got := h.admission(idx, true); got != AdmissionDegraded {
		t.Fatalf("admission after 4x RTT = %v, want Degraded", got)
	}
	if got := h.fallbackAdmission(idx, true); got != AdmissionAlive {
		t.Fatalf("fallbackAdmission after 4x RTT = %v, want Alive", got)
	}

	now = now.Add(time.Second)
	h.observeFailure(idx, now)
	if got := h.fallbackAdmission(idx, true); got != AdmissionDegraded {
		t.Fatalf("fallbackAdmission after failure = %v, want Degraded", got)
	}
	if got := h.admission(idx, true); got != AdmissionDegraded {
		t.Fatalf("admission after failure = %v, want Degraded", got)
	}

	now = now.Add(time.Second)
	h.observeProbe(idx, true, 50*time.Millisecond, now)
	if got := h.fallbackAdmission(idx, true); got != AdmissionAlive {
		t.Fatalf("fallbackAdmission after one success = %v, want Alive", got)
	}
}

func TestNodeHealthDeadIgnoresDegraded(t *testing.T) {
	var h nodeHealth
	h.setDegradedForTest(IdxTcp4, true)
	if got := h.admission(IdxTcp4, false); got != AdmissionDead {
		t.Fatalf("admission = %v, want Dead", got)
	}
}

func TestNodeHealthPenaltyRequiresConsecutiveSuccesses(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	h.observeProbe(idx, true, 40*time.Millisecond, now)
	h.observeFailure(idx, now)
	h.observeFailure(idx, now)
	if got := h.slots[idx].penaltyLevel; got != 2 {
		t.Fatalf("penalty after two failures = %d, want 2", got)
	}

	now = now.Add(time.Second)
	h.observeProbe(idx, true, 40*time.Millisecond, now)
	if got := h.slots[idx].penaltyLevel; got != 2 {
		t.Fatalf("penalty after one success = %d, want 2 (flap)", got)
	}

	now = now.Add(time.Second)
	h.observeProbe(idx, true, 40*time.Millisecond, now)
	if got := h.slots[idx].penaltyLevel; got != 1 {
		t.Fatalf("penalty after two consecutive successes = %d, want 1", got)
	}

	now = now.Add(time.Second)
	h.observeFailure(idx, now)
	if got := h.slots[idx].penaltyLevel; got != 2 {
		t.Fatalf("penalty after new failure = %d, want 2", got)
	}
	now = now.Add(time.Second)
	h.observeProbe(idx, true, 40*time.Millisecond, now)
	if got := h.slots[idx].penaltyLevel; got != 2 {
		t.Fatalf("penalty after isolated success = %d, want 2", got)
	}
}

func TestNodeHealthQualityPenaltyDecays(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	h.observeProbe(idx, true, 40*time.Millisecond, now)
	h.observeFailure(idx, now)
	q1, ok := h.quality(idx, 40*time.Millisecond, true, now)
	if !ok || q1 <= 40*time.Millisecond {
		t.Fatalf("quality after failure = %v ok=%v, want penalty", q1, ok)
	}
	q2, _ := h.quality(idx, 40*time.Millisecond, true, now.Add(2*nodeHealthPenaltyHalfLife))
	if q2 >= q1 {
		t.Fatalf("quality after decay = %v, want less than %v", q2, q1)
	}
}

func TestNodeHealthCongestionRequiresPersistentSaturation(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	h.pushSpeed(idx, 10<<20, now)
	h.observeSample(idx, 80*time.Millisecond, now)
	h.pushSpeed(idx, 9<<20, now)
	if got := h.admission(idx, true); got != AdmissionDegraded {
		// sample 80ms vs 40ms baseline is already degrade-by-RTT; congestion
		// is the extra congested flag. RTT degrade is enough here.
		t.Fatalf("admission after slow sample = %v, want Degraded", got)
	}

	var idle nodeHealth
	now = time.Unix(1_700_000_100, 0)
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		idle.observeProbe(idx, true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	idle.pushSpeed(idx, 10<<20, now)
	now = now.Add(time.Second)
	idle.observeSample(idx, 80*time.Millisecond, now)
	idle.pushSpeed(idx, 9<<20, now)
	if idle.slots[idx].congested {
		t.Fatal("congestion flagged without a sustained window")
	}
	now = now.Add(nodeHealthCongestionWindow)
	idle.pushSpeed(idx, 9<<20, now)
	if !idle.slots[idx].congested {
		t.Fatal("expected congestion after saturated window with degraded RTT")
	}
}

func TestNodeHealthIdleFinishDoesNotDegrade(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	h.observeConnFinished(IdxTcp4, nodeHealthSilentFail, 1500, 0, now)
	if h.slots[IdxTcp4].degraded {
		t.Fatal("upload-only flow must not degrade")
	}
	h.observeConnFinished(IdxTcp4, nodeHealthSilentFail, 0, 0, now)
	if h.slots[IdxTcp4].degraded {
		t.Fatal("idle zero-byte finish must not degrade the node")
	}
}

func TestNodeHealthReseedBaselineFromHighLatencyStreak(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 50*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	if got := h.slots[idx].baseline; got != 50*time.Millisecond {
		t.Fatalf("baseline after 50ms samples = %v, want 50ms", got)
	}
	for i := 0; i < nodeHealthReseedHighStreak; i++ {
		h.observeProbe(idx, true, 200*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	if got := h.slots[idx].baseline; got != 200*time.Millisecond {
		t.Fatalf("baseline after high-latency reseed = %v, want 200ms", got)
	}
}

func TestDialerHealthSnapshotPreservesNodeHealth(t *testing.T) {
	src := newNamedTestDialer(t, "health-src")
	dst := newNamedTestDialer(t, "health-dst")
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		src.health.observeProbe(typ.Index(), true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	src.SetDegradedForTest(typ, true)

	snap := src.ReloadHealthSnapshot()
	if snap.Health[typ.Index()].Baseline != 40*time.Millisecond {
		t.Fatalf("snapshot baseline = %v, want 40ms", snap.Health[typ.Index()].Baseline)
	}
	if !snap.Health[typ.Index()].Degraded {
		t.Fatal("snapshot dropped Degraded")
	}

	dst.RestoreHealthSnapshot(snap)
	if dst.AdmissionState(typ) != AdmissionDegraded {
		t.Fatalf("restored admission = %v, want Degraded", dst.AdmissionState(typ))
	}
	if got := dst.HealthSnapshot().Health[typ.Index()].Baseline; got != 40*time.Millisecond {
		t.Fatalf("restored baseline = %v, want 40ms", got)
	}
}

func TestDialerHealthSnapshotRestoresQualityBeforeGroupCache(t *testing.T) {
	src := newNamedTestDialer(t, "quality-src")
	dst := newNamedTestDialer(t, "quality-dst")
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		src.health.observeProbe(typ.Index(), true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	src.SetDegradedForTest(typ, true)
	snap := src.ReloadHealthSnapshot()

	set := NewAliveDialerSet(
		dst.Log,
		"restore-quality",
		typ,
		0,
		consts.DialerSelectionPolicy_UrlTest,
		[]*Dialer{dst},
		[]*Annotation{{}},
		func(bool) {},
		true,
	)
	dst.RegisterAliveDialerSet(set)
	t.Cleanup(func() { dst.UnregisterAliveDialerSet(set) })

	dst.RestoreHealthSnapshot(snap)
	got, latency := set.GetMinLatency(nil)
	if got != dst {
		t.Fatalf("url_test cache dialer = %p, want restored dest", got)
	}
	if latency < nodeHealthDegradePenalty {
		t.Fatalf("url_test cache latency = %v, want degraded penalty after restore", latency)
	}
}

func TestNodeHealthTTFBDoesNotMutateSlot(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	baseline := h.slots[idx].baseline
	if !h.ttfbSlow(idx, 200*time.Millisecond) {
		t.Fatal("TTFB well above baseline should be slow for PinSite")
	}
	if h.slots[idx].baseline != baseline {
		t.Fatalf("TTFB mutated baseline %v -> %v", baseline, h.slots[idx].baseline)
	}
	if h.slots[idx].degraded {
		t.Fatal("TTFB must not mark the node Degraded")
	}
	if got := h.admission(idx, true); got != AdmissionAlive {
		t.Fatalf("admission after TTFB = %v, want Alive", got)
	}
}

func TestDialerObserveTTFBDoesNotDegradeAdmission(t *testing.T) {
	d := newNamedTestDialer(t, "ttfb")
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		d.health.observeProbe(typ.Index(), true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	if !d.ObserveTTFB(typ, 200*time.Millisecond) {
		t.Fatal("ObserveTTFB should report slow against the handshake baseline")
	}
	if d.AdmissionState(typ) != AdmissionAlive {
		t.Fatalf("admission after ObserveTTFB = %v, want Alive", d.AdmissionState(typ))
	}
}

func TestNodeHealthCongestionRecoversWhenSpeedStale(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	h.slots[idx].lastSampleRTT = 200 * time.Millisecond
	h.slots[idx].degraded = false
	h.slots[idx].congested = true
	h.slots[idx].currentAt = now
	h.slots[idx].currentSpeed = 1 << 20
	h.slots[idx].peakSpeed = 1 << 20
	h.slots[idx].peakAt = now
	if got := h.admissionAt(idx, true, now); got != AdmissionDegraded {
		t.Fatalf("admission while congested = %v, want Degraded", got)
	}
	if got := h.admissionAt(idx, true, now.Add(nodeHealthSpeedStale+time.Second)); got != AdmissionAlive {
		t.Fatalf("admission after stale congestion = %v, want Alive", got)
	}
}

func TestNodeHealthSmallFlowsDoNotSetPeak(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	h.observeConnFinished(IdxTcp4, 200*time.Millisecond, 100, 100, now)
	if h.slots[IdxTcp4].peakSpeed != 0 {
		t.Fatalf("peakSpeed = %d, want 0 for a tiny flow", h.slots[IdxTcp4].peakSpeed)
	}
}

func TestNodeHealthProbeClassifiesBeforeUpdatingBaseline(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 50*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	if got := h.admission(idx, true); got != AdmissionAlive {
		t.Fatalf("admission after baseline = %v, want Alive", got)
	}
	h.observeProbe(idx, true, 76*time.Millisecond, now)
	if got := h.admission(idx, true); got != AdmissionDegraded {
		t.Fatalf("admission after 1.52× sample = %v, want Degraded", got)
	}
}

func TestDialerDataUDPTrafficSuccessRecoversDegraded(t *testing.T) {
	d := newNamedTestDialer(t, "udp-leaf")
	typ := &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: UdpHealthDomainData,
	}
	d.ReportUnavailable(typ, fmt.Errorf("udp loss"))
	if !d.MustGetAlive(typ) {
		t.Fatal("single UDP failure must keep the node Alive")
	}
	if got := d.AdmissionState(typ); got != AdmissionDegraded {
		t.Fatalf("admission after UDP failure = %v, want Degraded", got)
	}
	d.ReportAvailableTraffic(typ)
	d.ReportAvailableTraffic(typ)
	if got := d.AdmissionState(typ); got != AdmissionAlive {
		t.Fatalf("admission after UDP traffic success = %v, want Alive", got)
	}
}

func TestResetTrafficFailCountBreaksWriteFailStreakWithoutRecoveringDegraded(t *testing.T) {
	d := newNamedTestDialer(t, "udp-write-streak")
	typ := &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: UdpHealthDomainData,
	}
	for i := 0; i < 49; i++ {
		d.ReportUnavailable(typ, fmt.Errorf("udp write fail"))
	}
	if !d.MustGetAlive(typ) {
		t.Fatal("49 write failures must keep the node Alive")
	}
	if got := d.AdmissionState(typ); got != AdmissionDegraded {
		t.Fatalf("admission after write failures = %v, want Degraded", got)
	}
	d.ResetTrafficFailCount(typ)
	if got := d.AdmissionState(typ); got != AdmissionDegraded {
		t.Fatalf("write-success reset must not exit Degraded, got %v", got)
	}
	if !d.MustGetAlive(typ) {
		t.Fatal("write-success reset must keep the node Alive")
	}
	for i := 0; i < 49; i++ {
		d.ReportUnavailable(typ, fmt.Errorf("udp write fail"))
	}
	if !d.MustGetAlive(typ) {
		t.Fatal("write-fail streak must restart after a successful write")
	}
	d.ReportUnavailable(typ, fmt.Errorf("udp write fail"))
	if d.MustGetAlive(typ) {
		t.Fatal("50 consecutive write failures must mark the node Dead")
	}
}

func TestReportAvailableTrafficSkipsPublishWhenStable(t *testing.T) {
	d := newNamedTestDialer(t, "udp-stable")
	typ := &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: UdpHealthDomainData,
	}
	publishes := 0
	set := NewAliveDialerSet(
		d.Log,
		"udp-stable",
		typ,
		0,
		consts.DialerSelectionPolicy_Fallback,
		[]*Dialer{d},
		[]*Annotation{{}},
		func(bool) { publishes++ },
		true,
	)
	d.RegisterAliveDialerSet(set)
	t.Cleanup(func() { d.UnregisterAliveDialerSet(set) })

	d.ReportUnavailable(typ, fmt.Errorf("udp loss"))
	d.ReportAvailableTraffic(typ)
	d.ReportAvailableTraffic(typ)
	for i := 0; i < nodeHealthMaxTestResults; i++ {
		d.ReportAvailableTraffic(typ)
	}
	publishes = 0
	d.ReportAvailableTraffic(typ)
	d.ReportAvailableTraffic(typ)
	if publishes != 0 {
		t.Fatalf("stable UDP successes republished %d times, want 0", publishes)
	}
}

func TestNodeHealthTrafficSuccessFlushesLossWindow(t *testing.T) {
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxUdp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeFailure(idx, now)
		now = now.Add(time.Second)
	}
	now = now.Add(2 * nodeHealthPenaltyHalfLife)
	qFail, ok := h.quality(idx, 40*time.Millisecond, true, now)
	if !ok || qFail < 40*time.Millisecond+200*time.Millisecond {
		t.Fatalf("quality after UDP losses = %v, want a large loss penalty", qFail)
	}
	for i := 0; i < nodeHealthMaxTestResults; i++ {
		h.observeTrafficSuccess(idx, now)
		now = now.Add(time.Second)
	}
	qOk, _ := h.quality(idx, 40*time.Millisecond, true, now)
	if qOk > 40*time.Millisecond+50*time.Millisecond {
		t.Fatalf("quality after UDP successes = %v, want loss window flushed", qOk)
	}
}

func TestUDPTransportTCPIgnoresMildRTTAndSingleFailure(t *testing.T) {
	var h nodeHealth
	h.udpTransport = true
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 50*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	h.observeFailure(idx, now)
	if got := h.admission(idx, true); got != AdmissionAlive {
		t.Fatalf("admission after one TCP fail on UDP transport = %v, want Alive", got)
	}
	now = now.Add(time.Second)
	h.observeProbe(idx, true, 76*time.Millisecond, now)
	if got := h.admission(idx, true); got != AdmissionAlive {
		t.Fatalf("admission after 1.52× TCP RTT on UDP transport = %v, want Alive", got)
	}
	now = now.Add(time.Second)
	h.observeProbe(idx, true, 150*time.Millisecond, now)
	if got := h.admission(idx, true); got != AdmissionDegraded {
		t.Fatalf("admission after ~3× TCP RTT on UDP transport = %v, want Degraded", got)
	}
}

func TestUDPTransportTCPNeedsFailureStreakToDegrade(t *testing.T) {
	var h nodeHealth
	h.udpTransport = true
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	h.observeProbe(idx, true, 50*time.Millisecond, now)
	for i := 0; i < nodeHealthUDPTransportFailStreak-1; i++ {
		now = now.Add(time.Second)
		h.observeFailure(idx, now)
		if got := h.admission(idx, true); got != AdmissionAlive {
			t.Fatalf("admission after %d TCP fails = %v, want Alive", i+1, got)
		}
	}
	now = now.Add(time.Second)
	h.observeFailure(idx, now)
	if got := h.admission(idx, true); got != AdmissionDegraded {
		t.Fatalf("admission after %d TCP fails = %v, want Degraded", nodeHealthUDPTransportFailStreak, got)
	}
}

func TestUDPTransportTCPSkipsCongestion(t *testing.T) {
	var h nodeHealth
	h.udpTransport = true
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 40*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	h.pushSpeed(idx, 10<<20, now)
	now = now.Add(time.Second)
	h.observeSample(idx, 80*time.Millisecond, now)
	h.pushSpeed(idx, 9<<20, now)
	now = now.Add(nodeHealthCongestionWindow)
	h.pushSpeed(idx, 9<<20, now)
	if h.slots[idx].congested {
		t.Fatal("UDP transport TCP slot must not use Brutal-style congestion Degraded")
	}
	if got := h.admission(idx, true); got != AdmissionAlive {
		t.Fatalf("admission after saturated 2× RTT = %v, want Alive", got)
	}
}

func TestUDPTransportDataUDPStillDegradesOnSingleFailure(t *testing.T) {
	var h nodeHealth
	h.udpTransport = true
	now := time.Unix(1_700_000_000, 0)
	idx := IdxUdp4
	h.observeFailure(idx, now)
	if got := h.admission(idx, true); got != AdmissionDegraded {
		t.Fatalf("data-UDP admission after one fail = %v, want Degraded", got)
	}
}

func TestDialerHysteria2TCPSlotUsesRelaxedAdmission(t *testing.T) {
	d := newNamedTestDialer(t, "hy2")
	d.property.Protocol = "hysteria2"
	d.health.udpTransport = udpTransportFromProperty(d.property)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		d.health.observeProbe(typ.Index(), true, 50*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	if d.health.observeSample(typ.Index(), 76*time.Millisecond, now) {
		t.Fatal("1.52× must not count as site-slow on UDP-transport TCP")
	}
	if got := d.AdmissionState(typ); got != AdmissionAlive {
		t.Fatalf("Hysteria2 TCP admission after 1.52× = %v, want Alive", got)
	}
	if d.ObserveTTFB(typ, 76*time.Millisecond) {
		t.Fatal("1.52× TTFB must not count as site-slow on UDP-transport TCP")
	}
	if !d.ObserveTTFB(typ, 150*time.Millisecond) {
		t.Fatal("3× TTFB should count as site-slow on UDP-transport TCP")
	}
}

func TestUDPTransportIgnoresLocalHandshakeBaseline(t *testing.T) {
	d := newNamedTestDialer(t, "hy2-hs")
	d.property.Protocol = "hysteria2"
	d.health.udpTransport = udpTransportFromProperty(d.property)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	idx := typ.Index()
	if d.ObserveHandshake(typ, time.Millisecond) {
		t.Fatal("local QUIC stream-open must not count as site-slow")
	}
	if got := d.health.slots[idx].baseline; got != 0 {
		t.Fatalf("handshake seeded baseline = %v, want 0", got)
	}
	if got := d.health.slots[idx].baselineSamples; got != 0 {
		t.Fatalf("handshake seeded samples = %d, want 0", got)
	}
}

func TestUDPTransportReplacesTinyBaselineFromProbe(t *testing.T) {
	var h nodeHealth
	h.udpTransport = true
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	h.observeSample(idx, time.Millisecond, now)
	if got := h.slots[idx].baseline; got != 0 {
		t.Fatalf("sub-10ms sample seeded baseline = %v, want 0", got)
	}
	now = now.Add(time.Second)
	h.observeProbe(idx, true, 190*time.Millisecond, now)
	if got := h.slots[idx].baseline; got != 190*time.Millisecond {
		t.Fatalf("tiny baseline not replaced by probe = %v, want 190ms", got)
	}
	if h.ttfbSlow(idx, 250*time.Millisecond) {
		t.Fatal("250ms TTFB vs 190ms probe baseline must not be site-slow at 2×")
	}
	if !h.ttfbSlow(idx, 400*time.Millisecond) {
		t.Fatal("400ms TTFB vs 190ms probe baseline should be site-slow at 2×")
	}
}

func TestAdmissionReasonAndString(t *testing.T) {
	if AdmissionAlive.String() != "alive" || AdmissionDegraded.String() != "degraded" || AdmissionDead.String() != "dead" {
		t.Fatalf("String() = %s %s %s", AdmissionAlive, AdmissionDegraded, AdmissionDead)
	}
	var h nodeHealth
	now := time.Unix(1_700_000_000, 0)
	idx := IdxTcp4
	for i := 0; i < nodeHealthBaselineMinN; i++ {
		h.observeProbe(idx, true, 50*time.Millisecond, now)
		now = now.Add(time.Second)
	}
	if got := h.admissionReason(idx, true); got != "ok" {
		t.Fatalf("reason after baseline = %q, want ok", got)
	}
	h.observeProbe(idx, true, 200*time.Millisecond, now)
	if got := h.admissionReason(idx, true); got != "rtt" {
		t.Fatalf("reason after slow probe = %q, want rtt", got)
	}
	h.observeFailure(idx, now)
	if got := h.admissionReason(idx, true); !strings.Contains(got, "fail") {
		t.Fatalf("reason after fail = %q, want fail", got)
	}
	if got := h.admissionReason(idx, false); got != "not_alive" {
		t.Fatalf("reason when dead = %q, want not_alive", got)
	}
}
