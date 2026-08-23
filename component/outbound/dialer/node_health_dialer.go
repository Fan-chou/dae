/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

func (d *Dialer) AdmissionState(typ *NetworkType) AdmissionState {
	if d == nil || typ == nil {
		return AdmissionDead
	}
	return d.health.admission(typ.Index(), d.MustGetAlive(typ))
}

// FallbackAdmission is the fallback/first-available gate. Dead and
// failure/loss-based Degraded are skipped; RTT-only or congestion Degraded
// stays selectable so declaration order is not overridden by a slower probe.
func (d *Dialer) FallbackAdmission(typ *NetworkType) AdmissionState {
	if d == nil || typ == nil {
		return AdmissionDead
	}
	return d.health.fallbackAdmission(typ.Index(), d.MustGetAlive(typ))
}

// AdmissionReason is a stable, machine-readable cause for AdmissionState:
// ok, not_alive, fail, rtt, congestion, or a comma-joined combination.
func (d *Dialer) AdmissionReason(typ *NetworkType) string {
	if d == nil || typ == nil {
		return "not_alive"
	}
	return d.health.admissionReason(typ.Index(), d.MustGetAlive(typ))
}

func (d *Dialer) maybeLogAdmission(typ *NetworkType) {
	if d == nil || typ == nil || d.Log == nil || !d.Log.IsLevelEnabled(logrus.DebugLevel) {
		return
	}
	change, ok := d.health.consumeAdmissionChange(typ.Index(), d.MustGetAlive(typ), time.Now())
	if !ok {
		return
	}
	node := ""
	if d.property != nil {
		node = d.property.Name
	}
	fields := logrus.Fields{
		"node":            node,
		"network":         typ.String(),
		"from":            change.from.String(),
		"to":              change.to.String(),
		"reason":          change.toReason,
		"previous_reason": change.fromReason,
		"fallback_from":   change.fromFallback.String(),
		"fallback_to":     change.toFallback.String(),
		"behavior":        admissionSelectionBehavior(change.to, change.toFallback),
	}
	if change.rtt > 0 {
		fields["rtt"] = change.rtt.Truncate(time.Millisecond).String()
	}
	if change.baseline > 0 {
		fields["baseline"] = change.baseline.Truncate(time.Millisecond).String()
	}
	if change.failStreak > 0 {
		fields["fail_streak"] = change.failStreak
	}
	if change.congested {
		fields["congested"] = true
	}
	d.Log.WithFields(fields).Debugf("Node admission %s -> %s", change.from.String(), change.to.String())
}

func (d *Dialer) ObserveHandshake(typ *NetworkType, handshake time.Duration) (slow bool) {
	if d == nil || typ == nil || handshake <= 0 {
		return false
	}
	idx := typ.Index()
	// Hysteria/TUIC/Juicity inner TCP Dial is local QUIC stream-open, not
	// path RTT. Feeding it would pin the TCP-slot baseline near 1ms.
	if d.health.relaxedTCP(idx) {
		return false
	}
	slow = d.health.observeSample(idx, handshake, time.Now())
	d.publishQuality(typ)
	if slow {
		d.notifyImmediateCheck(typ)
	}
	return slow
}

func (d *Dialer) ObserveTTFB(typ *NetworkType, ttfb time.Duration) (slow bool) {
	if d == nil || typ == nil || ttfb <= 0 {
		return false
	}
	// TTFB includes client upload and origin processing. Compare against the
	// handshake/probe baseline for per-site PinSite, but never write it into
	// the node-level health slot.
	return d.health.ttfbSlow(typ.Index(), ttfb)
}

func (d *Dialer) ObserveSilentFailure(typ *NetworkType) {
	if d == nil || typ == nil {
		return
	}
	d.health.observeFailure(typ.Index(), time.Now())
	d.publishQuality(typ)
	d.notifyImmediateCheck(typ)
}

func (d *Dialer) ObserveConnFinished(typ *NetworkType, elapsed time.Duration, upload, download uint64) {
	if d == nil || typ == nil {
		return
	}
	d.health.observeConnFinished(typ.Index(), elapsed, upload, download, time.Now())
	d.publishQuality(typ)
}

func (d *Dialer) PushObservedSpeed(typ *NetworkType, bps uint64) {
	if d == nil || typ == nil || bps == 0 {
		return
	}
	d.health.pushSpeed(typ.Index(), bps, time.Now())
	d.publishQuality(typ)
}

// SetDegradedForTest forces the userspace admission state without flipping
// collection.Alive, so BPF connectivity stays up.
func (d *Dialer) SetDegradedForTest(typ *NetworkType, degraded bool) {
	if d == nil || typ == nil {
		return
	}
	d.health.setDegradedForTest(typ.Index(), degraded)
	d.publishQuality(typ)
}

// SetFailDegradedForTest marks failure-based Degraded so fallback will skip
// this leaf while url_test still sees the ordinary Degraded penalty.
func (d *Dialer) SetFailDegradedForTest(typ *NetworkType, failDegraded bool) {
	if d == nil || typ == nil {
		return
	}
	d.health.setFailDegradedForTest(typ.Index(), failDegraded)
	d.publishQuality(typ)
}

func (d *Dialer) publishQuality(typ *NetworkType) {
	if d == nil || typ == nil {
		return
	}
	d.collectionFineMu.RLock()
	collection := d.mustGetCollection(typ)
	update := collectionUpdate{
		alive:             collection.Alive.Load(),
		movingAverage:     collection.MovingAverage,
		aliveDialerGroups: d.snapshotAliveDialerGroupsLocked(collection),
	}
	d.collectionFineMu.RUnlock()
	d.maybeLogAdmission(typ)
	d.informDialerGroupUpdate(update)
}

func (d *Dialer) notifyImmediateCheck(typ *NetworkType) {
	if d == nil || typ == nil {
		return
	}
	if typ.L4Proto == consts.L4ProtoStr_UDP {
		d.NotifyCheckDnsUdp()
		return
	}
	d.NotifyCheckTcp()
}
