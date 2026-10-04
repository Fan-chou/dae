/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
	"time"
)

// A recovery token belongs to one selection, never to an interned path or a
// cached established-flow snapshot. Late callbacks cannot commit a newer trial.
type stickyRecovery struct {
	suppressed        int
	load              dialer.LoadContext
	network           dialer.NetworkType
	table             *siteStickyTable
	key               string
	entry             *siteStickyEntry
	stable, candidate *dialer.Dialer
	startedAt         time.Time
	deadline          time.Time
}

func (p SelectPath) WithoutRecovery() SelectPath { p.recovery = nil; return p }

// RecoveryFirstByte consumes only a recovery connection's callback, including
// stale callbacks. Ordinary pinning must not overwrite the retained stable leaf.
func (p SelectPath) RecoveryFirstByte(slow bool) bool {
	if p.recovery == nil {
		return false
	}
	reason := "first_byte_ok"
	if slow {
		reason = "slow_first_byte"
	}
	p.recovery.finishReason(!slow, time.Now(), reason)
	return true
}
func (p SelectPath) RecoveryFinish() {
	if p.recovery != nil {
		p.recovery.finish(false, time.Now())
	}
}

// RecoveryAbandon releases a trial whose connection never ran (adoption or
// bookkeeping failure). Unlike RecoveryFinish it records no node failure and
// leaves the retry schedule untouched.
func (p SelectPath) RecoveryAbandon() {
	if p.recovery != nil {
		p.recovery.abandon()
	}
}

// abandonRecovery releases a trial started while evaluating a candidate path
// that this selection did not adopt. Nested parents evaluate several children
// and keep one; the rest must not age into "expired" failures.
func (p *selectPathBuilder) abandonRecovery() {
	if p != nil && p.recovery != nil {
		p.recovery.abandon()
		p.recovery = nil
	}
}

// abandon returns the trial slot without touching failure counters or the
// next eligibility time. Stale or already replaced tokens are ignored.
func (r *stickyRecovery) abandon() {
	if r == nil || r.table == nil {
		return
	}
	t := r.table
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[r.key]
	if t.detached || e != r.entry || e.recovery != r {
		return
	}
	e.recovery = nil
	// Allow the next eligible connection to retry at once instead of waiting
	// for the group-wide probe spacing measured from this unused trial.
	if t.lastRecoveryProbe.Equal(r.startedAt) {
		t.lastRecoveryProbe = time.Time{}
	}
}

func recentRecoveries(v []time.Time, now time.Time) []time.Time {
	kept := v[:0]
	for _, at := range v {
		if now.Sub(at) < 30*time.Minute {
			kept = append(kept, at)
		}
	}
	return kept
}
func (t *siteStickyTable) recoveryBudget(e *siteStickyEntry, now time.Time) bool {
	e.recoverySwitches = recentRecoveries(e.recoverySwitches, now)
	t.recoverySwitches = recentRecoveries(t.recoverySwitches, now)
	return len(e.recoverySwitches) < 2 && len(t.recoverySwitches) < 10 && now.Sub(t.lastRecovery) >= 5*time.Second
}
func (t *siteStickyTable) recoveryEvent(reason, key string, r *stickyRecovery, next time.Time) {
	t.diagnosticReasons = countRecoveryReason(t.diagnosticReasons, reason)
	if t.recoveryLog != nil {
		now := time.Now()
		if now.Sub(t.recoveryLogAt) >= time.Minute {
			t.recoveryLogAt = now
			t.recoveryLogCount = 0
		}
		if reason != "recovered" && t.recoveryLogCount >= 20 {
			t.recoveryLogSuppressed++
			return
		}
		t.recoveryLogCount++
		copy := *r
		copy.load = r.candidate.LoadContext(now)
		copy.suppressed = t.recoveryLogSuppressed
		t.recoveryLogSuppressed = 0
		t.recoveryLog(reason, key, &copy, next)
	}
}
func (t *siteStickyTable) deferRecovery(e *siteStickyEntry, r *stickyRecovery, now time.Time, reason string) {
	e.recoveryFailures++
	delay := 2 * time.Minute
	if e.recoveryFailures == 2 {
		delay = 5 * time.Minute
	}
	if e.recoveryFailures >= 3 {
		delay = 10 * time.Minute
	}
	e.nextRecovery = now.Add(delay)
	e.recovery = nil
	t.recoveryEvent(reason, r.key, r, e.nextRecovery)
}
func (t *siteStickyTable) startRecovery(site string, stable, candidate *dialer.Dialer, now time.Time, network *dialer.NetworkType) *stickyRecovery {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := t.key(site)
	e := t.lookupLocked(key, now)
	if e == nil || e.leaf != stable || t.detached {
		return nil
	}
	if r := e.recovery; r != nil {
		if !now.Before(r.deadline) {
			t.deferRecovery(e, r, now, "expired")
		}
		return nil
	}
	if e.nextRecovery.IsZero() {
		e.nextRecovery = e.pinnedAt.Add(siteStickyRecoveryAfter)
	}
	if now.Sub(t.lastRecoveryProbe) < 5*time.Second || now.Before(e.nextRecovery) || now.Before(e.recoveryDwell) || !t.recoveryBudget(e, now) {
		return nil
	}
	// The token is fully populated before it becomes visible through the
	// entry; callers must not mutate it after this point.
	r := &stickyRecovery{table: t, key: key, entry: e, stable: stable, candidate: candidate, startedAt: now, deadline: now.Add(time.Minute), network: *network}
	e.recovery = r
	t.lastRecoveryProbe = now
	t.recoveryEvent("probe_started", key, r, e.nextRecovery)
	return r
}
func (r *stickyRecovery) finish(success bool, now time.Time) {
	r.finishReason(success, now, "closed_or_failed")
}
func (r *stickyRecovery) finishReason(success bool, now time.Time, reason string) {
	t := r.table
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[r.key]
	if t.detached || e != r.entry || e.recovery != r {
		return
	}
	if r.candidate.AdmissionState(&r.network) != dialer.AdmissionAlive {
		success = false
		reason = "candidate_not_healthy"
	}
	if !success || !now.Before(r.deadline) || e.leaf != r.stable {
		if !now.Before(r.deadline) {
			reason = "expired"
		} else if e.leaf != r.stable {
			reason = "stable_changed"
		}
		t.deferRecovery(e, r, now, reason)
		return
	}
	if !t.recoveryBudget(e, now) {
		// Scheduling limits are not evidence of a bad candidate.
		e.recovery = nil
		e.nextRecovery = now.Add(5 * time.Second)
		t.recoveryEvent("switch_budget", r.key, r, e.nextRecovery)
		return
	}
	e.leaf = r.candidate
	e.pinnedAt = now
	e.lastSuccess = now
	e.nextRecovery = now.Add(siteStickyRecoveryAfter)
	e.recoveryDwell = e.nextRecovery
	e.recovery = nil
	e.recoveryFailures = 0
	e.triedAlts = 0
	e.converged = false
	e.consecutiveSlow = 0
	e.probeNext = false
	e.probeArmed = false
	e.holdDown(r.stable, now)
	e.recoverySwitches = append(e.recoverySwitches, now)
	t.recoverySwitches = append(t.recoverySwitches, now)
	t.lastRecovery = now
	t.recoveryEvent("recovered", r.key, r, e.nextRecovery)
}
func (g *DialerGroup) initStickyRecoveryLog() {
	if g.log == nil {
		return
	}
	logger, name := g.log, g.Name
	// Capture only logger and identity, not the owning group and its dialers.
	g.siteSticky.recoveryLog = func(reason, key string, r *stickyRecovery, next time.Time) {
		logger.WithFields(logrus.Fields{"event": "site_recovery", "group": name, "site": key, "reason": reason, "stable_leaf": dialerName(r.stable), "candidate": dialerName(r.candidate), "deadline": r.deadline, "next_probe_at": next, "load": map[string]any{"class": r.load.Class, "active_connections": r.load.Active, "upload_bytes_per_second": r.load.Upload, "download_bytes_per_second": r.load.Download, "new_connections_per_second": r.load.StartsPerSecond, "upload_reference": r.load.UploadReference, "download_reference": r.load.DownloadReference, "samples": r.load.Samples}, "suppressed_logs": r.suppressed}).Info("Site recovery")
	}
}

// Check cooldown and group limits before walking the candidate routing graph.
// startRecovery repeats these checks when it reserves the lease.
func (t *siteStickyTable) recoveryEligible(site string, stable *dialer.Dialer, now time.Time) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.lookupLocked(t.key(site), now)
	if t.detached || e == nil || e.leaf != stable {
		return false
	}
	if e.recovery != nil {
		if !now.Before(e.recovery.deadline) {
			t.deferRecovery(e, e.recovery, now, "expired")
		}
		return false
	}
	next := e.nextRecovery
	if next.IsZero() {
		next = e.pinnedAt.Add(siteStickyRecoveryAfter)
	}
	return !now.Before(next) && !now.Before(e.recoveryDwell) && now.Sub(t.lastRecoveryProbe) >= 5*time.Second && t.recoveryBudget(e, now)
}
