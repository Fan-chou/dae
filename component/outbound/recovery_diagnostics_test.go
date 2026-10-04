// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestRecoveryDiagnosticsIncludesSuppressedDecisionsAndPreservesBudgets(t *testing.T) {
	now := time.Now()
	q := &qualityRuntime{group: "proxy", options: QualityOptions{Mode: "observe"}, switches: []time.Time{now.Add(-31 * time.Minute), now.Add(-time.Minute)}}
	// No logger, so all these decisions are invisible in daemon logs.
	q.mu.Lock()
	for i := 0; i < 25; i++ {
		q.eventAt(logrus.InfoLevel, qualityScope{}, "relative_speed_collapse", nil)
	}
	r := &qualityRate{at: now}
	q.report(nil, r)
	q.report(nil, r) // Relative and absolute gates in one window count once.
	if q.diagnosticReasons["verify_alternative_windows"] != 1 {
		t.Fatal("verification window counted twice")
	}
	q.mu.Unlock()
	sticky := newSiteStickyTable()
	sticky.mu.Lock()
	sticky.recoverySwitches = []time.Time{now.Add(-31 * time.Minute), now.Add(-time.Minute)}
	sticky.recoveryEvent("probe_started", "test", nil, now)
	sticky.recoveryEvent("slow_first_byte", "test", nil, now)
	sticky.mu.Unlock()
	g := &DialerGroup{Name: "proxy", quality: q, siteSticky: sticky, siteStickyUDP: newSiteStickyTable()}
	s := g.RecoveryDiagnostics(now)
	if s.QualityReasons["relative_speed_collapse"] != 25 || s.QualitySwitches != 1 || len(s.SiteRecovery) != 2 {
		t.Fatalf("missing diagnostics: %+v", s)
	}
	if s.SiteRecovery[0].Reasons["probe_started"] != 1 || s.SiteRecovery[0].Reasons["slow_first_byte"] != 1 || s.SiteRecovery[0].Switches != 1 {
		t.Fatalf("sticky budget: %+v", s.SiteRecovery)
	}
	if len(sticky.recoverySwitches) != 2 || len(q.switches) != 2 || !sticky.lastRecovery.IsZero() || !sticky.lastRecoveryProbe.IsZero() {
		t.Fatal("read advanced/pruned a budget")
	}
	s.QualityReasons["relative_speed_collapse"] = 0
	s.SiteRecovery[0].Reasons["probe_started"] = 0
	if next := g.RecoveryDiagnostics(now); next.QualityReasons["relative_speed_collapse"] != 25 || next.SiteRecovery[0].Reasons["probe_started"] != 1 {
		t.Fatal("snapshot aliases live counters")
	}
}
