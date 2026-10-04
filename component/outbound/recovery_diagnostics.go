// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import "time"

// Reason counts include events hidden by log level or log throttling. They
// count decisions, not packets, and reset with the owning group generation.
func countRecoveryReason(counts map[string]uint64, reason string) map[string]uint64 {
	if counts == nil {
		counts = make(map[string]uint64)
	}
	if _, exists := counts[reason]; !exists && len(counts) >= 32 {
		reason = "other"
	}
	counts[reason]++
	return counts
}

type RecoveryDiagnostics struct {
	PolicyEpoch        uint64                    `json:"policy_epoch"`
	Group              string                    `json:"group"`
	QualityMode        string                    `json:"quality_mode"`
	QualityReasons     map[string]uint64         `json:"quality_reasons"`
	QualitySwitches    int                       `json:"quality_switches_in_window"`
	QualitySwitchLimit int                       `json:"quality_switch_limit"`
	QualityWindowMS    int64                     `json:"quality_window_ms"`
	SiteRecovery       []SiteRecoveryDiagnostics `json:"site_recovery"`
}

type SiteRecoveryDiagnostics struct {
	Network        string            `json:"network"`
	Reasons        map[string]uint64 `json:"reasons"`
	Switches       int               `json:"switches_in_window"`
	SwitchLimit    int               `json:"switch_limit"`
	WindowMS       int64             `json:"window_ms"`
	InFlight       int               `json:"in_flight"`
	LastProbeAt    time.Time         `json:"last_probe_at"`
	LastRecoveryAt time.Time         `json:"last_recovery_at"`
}

func copyRecoveryCounts(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, n := range in {
		out[k] = n
	}
	return out
}

func countRecentRecoverySwitches(times []time.Time, now time.Time) int {
	n := 0
	for _, t := range times {
		if now.Sub(t) < 30*time.Minute {
			n++
		}
	}
	return n
}

// RecoveryDiagnostics is a read-only view. It never prunes budget slices,
// advances a retry deadline, expires a probe or changes node admission.
func (g *DialerGroup) RecoveryDiagnostics(now time.Time) RecoveryDiagnostics {
	s := RecoveryDiagnostics{Group: g.Name, QualityMode: "off", QualityReasons: map[string]uint64{}, SiteRecovery: []SiteRecoveryDiagnostics{}, QualitySwitchLimit: 10, QualityWindowMS: (30 * time.Minute).Milliseconds()}
	if q := g.quality; q != nil {
		q.mu.Lock()
		s.QualityMode = q.options.Mode
		s.QualityReasons = copyRecoveryCounts(q.diagnosticReasons)
		s.QualitySwitches = countRecentRecoverySwitches(q.switches, now)
		q.mu.Unlock()
	}
	for i, t := range []*siteStickyTable{g.siteSticky, g.siteStickyUDP} {
		if t == nil {
			continue
		}
		network := "tcp"
		if i == 1 {
			network = "udp"
		}
		t.mu.Lock()
		r := SiteRecoveryDiagnostics{Network: network, Reasons: copyRecoveryCounts(t.diagnosticReasons), Switches: countRecentRecoverySwitches(t.recoverySwitches, now), SwitchLimit: 10, WindowMS: (30 * time.Minute).Milliseconds(), LastProbeAt: t.lastRecoveryProbe, LastRecoveryAt: t.lastRecovery}
		for _, e := range t.entries {
			if e.recovery != nil {
				r.InFlight++
			}
		}
		t.mu.Unlock()
		s.SiteRecovery = append(s.SiteRecovery, r)
	}
	return s
}
