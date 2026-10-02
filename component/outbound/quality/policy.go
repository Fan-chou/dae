/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Package quality contains local speed policy and optional model shadow evaluation.
package quality

import (
	"fmt"
	"math"
	"time"
)

// Policy is immutable for a group's quality runtime generation.
type Policy struct {
	SevereRatio, RecoveryRatio         float64
	Window                             time.Duration
	SevereWindows, RecoveryWindows     int
	EvidenceTTL                        time.Duration
	ImprovementRatio, ImprovementBytes float64
}

func DefaultPolicy() Policy {
	return Policy{.30, .60, 15 * time.Second, 3, 3, 2 * time.Minute, 1.5, 256 * 1024}
}
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func (p Policy) Validate() error {
	if !finite(p.SevereRatio) || !finite(p.RecoveryRatio) || p.SevereRatio <= 0 || p.RecoveryRatio <= p.SevereRatio || p.RecoveryRatio > 1 {
		return fmt.Errorf("speed ratios require 0 < severe < recovery <= 1")
	}
	if p.Window < 10*time.Second || p.Window > time.Minute || p.Window%(5*time.Second) != 0 || p.SevereWindows < 1 || p.SevereWindows > 60 || p.RecoveryWindows < 1 || p.RecoveryWindows > 60 {
		return fmt.Errorf("invalid speed observation windows")
	}
	if p.EvidenceTTL < p.Window || p.EvidenceTTL > 10*time.Minute {
		return fmt.Errorf("invalid speed evidence lifetime")
	}
	if !finite(p.ImprovementRatio) || p.ImprovementRatio <= 1 || !finite(p.ImprovementBytes) || p.ImprovementBytes <= 0 {
		return fmt.Errorf("invalid candidate improvement thresholds")
	}
	return nil
}

// CandidateImproves is a numerical gate only. Identity, independent windows,
// freshness, membership, health and switch budgets remain caller obligations.
func (p Policy) CandidateImproves(current, candidate float64) bool {
	return p.Validate() == nil && finite(current) && finite(candidate) && current >= 0 && candidate > 0 &&
		candidate >= current*p.ImprovementRatio && candidate-current >= p.ImprovementBytes
}
