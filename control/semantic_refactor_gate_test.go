/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"strings"
	"testing"
)

func TestSemanticRefactorFeatureGateDefaultsDisabled(t *testing.T) {
	if got := semanticRefactorFeatureGateSnapshot(); got != (SemanticRefactorFeatureSet{}) {
		t.Fatalf("semanticRefactorFeatureGateSnapshot() = %+v, want all disabled", got)
	}
}

func TestSemanticRefactorFeatureGateOwnership(t *testing.T) {
	handle, err := EnableSemanticRefactorFeatures(SemanticRefactorFeatureRoutingEpoch)
	if err != nil {
		t.Fatalf("EnableSemanticRefactorFeatures() error = %v", err)
	}
	t.Cleanup(handle.Disable)
	if got := semanticRefactorFeatureGateSnapshot(); !got.RoutingEpoch {
		t.Fatalf("semanticRefactorFeatureGateSnapshot() = %+v, want routing epoch", got)
	}
	if !handle.Enabled(SemanticRefactorFeatureRoutingEpoch) || handle.Enabled("unknown") {
		t.Fatal("SemanticRefactorFeatureGateHandle.Enabled() did not report its owned features")
	}
	if _, err := EnableSemanticRefactorFeatures(SemanticRefactorFeatureRoutingEpoch); !stderrors.Is(err, ErrSemanticRefactorFeatureAlreadyEnabled) {
		t.Fatalf("second EnableSemanticRefactorFeatures() error = %v, want ownership error", err)
	}
	handle.Disable()
	if handle.Enabled(SemanticRefactorFeatureRoutingEpoch) {
		t.Fatal("SemanticRefactorFeatureGateHandle.Enabled() = true after Disable()")
	}
	if got := semanticRefactorFeatureGateSnapshot(); got != (SemanticRefactorFeatureSet{}) {
		t.Fatalf("feature snapshot after Disable() = %+v, want all disabled", got)
	}
}

func TestSemanticRefactorFeatureGateGenerationSnapshotSurvivesOwnerDisable(t *testing.T) {
	handle, err := EnableSemanticRefactorFeatures(SemanticRefactorFeatureRoutingEpoch)
	if err != nil {
		t.Fatalf("EnableSemanticRefactorFeatures() error = %v", err)
	}
	features := semanticRefactorFeatureGateSnapshot()
	handle.Disable()

	if got := semanticRefactorFeatureGateSnapshot(); got != (SemanticRefactorFeatureSet{}) {
		t.Fatalf("global feature snapshot after owner disable = %+v, want all disabled", got)
	}
	want := SemanticRefactorFeatureSet{RoutingEpoch: true}
	if features != want {
		t.Fatalf("captured generation features = %+v, want %+v", features, want)
	}

	plane := &ControlPlane{semanticRefactorFeatures: features}
	if err := plane.Close(); err != nil {
		t.Fatalf("captured generation ControlPlane.Close() error = %v", err)
	}
}

func TestParseSemanticRefactorFeature(t *testing.T) {
	got, err := ParseSemanticRefactorFeature(string(SemanticRefactorFeatureRoutingEpoch))
	if err != nil || got != SemanticRefactorFeatureRoutingEpoch {
		t.Fatalf("ParseSemanticRefactorFeature(%q) = (%q, %v), want (%q, nil)",
			SemanticRefactorFeatureRoutingEpoch, got, err, SemanticRefactorFeatureRoutingEpoch)
	}
	// Names of migration paths that have since been collapsed into the single
	// production path must not silently parse into a no-op gate.
	for _, retired := range []string{
		"compiled-policy",
		"dns-resolver",
		"udp-ordered-dispatcher",
		"udp-reply-dispatcher",
	} {
		if _, err := ParseSemanticRefactorFeature(retired); err == nil {
			t.Fatalf("ParseSemanticRefactorFeature(%q) error = nil, want rejection", retired)
		} else if !strings.Contains(err.Error(), "retired") {
			t.Fatalf("ParseSemanticRefactorFeature(%q) error = %v, want retired", retired, err)
		}
	}
	if _, err := ParseSemanticRefactorFeature("unknown"); err == nil {
		t.Fatal("ParseSemanticRefactorFeature(\"unknown\") error = nil, want rejection")
	}
}
