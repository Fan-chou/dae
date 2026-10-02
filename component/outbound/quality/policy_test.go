/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quality

import (
	"math"
	"testing"
)

func TestCandidateNeedsRelativeAndAbsoluteImprovement(t *testing.T) {
	p := DefaultPolicy()
	for _, c := range []struct {
		a, b float64
		want bool
	}{{1024, 2048, false}, {1024 * 1024, 1.4 * 1024 * 1024, false}, {1024 * 1024, 2 * 1024 * 1024, true}, {0, 300 * 1024, true}, {math.NaN(), 1e6, false}, {1, math.Inf(1), false}} {
		if p.CandidateImproves(c.a, c.b) != c.want {
			t.Fatalf("candidate %v -> %v", c.a, c.b)
		}
	}
}
