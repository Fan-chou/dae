/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

func TestRuntimeStatsRateAccuracyUnderSlowPolling(t *testing.T) {
	stats := newRuntimeStats()
	t0 := time.Unix(1_700_000_000, 0)

	// Prime the bucket and monotonic baseline.
	s0 := stats.scalars(3, 2, t0)
	if s0.UploadRate != 0 || s0.DownloadRate != 0 {
		t.Fatalf("expected initial zero rates, got up=%d down=%d", s0.UploadRate, s0.DownloadRate)
	}

	// Simulate steady 1 MiB/s upload and 4 MiB/s download polled every 2 seconds.
	const upBytesPer2s = 2 * 1024 * 1024
	const downBytesPer2s = 8 * 1024 * 1024

	stats.record(upBytesPer2s, downBytesPer2s)
	s1 := stats.scalars(3, 2, t0.Add(2*time.Second))
	if s1.UploadRate != upBytesPer2s/2 {
		t.Fatalf("expected upload rate %d under 2s polling, got %d", upBytesPer2s/2, s1.UploadRate)
	}
	if s1.DownloadRate != downBytesPer2s/2 {
		t.Fatalf("expected download rate %d under 2s polling, got %d", downBytesPer2s/2, s1.DownloadRate)
	}

	// Burst another poll only 100ms later with zero extra bytes: should look back to t0 (>= 800ms),
	// returning ~2 MiB / 2.1s instead of collapsing to 0 or exploding from tiny dt.
	sBurst := stats.scalars(3, 2, t0.Add(2100*time.Millisecond))
	if sBurst.UploadRate == 0 || sBurst.DownloadRate == 0 {
		t.Fatalf("expected non-zero smoothed rate on rapid poll, got up=%d down=%d", sBurst.UploadRate, sBurst.DownloadRate)
	}

	// Continue 2 more seconds and check history smoothness (no zero holes inside the 2s gap).
	stats.record(upBytesPer2s, downBytesPer2s)
	hist := stats.snapshot(3, 2, 60, 180, t0.Add(4*time.Second))
	if len(hist.Samples) < 12 {
		t.Fatalf("expected evenly distributed 250ms buckets, got %d samples", len(hist.Samples))
	}
	for i, sample := range hist.Samples {
		if sample.UploadRate == 0 || sample.DownloadRate == 0 {
			t.Fatalf("sample %d unexpectedly zero during steady transfer: %+v", i, sample)
		}
	}
}

func TestRuntimeStatsIdleGapAndLargeSleepBounded(t *testing.T) {
	stats := newRuntimeStats()
	t0 := time.Unix(1_700_000_000, 0)

	stats.scalars(0, 0, t0)
	stats.record(1000, 2000)
	stats.scalars(0, 0, t0.Add(1*time.Second))

	// Jump forward 2 hours with zero traffic: should bound rollover without panicking or allocating > maxHist.
	later := t0.Add(2 * time.Hour)
	s2 := stats.snapshot(0, 0, 1800, 180, later)
	if s2.UploadRate != 0 || s2.DownloadRate != 0 {
		t.Fatalf("expected zero rate after 2h idle, got up=%d down=%d", s2.UploadRate, s2.DownloadRate)
	}
	if s2.UploadTotal != 1000 || s2.DownloadTotal != 2000 {
		t.Fatalf("expected preserved totals (1000, 2000), got (%d, %d)", s2.UploadTotal, s2.DownloadTotal)
	}
}
