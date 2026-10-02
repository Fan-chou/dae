/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"
	"time"
)

func TestLoadContextDirectionsAndSettling(t *testing.T) {
	for _, upload := range []bool{true, false} {
		now := time.Now()
		l := &nodeLoad{at: now, peakAt: now}
		l.active.Store(2)
		for i := 0; i < 6; i++ {
			if upload {
				l.up.Add(5 * 5 * 1024 * 1024)
			} else {
				l.down.Add(5 * 10 * 1024 * 1024)
			}
			now = now.Add(5 * time.Second)
			l.snapshot(now)
		}
		if got := l.snapshot(now); got.Class != "busy" {
			t.Fatalf("upload=%v: %+v", upload, got)
		}
		now = now.Add(5 * time.Second)
		if got := l.snapshot(now); got.Class != "settling" {
			t.Fatalf("missing settling: %+v", got)
		}
		now = now.Add(31 * time.Second)
		if got := l.snapshot(now); got.Class != "ordinary" {
			t.Fatalf("never left load protection: %+v", got)
		}
	}
}
func TestLowThroughputDoesNotBecomeHighLoad(t *testing.T) {
	now := time.Now()
	l := &nodeLoad{at: now}
	l.active.Store(1)
	for i := 0; i < 8; i++ {
		l.down.Add(5 * 32 * 1024)
		now = now.Add(5 * time.Second)
		l.snapshot(now)
	}
	if got := l.snapshot(now); got.Class != "ordinary" {
		t.Fatalf("slow from outset excused as high load: %+v", got)
	}
	// Ordinary browsing: dozens of mostly idle connections and a modest
	// connection rate are not contention.
	l.active.Store(40)
	l.starts.Add(15)
	now = now.Add(5 * time.Second)
	if got := l.snapshot(now); got.Class != "ordinary" {
		t.Fatalf("idle connections mistaken for load: %+v", got)
	}
	l.active.Store(64)
	l.starts.Add(100)
	now = now.Add(5 * time.Second)
	if got := l.snapshot(now); got.Class != "busy" {
		t.Fatalf("high concurrency not detected: %+v", got)
	}
}

// A single large download establishes the node's peak. It must not be judged
// "busy" by its own traffic, but genuinely concurrent traffic still defers it.
func TestSingleDownloadDoesNotExcuseItself(t *testing.T) {
	now := time.Now()
	l := &nodeLoad{at: now, peakAt: now}
	l.active.Store(3)
	const own = 8 * 1024 * 1024
	for i := 0; i < 8; i++ {
		l.down.Add(5 * own)
		now = now.Add(5 * time.Second)
		l.snapshot(now)
	}
	got := l.snapshot(now)
	if got.Class != "busy" || !got.DeferQuality() {
		t.Fatalf("aggregate verdict should defer latency signals: %+v", got)
	}
	// Window-aligned attribution: the node carried only this download.
	if got.DeferQualityForOthers(0, 0) {
		t.Fatalf("download excused by its own peak: %+v", got)
	}
	// Other flows near the reference peak during the same window must defer.
	if !got.DeferQualityForOthers(0, own*7/8) {
		t.Fatalf("other traffic near the reference peak must defer: %+v", got)
	}
	warm := LoadContext{Class: "warming_up"}
	if !warm.DeferQualityForOthers(0, 0) {
		t.Fatal("warmup must stay unknown")
	}
	if (LoadContext{Class: "unobserved"}).DeferQualityForOthers(0, 1<<30) {
		t.Fatal("unobserved node is not busy")
	}
	d := &Dialer{load: l}
	if up, down, ok := d.LoadTotals(); ok || up != 0 || down != 0 {
		t.Fatal("untracked node must report no totals")
	}
	d.LoadStart()
	if _, down, ok := d.LoadTotals(); !ok || down != 8*5*own {
		t.Fatalf("totals mismatch: %d", down)
	}
}
func TestLoadSharedAcrossClonesAndBalanced(t *testing.T) {
	// The clone wiring is exercised by existing clone construction tests; shared
	// load accounting itself must include both directions and independent flows.
	shared := &nodeLoad{}
	a := &Dialer{load: shared}
	b := &Dialer{load: shared}
	a.LoadStart()
	b.LoadStart()
	a.LoadBytes(123, 0)
	b.LoadBytes(0, 456)
	if shared.active.Load() != 2 || shared.up.Load() != 123 || shared.down.Load() != 456 {
		t.Fatal("accounting mismatch")
	}
	a.LoadFinish()
	b.LoadFinish()
	if shared.active.Load() != 0 {
		t.Fatal("active count leaked")
	}
}
func TestURLTestKeepsQualityPenalties(t *testing.T) {
	h := &nodeHealth{}
	now := time.Now()
	base := 100 * time.Millisecond
	h.setDegradedForTest(IdxTcp4, true)
	penalized, _ := h.quality(IdxTcp4, base, true, now)
	if penalized <= base {
		t.Fatal("degraded penalty missing")
	}
	h.setFailDegradedForTest(IdxTcp4, true)
	failure, _ := h.quality(IdxTcp4, base, true, now)
	if failure <= base {
		t.Fatal("failure penalty missing")
	}
}
