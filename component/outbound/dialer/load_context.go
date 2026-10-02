/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync"
	"sync/atomic"
	"time"
)

// Load thresholds describe local contention, not remote capacity. Idle
// connections alone never count; a busy verdict needs concurrent throughput or
// connection churn well above ordinary browsing.
const (
	loadBusyActiveFlows     = 64
	loadBusyAggregateBytes  = 2 << 20 // bytes/s across both directions
	loadBusyStartsPerSecond = 16.0
	loadPeakMinUpload       = 1 << 20 // bytes/s before an upload peak is a reference
	loadPeakMinDownload     = 4 << 20 // bytes/s before a download peak is a reference
	loadPeakBusyFraction    = 0.8
	loadReferenceSamples    = 6
	loadSettlingWindow      = 30 * time.Second
	loadWarmupWindow        = 30 * time.Second
	loadSampleInterval      = 5 * time.Second
	loadPeakLifetime        = 30 * time.Minute
)

// LoadContext describes local demand, not remote capacity or packet loss.
// Directional observed peaks are references only; warmup is explicitly unknown.
type LoadContext struct {
	StartsPerSecond   float64 `json:"new_connections_per_second"`
	Active            int64   `json:"active_connections"`
	Upload            float64 `json:"upload_bytes_per_second"`
	Download          float64 `json:"download_bytes_per_second"`
	UploadReference   float64 `json:"upload_reference"`
	DownloadReference float64 `json:"download_reference"`
	Samples           int     `json:"samples"`
	Class             string  `json:"class"`
}

// DeferQuality is the aggregate verdict for signals that have no flow of
// their own (slow handshake or first byte). Heavy traffic through the
// node, whoever owns it, makes those latency signals unattributable.
func (l LoadContext) DeferQuality() bool {
	return l.Class == "busy" || l.Class == "settling" || l.Class == "warming_up"
}

// DeferQualityForOthers is the verdict for a flow whose own throughput is
// being judged. The caller supplies the rate of traffic *other than* that
// flow, measured over the flow's own observation window from LoadTotals
// deltas, so a single large download cannot make its node "busy" and excuse
// its own speed, and a finished download cannot be subtracted from load it no
// longer contributes to. Peak references remain aggregate 5s samples; a
// window average compared against them errs toward "not busy". Settling is
// the caller's responsibility because only it knows whether the previous
// window's contention was external.
func (l LoadContext) DeferQualityForOthers(othersUpload, othersDownload float64) bool {
	if l.Class == "warming_up" {
		return true
	}
	if l.Class == "unobserved" {
		return false
	}
	others := l
	others.Upload = max(0, othersUpload)
	others.Download = max(0, othersDownload)
	return others.busy()
}

// LoadTotals exposes cumulative byte counters so a caller can attribute node
// traffic over exactly its own window. ok is false for untracked nodes.
func (d *Dialer) LoadTotals() (up, down uint64, ok bool) {
	if d == nil || d.load == nil || !d.load.tracked.Load() {
		return 0, 0, false
	}
	return d.load.up.Load(), d.load.down.Load(), true
}

func (l LoadContext) busy() bool {
	if l.Active >= loadBusyActiveFlows && (l.Upload+l.Download >= loadBusyAggregateBytes || l.StartsPerSecond >= loadBusyStartsPerSecond) {
		return true
	}
	if l.Samples < loadReferenceSamples {
		return false
	}
	if l.UploadReference >= loadPeakMinUpload && l.Upload >= loadPeakBusyFraction*l.UploadReference {
		return true
	}
	return l.DownloadReference >= loadPeakMinDownload && l.Download >= loadPeakBusyFraction*l.DownloadReference
}

type nodeLoad struct {
	startedAt        time.Time
	starts           atomic.Uint64
	lastStarts       uint64
	active           atomic.Int64
	up, down         atomic.Uint64
	tracked          atomic.Bool
	mu               sync.Mutex
	at               time.Time
	lastUp, lastDown uint64
	samples          int
	peakUp, peakDown float64
	peakAt, timeBusy time.Time
	cached           LoadContext
}

func (d *Dialer) LoadStart() {
	if d == nil || d.load == nil {
		return
	}
	l := d.load
	if !l.tracked.Load() {
		l.mu.Lock()
		if !l.tracked.Load() {
			l.at = time.Now()
			l.startedAt = l.at
			l.tracked.Store(true)
		}
		l.mu.Unlock()
	}
	l.active.Add(1)
	l.starts.Add(1)
}
func (d *Dialer) LoadFinish() {
	if d != nil && d.load != nil {
		d.load.active.Add(-1)
	}
}
func (d *Dialer) LoadBytes(up, down uint64) {
	if d != nil && d.load != nil {
		if up > 0 {
			d.load.up.Add(up)
		}
		if down > 0 {
			d.load.down.Add(down)
		}
	}
}
func (d *Dialer) LoadContext(now time.Time) LoadContext {
	if d == nil || d.load == nil || !d.load.tracked.Load() {
		return LoadContext{Class: "unobserved"}
	}
	return d.load.snapshot(now)
}
func (l *nodeLoad) snapshot(now time.Time) LoadContext {
	l.mu.Lock()
	defer l.mu.Unlock()
	active := max(int64(0), l.active.Load())
	elapsed := now.Sub(l.at)
	if elapsed >= loadSampleInterval {
		up, down := l.up.Load(), l.down.Load()
		starts := l.starts.Load()
		l.cached.StartsPerSecond = float64(starts-l.lastStarts) / elapsed.Seconds()
		l.lastStarts = starts
		l.cached.Upload = float64(up-l.lastUp) / elapsed.Seconds()
		l.cached.Download = float64(down-l.lastDown) / elapsed.Seconds()
		l.lastUp, l.lastDown, l.at = up, down, now
		if elapsed > loadPeakLifetime {
			l.samples = 0
		}
		l.samples++
		if now.Sub(l.peakAt) > loadPeakLifetime {
			l.peakUp, l.peakDown = 0, 0
			l.peakAt = now
		}
		l.peakUp = max(l.peakUp, l.cached.Upload)
		l.peakDown = max(l.peakDown, l.cached.Download)
	}
	v := l.cached
	v.Active = active
	v.Samples = l.samples
	v.UploadReference, v.DownloadReference = l.peakUp, l.peakDown
	switch {
	case v.busy():
		v.Class = "busy"
		l.timeBusy = now
	case !l.timeBusy.IsZero() && now.Sub(l.timeBusy) < loadSettlingWindow:
		v.Class = "settling"
	case l.samples < 1 || (!l.startedAt.IsZero() && now.Sub(l.startedAt) < loadWarmupWindow):
		v.Class = "warming_up"
	default:
		v.Class = "ordinary"
	}
	return v
}

// LoadCounts exposes only atomic instantaneous/cumulative counters. These are
// not a same-window connection rate and do not indicate application demand.
func (d *Dialer) LoadCounts() (active int64, starts uint64, ok bool) {
	if d == nil || d.load == nil || !d.load.tracked.Load() {
		return 0, 0, false
	}
	return d.load.active.Load(), d.load.starts.Load(), true
}
