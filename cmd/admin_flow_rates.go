/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/control"
)

const (
	adminConnectionCoalesceTTL = 500 * time.Millisecond
	adminFlowRateMinWindow     = time.Second
	adminFlowRateHoldMinGap    = 250 * time.Millisecond
	adminFlowMaxSnapshotLimit  = 1024
)

type flowRateState struct {
	prevUp   uint64
	prevDown uint64
	prevAt   time.Time
	upRate   uint64
	downRate uint64
	lastSeen time.Time
}

// adminConnectionTracker coalesces unfiltered active-flow snapshots for 500ms
// and derives monotonic per-flow rates on top of raw flow byte counters.
type adminConnectionTracker struct {
	mu             sync.Mutex
	coalesceTTL    time.Duration
	lastFetchedAt  time.Time
	cachedSnapshot control.AdminConnectionsSnapshot
	cachedForPlane adminPlane
	rates          map[string]flowRateState
	now            func() time.Time
}

func newAdminConnectionTracker() *adminConnectionTracker {
	return &adminConnectionTracker{
		coalesceTTL: adminConnectionCoalesceTTL,
		rates:       make(map[string]flowRateState),
		now:         time.Now,
	}
}

func (t *adminConnectionTracker) Invalidate() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.lastFetchedAt = time.Time{}
	t.mu.Unlock()
}

func (t *adminConnectionTracker) baseSnapshot(plane adminPlane) control.AdminConnectionsSnapshot {
	if t == nil || plane == nil {
		return control.AdminConnectionsSnapshot{Connections: []control.AdminConnection{}}
	}
	nowFn := t.now
	if nowFn == nil {
		nowFn = time.Now
	}

	t.mu.Lock()
	now := nowFn()
	if t.coalesceTTL > 0 && t.cachedForPlane == plane && !t.lastFetchedAt.IsZero() && now.Sub(t.lastFetchedAt) < t.coalesceTTL {
		snap := cloneConnectionsSnapshot(t.cachedSnapshot)
		t.mu.Unlock()
		return snap
	}
	t.mu.Unlock()

	fresh := plane.AdminConnections(adminFlowMaxSnapshotLimit, control.AdminConnectionFilter{})
	fetchedAt := nowFn()

	t.mu.Lock()
	seen := make(map[string]struct{}, len(fresh.Connections))
	for i := range fresh.Connections {
		conn := &fresh.Connections[i]
		if conn.ID == "" {
			continue
		}
		seen[conn.ID] = struct{}{}
		st, ok := t.rates[conn.ID]
		if !ok {
			t.rates[conn.ID] = flowRateState{
				prevUp:   conn.Upload,
				prevDown: conn.Download,
				prevAt:   fetchedAt,
				lastSeen: fetchedAt,
			}
			continue
		}
		dt := fetchedAt.Sub(st.prevAt)
		advanced := conn.Upload > st.prevUp || conn.Download > st.prevDown
		if dt >= adminFlowRateMinWindow || (advanced && dt >= adminFlowRateHoldMinGap) {
			var dUp, dDown uint64
			if conn.Upload >= st.prevUp {
				dUp = conn.Upload - st.prevUp
			}
			if conn.Download >= st.prevDown {
				dDown = conn.Download - st.prevDown
			}
			st.upRate = uint64(float64(dUp) * float64(time.Second) / float64(dt))
			st.downRate = uint64(float64(dDown) * float64(time.Second) / float64(dt))
			st.prevUp = conn.Upload
			st.prevDown = conn.Download
			st.prevAt = fetchedAt
		}
		st.lastSeen = fetchedAt
		t.rates[conn.ID] = st
		conn.UploadRate = st.upRate
		conn.DownloadRate = st.downRate
	}
	for id := range t.rates {
		if _, ok := seen[id]; !ok {
			delete(t.rates, id)
		}
	}
	t.lastFetchedAt = fetchedAt
	t.cachedForPlane = plane
	t.cachedSnapshot = cloneConnectionsSnapshot(fresh)
	out := cloneConnectionsSnapshot(t.cachedSnapshot)
	t.mu.Unlock()

	return out
}

func cloneConnectionsSnapshot(s control.AdminConnectionsSnapshot) control.AdminConnectionsSnapshot {
	out := s
	if s.Connections != nil {
		out.Connections = make([]control.AdminConnection, len(s.Connections))
		copy(out.Connections, s.Connections)
	} else {
		out.Connections = []control.AdminConnection{}
	}
	return out
}

func (t *adminConnectionTracker) Snapshot(
	plane adminPlane,
	limit int,
	filter control.AdminConnectionFilter,
	sortBy string,
	order string,
) control.AdminConnectionsSnapshot {
	snap := t.baseSnapshot(plane)
	if limit <= 0 {
		limit = 256
	}
	if limit > adminFlowMaxSnapshotLimit {
		limit = adminFlowMaxSnapshotLimit
	}

	if !filter.IsEmpty() {
		filtered := make([]control.AdminConnection, 0, len(snap.Connections))
		for _, c := range snap.Connections {
			if c.Matches(filter) {
				filtered = append(filtered, c)
			}
		}
		snap.Connections = filtered
		snap.Total = len(filtered)
	}

	sortBy = strings.ToLower(strings.TrimSpace(sortBy))
	desc := strings.ToLower(strings.TrimSpace(order)) != "asc"
	if sortBy != "" {
		sortAdminConnectionsBy(snap.Connections, sortBy, desc)
	}

	if len(snap.Connections) > limit {
		snap.Connections = snap.Connections[:limit]
	}
	snap.Truncated = snap.Total > len(snap.Connections)
	return snap
}

func sortAdminConnectionsBy(conns []control.AdminConnection, field string, desc bool) {
	lessVal := func(a, b control.AdminConnection) int {
		switch field {
		case "upload":
			return cmpUint64(a.Upload, b.Upload)
		case "download":
			return cmpUint64(a.Download, b.Download)
		case "upload_rate":
			return cmpUint64(a.UploadRate, b.UploadRate)
		case "download_rate":
			return cmpUint64(a.DownloadRate, b.DownloadRate)
		case "duration":
			if a.DurationMs < b.DurationMs {
				return -1
			}
			if a.DurationMs > b.DurationMs {
				return 1
			}
			return 0
		case "start_time":
			return strings.Compare(a.StartTime, b.StartTime)
		default: // "total"
			return cmpUint64(a.Upload+a.Download, b.Upload+b.Download)
		}
	}
	sort.Slice(conns, func(i, j int) bool {
		c := lessVal(conns[i], conns[j])
		if c != 0 {
			if desc {
				return c > 0
			}
			return c < 0
		}
		return conns[i].ID < conns[j].ID
	})
}

func cmpUint64(a, b uint64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
