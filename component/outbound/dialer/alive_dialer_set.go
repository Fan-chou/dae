/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/sirupsen/logrus"
)

const (
	Init = 1 + iota
	NotAlive
)

type minLatency struct {
	sortingLatency time.Duration
	dialer         *Dialer
}

// aliveEntry combines a dialer pointer with its cached sorting latency.
// This struct enables slice-based storage that eliminates map lookups in hot paths.
type aliveEntry struct {
	dialer         *Dialer
	sortingLatency time.Duration
}

// AliveDialerSet assumes mapping between index and dialer MUST remain unchanged.
//
// It is thread-safe.
type AliveDialerSet struct {
	log             *logrus.Logger
	dialerGroupName string
	CheckTyp        *NetworkType
	tolerance       time.Duration

	aliveChangeCallback func(alive bool)

	mu                    sync.RWMutex
	dialerToIndex         map[*Dialer]int // *Dialer -> index in aliveEntries, -Init, or -NotAlive
	dialerToLatency       map[*Dialer]time.Duration
	dialerToLatencyOffset map[*Dialer]time.Duration

	// aliveEntries stores all alive dialers with their precomputed sorting latency.
	// This is the primary data structure for hot path operations (GetMinLatency, GetRandExcluded).
	// Using a slice of structs provides better cache locality and eliminates map lookups.
	aliveEntries []aliveEntry

	selectionPolicy consts.DialerSelectionPolicy
	minLatency      minLatency
	// urlTestReturned is the leaf actually returned by a live url_test scan.
	// minLatency stays the last NotifyLatencyChange cache and can lag behind
	// penalty decay; hysteresis must follow what Select really used.
	urlTestReturned atomic.Pointer[Dialer]
}

func NewAliveDialerSet(
	log *logrus.Logger,
	dialerGroupName string,
	networkType *NetworkType,
	tolerance time.Duration,
	selectionPolicy consts.DialerSelectionPolicy,
	dialers []*Dialer,
	dialersAnnotations []*Annotation,
	aliveChangeCallback func(alive bool),
	setAlive bool,
) *AliveDialerSet {
	if len(dialers) != len(dialersAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(dialers), len(dialersAnnotations)))
	}
	dialerToLatencyOffset := make(map[*Dialer]time.Duration)
	for i := range dialers {
		d, a := dialers[i], dialersAnnotations[i]
		dialerToLatencyOffset[d] = a.AddLatency
	}
	a := &AliveDialerSet{
		log:                   log,
		dialerGroupName:       dialerGroupName,
		CheckTyp:              networkType,
		tolerance:             tolerance,
		aliveChangeCallback:   aliveChangeCallback,
		dialerToIndex:         make(map[*Dialer]int),
		dialerToLatency:       make(map[*Dialer]time.Duration),
		dialerToLatencyOffset: dialerToLatencyOffset,
		aliveEntries:          make([]aliveEntry, 0, len(dialers)),
		selectionPolicy:       selectionPolicy,
		minLatency: minLatency{
			// Initiate the latency with a very big value.
			sortingLatency: time.Hour,
		},
	}
	for _, d := range dialers {
		a.dialerToIndex[d] = -Init
	}
	for _, d := range dialers {
		a.NotifyLatencyChange(d, setAlive)
	}
	return a
}

func (a *AliveDialerSet) GetRand() *Dialer {
	return a.GetRandExcluded(nil)
}

func (a *AliveDialerSet) GetRandExcluded(excluded *Dialer) *Dialer {
	if excluded == nil {
		return a.GetRandSkipping(nil)
	}
	return a.GetRandSkipping(map[*Dialer]struct{}{excluded: {}})
}

func (a *AliveDialerSet) GetRandSkipping(skip map[*Dialer]struct{}) *Dialer {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.aliveEntries) == 0 {
		return nil
	}
	if len(skip) == 0 {
		return a.aliveEntries[fastrand.Intn(len(a.aliveEntries))].dialer
	}

	var chosen *Dialer
	var candidateCount int
	for i := range a.aliveEntries {
		d := a.aliveEntries[i].dialer
		if _, skipped := skip[d]; skipped {
			continue
		}
		candidateCount++
		if fastrand.Intn(candidateCount) == 0 {
			chosen = d
		}
	}

	return chosen
}

func (a *AliveDialerSet) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.aliveEntries)
}

// IsAlive reports whether dialer is currently admitted by this group's health
// set. The caller may impose a separate order over the group's dialers.
func (a *AliveDialerSet) IsAlive(dialer *Dialer) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	index, ok := a.dialerToIndex[dialer]
	return ok && index >= 0 && index < len(a.aliveEntries) && a.aliveEntries[index].dialer == dialer
}

func (a *AliveDialerSet) SortingLatency(d *Dialer) time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if idx, ok := a.dialerToIndex[d]; ok && idx >= 0 && idx < len(a.aliveEntries) {
		return a.aliveEntries[idx].sortingLatency
	}
	// Fallback to direct calculation (should not happen in normal operation).
	return a.dialerToLatency[d] + a.dialerToLatencyOffset[d]
}

// GetMinLatency acquires correct selectionPolicy.
// CachedMinDialer returns the last published minimum without a live rescan.
// Nested url_test uses this as the incumbent identity so check_tolerance can
// apply to child-member scores the same way the flat selector does.
func (a *AliveDialerSet) CachedMinDialer() *Dialer {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.minLatency.dialer
}

func (a *AliveDialerSet) GetMinLatency(excluded *Dialer) (d *Dialer, latency time.Duration) {
	if excluded == nil {
		return a.GetMinLatencySkipping(nil)
	}
	return a.GetMinLatencySkipping(map[*Dialer]struct{}{excluded: {}})
}

func (a *AliveDialerSet) GetMinLatencySkipping(skip map[*Dialer]struct{}) (d *Dialer, latency time.Duration) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.selectionPolicy == consts.DialerSelectionPolicy_UrlTest {
		d, latency := a.liveMinLatencyLocked(skip)
		if len(skip) == 0 && d != nil {
			a.urlTestReturned.Store(d)
		}
		return d, latency
	}

	if a.minLatency.dialer != nil {
		if _, skipped := skip[a.minLatency.dialer]; !skipped {
			return a.minLatency.dialer, a.minLatency.sortingLatency
		}
	}

	var nextBest *Dialer
	var nextBestSortingLatency = time.Hour
	for i := range a.aliveEntries {
		entry := &a.aliveEntries[i]
		if _, skipped := skip[entry.dialer]; skipped {
			continue
		}
		if entry.sortingLatency < nextBestSortingLatency {
			nextBestSortingLatency = entry.sortingLatency
			nextBest = entry.dialer
		}
	}

	if nextBest != nil {
		return nextBest, nextBestSortingLatency
	}

	return nil, time.Hour
}

func (a *AliveDialerSet) liveMinLatencyLocked(skip map[*Dialer]struct{}) (*Dialer, time.Duration) {
	var nextBest *Dialer
	nextBestSortingLatency := time.Hour
	var unscored []*Dialer
	for i := range a.aliveEntries {
		entry := &a.aliveEntries[i]
		if _, skipped := skip[entry.dialer]; skipped {
			continue
		}
		lat, ok := entry.dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		if !ok {
			unscored = append(unscored, entry.dialer)
			continue
		}
		lat += a.dialerToLatencyOffset[entry.dialer]
		if lat < nextBestSortingLatency {
			nextBestSortingLatency = lat
			nextBest = entry.dialer
		}
	}
	if nextBest == nil {
		return a.unscoredMinLatencyLocked(skip, unscored)
	}
	incumbent := a.urlTestReturned.Load()
	if incumbent == nil || !a.isAdmittedLocked(incumbent) {
		incumbent = a.minLatency.dialer
	}
	if incumbent == nil || incumbent == nextBest {
		return nextBest, nextBestSortingLatency
	}
	if _, skipped := skip[incumbent]; skipped || !a.isAdmittedLocked(incumbent) {
		return nextBest, nextBestSortingLatency
	}
	incLat, ok := incumbent.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
	if !ok {
		return nextBest, nextBestSortingLatency
	}
	incLat += a.dialerToLatencyOffset[incumbent]
	if a.betterThanIncumbent(nextBestSortingLatency, incLat) {
		return nextBest, nextBestSortingLatency
	}
	return incumbent, incLat
}

func (a *AliveDialerSet) isAdmittedLocked(d *Dialer) bool {
	if d == nil {
		return false
	}
	index, ok := a.dialerToIndex[d]
	return ok && index >= 0 && index < len(a.aliveEntries) && a.aliveEntries[index].dialer == d
}

// LatencyBeatsIncumbent reports whether candidate is far enough ahead of
// incumbent to justify a switch. Subtraction is used because candidate is
// already known to be <= incumbent, so incumbent-candidate cannot underflow;
// adding candidate+tolerance can overflow near MaxInt64. Opposite-signed
// values still overflow subtraction (MinInt64 vs MaxInt64); a negative
// candidate against a non-negative incumbent always beats any duration
// tolerance because add_latency may produce negative ranking values.
func LatencyBeatsIncumbent(candidate, incumbent, tolerance time.Duration) bool {
	if candidate > incumbent {
		return false
	}
	if tolerance <= 0 {
		return true
	}
	// candidate <= incumbent is already known, but incumbent-candidate still
	// overflows when the values straddle MinInt64 and MaxInt64. A negative
	// candidate against a non-negative incumbent always beats any duration
	// tolerance; add_latency may produce negative ranking values.
	if candidate < 0 && incumbent >= 0 {
		return true
	}
	return incumbent-candidate >= tolerance
}

func (a *AliveDialerSet) betterThanIncumbent(candidate, incumbent time.Duration) bool {
	return LatencyBeatsIncumbent(candidate, incumbent, a.tolerance)
}

func (a *AliveDialerSet) unscoredMinLatencyLocked(skip map[*Dialer]struct{}, unscored []*Dialer) (*Dialer, time.Duration) {
	if inc := a.minLatency.dialer; inc != nil {
		if _, skipped := skip[inc]; !skipped && a.isAdmittedLocked(inc) {
			return inc, a.minLatency.sortingLatency
		}
	}
	var next *Dialer
	nextLat := time.Hour
	for _, d := range unscored {
		lat := a.dialerToLatencyOffset[d]
		if next == nil || lat < nextLat {
			next = d
			nextLat = lat
		}
	}
	if next != nil {
		return next, nextLat
	}
	return nil, time.Hour
}

func (a *AliveDialerSet) printLatencies() {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Group '%v' [%v]:\n", a.dialerGroupName, a.CheckTyp.String())
	var alive []*struct {
		d *Dialer
		l time.Duration
		o time.Duration
	}
	for i := range a.aliveEntries {
		d := a.aliveEntries[i].dialer
		latency, ok := a.dialerToLatency[d]
		if !ok {
			continue
		}
		offset := a.dialerToLatencyOffset[d]
		alive = append(alive, &struct {
			d *Dialer
			l time.Duration
			o time.Duration
		}{d, latency, offset})
	}
	sort.SliceStable(alive, func(i, j int) bool {
		return alive[i].l+alive[i].o < alive[j].l+alive[j].o
	})
	for i, dl := range alive {
		fmt.Fprintf(&builder, "%4d. [%v] %v: %v\n", i+1, dl.d.property.SubscriptionTag, dl.d.property.Name, latencyString(dl.l, dl.o))
	}
	a.log.Infoln(strings.TrimSuffix(builder.String(), "\n"))
}

// NotifyLatencyChange should be invoked when dialer every time latency and alive state changes.
func (a *AliveDialerSet) NotifyLatencyChange(dialer *Dialer, alive bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fromInit := a.dialerToIndex[dialer] == -Init
	oldLen := len(a.aliveEntries)
	var (
		rawLatency     time.Duration
		sortingLatency time.Duration
		hasLatency     bool
		minPolicy      bool
	)

	switch a.selectionPolicy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		rawLatency, hasLatency = dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		minPolicy = true
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		rawLatency, hasLatency = dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		minPolicy = true
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		consts.DialerSelectionPolicy_UrlTest:
		rawLatency, hasLatency = dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		minPolicy = true
	}

	if alive {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			// This dialer is already alive.
		} else {
			// Dialer: not alive -> alive.
			if index == -NotAlive {
				if a.log.IsLevelEnabled(logrus.InfoLevel) {
					a.log.WithFields(logrus.Fields{
						"dialer": dialer.property.Name,
						"group":  a.dialerGroupName,
					}).Infof("[NOT ALIVE --%v-> ALIVE]", a.CheckTyp.String())
				}
			}
			a.dialerToIndex[dialer] = len(a.aliveEntries)
			a.aliveEntries = append(a.aliveEntries, aliveEntry{
				dialer:         dialer,
				sortingLatency: rawLatency + a.dialerToLatencyOffset[dialer],
			})
		}
	} else {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			removedBestWithoutLatency := minPolicy && !hasLatency && a.minLatency.dialer == dialer
			// Dialer: alive -> not alive.
			if a.log.IsLevelEnabled(logrus.InfoLevel) {
				a.log.WithFields(logrus.Fields{
					"dialer": dialer.property.Name,
					"group":  a.dialerGroupName,
				}).Infof("[ALIVE --%v-> NOT ALIVE]", a.CheckTyp.String())
			}
			// Remove the dialer from aliveEntries.
			if index >= len(a.aliveEntries) {
				a.log.Panicf("index:%v >= len(a.aliveEntries):%v", index, len(a.aliveEntries))
			}
			a.dialerToIndex[dialer] = -NotAlive
			if index < len(a.aliveEntries)-1 {
				// Swap this element with the last element.
				// CRITICAL: Must update dialerToIndex for the swapped dialer.
				lastIdx := len(a.aliveEntries) - 1
				swappedEntry := a.aliveEntries[lastIdx]
				if dialer == swappedEntry.dialer {
					a.log.Panicf("dialer[%p] == swappedEntry.dialer[%p]", dialer, swappedEntry.dialer)
				}

				a.dialerToIndex[swappedEntry.dialer] = index
				a.aliveEntries[index] = swappedEntry
			}
			// Pop the last element.
			a.aliveEntries = a.aliveEntries[:len(a.aliveEntries)-1]
			if removedBestWithoutLatency {
				a.minLatency.dialer = nil
				a.minLatency.sortingLatency = time.Hour
				a.calcMinLatency()
				if a.minLatency.dialer == nil && a.log.IsLevelEnabled(logrus.InfoLevel) {
					a.log.WithFields(logrus.Fields{
						"group":   a.dialerGroupName,
						"network": a.CheckTyp.String(),
					}).Infof("Group has no dialer alive")
				}
			}
		}
	}

	if hasLatency {
		bakOldBestDialer := a.minLatency.dialer
		bakOldMinSortingLatency := a.minLatency.sortingLatency
		// Calc minLatency.
		a.dialerToLatency[dialer] = rawLatency
		// Update sorting latency in aliveEntries for GetMinLatency hot path optimization.
		sortingLatency = rawLatency + a.dialerToLatencyOffset[dialer]
		// If dialer is alive, update its sortingLatency in aliveEntries.
		if index := a.dialerToIndex[dialer]; index >= 0 {
			a.aliveEntries[index].sortingLatency = sortingLatency
		}
		if alive && LatencyBeatsIncumbent(sortingLatency, a.minLatency.sortingLatency, a.tolerance) {
			a.minLatency.sortingLatency = sortingLatency
			a.minLatency.dialer = dialer
		} else if a.minLatency.dialer == dialer {
			a.minLatency.sortingLatency = sortingLatency
			if !alive || sortingLatency > bakOldMinSortingLatency {
				// Latency increases.
				if !alive {
					a.minLatency.dialer = nil
				}
				a.calcMinLatency()
				// Now `a.minLatency.dialer` will be nil if there is no alive dialer.
			}
		}
		currentAlive := a.minLatency.dialer != nil
		// If best dialer changed.
		if a.minLatency.dialer != bakOldBestDialer {
			if currentAlive {
				newBestDialer := a.minLatency.dialer
				newBestLatency := a.dialerToLatency[newBestDialer]
				newBestOffset := a.dialerToLatencyOffset[newBestDialer]
				re := "re-"
				var oldDialerName string
				if bakOldBestDialer == nil {
					re = ""
					oldDialerName = "<nil>"
				} else {
					oldDialerName = bakOldBestDialer.property.Name
				}
				if a.log.IsLevelEnabled(logrus.InfoLevel) {
					a.log.WithFields(logrus.Fields{
						string(a.selectionPolicy): latencyString(newBestLatency, newBestOffset),
						"_new_dialer":             newBestDialer.property.Name,
						"_old_dialer":             oldDialerName,
						"group":                   a.dialerGroupName,
						"network":                 a.CheckTyp.String(),
					}).Infof("Group %vselects dialer", re)
				}

				a.printLatencies()
			} else if a.log.IsLevelEnabled(logrus.InfoLevel) {
				a.log.WithFields(logrus.Fields{
					"group":   a.dialerGroupName,
					"network": a.CheckTyp.String(),
				}).Infof("Group has no dialer alive")
			}
		}
	} else if alive && minPolicy {
		// No active latency probe for this network type (e.g. data-UDP), so
		// hasLatency is false here. Honor add_latency as a manual weight and
		// let it override the optimistic first-dialer selection.
		sortingLatency = rawLatency + a.dialerToLatencyOffset[dialer]
		if index := a.dialerToIndex[dialer]; index >= 0 {
			a.aliveEntries[index].sortingLatency = sortingLatency
		}
		if a.minLatency.dialer == nil || sortingLatency < a.minLatency.sortingLatency {
			a.minLatency.dialer = dialer
			a.minLatency.sortingLatency = sortingLatency
		}
		if a.log.IsLevelEnabled(logrus.InfoLevel) {
			a.log.WithFields(logrus.Fields{
				"group":   a.dialerGroupName,
				"network": a.CheckTyp.String(),
				"dialer":  dialer.property.Name,
			}).Infof("Group selects dialer")
		}
	}
	a.notifySelectionChangeLocked(fromInit, oldLen)
}

func (a *AliveDialerSet) calcMinLatency() {
	var minLatency = time.Hour
	var minDialer *Dialer
	for i := range a.aliveEntries {
		if a.aliveEntries[i].sortingLatency < minLatency {
			minLatency = a.aliveEntries[i].sortingLatency
			minDialer = a.aliveEntries[i].dialer
		}
	}
	if a.minLatency.dialer == nil {
		a.minLatency.sortingLatency = minLatency
		a.minLatency.dialer = minDialer
	} else if minDialer != nil && LatencyBeatsIncumbent(minLatency, a.minLatency.sortingLatency, a.tolerance) {
		a.minLatency.sortingLatency = minLatency
		a.minLatency.dialer = minDialer
	}
}

func (a *AliveDialerSet) notifySelectionChangeLocked(fromInit bool, oldLen int) {
	if fromInit || a.aliveChangeCallback == nil {
		return
	}
	newLen := len(a.aliveEntries)
	shouldNotify := false
	alive := newLen > 0
	switch a.selectionPolicy {
	case consts.DialerSelectionPolicy_FirstAlive:
		shouldNotify = oldLen != newLen
	case consts.DialerSelectionPolicy_Fallback:
		// Degraded is still Alive in this set; republish so kernel-direct
		// tracks the userspace fallback leaf.
		shouldNotify = true
	case consts.DialerSelectionPolicy_Random:
		// Random has no stable leaf, but 0↔n changes whether a nested
		// first_alive/min parent can select this group. A parent that already
		// published backup DIRECT must republish when this group recovers.
		shouldNotify = (oldLen == 0) != (newLen == 0)
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		consts.DialerSelectionPolicy_UrlTest:
		// Nested min compares the selected child leaf and parent health views,
		// not this set's minLatency.dialer pointer. Republish on every update
		// so a real winner change is not missed.
		shouldNotify = true
	default:
		return
	}
	if !shouldNotify {
		return
	}
	a.mu.Unlock()
	a.aliveChangeCallback(alive)
	a.mu.Lock()
}

func (a *AliveDialerSet) SetSelectionPolicy(policy consts.DialerSelectionPolicy) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.selectionPolicy == policy {
		return
	}
	a.selectionPolicy = policy
	a.recomputeSelectionStateLocked()
}

func (a *AliveDialerSet) recomputeSelectionStateLocked() {
	a.dialerToLatency = make(map[*Dialer]time.Duration, len(a.dialerToLatencyOffset))
	a.minLatency = minLatency{
		sortingLatency: time.Hour,
	}

	if !isMinLatencyPolicy(a.selectionPolicy) {
		return
	}

	for i := range a.aliveEntries {
		entry := &a.aliveEntries[i]
		rawLatency, hasLatency := entry.dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		if hasLatency {
			a.dialerToLatency[entry.dialer] = rawLatency
		}
		// Always apply the manual latency offset. For network types without
		// an active latency probe (e.g. data-UDP) the offset is the only
		// ranking signal, so add_latency acts as a true manual weight.
		entry.sortingLatency = rawLatency + a.dialerToLatencyOffset[entry.dialer]
	}

	a.calcMinLatency()
}

func isMinLatencyPolicy(policy consts.DialerSelectionPolicy) bool {
	switch policy {
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		consts.DialerSelectionPolicy_UrlTest:
		return true
	default:
		return false
	}
}
