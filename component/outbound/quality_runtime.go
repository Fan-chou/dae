/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/outbound/quality"
	"github.com/sirupsen/logrus"
)

// QualityOptions contains only local policy. Model availability never gates it.
type QualityOptions struct {
	MinDownloadBytes      float64
	RequiredDownloadBytes float64
	Mode                  string
	Policy                quality.Policy
	Report                func(map[string]any)
}
type qualityLog struct {
	level  logrus.Level
	fields logrus.Fields
}

type qualityScope struct {
	host    string
	network dialer.NetworkType
}
type qualityRecord struct {
	stable                *dialer.Dialer
	path                  SelectPath
	pinned, next, touched time.Time
	generation            uint64
	probe                 *QualityFlow
	failures              int
	switches              []time.Time
	rates                 map[*dialer.Dialer]*qualityRate
}
type qualityRate struct {
	load                           dialer.LoadContext
	relativeSevere, absoluteSevere bool
	absoluteLow, absoluteRecovered int
	baseline                       float64
	baselineUntil                  time.Time
	healthy                        []float64
	flows                          map[uint64]bool
	current                        float64
	at                             time.Time
	low                            int
	severe                         bool
}
type qualityRuntime struct {
	mu                   sync.Mutex
	sampleMu             sync.Mutex
	pendingLogs          []qualityLog
	options              QualityOptions
	group                string
	log                  *logrus.Logger
	entries              map[qualityScope]*qualityRecord
	flows                map[*QualityFlow]struct{}
	serial               uint64
	logAt                time.Time
	logCount, suppressed int
	rejected             uint64
	rateCount            int
	switches             []time.Time
	lastSwitch           time.Time
	closed               bool
	stop                 chan struct{}
	done                 chan struct{}
}

// QualityFlow is per-selection feedback, deliberately separate from the
// interned SelectPath used by established-flow caches.
type QualityFlow struct {
	runtime                *qualityRuntime
	key                    qualityScope
	record                 *qualityRecord
	generation, id         uint64
	node                   *dialer.Dialer
	path                   SelectPath
	probe, qualityProbe    bool
	deadline               time.Time
	started                time.Time
	bytes, blocked         atomic.Int64
	observed               atomic.Bool
	finished               atomic.Bool
	first                  atomic.Bool
	lastBytes, lastBlocked int64
	windowStart            time.Time
	windowNodeUp           uint64 // node cumulative totals at windowStart
	windowNodeDown         uint64
	// Contention is relative to the flow: traffic "external" to a small flow
	// may be the very download another flow is measuring. So both the raw
	// verdict and settling live on the flow, never on shared per-node state.
	othersBusy                 bool      // last closed window: other traffic made the node busy
	othersDeferred             bool      // othersBusy, or the window right after one (settling)
	othersAt                   time.Time // when that window closed; zero until the first close
	ticks, active              int
	windowBytes, windowBlocked int64
	good                       int
	recovered                  int
	registrationAttempted      atomic.Bool
	registered                 atomic.Bool
	lastReason                 string
}

func newQualityRuntime(group string, o QualityOptions, log *logrus.Logger) *qualityRuntime {
	if o.Mode == "" || o.Mode == "off" {
		return nil
	}
	if o.Policy.Validate() != nil {
		return nil
	}
	q := &qualityRuntime{options: o, group: group, log: log, entries: make(map[qualityScope]*qualityRecord), flows: make(map[*QualityFlow]struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(q.done)
		tick := time.NewTicker(qualitySampleInterval)
		defer tick.Stop()
		for {
			select {
			case now := <-tick.C:
				q.sample(now)
			case <-q.stop:
				return
			}
		}
	}()
	return q
}
func qualityNode(d *dialer.Dialer) string {
	if d == nil || d.Property() == nil {
		return ""
	}
	return d.Property().Name
}
func (q *qualityRuntime) event(key qualityScope, reason string, fields logrus.Fields) {
	q.eventAt(logrus.InfoLevel, key, reason, fields)
}

// eventAt logs state changes at Info. Per-flow bookkeeping outcomes use Debug
// and do not consume the Info budget, so steady-state traffic stays quiet.
func (q *qualityRuntime) eventAt(level logrus.Level, key qualityScope, reason string, fields logrus.Fields) {
	if q.log == nil || !q.log.IsLevelEnabled(level) {
		return
	}
	if level == logrus.DebugLevel {
		if fields == nil {
			fields = logrus.Fields{}
		}
		fields["event"] = "local_quality"
		fields["group"] = q.group
		fields["host"] = key.host
		fields["network"] = key.network.StringWithoutDns()
		fields["mode"] = q.options.Mode
		fields["reason"] = reason
		q.pendingLogs = append(q.pendingLogs, qualityLog{logrus.DebugLevel, fields})
		return
	}
	now := time.Now()
	if now.Sub(q.logAt) >= time.Minute {
		q.logAt = now
		q.logCount = 0
	}
	critical := reason == "verified_throughput_improvement" || reason == "preferred_recovery"
	if q.logCount >= 20 && !critical {
		q.suppressed++
		return
	}
	q.logCount++
	if fields == nil {
		fields = logrus.Fields{}
	}
	fields["event"] = "local_quality"
	fields["group"] = q.group
	fields["host"] = key.host
	fields["network"] = key.network.StringWithoutDns()
	fields["mode"] = q.options.Mode
	fields["reason"] = reason
	fields["suppressed_logs"] = q.suppressed
	q.pendingLogs = append(q.pendingLogs, qualityLog{logrus.InfoLevel, fields})
}

// Detach log payloads while holding the state lock, then write outside it.
func (q *qualityRuntime) unlock() {
	logs := q.pendingLogs
	q.pendingLogs = nil
	q.mu.Unlock()
	for _, entry := range logs {
		q.log.WithFields(entry.fields).Log(entry.level, "Local quality observation")
	}
}

func (q *qualityRuntime) close() {
	q.mu.Lock()
	if q.closed {
		q.unlock()
		return
	}
	q.closed = true
	close(q.stop)
	clear(q.entries)
	q.rateCount = 0
	clear(q.flows)
	q.unlock()
	<-q.done
}
func (q *qualityRuntime) reset() {
	q.mu.Lock()
	defer q.unlock()
	clear(q.entries)
	clear(q.flows)
	q.rateCount = 0
}
func (q *qualityRuntime) entry(key qualityScope, now time.Time) *qualityRecord {
	e := q.entries[key]
	if e != nil {
		e.touched = now
		return e
	}
	if len(q.entries) >= 4096 {
		var oldest qualityScope
		var at time.Time
		found := false
		for k, v := range q.entries {
			if v.probe == nil && (!found || v.touched.Before(at)) {
				oldest = k
				at = v.touched
				found = true
			}
		}
		if !found {
			return nil
		}
		q.rateCount = max(0, q.rateCount-len(q.entries[oldest].rates))
		delete(q.entries, oldest)
	}
	e = &qualityRecord{touched: now, rates: make(map[*dialer.Dialer]*qualityRate)}
	q.entries[key] = e
	return e
}
func (q *qualityRuntime) backoff(e *qualityRecord, now time.Time) {
	e.failures++
	delay := 2 * time.Minute
	if e.failures == 2 {
		delay = 5 * time.Minute
	}
	if e.failures >= 3 {
		delay = 10 * time.Minute
	}
	e.next = now.Add(delay)
	e.probe = nil
}
func (q *qualityRuntime) budget(e *qualityRecord, now time.Time) bool {
	kept := e.switches[:0]
	for _, t := range e.switches {
		if now.Sub(t) < 30*time.Minute {
			kept = append(kept, t)
		}
	}
	e.switches = kept
	groupKept := q.switches[:0]
	for _, t := range q.switches {
		if now.Sub(t) < 30*time.Minute {
			groupKept = append(groupKept, t)
		}
	}
	q.switches = groupKept
	return now.Sub(e.pinned) >= 5*time.Minute && len(kept) < 2 && len(groupKept) < 10 && now.Sub(q.lastSwitch) >= 5*time.Second
}

const qualitySampleInterval = 5 * time.Second

// contentionSettle is how long after an externally busy window the node's
// closing windows are still treated as settling: the next window (which
// closes one Window later, plus tick jitter) is covered, the one after is not.
func (q *qualityRuntime) contentionSettle() time.Duration {
	return q.options.Policy.Window + 2*qualitySampleInterval
}

// aggregateDeferred protects negative quality attribution without a
// measurement window: low-speed probe eligibility and the diagnostics view.
// Positive first-byte recovery does not use this exemption. Nothing is subtracted, so a verdict can never be
// borrowed from some other flow's aligned measurement.
func (q *qualityRuntime) aggregateDeferred(node *dialer.Dialer, now time.Time) bool {
	return node != nil && node.LoadContext(now).DeferQuality()
}

// alignedDeferred is this flow's own window-aligned verdict. ok is false when
// the flow has no fresh closed window; throughput commits then must not
// proceed rather than fall back to some other flow's result.
func (f *QualityFlow) alignedDeferred(now time.Time, settle time.Duration) (deferred, ok bool) {
	if f == nil || f.othersAt.IsZero() || f.finished.Load() || now.Sub(f.othersAt) > settle {
		return true, false
	}
	return f.othersDeferred, true
}

// recordContention stores one closed window's aligned verdict on the flow.
// Settling is the flow's own previous window having been externally busy, so
// flows closing in the same sample cannot affect each other, and a flow is
// never deferred by contention that was its own traffic seen from another
// flow. A flow's first window has no history and therefore no settling.
func (q *qualityRuntime) recordContention(f *QualityFlow, othersBusy bool, now time.Time) {
	settling := f.othersBusy && !f.othersAt.IsZero() && now.Sub(f.othersAt) <= q.contentionSettle()
	f.othersDeferred = othersBusy || settling
	f.othersBusy = othersBusy
	f.othersAt = now
}

// commit switches the stable leaf to f.node. candidateDeferred is the
// caller's load verdict for the candidate: sample() passes the probe flow's
// own aligned result; a successful recovery first byte needs no load exemption.
// The stable leaf's load cannot invalidate the candidate's positive evidence.
func (q *qualityRuntime) commit(f *QualityFlow, now time.Time, reason string, candidateDeferred bool) bool {
	e := f.record
	if f.node == nil || candidateDeferred || f.node.AdmissionState(&f.key.network) == dialer.AdmissionDead {
		return false
	}
	if q.options.Mode != "enforce" || q.closed || q.entries[f.key] != e || e.generation != f.generation || e.probe != f || !now.Before(f.deadline) {
		return false
	}
	if !q.budget(e, now) {
		e.probe = nil
		e.next = now.Add(5 * time.Second)
		q.eventAt(logrus.DebugLevel, f.key, "switch_budget", logrus.Fields{"next_probe_at": e.next})
		return false
	}
	old := e.stable
	e.stable = f.node
	e.path = f.path
	e.pinned = now
	e.next = now.Add(2 * time.Minute)
	e.switches = append(e.switches, now)
	q.switches = append(q.switches, now)
	q.lastSwitch = now
	e.failures = 0
	e.probe = nil
	e.generation++
	q.event(f.key, reason, logrus.Fields{"old_leaf": qualityNode(old), "candidate": qualityNode(f.node), "probe_id": f.id, "generation": e.generation, "next_probe_at": e.next})
	return true
}

// SelectWithQuality retains the existing selector as the legality/health
// authority. Probe candidates are selected through that same nested graph,
// never by flattening members or overriding a fixed child.
func (g *DialerGroup) SelectWithQuality(nt *dialer.NetworkType, strict bool, excluded *dialer.Dialer, site string) (*dialer.Dialer, time.Duration, *dialer.NetworkType, SelectPath, *QualityFlow, error) {
	d, lat, selected, path, err := g.SelectWithPath(nt, strict, excluded, site)
	if !g.hasQuality || err != nil || selected == nil || selected.L4Proto != consts.L4ProtoStr_TCP {
		return d, lat, selected, path, nil, err
	}
	owner := g.qualityOwner(path)
	if owner == nil {
		return d, lat, selected, path, nil, err
	}
	q := owner.quality
	host := StickyKey(site)
	if host == "" {
		return d, lat, selected, path, nil, err
	}
	now := g.now()
	key := qualityScope{host, *selected}
	q.mu.Lock()
	defer q.unlock()
	if q.closed {
		return d, lat, selected, path, nil, err
	}
	e := q.entry(key, now)
	if e == nil {
		return d, lat, selected, path, nil, err
	}
	if e.probe != nil && !now.Before(e.probe.deadline) {
		q.event(key, "probe_expired", logrus.Fields{"probe_id": e.probe.id})
		q.backoff(e, now)
	}
	// Recheck the pin through the original graph with every other leaf skipped.
	// This also rejects pins excluded by an updated fixed child selection, and
	// a stable leaf that a recent same-site failure placed under hold-down.
	if q.options.Mode == "enforce" && e.stable != nil && e.stable != excluded {
		stable, generation := e.stable, e.generation
		q.unlock()
		skip := owner.siteHoldDownSet(site)
		if skip == nil {
			skip = make(map[*dialer.Dialer]struct{})
		}
		for _, leaf := range g.nestedConcreteDialers() {
			if leaf != stable {
				skip[leaf] = struct{}{}
			}
		}
		var b selectPathBuilder
		pinned, _, pn, _, pe := g.selectWithSkip(selected, true, excluded, skip, true, site, false, true, &b)
		pinPath := internSelectPath(g, b)
		valid := pe == nil && pinned == stable && pn != nil && *pn == *selected && g.qualityOwner(pinPath) == owner
		q.mu.Lock()
		if q.closed || q.entries[key] != e || e.generation != generation || e.stable != stable {
			b.abandonRecovery()
			return d, lat, selected, path, nil, err
		}
		if valid {
			// The original selection's trial, if any, is superseded by the
			// enforced pin; release it without recording a failure.
			path.RecoveryAbandon()
			d = pinned
			path = pinPath
		} else {
			b.abandonRecovery()
			e.stable = nil
			e.generation++
			e.probe = nil
		}
	}
	if e.stable == nil || (q.options.Mode == "observe" && e.stable != d) {
		e.stable = d
		e.path = path
		e.pinned = now
		e.next = now.Add(2 * time.Minute)
		e.generation++
	}
	q.serial++
	f := &QualityFlow{runtime: q, key: key, record: e, generation: e.generation, id: q.serial, node: d, path: path, started: now, windowStart: now}
	if q.options.Mode == "enforce" && excluded == nil && e.probe == nil && !now.Before(e.next) && q.budget(e, now) {
		rate := e.rates[e.stable]
		bad := rate != nil && rate.severe && now.Sub(rate.at) < q.options.Policy.EvidenceTTL && !q.aggregateDeferred(e.stable, now)
		// Skip the stable leaf for quality verification. Periodic recovery only
		// probes a higher-priority fallback member, not arbitrary rotation.
		stable, generation := e.stable, e.generation
		q.unlock()
		var b selectPathBuilder
		skip := owner.siteHoldDownSet(site)
		if skip == nil {
			skip = make(map[*dialer.Dialer]struct{})
		}
		for _, leaf := range g.nestedConcreteDialers() {
			if !owner.hasConcreteMember(leaf) {
				skip[leaf] = struct{}{}
			}
		}
		alt, al, an, _, ae := g.selectWithSkip(selected, true, stable, skip, true, site, false, false, &b)
		preferred := owner.GetSelectionPolicy() == consts.DialerSelectionPolicy_Fallback && owner.fallbackRank(alt) < owner.fallbackRank(stable)
		altPath := internSelectPath(g, b)
		valid := ae == nil && alt != nil && an != nil && *an == *selected && g.qualityOwner(altPath) == owner && (bad || preferred)
		q.mu.Lock()
		if q.closed || q.entries[key] != e || e.generation != generation || e.stable != stable || e.probe != nil || now.Before(e.next) || !q.budget(e, now) {
			b.abandonRecovery()
			return d, lat, selected, path, f, nil
		}
		if valid {
			path.RecoveryAbandon()
			f.node = alt
			f.path = altPath
			f.probe = true
			f.qualityProbe = bad
			f.deadline = now.Add(time.Minute)
			e.probe = f
			d = alt
			lat = al
			path = f.path
			reason := "preferred_recovery_probe"
			if bad {
				reason = "severe_speed_probe"
			}
			q.event(key, reason, logrus.Fields{"old_leaf": qualityNode(e.stable), "candidate": qualityNode(alt), "probe_id": f.id, "deadline": f.deadline, "generation": f.generation})
		} else {
			b.abandonRecovery()
			e.next = now.Add(2 * time.Minute)
			q.eventAt(logrus.DebugLevel, key, "no_eligible_alternative", logrus.Fields{"stable_leaf": qualityNode(e.stable), "next_probe_at": e.next})
		}
	}
	return d, lat, selected, path, f, nil
}
func (g *DialerGroup) qualityOwner(path SelectPath) *DialerGroup {
	if g == nil || !g.hasQuality {
		return nil
	}
	// Prefer the highest explicitly enabled group on the actual path. Fixed
	// parents are traversed but never become a quality-control authority.
	for _, t := range path.stickyTables() {
		if t == g.siteSticky && g.quality != nil && g.usesSiteSticky() {
			return g
		}
	}
	for _, m := range g.nestedMembers {
		if m.group != nil {
			if o := m.group.qualityOwner(path); o != nil {
				return o
			}
		}
	}
	return nil
}
func (f *QualityFlow) FirstByte(slow bool) {
	if f == nil || !f.first.CompareAndSwap(false, true) {
		return
	}
	q := f.runtime
	q.mu.Lock()
	defer q.unlock()
	if f.probe && !f.qualityProbe && !slow {
		now := time.Now()
		q.commit(f, now, "preferred_recovery", false)
	}
}

// MeasureWrites avoids timing small flows or a rejected registration.
func (f *QualityFlow) MeasureWrites() bool {
	return f != nil && !f.finished.Load() && f.bytes.Load() >= 1<<20 && (!f.registrationAttempted.Load() || f.registered.Load())
}

// ObserveWrite is called only from the measured userspace downstream relay.
func (f *QualityFlow) ObserveWrite(n int, d time.Duration) {
	if f == nil || n <= 0 || f.finished.Load() {
		return
	}
	f.bytes.Add(int64(n))
	f.blocked.Add(int64(d))
	f.observed.Store(true)
	if f.bytes.Load() < 1<<20 || !f.registrationAttempted.CompareAndSwap(false, true) {
		return
	}
	q := f.runtime
	q.mu.Lock()
	defer q.unlock()
	if !q.closed && !f.finished.Load() && q.entries[f.key] == f.record && len(q.flows) < 4096 {
		q.flows[f] = struct{}{}
		f.windowStart = time.Now()
		f.windowNodeUp, f.windowNodeDown, _ = f.node.LoadTotals()
		f.lastBytes = f.bytes.Load()
		f.lastBlocked = f.blocked.Load()
		f.registered.Store(true)
	}
}
func (f *QualityFlow) Finish() {
	if f == nil || !f.finished.CompareAndSwap(false, true) {
		return
	}
	q := f.runtime
	q.mu.Lock()
	defer q.unlock()
	delete(q.flows, f)
	if q.closed || q.entries[f.key] != f.record {
		return
	}
	if !f.observed.Load() {
		q.rejected++
		q.eventAt(logrus.DebugLevel, f.key, "offload_or_unmeasured", logrus.Fields{"leaf": qualityNode(f.node)})
	} else if !f.registered.Load() {
		q.rejected++
		q.eventAt(logrus.DebugLevel, f.key, "below_sampling_threshold", logrus.Fields{"leaf": qualityNode(f.node), "bytes": f.bytes.Load()})
	}
	if f.record.probe == f {
		q.event(f.key, "probe_inconclusive_or_closed", logrus.Fields{"probe_id": f.id, "measured": f.observed.Load()})
		q.backoff(f.record, time.Now())
	}
}

// Abandon releases a selection that will never be observed (no FlowRuntime
// adopted it, or the caller has no relay to measure). A probe slot is
// returned without backoff or a failure count: absence of measurement is not
// evidence about the candidate.
func (f *QualityFlow) Abandon() {
	if f == nil || !f.finished.CompareAndSwap(false, true) {
		return
	}
	q := f.runtime
	q.mu.Lock()
	defer q.unlock()
	delete(q.flows, f)
	if q.closed || q.entries[f.key] != f.record {
		return
	}
	if f.record.probe == f {
		f.record.probe = nil
		q.eventAt(logrus.DebugLevel, f.key, "probe_abandoned_unobserved", logrus.Fields{"probe_id": f.id})
	}
}
func (q *qualityRuntime) sample(now time.Time) {
	q.sampleMu.Lock()
	defer q.sampleMu.Unlock()
	q.mu.Lock()
	if q.closed {
		q.unlock()
		return
	}
	flows := make([]*QualityFlow, 0, len(q.flows))
	for f := range q.flows {
		flows = append(flows, f)
	}
	q.unlock()
	for _, f := range flows {
		q.sampleFlow(f, now)
	}
	q.mu.Lock()
	entries := make(map[qualityScope]*qualityRecord, len(q.entries))
	for key, e := range q.entries {
		entries[key] = e
	}
	q.unlock()
	for key, e := range entries {
		q.sampleEntry(key, e, now)
	}
}
func (q *qualityRuntime) sampleFlow(f *QualityFlow, now time.Time) {
	q.mu.Lock()
	defer q.unlock()
	if q.closed {
		return
	}
	if _, ok := q.flows[f]; !ok {
		return
	}
	if f.finished.Load() || q.entries[f.key] != f.record {
		delete(q.flows, f)
		return
	}
	n, b := f.bytes.Load(), f.blocked.Load()
	dn, db := n-f.lastBytes, b-f.lastBlocked
	f.lastBytes = n
	f.lastBlocked = b
	load := f.node.LoadContext(now)
	f.ticks++
	if dn > 0 {
		f.active++
	}
	f.windowBytes += dn
	f.windowBlocked += db
	elapsed := now.Sub(f.windowStart)
	if elapsed < q.options.Policy.Window {
		return
	}
	valid := f.active == f.ticks && f.ticks >= 2 && f.windowBlocked < int64(elapsed)/5 && now.Sub(f.started) >= 15*time.Second
	speed := float64(f.windowBytes) / elapsed.Seconds()
	if f.windowBytes == 0 {
		valid = false
	}
	// Traffic by everything except this flow, over exactly this window.
	// Without aligned totals nothing is subtracted (aggregate verdict).
	othersBusy := load.DeferQuality()
	if nodeUp, nodeDown, ok := f.node.LoadTotals(); ok {
		othersUp := float64(nodeUp-f.windowNodeUp) / elapsed.Seconds()
		othersDown := max(0, float64(nodeDown-f.windowNodeDown)-float64(f.windowBytes)) / elapsed.Seconds()
		othersBusy = load.DeferQualityForOthers(othersUp, othersDown)
		f.windowNodeUp, f.windowNodeDown = nodeUp, nodeDown
	}
	blockedWindow := f.windowBlocked
	f.ticks = 0
	f.active = 0
	f.windowBytes = 0
	f.windowBlocked = 0
	f.windowStart = now
	e := f.record
	r := e.rates[f.node]
	// Recorded even for invalid windows so the flow's settling history
	// stays contiguous.
	q.recordContention(f, othersBusy, now)
	if !valid {
		q.rejected++
		reason := "insufficient_activity"
		if blockedWindow >= int64(elapsed)/5 {
			reason = "client_backpressure"
		}
		if f.lastReason != reason {
			q.event(f.key, reason, logrus.Fields{"leaf": qualityNode(f.node)})
			f.lastReason = reason
		}
		if r != nil {
			r.low = 0
			r.absoluteLow = 0
			r.absoluteRecovered = 0
			f.recovered = 0
		}
		f.good = 0
		return
	}
	if r == nil {
		if len(e.rates) >= 32 || q.rateCount >= 8192 {
			return
		}
		r = &qualityRate{flows: make(map[uint64]bool)}
		e.rates[f.node] = r
		q.rateCount++
	}
	if now.Sub(r.at) < q.options.Policy.Window {
		return
	} // overlapping flows are not independent windows
	if now.Sub(r.at) > q.options.Policy.Window+10*time.Second {
		r.absoluteLow = 0
		r.absoluteRecovered = 0
		r.low = 0
	}
	if !r.at.IsZero() && now.Sub(r.at) >= 30*time.Minute {
		r.healthy = nil
		clear(r.flows)
	}
	r.load = load
	if f.othersDeferred {
		r.low = 0
		r.absoluteLow = 0
		r.absoluteRecovered = 0
		f.recovered = 0
		f.good = 0
		if f.lastReason != "load_deferred" {
			q.event(f.key, "load_deferred", logrus.Fields{"leaf": qualityNode(f.node), "load": r.load})
			f.lastReason = "load_deferred"
		}
		return
	}
	f.lastReason = ""
	r.current = speed
	r.at = now
	if q.options.RequiredDownloadBytes > 0 {
		r.baseline = q.options.RequiredDownloadBytes
		r.baselineUntil = now.Add(q.options.Policy.EvidenceTTL)
	}
	if r.baseline > 0 && !now.Before(r.baselineUntil) {
		r.baseline = 0
		r.relativeSevere = false
		r.low = 0
		r.healthy = nil
		clear(r.flows)
		q.event(f.key, "baseline_expired", logrus.Fields{"leaf": qualityNode(f.node)})
	}
	if r.baseline > 0 {
		ratio := speed / r.baseline
		if ratio < q.options.Policy.SevereRatio {
			r.low++
			f.recovered = 0
			if r.low >= q.options.Policy.SevereWindows && !r.relativeSevere {
				r.relativeSevere = true
				q.event(f.key, "relative_speed_collapse", logrus.Fields{"leaf": qualityNode(f.node), "bytes_per_second": speed, "reference_bytes_per_second": r.baseline, "ratio": ratio, "interpretation": "local_comparison_only"})
				q.report(f, r)
			}
		} else {
			r.low = 0
			if ratio >= q.options.Policy.RecoveryRatio {
				f.recovered++
				if f.recovered >= q.options.Policy.RecoveryWindows && r.relativeSevere {
					r.relativeSevere = false
					q.event(f.key, "relative_speed_recovered", logrus.Fields{"leaf": qualityNode(f.node), "ratio": ratio})
				}
			} else {
				f.recovered = 0
			}
		}
	}
	floor := q.options.MinDownloadBytes
	if floor > 0 {
		if speed < floor {
			r.absoluteLow++
			r.absoluteRecovered = 0
			if r.absoluteLow >= q.options.Policy.SevereWindows && !r.absoluteSevere {
				r.absoluteSevere = true
				q.event(f.key, "absolute_speed_below_floor", logrus.Fields{"leaf": qualityNode(f.node), "bytes_per_second": speed, "minimum_bytes_per_second": floor, "recovery_bytes_per_second": 1.5 * floor})
				q.report(f, r)
			}
		} else {
			r.absoluteLow = 0
			if speed >= 1.5*floor {
				r.absoluteRecovered++
				if r.absoluteRecovered >= q.options.Policy.RecoveryWindows && r.absoluteSevere {
					r.absoluteSevere = false
					q.event(f.key, "absolute_speed_recovered", logrus.Fields{"leaf": qualityNode(f.node), "bytes_per_second": speed, "minimum_bytes_per_second": floor})
				}
			} else {
				r.absoluteRecovered = 0
			}
		}
	}
	r.severe = r.relativeSevere || r.absoluteSevere

	if !r.severe && r.low == 0 && r.absoluteLow == 0 {
		r.healthy = append(r.healthy, speed)
		if len(r.healthy) > 12 {
			r.healthy = r.healthy[1:]
		}
		if len(r.flows) < 2 {
			r.flows[f.id] = true
		}
		if len(r.healthy) >= 6 && len(r.flows) >= 2 && r.baseline == 0 {
			values := append([]float64(nil), r.healthy...)
			sort.Float64s(values)
			r.baseline = values[len(values)/2]
			r.baselineUntil = now.Add(30 * time.Minute)
			q.event(f.key, "baseline_ready", logrus.Fields{"leaf": qualityNode(f.node), "reference_bytes_per_second": r.baseline, "valid_until": r.baselineUntil})
		}
	}
	if f.probe && f.qualityProbe && e.probe == f && now.Before(f.deadline) {
		old := e.rates[e.stable]
		if old != nil && old.severe && now.Sub(old.at) < q.options.Policy.EvidenceTTL && q.options.Policy.CandidateImproves(old.current, speed) && !r.severe && q.candidateRecovered(r, speed) {
			f.good++
			if f.good >= 2 {
				// Only this probe flow's own fresh aligned verdict may
				// clear the candidate; never another flow's.
				deferred, ok := f.alignedDeferred(now, q.contentionSettle())
				q.commit(f, now, "verified_throughput_improvement", deferred || !ok)
			}
		} else {
			f.good = 0
		}
	}

}
func (q *qualityRuntime) sampleEntry(key qualityScope, e *qualityRecord, now time.Time) {
	q.mu.Lock()
	defer q.unlock()
	if q.closed || q.entries[key] != e {
		return
	}
	for node, r := range e.rates {
		if (r.severe || r.low > 0 || r.absoluteLow > 0) && now.Sub(r.at) >= q.options.Policy.EvidenceTTL {
			r.severe = false
			r.relativeSevere = false
			r.absoluteSevere = false
			r.absoluteLow = 0
			r.absoluteRecovered = 0
			r.low = 0
			q.event(key, "evidence_expired", logrus.Fields{"leaf": qualityNode(node)})
		}
	}
	if e.probe != nil && !now.Before(e.probe.deadline) {
		q.event(key, "probe_expired", logrus.Fields{"probe_id": e.probe.id})
		q.backoff(e, now)
	}
	if now.Sub(e.touched) > time.Hour && e.probe == nil {
		q.rateCount = max(0, q.rateCount-len(e.rates))
		delete(q.entries, key)
	}

}
func (q *qualityRuntime) report(f *QualityFlow, r *qualityRate) {
	if q.options.Report != nil {
		q.options.Report(map[string]any{"group": q.group, "evidence_id": f.id, "observed_at": r.at, "measurement_validity": "relative_activity_only", "network": f.key.network.StringWithoutDns(), "current_bytes_per_second": r.current, "reference_bytes_per_second": r.baseline, "minimum_bytes_per_second": q.options.MinDownloadBytes, "local_decision": "verify_alternative", "scope": "single_host", "capacity_claim": false, "load": r.load})
	}
}

// Fail invalidates an unusable stable path without penalizing cancellations.
func (f *QualityFlow) Fail() {
	if f == nil {
		return
	}
	q := f.runtime
	q.mu.Lock()
	if !q.closed && q.entries[f.key] == f.record && f.record.generation == f.generation && f.record.stable == f.node && !f.probe {
		f.record.stable = nil
		f.record.generation++
		q.event(f.key, "connection_failed", logrus.Fields{"leaf": qualityNode(f.node)})
	}
	q.unlock()
	f.Finish()
}

// QualityStatus returns bounded read-only diagnostics. It never selects a node
// or arms a probe; listing the management API cannot perturb routing.
func (g *DialerGroup) QualityStatus(host string, limit int) []map[string]any {
	if g == nil || g.quality == nil {
		return nil
	}
	q := g.quality
	q.mu.Lock()
	defer q.unlock()
	if limit <= 0 || limit > 256 {
		limit = 256
	}
	out := make([]map[string]any, 0)
	keys := make([]qualityScope, 0, len(q.entries))
	for k := range q.entries {
		if host == "" || k.host == StickyKey(host) {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].host == keys[j].host {
			return keys[i].network.StringWithoutDns() < keys[j].network.StringWithoutDns()
		}
		return keys[i].host < keys[j].host
	})
	for _, k := range keys {
		if len(out) >= limit {
			break
		}
		e := q.entries[k]
		v := map[string]any{"group": q.group, "host": k.host, "network": k.network.StringWithoutDns(), "mode": q.options.Mode, "stable_leaf": qualityNode(e.stable), "next_probe_at": e.next, "generation": e.generation, "suppressed_logs": q.suppressed, "invalid_windows": q.rejected}
		if e.probe != nil {
			v["candidate"] = qualityNode(e.probe.node)
			v["probe_id"] = e.probe.id
			v["probe_deadline"] = e.probe.deadline
		}
		if r := e.rates[e.stable]; r != nil {
			now := time.Now()
			deferred := q.aggregateDeferred(e.stable, now)
			v["load"] = e.stable.LoadContext(now)
			v["quality_deferred"] = deferred
			v["historical_severe"] = r.severe && time.Since(r.at) < q.options.Policy.EvidenceTTL
			v["minimum_bytes_per_second"] = q.options.MinDownloadBytes
			v["absolute_severe"] = !deferred && r.absoluteSevere && time.Since(r.at) < q.options.Policy.EvidenceTTL
			v["current_bytes_per_second"] = r.current
			v["reference_bytes_per_second"] = r.baseline
			v["severe"] = !deferred && r.severe && time.Since(r.at) < q.options.Policy.EvidenceTTL
			v["last_sample_at"] = r.at
		}
		out = append(out, v)
	}
	return out
}

func (f *QualityFlow) ControlsPin() bool { return f != nil && f.runtime.options.Mode == "enforce" }

// An absolute floor provides a recovery reference even during cold start.
// If a historical/demand reference also exists, both recovery gates apply.
func (q *qualityRuntime) candidateRecovered(r *qualityRate, speed float64) bool {
	if q.options.MinDownloadBytes > 0 && speed < 1.5*q.options.MinDownloadBytes {
		return false
	}
	if r.baseline > 0 {
		return speed >= r.baseline*q.options.Policy.RecoveryRatio
	}
	return q.options.MinDownloadBytes > 0
}
