/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"bytes"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/outbound/quality"
	"github.com/sirupsen/logrus"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStickyKeySeparatesHosts(t *testing.T) {
	for _, tc := range []struct{ in, want string }{{"A.Example.COM.:443", "a.example.com"}, {"b.example.com", "b.example.com"}, {"internal_node.example", "internal_node.example"}, {"nas", "nas"}, {"[::ffff:8.8.8.8]:443", "8.8.8.8"}, {"127.0.0.1", ""}, {"bad/path.example", ""}, {"https://example.com", ""}} {
		if got := StickyKey(tc.in); got != tc.want {
			t.Fatalf("%s => %s", tc.in, got)
		}
	}
	if SiteKey("a.example.com") != "example.com" {
		t.Fatal("legacy key changed")
	}
}
func TestQualityTrialDoesNotCommitOnFirstByteAndKeepsOtherFlows(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	g.quality = newQualityRuntime(g.Name, QualityOptions{Mode: "enforce", Policy: quality.DefaultPolicy()}, g.log)
	g.hasQuality = true
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	_, _, _, _, flow, err := g.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
	if err != nil || flow == nil {
		t.Fatalf("initial: %v", err)
	}
	q := g.quality
	q.mu.Lock()
	e := flow.record
	e.pinned = now.Add(-6 * time.Minute)
	e.next = now.Add(-time.Second)
	e.rates[e.stable] = &qualityRate{severe: true, current: 1024, at: now}
	q.mu.Unlock()
	selected, _, _, _, probe, err := g.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
	if err != nil || !probe.probe || selected == e.stable {
		t.Fatalf("trial not selected: %v", err)
	}
	probe.FirstByte(false)
	q.mu.Lock()
	unchanged := e.stable == ds[0]
	q.mu.Unlock()
	if !unchanged {
		t.Fatal("quality trial committed on first byte")
	}
	selected, _, _, _, other, err := g.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
	if err != nil || selected != ds[0] || other.probe {
		t.Fatal("parallel connection did not retain stable pin")
	}
	probe.Finish()
	if !e.next.After(now) {
		t.Fatal("inconclusive trial not backed off")
	}
	flow.Finish()
	other.Finish()
}
func TestQualityObserveDoesNotChangeSelection(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	g.quality = newQualityRuntime(g.Name, QualityOptions{Mode: "observe", Policy: quality.DefaultPolicy()}, g.log)
	g.hasQuality = true
	d, _, _, path, flow, err := g.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
	if err != nil || flow == nil || d != ds[0] {
		t.Fatalf("observe %v", err)
	}
	original, _, _, originalPath, err := g.SelectWithPath(TestNetworkType, true, nil, "a.example.com")
	if err != nil || d != original || path != originalPath {
		t.Fatal("observe changed selection")
	}
	flow.Finish()
}
func TestQualityLateFeedbackAfterResetCannotCommit(t *testing.T) {
	q := newQualityRuntime("g", QualityOptions{Mode: "enforce", Policy: quality.DefaultPolicy()}, nil)
	defer q.close()
	now := time.Now()
	key := qualityScope{"a.example.com", *TestNetworkType}
	q.mu.Lock()
	e := q.entry(key, now)
	e.pinned = now.Add(-time.Hour)
	f := &QualityFlow{runtime: q, key: key, record: e, probe: true, deadline: now.Add(time.Minute)}
	e.probe = f
	q.mu.Unlock()
	q.reset()
	q.mu.Lock()
	if q.commit(f, now, "test", false) {
		t.Fatal("retired feedback committed")
	}
	q.mu.Unlock()
}

func TestQualitySamplingSustainedDropAndBackpressure(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "sustained", true: "backpressure"}[blocked], func(t *testing.T) {
			g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
			defer g.Close()
			for _, d := range ds {
				defer d.Close()
			}
			q := newQualityRuntime("test", QualityOptions{Mode: "observe", Policy: quality.DefaultPolicy()}, nil)
			defer q.close()
			base := time.Now()
			key := qualityScope{"a.example.com", *TestNetworkType}
			q.mu.Lock()
			e := q.entry(key, base)
			e.stable = ds[0]
			r := &qualityRate{baseline: 1 << 20, baselineUntil: base.Add(time.Hour), flows: map[uint64]bool{}, at: base.Add(-time.Minute)}
			e.rates[ds[0]] = r
			f := &QualityFlow{runtime: q, key: key, record: e, node: ds[0], started: base.Add(-time.Minute), windowStart: base, id: 1}
			q.flows[f] = struct{}{}
			q.mu.Unlock()
			for i := 1; i <= 9; i++ {
				f.bytes.Add(5 * 100 * 1024)
				if blocked {
					f.blocked.Add(int64(4 * time.Second))
				}
				q.sample(base.Add(time.Duration(i) * 5 * time.Second))
				if i < 9 && r.severe {
					t.Fatal("transient decline became severe")
				}
			}
			if r.severe == blocked {
				t.Fatalf("severe=%v backpressure=%v", r.severe, blocked)
			}
			q.sample(base.Add(5 * time.Minute))
			if r.severe {
				t.Fatal("stale low speed retained")
			}
		})
	}
}
func TestQualityValidatedCandidateCommitsOnlyAfterTwoWindows(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	q := newQualityRuntime("test", QualityOptions{Mode: "enforce", Policy: quality.DefaultPolicy()}, nil)
	defer q.close()
	base := time.Now()
	key := qualityScope{"a.example.com", *TestNetworkType}
	q.mu.Lock()
	e := q.entry(key, base)
	e.stable = ds[0]
	e.pinned = base.Add(-10 * time.Minute)
	e.rates[ds[0]] = &qualityRate{severe: true, current: 100 * 1024, at: base, baseline: 1 << 20, baselineUntil: base.Add(time.Hour)}
	e.rates[ds[1]] = &qualityRate{baseline: 1 << 20, baselineUntil: base.Add(time.Hour), flows: map[uint64]bool{}}
	f := &QualityFlow{runtime: q, key: key, record: e, node: ds[1], probe: true, qualityProbe: true, deadline: base.Add(time.Minute), started: base.Add(-time.Minute), windowStart: base, id: 1}
	e.probe = f
	q.flows[f] = struct{}{}
	q.mu.Unlock()
	for i := 1; i <= 6; i++ {
		f.bytes.Add(5 << 20)
		q.sample(base.Add(time.Duration(i) * 5 * time.Second))
		if i < 6 && e.stable != ds[0] {
			t.Fatal("candidate committed early")
		}
	}
	if e.stable != ds[1] || e.probe != nil || len(e.switches) != 1 {
		t.Fatal("valid comparison did not commit")
	}
	f.FirstByte(false)
	if e.stable != ds[1] {
		t.Fatal("late byte changed pin")
	}
}
func TestQualityNestedFixedParentDoesNotEscape(t *testing.T) {
	child, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer child.Close()
	for _, d := range ds {
		defer d.Close()
	}
	child.Name = "child"
	child.quality = newQualityRuntime("child", QualityOptions{Mode: "enforce", Policy: quality.DefaultPolicy()}, nil)
	child.hasQuality = true
	// Reuse the fixture option from an existing leaf; the parent has no probes.
	sibling := newDirectDialer(ds[0].GlobalOption, false)
	defer sibling.Close()
	parent, err := NewNestedDialerGroup(ds[0].GlobalOption, "parent", []NestedDialerGroupMember{{Group: child}, {Dialer: sibling}}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	_, _, _, _, f, err := parent.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
	if err != nil || f == nil {
		t.Fatalf("nested selection: %v", err)
	}
	q := child.quality
	now := time.Now()
	q.mu.Lock()
	f.record.pinned = now.Add(-time.Hour)
	f.record.next = now.Add(-time.Second)
	f.record.rates[f.node] = &qualityRate{current: 1024, severe: true, at: now}
	q.mu.Unlock()
	d, _, _, path, probe, err := parent.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
	if err != nil || probe == nil || !probe.probe || path.NestedMember != "child" || !child.hasConcreteMember(d) {
		t.Fatalf("escaped fixed child: %v %s", err, path.NestedMember)
	}
	probe.Finish()
	f.Finish()
}

func BenchmarkQualitySelection(b *testing.B) {
	for _, mode := range []string{"off", "observe", "enforce"} {
		b.Run(mode, func(b *testing.B) {
			g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
			defer g.Close()
			for _, d := range ds {
				defer d.Close()
			}
			if mode != "off" {
				g.quality = newQualityRuntime("bench", QualityOptions{Mode: mode, Policy: quality.DefaultPolicy()}, nil)
				g.hasQuality = true
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, _, _, f, err := g.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
				if err != nil {
					b.Fatal(err)
				}
				f.Finish()
			}
		})
	}
}

func TestQualityCommitLogSurvivesObservationLogLimit(t *testing.T) {
	var output bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&output)
	q := newQualityRuntime("g", QualityOptions{Mode: "enforce", Policy: quality.DefaultPolicy()}, logger)
	defer q.close()
	q.mu.Lock()
	q.logAt = time.Now()
	q.logCount = 20
	q.event(qualityScope{"a.example.com", *TestNetworkType}, "insufficient_activity", nil)
	q.event(qualityScope{"a.example.com", *TestNetworkType}, "verified_throughput_improvement", nil)
	q.unlock()
	if strings.Contains(output.String(), "insufficient_activity") || !strings.Contains(output.String(), "verified_throughput_improvement") {
		t.Fatal("critical commit log was lost")
	}
}

func TestAbsoluteSpeedFloorColdStartAndHysteresis(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	q := newQualityRuntime("floor", QualityOptions{Mode: "observe", Policy: quality.DefaultPolicy(), MinDownloadBytes: 256 * 1024}, nil)
	defer q.close()
	base := time.Now()
	key := qualityScope{"download.example.com", *TestNetworkType}
	q.mu.Lock()
	e := q.entry(key, base)
	e.stable = ds[0]
	f := &QualityFlow{runtime: q, key: key, record: e, node: ds[0], started: base.Add(-time.Minute), windowStart: base, id: 1}
	q.flows[f] = struct{}{}
	q.mu.Unlock()
	tick := 0
	window := func(rate int64, blocked bool) {
		for j := 0; j < 3; j++ {
			tick++
			f.bytes.Add(5 * rate)
			if blocked {
				f.blocked.Add(int64(4 * time.Second))
			}
			q.sample(base.Add(time.Duration(tick) * 5 * time.Second))
		}
	}
	window(128*1024, false)
	window(128*1024, false)
	if e.rates[ds[0]].severe {
		t.Fatal("short low speed triggered floor")
	}
	window(128*1024, true) // interruption must discard the two low windows
	window(128*1024, false)
	window(128*1024, false)
	if e.rates[ds[0]].severe {
		t.Fatal("backpressure failed to break consecutive evidence")
	}
	window(128*1024, false)
	r := e.rates[ds[0]]
	if !r.severe || !r.absoluteSevere || r.baseline != 0 {
		t.Fatalf("cold-start floor not detected: %+v", r)
	}
	window(300*1024, false)
	window(300*1024, false)
	window(300*1024, false)
	if !r.absoluteSevere {
		t.Fatal("near-floor oscillation recovered too early")
	}
	window(384*1024, false)
	window(384*1024, false)
	if !r.absoluteSevere {
		t.Fatal("recovery needs three windows")
	}
	window(384*1024, false)
	if r.absoluteSevere || r.severe {
		t.Fatal("sustained absolute recovery ignored")
	}
}

func TestAbsoluteFloorCandidateMustClearBothRecoveryGates(t *testing.T) {
	q := &qualityRuntime{options: QualityOptions{Policy: quality.DefaultPolicy(), MinDownloadBytes: 256 * 1024}}
	for _, tc := range []struct {
		speed, baseline float64
		want            bool
	}{{300 * 1024, 0, false}, {384 * 1024, 0, true}, {400 * 1024, 1 << 20, false}, {700 * 1024, 1 << 20, true}} {
		if q.candidateRecovered(&qualityRate{baseline: tc.baseline}, tc.speed) != tc.want {
			t.Fatalf("speed %v baseline %v", tc.speed, tc.baseline)
		}
	}
	q.options.MinDownloadBytes = 0
	if q.candidateRecovered(&qualityRate{}, 1<<20) {
		t.Fatal("disabled floor invented a cold-start reference")
	}
}

func TestAbsoluteFloorIndependentOfRelativeNormalOrDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
		floor := 0.0
		if enabled {
			floor = 256 * 1024
		}
		q := newQualityRuntime("floor", QualityOptions{Mode: "observe", Policy: quality.DefaultPolicy(), MinDownloadBytes: floor}, nil)
		base := time.Now()
		key := qualityScope{"download.example.com", *TestNetworkType}
		q.mu.Lock()
		e := q.entry(key, base)
		e.stable = ds[0]
		r := &qualityRate{baseline: 64 * 1024, baselineUntil: base.Add(time.Hour), flows: map[uint64]bool{}}
		e.rates[ds[0]] = r
		f := &QualityFlow{runtime: q, key: key, record: e, node: ds[0], started: base.Add(-time.Minute), windowStart: base, id: 1}
		q.flows[f] = struct{}{}
		q.mu.Unlock()
		for i := 1; i <= 9; i++ {
			f.bytes.Add(5 * 128 * 1024)
			q.sample(base.Add(time.Duration(i) * 5 * time.Second))
		}
		if r.severe != enabled || r.relativeSevere {
			t.Fatalf("floor enabled=%v relative=%v severe=%v", enabled, r.relativeSevere, r.severe)
		}
		q.close()
		g.Close()
		for _, d := range ds {
			d.Close()
		}
	}
}

// A slow stream during bulk transfer is not independent proof of a bad node.
// Once demand subsides, fresh low-load windows must still detect the floor.
func TestQualityLoadDefersBothDirectionsThenReevaluates(t *testing.T) {
	for _, upload := range []bool{false, true} {
		g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
		q := newQualityRuntime("load", QualityOptions{Mode: "observe", Policy: quality.DefaultPolicy(), MinDownloadBytes: 64 * 1024}, nil)
		ds[0].LoadStart()
		base := time.Now()
		key := qualityScope{"download.example.com", *TestNetworkType}
		q.mu.Lock()
		e := q.entry(key, base)
		e.stable = ds[0]
		f := &QualityFlow{runtime: q, key: key, record: e, node: ds[0], started: base.Add(-time.Minute), windowStart: base, id: 1}
		q.flows[f] = struct{}{}
		q.mu.Unlock()
		tick := 0
		step := func(busy bool) {
			tick++
			f.bytes.Add(5 * 32 * 1024)
			ds[0].LoadBytes(0, 5*32*1024)
			// Concurrent traffic from other flows on the node, well above the
			// reference floors; the measured flow's own bytes are excluded.
			if busy {
				if upload {
					ds[0].LoadBytes(5*2*1024*1024, 0)
				} else {
					ds[0].LoadBytes(0, 5*8*1024*1024)
				}
			}
			q.sample(base.Add(time.Duration(tick) * 5 * time.Second))
		}
		for i := 0; i < 18; i++ {
			step(true)
		}
		r := e.rates[ds[0]]
		if r == nil || r.severe || r.absoluteLow != 0 || r.baseline != 0 {
			t.Fatalf("busy node penalized/learned as normal: %+v", r)
		}
		for i := 0; i < 24; i++ {
			step(false)
		}
		if !r.absoluteSevere {
			t.Fatalf("fresh low-load collapse was hidden: %+v", r)
		}
		ds[0].LoadFinish()
		q.close()
		g.Close()
		for _, d := range ds {
			d.Close()
		}
	}
}

// contentionHarness drives sample() with a simulated clock over one node and
// one host. Byte contributions are per flow; "external" bytes reach the node
// counters without belonging to any sampled flow.
type contentionHarness struct {
	t    *testing.T
	q    *qualityRuntime
	node *dialer.Dialer
	e    *qualityRecord
	key  qualityScope
	base time.Time
	tick int
	now  time.Time
}

func newContentionHarness(t *testing.T, node *dialer.Dialer) *contentionHarness {
	q := newQualityRuntime("aligned", QualityOptions{Mode: "observe", Policy: quality.DefaultPolicy(), MinDownloadBytes: 64 * 1024}, nil)
	node.LoadStart()
	base := time.Now()
	key := qualityScope{"download.example.com", *TestNetworkType}
	q.mu.Lock()
	e := q.entry(key, base)
	e.stable = node
	q.mu.Unlock()
	return &contentionHarness{t: t, q: q, node: node, e: e, key: key, base: base, now: base}
}
func (h *contentionHarness) close() { h.node.LoadFinish(); h.q.close() }
func (h *contentionHarness) newFlow(id uint64) *QualityFlow {
	f := &QualityFlow{runtime: h.q, key: h.key, record: h.e, node: h.node, started: h.base.Add(-time.Minute), windowStart: h.now, id: id}
	f.windowNodeUp, f.windowNodeDown, _ = h.node.LoadTotals()
	h.q.mu.Lock()
	h.q.flows[f] = struct{}{}
	h.q.mu.Unlock()
	return f
}

// step advances one 5s tick: each flow receives 5*own[i] bytes, the node
// additionally carries 5*external bytes, then sample runs once for all flows.
func (h *contentionHarness) step(external uint64, flows []*QualityFlow, own []uint64) {
	h.tick++
	var total uint64 = external
	for i, f := range flows {
		f.bytes.Add(int64(5 * own[i]))
		total += own[i]
	}
	h.node.LoadBytes(0, 5*total)
	h.now = h.base.Add(time.Duration(h.tick) * 5 * time.Second)
	h.q.sample(h.now)
}
func (h *contentionHarness) window(external uint64, flows []*QualityFlow, own ...uint64) {
	for i := 0; i < 3; i++ {
		h.step(external, flows, own)
	}
}

const (
	contentionBig   = 8 * 1024 * 1024
	contentionSmall = 32 * 1024
)

// A finished download's speed must never be subtracted from current node
// load: contention is attributed over the judged flow's own window using node
// byte totals, and the window right after an external burst is still deferred.
func TestQualityContentionIsWindowAlignedAndIgnoresFinishedFlows(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	h := newContentionHarness(t, ds[0])
	defer h.close()
	q, e := h.q, h.e
	// Phase A: one large download alone. Its own peak must not defer it, but
	// window-less callers still see the aggregate "busy".
	f1 := h.newFlow(1)
	for i := 0; i < 8; i++ {
		h.window(0, []*QualityFlow{f1}, contentionBig)
	}
	r := e.rates[ds[0]]
	if r == nil || f1.othersDeferred || r.current != float64(contentionBig) {
		t.Fatalf("lone download deferred by itself: %+v flow=%v", r, f1.othersDeferred)
	}
	if d, ok := f1.alignedDeferred(h.now, q.contentionSettle()); d || !ok {
		t.Fatal("aligned verdict should not defer a lone download")
	}
	if !q.aggregateDeferred(ds[0], h.now) {
		t.Fatal("window-less callers must keep the aggregate verdict")
	}
	// Phase B: the download ends; a small flow runs beside 8 MiB/s of other
	// traffic. The stale 8 MiB/s must not be subtracted from that traffic.
	f1.Finish()
	if _, ok := f1.alignedDeferred(h.now, q.contentionSettle()); ok {
		t.Fatal("finished flow still offers an aligned verdict")
	}
	f2 := h.newFlow(2)
	h.window(contentionBig, []*QualityFlow{f2}, contentionSmall)
	if !f2.othersDeferred || !f2.othersBusy {
		t.Fatalf("external load excused by a finished flow: deferred=%v busy=%v", f2.othersDeferred, f2.othersBusy)
	}
	// Phase C: the external burst stops. The next window is aligned settling
	// (still deferred); the one after is judged normally and the small flow's
	// absolute low speed starts counting.
	h.window(0, []*QualityFlow{f2}, contentionSmall)
	if !f2.othersDeferred || f2.othersBusy || r.absoluteLow != 0 {
		t.Fatalf("no aligned settling after external burst: %+v", r)
	}
	h.window(0, []*QualityFlow{f2}, contentionSmall)
	if f2.othersDeferred || r.absoluteLow != 1 {
		t.Fatalf("settling did not end after one quiet window: %+v", r)
	}
	f2.Finish()
}

// Two live flows on the same node and host judge contention independently:
// the large flow sees only the small one as "others" and is not deferred; the
// small flow sees the large one and is deferred. Neither borrows the other's
// verdict, and window-less callers see only the aggregate.
func TestQualityLiveFlowsDoNotBorrowAlignedVerdicts(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	h := newContentionHarness(t, ds[0])
	defer h.close()
	big, small := h.newFlow(1), h.newFlow(2)
	flows := []*QualityFlow{big, small}
	for i := 0; i < 8; i++ {
		h.window(0, flows, contentionBig, contentionSmall)
	}
	if big.othersDeferred {
		t.Fatal("large flow deferred by the small flow beside it")
	}
	if !small.othersDeferred {
		t.Fatal("small flow borrowed the large flow's not-busy verdict")
	}
	if d, ok := small.alignedDeferred(h.now, h.q.contentionSettle()); !d || !ok {
		t.Fatal("small flow's own aligned verdict must defer")
	}
	if !h.q.aggregateDeferred(ds[0], h.now) {
		t.Fatal("aggregate verdict must not be replaced by any flow's aligned result")
	}
	// A throughput commit for the small flow as a probe must be blocked by its
	// own verdict even though the large flow on the same node is clear.
	h.q.mu.Lock()
	h.e.stable = ds[1] // untracked stable: its aggregate verdict is never deferred
	h.e.probe = small
	small.probe, small.qualityProbe = true, true
	small.generation = h.e.generation
	small.deadline = h.now.Add(time.Minute)
	h.e.pinned = h.now.Add(-time.Hour)
	h.q.options.Mode = "enforce"
	d, _ := small.alignedDeferred(h.now, h.q.contentionSettle())
	committed := h.q.commit(small, h.now, "test", d)
	// Control: the same commit with a clear candidate verdict succeeds, so the
	// block above came from the flow's own verdict and nothing else.
	control := h.q.commit(small, h.now, "test", false)
	h.q.mu.Unlock()
	if committed {
		t.Fatal("commit cleared by another flow's verdict")
	}
	if !control {
		t.Fatal("control commit did not succeed; the block above is not attributable")
	}
	big.Finish()
	small.Finish()
}

// When several flows close windows in one sample after an external burst,
// the first quiet result must not cancel settling for the others: settling
// state is per flow, so sample order over the flow map cannot matter.
func TestQualitySettlingSurvivesMultipleFlowsInOneSample(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	h := newContentionHarness(t, ds[0])
	defer h.close()
	// Establish a reference peak and warm the node.
	warm := h.newFlow(1)
	for i := 0; i < 6; i++ {
		h.window(0, []*QualityFlow{warm}, contentionBig)
	}
	warm.Finish()
	// Several small flows all see the same external burst in one window.
	var flows []*QualityFlow
	var own []uint64
	for i := 0; i < 6; i++ {
		flows = append(flows, h.newFlow(uint64(10+i)))
		own = append(own, contentionSmall)
	}
	h.window(contentionBig, flows, own...)
	for i, f := range flows {
		if !f.othersDeferred {
			t.Fatalf("flow %d not deferred during external burst", i)
		}
	}
	r := h.e.rates[ds[0]]
	// The burst stops. Every flow closing in this sample must still be
	// deferred, whatever the map iteration order.
	h.window(0, flows, own...)
	for i, f := range flows {
		if !f.othersDeferred || f.othersBusy {
			t.Fatalf("flow %d lost settling because another flow closed first: %+v", i, f.othersDeferred)
		}
	}
	if r.absoluteLow != 0 {
		t.Fatalf("settling window counted as low speed: %+v", r)
	}
	// One more quiet window: settling is over for all of them.
	h.window(0, flows, own...)
	for i, f := range flows {
		if f.othersDeferred {
			t.Fatalf("flow %d still deferred after settling", i)
		}
	}
	for _, f := range flows {
		f.Finish()
	}
}

// Abandoning a probe that was never observed returns the slot without a
// failure or backoff, unlike Finish on an inconclusive probe.
func TestQualityProbeAbandonDoesNotBackOff(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	g.quality = newQualityRuntime(g.Name, QualityOptions{Mode: "enforce", Policy: quality.DefaultPolicy()}, g.log)
	g.hasQuality = true
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	_, _, _, _, flow, err := g.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
	if err != nil || flow == nil {
		t.Fatalf("initial: %v", err)
	}
	q := g.quality
	q.mu.Lock()
	e := flow.record
	e.pinned = now.Add(-6 * time.Minute)
	e.next = now.Add(-time.Second)
	e.rates[e.stable] = &qualityRate{severe: true, current: 1024, at: now}
	q.mu.Unlock()
	_, _, _, _, probe, err := g.SelectWithQuality(TestNetworkType, true, nil, "a.example.com")
	if err != nil || !probe.probe {
		t.Fatalf("trial not selected: %v", err)
	}
	next := e.next
	probe.Abandon()
	probe.Finish() // no-op after Abandon
	q.mu.Lock()
	probeSlot, failures, nextAfter := e.probe, e.failures, e.next
	_, sampled := q.flows[probe]
	q.mu.Unlock()
	if probeSlot != nil || failures != 0 || !nextAfter.Equal(next) {
		t.Fatalf("abandon recorded a failure: probe=%v failures=%d next=%v want %v", probeSlot, failures, nextAfter, next)
	}
	if sampled {
		t.Fatal("abandoned flow still sampled")
	}
	flow.Finish()
}

func TestNodeClonesShareLoadContext(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	clone := ds[0].Clone()
	defer clone.Close()
	ds[0].LoadStart()
	clone.LoadStart()
	if got := ds[0].LoadContext(time.Now()); got.Active != 2 {
		t.Fatalf("group clone load missing: %+v", got)
	}
	clone.LoadFinish()
	ds[0].LoadFinish()
	if got := clone.LoadContext(time.Now()); got.Active != 0 {
		t.Fatalf("unbalanced shared load: %+v", got)
	}
}

func TestQualityPreferredRecoveryAcceptsWarmCandidate(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	g.quality = newQualityRuntime(g.Name, QualityOptions{Mode: "enforce", Policy: quality.DefaultPolicy()}, g.log)
	g.hasQuality = true
	_, _, _, _, initial, err := g.SelectWithQuality(TestNetworkType, true, ds[0], "example.com")
	if err != nil || initial == nil {
		t.Fatalf("initial: %v", err)
	}
	defer initial.Finish()
	now := time.Now()
	q := g.quality
	q.mu.Lock()
	initial.record.pinned = now.Add(-6 * time.Minute)
	initial.record.next = now.Add(-time.Second)
	q.mu.Unlock()
	ds[0].LoadStart()
	defer ds[0].LoadFinish()
	ds[1].LoadStart()
	defer ds[1].LoadFinish()
	d, _, _, _, probe, err := g.SelectWithQuality(TestNetworkType, true, nil, "example.com")
	if err != nil || probe == nil || !probe.probe || probe.qualityProbe || d != ds[0] {
		t.Fatalf("trial: %v", err)
	}
	defer probe.Finish()
	probe.FirstByte(false)
	q.mu.Lock()
	defer q.mu.Unlock()
	if initial.record.stable != ds[0] || initial.record.failures != 0 {
		t.Fatal("warm recovery did not commit")
	}
}

func TestQualityRejectedRegistrationDoesNotRetry(t *testing.T) {
	q := newQualityRuntime("g", QualityOptions{Mode: "observe", Policy: quality.DefaultPolicy()}, nil)
	defer q.close()
	key := qualityScope{"example.com", *TestNetworkType}
	q.mu.Lock()
	e := q.entry(key, time.Now())
	for i := 0; i < 4096; i++ {
		q.flows[&QualityFlow{}] = struct{}{}
	}
	q.mu.Unlock()
	f := &QualityFlow{runtime: q, key: key, record: e}
	f.ObserveWrite(1<<20, 0)
	if !f.registrationAttempted.Load() || f.registered.Load() {
		t.Fatal("registration fixture failed")
	}
	q.mu.Lock()
	clear(q.flows)
	q.mu.Unlock()
	f.ObserveWrite(1<<20, 0)
	if f.registered.Load() || f.MeasureWrites() {
		t.Fatal("rejected flow retried registration")
	}
}

func TestRequiredSpeedRecoveryNeedsConsecutiveWindows(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	q := newQualityRuntime("g", QualityOptions{Mode: "observe", Policy: quality.DefaultPolicy(), RequiredDownloadBytes: 1 << 20}, nil)
	defer q.close()
	base := time.Now()
	key := qualityScope{"example.com", *TestNetworkType}
	q.mu.Lock()
	e := q.entry(key, base)
	r := &qualityRate{baseline: 1 << 20, baselineUntil: base.Add(time.Hour), relativeSevere: true, severe: true, at: base, flows: map[uint64]bool{}}
	e.rates[ds[0]] = r
	f := &QualityFlow{runtime: q, key: key, record: e, node: ds[0], started: base.Add(-time.Minute), windowStart: base}
	q.flows[f] = struct{}{}
	q.mu.Unlock()
	for i := 1; i <= 9; i++ {
		f.bytes.Add(5 << 20)
		q.sample(base.Add(time.Duration(i) * 5 * time.Second))
		if i < 9 && !r.relativeSevere {
			t.Fatal("one satisfied demand window cleared severe")
		}
	}
	if r.relativeSevere {
		t.Fatal("sustained recovery ignored")
	}
}

func TestQualityConcurrentSelectionsReserveSingleRecovery(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	g.quality = newQualityRuntime(g.Name, QualityOptions{Mode: "enforce", Policy: quality.DefaultPolicy()}, nil)
	g.hasQuality = true
	_, _, _, _, initial, err := g.SelectWithQuality(TestNetworkType, true, ds[0], "example.com")
	if err != nil || initial == nil {
		t.Fatal(err)
	}
	defer initial.Abandon()
	q := g.quality
	q.mu.Lock()
	initial.record.pinned = time.Now().Add(-6 * time.Minute)
	initial.record.next = time.Now().Add(-time.Second)
	q.mu.Unlock()
	results := make(chan *QualityFlow, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, _, _, _, f, err := g.SelectWithQuality(TestNetworkType, true, nil, "example.com")
			if err != nil || f == nil {
				t.Errorf("concurrent selection: %v", err)
				return
			}
			if !f.probe && d != ds[1] {
				t.Error("ordinary connection lost stable pin")
			}
			results <- f
		}()
	}
	wg.Wait()
	close(results)
	trials := 0
	for f := range results {
		if f.probe {
			trials++
		}
		f.Abandon()
	}
	if trials != 1 {
		t.Fatalf("concurrent trials: %d", trials)
	}
}
