/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStickyRecoverySingleTrialAndCommit(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	g.PinSite("api.cursor.sh", ds[1], false)
	// Historical convergence must not permanently suppress recovery. Regular
	// successful traffic must not push the recovery deadline forward either.
	e := g.siteSticky.entries["cursor.sh"]
	e.triedAlts = 2
	e.converged = true
	now = now.Add(siteStickyRecoveryAfter + time.Second)
	g.PinSite("api.cursor.sh", ds[1], false)
	var trials atomic.Int32
	var token SelectPath
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, _, _, p, err := g.SelectWithPath(TestNetworkType, true, nil, "api.cursor.sh")
			if err != nil {
				t.Error(err)
				return
			}
			if d == ds[0] {
				trials.Add(1)
				mu.Lock()
				token = p
				mu.Unlock()
			} else if d != ds[1] {
				t.Error("unexpected stable leaf")
			}
		}()
	}
	wg.Wait()
	if trials.Load() != 1 || token.recovery == nil {
		t.Fatalf("trials=%d", trials.Load())
	}
	if e.leaf != ds[1] {
		t.Fatal("selection prematurely changed stable pin")
	}
	if token.WithoutRecovery().recovery != nil {
		t.Fatal("trial leaked into snapshot key")
	}
	token.recovery.finish(true, now.Add(time.Second))
	if e.leaf != ds[0] || e.converged || e.triedAlts != 0 {
		t.Fatal("verified recovery did not commit/reset round")
	}
	token.recovery.finish(false, now.Add(2*time.Second))
	if e.leaf != ds[0] {
		t.Fatal("late close reverted successful recovery")
	}
	now = now.Add(time.Minute)
	g.PinSite("api.cursor.sh", ds[0], true)
	g.PinSite("api.cursor.sh", ds[0], true)
	if e.probeNext {
		t.Fatal("slow samples bypassed recovery dwell")
	}
}

func TestStickyRecoveryBackoffExpiryAndStaleCallbacks(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	g.PinSite("chatgpt.com", ds[1], false)
	now = now.Add(siteStickyRecoveryAfter + time.Second)
	table := g.siteSticky
	e := table.entries["chatgpt.com"]
	r := table.startRecovery("chatgpt.com", ds[1], ds[0], now, TestNetworkType)
	if r == nil {
		t.Fatal("no first trial")
	}
	r.finish(false, now)
	if e.leaf != ds[1] || e.nextRecovery != now.Add(2*time.Minute) {
		t.Fatal("failure did not retain pin/back off")
	}
	if table.startRecovery("chatgpt.com", ds[1], ds[0], now.Add(time.Minute), TestNetworkType) != nil {
		t.Fatal("premature retry")
	}
	now = e.nextRecovery
	newer := table.startRecovery("chatgpt.com", ds[1], ds[0], now, TestNetworkType)
	if newer == nil {
		t.Fatal("no retry")
	}
	r.finish(true, now)
	if e.leaf != ds[1] || e.recovery != newer {
		t.Fatal("stale success committed")
	}
	now = newer.deadline.Add(time.Second)
	newer.finish(true, now)
	if e.leaf != ds[1] || e.nextRecovery != now.Add(5*time.Minute) {
		t.Fatal("expired success committed or bad backoff")
	}
	now = e.nextRecovery
	r = table.startRecovery("chatgpt.com", ds[1], ds[0], now, TestNetworkType)
	r.finish(false, now)
	if e.nextRecovery != now.Add(10*time.Minute) {
		t.Fatal("backoff must cap at ten minutes")
	}
	now = e.nextRecovery
	r = table.startRecovery("chatgpt.com", ds[1], ds[0], now, TestNetworkType)
	table.detach()
	r.finish(true, now)
	if len(table.entries) != 0 {
		t.Fatal("retired table resurrected")
	}
}

// Failure-driven migration (FailSite then a successful pin elsewhere) is the
// real fallback escape path. It must not consume the recovery switch budget,
// otherwise one node flap across many sites locks the whole group out of
// recovering for 30 minutes.
func TestStickyFailoverDoesNotConsumeRecoveryBudget(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	table := g.siteSticky
	for i, site := range []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example", "h.example", "i.example", "j.example", "k.example"} {
		g.PinSite(site, ds[0], false)
		now = now.Add(time.Second)
		g.FailSite(site, ds[0])
		g.PinSite(site, ds[1], false)
		e := table.entries[SiteKey(site)]
		if e == nil || e.leaf != ds[1] {
			t.Fatalf("site %d: failover pin missing", i)
		}
		if len(e.recoverySwitches) != 0 {
			t.Fatalf("site %d: failover counted as a recovery switch", i)
		}
	}
	if len(table.recoverySwitches) != 0 || !table.lastRecovery.IsZero() {
		t.Fatalf("group budget consumed by failover: %d", len(table.recoverySwitches))
	}
	if !table.recoveryBudget(table.entries["a.example"], now) {
		t.Fatal("recovery budget exhausted by failure-driven migration")
	}
}

// A nested parent evaluates several children and adopts one. A recovery trial
// started while evaluating a non-adopted child never gets a connection; it
// must be released without counting as a failure or delaying the next trial.
func TestStickyRecoveryAbandonedWhenParentDoesNotAdoptChild(t *testing.T) {
	childA, dsA := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	childB, dsB := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	childA.Name, childB.Name = "child-a", "child-b"
	defer childA.Close()
	defer childB.Close()
	for _, d := range append(append([]*dialer.Dialer(nil), dsA...), dsB...) {
		defer d.Close()
	}
	// Min-latency parent with zero tolerance evaluates every child and keeps
	// the first of equal latencies.
	parent, err := NewNestedDialerGroup(dsA[0].GlobalOption, "parent", []NestedDialerGroupMember{{Group: childA}, {Group: childB}}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	now := time.Now()
	clock := func() time.Time { return now }
	parent.nowFn, childA.nowFn, childB.nowFn = clock, clock, clock
	const site = "cdn.example.com"
	childA.PinSite(site, dsA[1], false)
	childB.PinSite(site, dsB[1], false)
	now = now.Add(siteStickyRecoveryAfter + time.Second)

	d, _, _, path, err := parent.SelectWithPath(TestNetworkType, true, nil, site)
	if err != nil {
		t.Fatal(err)
	}
	eA := childA.siteSticky.entries[SiteKey(site)]
	eB := childB.siteSticky.entries[SiteKey(site)]
	if d != dsA[0] || path.recovery == nil || eA.recovery != path.recovery {
		t.Fatalf("adopted child A trial missing: d=%p recovery=%v", d, path.recovery)
	}
	if eB.recovery != nil {
		t.Fatal("non-adopted child B kept a trial slot it can never resolve")
	}
	if eB.recoveryFailures != 0 || eB.leaf != dsB[1] {
		t.Fatalf("abandoned trial recorded as failure: failures=%d", eB.recoveryFailures)
	}
	// B's trial slot is free again right away, not after the expiry backoff.
	if childB.siteSticky.startRecovery(site, dsB[1], dsB[0], now, TestNetworkType) == nil {
		t.Fatal("abandoned trial left child B in backoff")
	}
	// The adopted trial still resolves normally.
	if !path.RecoveryFirstByte(false) || eA.leaf != dsA[0] {
		t.Fatal("adopted trial did not commit")
	}
}

// A later member's hard error aborts the parent's selection. Trials taken while
// evaluating earlier members never get a connection and must be released.
func TestStickyRecoveryReleasedWhenLaterMemberErrors(t *testing.T) {
	childA, dsA := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	childA.Name = "child-a"
	defer childA.Close()
	for _, d := range dsA {
		defer d.Close()
	}
	broken := newDirectDialer(dsA[0].GlobalOption, false)
	defer broken.Close()
	childB, err := NewNestedDialerGroup(dsA[0].GlobalOption, "child-b", []NestedDialerGroupMember{{Dialer: broken}}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer childB.Close()
	// An out-of-range fixed index is a hard (non ErrNoAliveDialer) error.
	childB.SetSelectionPolicy(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 7})
	// Min-latency evaluates every member, so A's trial is taken before B's
	// hard error aborts the selection.
	parent, err := NewNestedDialerGroup(dsA[0].GlobalOption, "parent", []NestedDialerGroupMember{{Group: childA}, {Group: childB}}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	now := time.Now()
	clock := func() time.Time { return now }
	parent.nowFn, childA.nowFn = clock, clock
	const site = "assets.example.com"
	childA.PinSite(site, dsA[1], false)
	now = now.Add(siteStickyRecoveryAfter + time.Second)
	_, _, _, path, err := parent.SelectWithPath(TestNetworkType, true, nil, site)
	if err == nil || errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("expected hard error, got %v", err)
	}
	eA := childA.siteSticky.entries[SiteKey(site)]
	if path.recovery != nil || eA.recovery != nil || eA.recoveryFailures != 0 {
		t.Fatalf("trial leaked past aborted selection: %+v", eA.recovery)
	}
	if childA.siteSticky.startRecovery(site, dsA[1], dsA[0], now, TestNetworkType) == nil {
		t.Fatal("released trial left backoff behind")
	}
}

func TestStickyRecoverySwitchBudget(t *testing.T) {
	table := newSiteStickyTable()
	now := time.Now()
	e := &siteStickyEntry{recoverySwitches: []time.Time{now.Add(-20 * time.Minute), now.Add(-10 * time.Minute)}}
	if table.recoveryBudget(e, now) {
		t.Fatal("site switch budget ignored")
	}
	if !table.recoveryBudget(e, now.Add(11*time.Minute)) {
		t.Fatal("site budget never replenished")
	}
	for i := 0; i < 10; i++ {
		table.recoverySwitches = append(table.recoverySwitches, now)
	}
	if table.recoveryBudget(&siteStickyEntry{}, now) {
		t.Fatal("group switch budget ignored")
	}
}

func TestStickyRecoveryWithWarmCandidateAndBusyStable(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	g.PinSite("example.com", ds[1], false)
	e := g.siteSticky.entries["example.com"]
	e.pinnedAt = now.Add(-6 * time.Minute)
	e.nextRecovery = now.Add(-time.Second)
	for i := 0; i < 64; i++ {
		ds[1].LoadStart()
		defer ds[1].LoadFinish()
	}
	ds[1].LoadBytes(0, 6*3*1024*1024)
	if load := ds[1].LoadContext(now.Add(6 * time.Second)); load.Class != "busy" {
		t.Fatalf("stable fixture: %+v", load)
	}
	ds[0].LoadStart()
	defer ds[0].LoadFinish()
	if load := ds[0].LoadContext(time.Now()); load.Class != "warming_up" {
		t.Fatalf("candidate fixture: %+v", load)
	}
	d, _, _, path, err := g.SelectWithPath(TestNetworkType, true, nil, "example.com")
	if err != nil || d != ds[0] || path.recovery == nil {
		t.Fatalf("recovery blocked by load: %v", err)
	}
	if !path.RecoveryFirstByte(false) || e.leaf != ds[0] || e.recoveryFailures != 0 {
		t.Fatal("first use could not recover")
	}
}

func TestPinSiteUpdatesBusyLeafWithoutSlowEvidence(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	g.PinSite("example.com", ds[0], false)
	e := g.siteSticky.entries["example.com"]
	e.pinnedAt = now.Add(-time.Minute)
	ds[1].LoadStart()
	defer ds[1].LoadFinish()
	g.PinSite("example.com", ds[1], true)
	if e.leaf != ds[1] || e.consecutiveSlow != 0 || len(e.recoverySwitches) != 0 || len(g.siteSticky.recoverySwitches) != 0 {
		t.Fatalf("successful failover not recorded: %+v", e)
	}
}

func TestStickyRecoveryBudgetContentionDoesNotBackOff(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	g.PinSite("example.com", ds[1], false)
	e := g.siteSticky.entries["example.com"]
	e.nextRecovery = now.Add(-time.Second)
	r := g.siteSticky.startRecovery("example.com", ds[1], ds[0], now, TestNetworkType)
	if r == nil {
		t.Fatal("trial missing")
	}
	g.siteSticky.lastRecovery = now
	r.finish(true, now.Add(time.Second))
	if e.recoveryFailures != 0 || e.recovery != nil || e.leaf != ds[1] || e.nextRecovery.After(now.Add(10*time.Second)) {
		t.Fatal("budget race treated as candidate failure")
	}
}

func TestUDPReclaimAndCallbacksLeaveTCPRecoveryIntact(t *testing.T) {
	g, ds := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range ds {
		defer d.Close()
	}
	now := time.Now()
	g.nowFn = func() time.Time { return now }
	g.PinSite("example.com", ds[1], false)
	tcp := g.siteSticky.entries["example.com"]
	tcp.nextRecovery = now.Add(-time.Second)
	r := g.siteSticky.startRecovery("example.com", ds[1], ds[0], now, TestNetworkType)
	if r == nil {
		t.Fatal("TCP trial missing")
	}
	udp := *TestNetworkType
	udp.L4Proto = consts.L4ProtoStr_UDP
	g.siteStickyUDP.pin("example.com", ds[1], now.Add(-3*time.Minute), false, nil)
	d, _, _, path, err := g.SelectWithPath(&udp, true, nil, "example.com")
	if err != nil || d != ds[0] {
		t.Fatalf("UDP reclaim: %v", err)
	}
	g.SnapshotForEstablishedFlowPath(d, path).PinSite("example.com", d, false)
	if tcp.leaf != ds[1] || tcp.recovery != r || tcp.recoveryFailures != 0 {
		t.Fatal("UDP changed TCP recovery")
	}
	r.finish(true, now.Add(time.Second))
	if tcp.leaf != ds[0] {
		t.Fatal("TCP recovery was invalidated")
	}
}
