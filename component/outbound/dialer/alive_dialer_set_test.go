/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func TestAliveDialerSet_GetRandExcludedConcurrent(t *testing.T) {
	networkType := newTestNetworkType()
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
		newNamedTestDialer(t, "dialer-3"),
	}

	set := NewAliveDialerSet(
		dialers[0].Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		[]*Annotation{{}, {}, {}},
		func(bool) {},
		true,
	)
	for _, d := range dialers {
		d.RegisterAliveDialerSet(set)
	}
	t.Cleanup(func() {
		for _, d := range dialers {
			d.UnregisterAliveDialerSet(set)
		}
	})

	excluded := dialers[0]
	errCh := make(chan error, 32)
	var wg sync.WaitGroup

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				selected := set.GetRandExcluded(excluded)
				if selected == nil {
					errCh <- fmt.Errorf("GetRandExcluded returned nil")
					return
				}
				if selected == excluded {
					errCh <- fmt.Errorf("GetRandExcluded returned the excluded dialer")
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

func TestAliveDialerSet_RandomNotifiesZeroBoundary(t *testing.T) {
	networkType := newTestNetworkType()
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
	}
	var notifies int
	set := NewAliveDialerSet(
		dialers[0].Log,
		"random-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		[]*Annotation{{}, {}},
		func(bool) { notifies++ },
		true,
	)
	if notifies != 0 {
		t.Fatalf("init notifies = %d, want 0", notifies)
	}

	set.NotifyLatencyChange(dialers[0], false)
	if notifies != 0 {
		t.Fatalf("2→1 notifies = %d, want 0", notifies)
	}
	set.NotifyLatencyChange(dialers[1], false)
	if notifies != 1 {
		t.Fatalf("1→0 notifies = %d, want 1", notifies)
	}
	set.NotifyLatencyChange(dialers[0], true)
	if notifies != 2 {
		t.Fatalf("0→1 notifies = %d, want 2", notifies)
	}
	set.NotifyLatencyChange(dialers[1], true)
	if notifies != 2 {
		t.Fatalf("1→2 notifies = %d, want 2", notifies)
	}
}

func TestAliveDialerSet_MinNotifiesLatencySampleWithoutBestChange(t *testing.T) {
	networkType := newTestNetworkType()
	best := newNamedTestDialer(t, "best")
	other := newNamedTestDialer(t, "other")
	dialers := []*Dialer{best, other}
	var notifies int
	set := NewAliveDialerSet(
		best.Log,
		"min-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		dialers,
		[]*Annotation{{}, {}},
		func(bool) { notifies++ },
		true,
	)
	best.MustGetLatencies10(networkType).AppendLatency(time.Millisecond)
	other.MustGetLatencies10(networkType).AppendLatency(100 * time.Millisecond)
	set.NotifyLatencyChange(best, true)
	set.NotifyLatencyChange(other, true)
	if got, _ := set.GetMinLatency(nil); got != best {
		t.Fatalf("flat best = %v, want %v", got, best)
	}
	before := notifies
	other.MustGetLatencies10(networkType).AppendLatency(50 * time.Millisecond)
	set.NotifyLatencyChange(other, true)
	if got, _ := set.GetMinLatency(nil); got != best {
		t.Fatalf("flat best changed to %v, want %v", got, best)
	}
	if notifies == before {
		t.Fatal("min must notify on a latency sample even when the flat best pointer is unchanged")
	}
}

func TestAliveDialerSetUrlTestSelectRefreshesDecayedPenalty(t *testing.T) {
	networkType := newTestNetworkType()
	fast := newNamedTestDialer(t, "fast")
	slow := newNamedTestDialer(t, "slow")
	set := NewAliveDialerSet(
		fast.Log,
		"url-test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_UrlTest,
		[]*Dialer{fast, slow},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	fast.MustGetLatencies10(networkType).AppendLatency(10 * time.Millisecond)
	slow.MustGetLatencies10(networkType).AppendLatency(50 * time.Millisecond)

	idx := networkType.Index()
	fast.health.mu.Lock()
	fast.health.slots[idx].penaltyLevel = 8
	fast.health.slots[idx].lastPenaltyAt = time.Now()
	fast.health.mu.Unlock()

	set.NotifyLatencyChange(fast, true)
	set.NotifyLatencyChange(slow, true)
	if got, _ := set.GetMinLatency(nil); got != slow {
		t.Fatalf("cached url_test winner = %p, want penalized-slow %p", got, slow)
	}

	fast.health.mu.Lock()
	fast.health.slots[idx].lastPenaltyAt = time.Now().Add(-10 * nodeHealthPenaltyHalfLife)
	fast.health.mu.Unlock()
	if got, _ := set.GetMinLatency(nil); got != fast {
		t.Fatalf("live url_test winner = %p, want decayed-fast %p", got, fast)
	}
}

func TestAliveDialerSetUrlTestSelectsAdmittedWithoutSamples(t *testing.T) {
	networkType := newTestNetworkType()
	first := newNamedTestDialer(t, "first")
	second := newNamedTestDialer(t, "second")
	set := NewAliveDialerSet(
		first.Log,
		"url-test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_UrlTest,
		[]*Dialer{first, second},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	got, _ := set.GetMinLatency(nil)
	if got == nil {
		t.Fatal("url_test with admitted unscored dialers must still select one")
	}
	if got != first {
		t.Fatalf("cold url_test winner = %p, want first admitted %p", got, first)
	}
}

func TestAliveDialerSetUrlTestSelectHonorsCheckTolerance(t *testing.T) {
	networkType := newTestNetworkType()
	incumbent := newNamedTestDialer(t, "incumbent")
	challenger := newNamedTestDialer(t, "challenger")
	incumbent.MustGetLatencies10(networkType).AppendLatency(50 * time.Millisecond)
	challenger.MustGetLatencies10(networkType).AppendLatency(40 * time.Millisecond)
	set := NewAliveDialerSet(
		incumbent.Log,
		"url-test-group",
		networkType,
		20*time.Millisecond,
		consts.DialerSelectionPolicy_UrlTest,
		[]*Dialer{incumbent, challenger},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	if got, _ := set.GetMinLatency(nil); got != incumbent {
		t.Fatalf("url_test within check_tolerance winner = %p, want incumbent %p", got, incumbent)
	}
}

func TestLatencyBeatsIncumbent(t *testing.T) {
	if LatencyBeatsIncumbent(5*time.Millisecond, 10*time.Millisecond, 20*time.Millisecond) {
		t.Fatal("5ms must not beat 10ms when tolerance is 20ms")
	}
	if !LatencyBeatsIncumbent(20*time.Millisecond, 50*time.Millisecond, 20*time.Millisecond) {
		t.Fatal("20ms must beat 50ms when tolerance is 20ms")
	}
	nearMax := time.Duration(1<<63 - 1)
	if LatencyBeatsIncumbent(nearMax-5, nearMax, 10) {
		t.Fatal("delta 5 must not beat tolerance 10 near MaxInt64")
	}
	if !LatencyBeatsIncumbent(time.Duration(math.MinInt64), time.Duration(math.MaxInt64), 10) {
		t.Fatal("MinInt64 must beat MaxInt64 without overflowing subtraction")
	}
}

func TestAliveDialerSetUrlTestKeepsReturnedIncumbentAfterPenaltyClears(t *testing.T) {
	networkType := newTestNetworkType()
	incumbent := newNamedTestDialer(t, "cached-incumbent")
	challenger := newNamedTestDialer(t, "live-winner")
	incumbent.MustGetLatencies10(networkType).AppendLatency(50 * time.Millisecond)
	challenger.MustGetLatencies10(networkType).AppendLatency(40 * time.Millisecond)
	set := NewAliveDialerSet(
		incumbent.Log,
		"url-test-returned",
		networkType,
		20*time.Millisecond,
		consts.DialerSelectionPolicy_UrlTest,
		[]*Dialer{incumbent, challenger},
		[]*Annotation{{}, {}},
		func(bool) {},
		true,
	)
	if got, _ := set.GetMinLatency(nil); got != incumbent {
		t.Fatalf("initial winner = %p, want cached incumbent %p", got, incumbent)
	}

	now := time.Now()
	incumbent.health.observeFailure(networkType.Index(), now)
	if got, _ := set.GetMinLatency(nil); got != challenger {
		t.Fatalf("after incumbent penalty winner = %p, want challenger %p", got, challenger)
	}

	now = now.Add(time.Second)
	incumbent.health.observeProbe(networkType.Index(), true, 50*time.Millisecond, now)
	now = now.Add(time.Second)
	incumbent.health.observeProbe(networkType.Index(), true, 50*time.Millisecond, now)
	if got, _ := set.GetMinLatency(nil); got != challenger {
		t.Fatalf("after penalty cleared winner = %p, want returned incumbent %p", got, challenger)
	}
}
