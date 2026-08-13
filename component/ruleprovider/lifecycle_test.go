package ruleprovider

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const refreshLifecycleTestTimeout = 2 * time.Second

type refreshLifecycleResult struct {
	report RefreshReport
	err    error
}

type refreshLifecycleJoinSignalContext struct {
	context.Context
	joined chan<- struct{}
	once   sync.Once
}

func (c *refreshLifecycleJoinSignalContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.joined) })
	return c.Context.Done()
}

func waitRefreshLifecycleSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()

	timer := time.NewTimer(refreshLifecycleTestTimeout)
	defer timer.Stop()
	select {
	case <-signal:
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitRefreshLifecycleResult(t *testing.T, results <-chan refreshLifecycleResult, description string) refreshLifecycleResult {
	t.Helper()

	timer := time.NewTimer(refreshLifecycleTestTimeout)
	defer timer.Stop()
	select {
	case result := <-results:
		return result
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", description)
		return refreshLifecycleResult{}
	}
}

func waitRefreshLifecycleError(t *testing.T, errorCh <-chan error, want error, description string) {
	t.Helper()

	timer := time.NewTimer(refreshLifecycleTestTimeout)
	defer timer.Stop()
	select {
	case got := <-errorCh:
		if !errors.Is(got, want) {
			t.Fatalf("%s error = %v, want errors.Is(..., %v)", description, got, want)
		}
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestRefreshLifecycleRejectsNegativeInterval(t *testing.T) {
	_, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Interval: -time.Nanosecond,
		Refresh: func(context.Context) (RefreshReport, error) {
			return RefreshReport{}, nil
		},
		Reload: func(context.Context) error {
			return nil
		},
		OnError: func(error) {},
	})
	if err == nil {
		t.Fatal("NewRefreshLifecycle() error = nil, want negative interval rejection")
	}
}

func TestRefreshLifecycleChangedTriggersReload(t *testing.T) {
	var refreshCalls atomic.Int32
	var reloadCalls atomic.Int32
	wantReport := RefreshReport{Changed: true}

	lifecycle, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Refresh: func(context.Context) (RefreshReport, error) {
			refreshCalls.Add(1)
			return wantReport, nil
		},
		Reload: func(context.Context) error {
			reloadCalls.Add(1)
			return nil
		},
		OnError: func(error) {},
	})
	if err != nil {
		t.Fatalf("NewRefreshLifecycle() error = %v", err)
	}

	gotReport, err := lifecycle.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if gotReport != wantReport {
		t.Fatalf("Refresh() report = %#v, want %#v", gotReport, wantReport)
	}
	if got := refreshCalls.Load(); got != 1 {
		t.Fatalf("Refresh callback calls = %d, want 1", got)
	}
	if got := reloadCalls.Load(); got != 1 {
		t.Fatalf("Reload callback calls = %d, want 1 for Changed report", got)
	}
}

func TestRefreshLifecycleUsedLastGoodDoesNotTriggerReload(t *testing.T) {
	var reloadCalls atomic.Int32
	wantReport := RefreshReport{UsedLastGood: true}

	lifecycle, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Refresh: func(context.Context) (RefreshReport, error) {
			return wantReport, nil
		},
		Reload: func(context.Context) error {
			reloadCalls.Add(1)
			return nil
		},
		OnError: func(error) {},
	})
	if err != nil {
		t.Fatalf("NewRefreshLifecycle() error = %v", err)
	}

	gotReport, err := lifecycle.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if gotReport != wantReport {
		t.Fatalf("Refresh() report = %#v, want %#v", gotReport, wantReport)
	}
	if got := reloadCalls.Load(); got != 0 {
		t.Fatalf("Reload callback calls = %d, want 0 for unchanged last-good report", got)
	}
}

func TestRefreshLifecycleConcurrentRefreshesUseSingleFlight(t *testing.T) {
	const waiterCount = 4

	var refreshCalls atomic.Int32
	var reloadCalls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var startOnce sync.Once
	wantReport := RefreshReport{Changed: true}

	lifecycle, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Refresh: func(ctx context.Context) (RefreshReport, error) {
			if refreshCalls.Add(1) == 1 {
				startOnce.Do(func() { close(refreshStarted) })
				select {
				case <-releaseRefresh:
				case <-ctx.Done():
					return RefreshReport{}, ctx.Err()
				}
			}
			return wantReport, nil
		},
		Reload: func(context.Context) error {
			reloadCalls.Add(1)
			return nil
		},
		OnError: func(error) {},
	})
	if err != nil {
		t.Fatalf("NewRefreshLifecycle() error = %v", err)
	}

	results := make(chan refreshLifecycleResult, waiterCount)
	go func() {
		report, err := lifecycle.Refresh(context.Background())
		results <- refreshLifecycleResult{report: report, err: err}
	}()
	waitRefreshLifecycleSignal(t, refreshStarted, "first Refresh callback")

	ready := make(chan struct{}, waiterCount-1)
	for i := 0; i < waiterCount-1; i++ {
		go func() {
			ready <- struct{}{}
			report, err := lifecycle.Refresh(context.Background())
			results <- refreshLifecycleResult{report: report, err: err}
		}()
	}
	for i := 0; i < waiterCount-1; i++ {
		waitRefreshLifecycleSignal(t, ready, "concurrent Refresh waiter launch")
	}
	// Give each launched waiter a scheduling opportunity to join the blocked
	// round before allowing its callback to complete.
	for i := 0; i < waiterCount; i++ {
		runtime.Gosched()
	}
	close(releaseRefresh)

	for i := 0; i < waiterCount; i++ {
		result := waitRefreshLifecycleResult(t, results, "single-flight Refresh result")
		if result.err != nil {
			t.Fatalf("single-flight Refresh() error = %v", result.err)
		}
		if result.report != wantReport {
			t.Fatalf("single-flight Refresh() report = %#v, want %#v", result.report, wantReport)
		}
	}
	if got := refreshCalls.Load(); got != 1 {
		t.Fatalf("Refresh callback calls = %d, want 1 for one shared round", got)
	}
	if got := reloadCalls.Load(); got != 1 {
		t.Fatalf("Reload callback calls = %d, want 1 for one shared round", got)
	}
}

func TestRefreshLifecycleCanceledWaiterDoesNotCancelSharedRefresh(t *testing.T) {
	var refreshCalls atomic.Int32
	var reloadCalls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var startOnce sync.Once
	wantReport := RefreshReport{Changed: true}

	lifecycle, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Refresh: func(ctx context.Context) (RefreshReport, error) {
			refreshCalls.Add(1)
			startOnce.Do(func() { close(refreshStarted) })
			select {
			case <-releaseRefresh:
				return wantReport, nil
			case <-ctx.Done():
				return RefreshReport{}, ctx.Err()
			}
		},
		Reload: func(context.Context) error {
			reloadCalls.Add(1)
			return nil
		},
		OnError: func(error) {},
	})
	if err != nil {
		t.Fatalf("NewRefreshLifecycle() error = %v", err)
	}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	secondJoined := make(chan struct{})
	secondCtx := &refreshLifecycleJoinSignalContext{
		Context: context.Background(),
		joined:  secondJoined,
	}
	firstResult := make(chan refreshLifecycleResult, 1)
	secondResult := make(chan refreshLifecycleResult, 1)
	go func() {
		report, err := lifecycle.Refresh(firstCtx)
		firstResult <- refreshLifecycleResult{report: report, err: err}
	}()
	waitRefreshLifecycleSignal(t, refreshStarted, "shared Refresh callback")

	go func() {
		report, err := lifecycle.Refresh(secondCtx)
		secondResult <- refreshLifecycleResult{report: report, err: err}
	}()
	waitRefreshLifecycleSignal(t, secondJoined, "second Refresh waiter joined shared round")

	cancelFirst()
	first := waitRefreshLifecycleResult(t, firstResult, "canceled waiter result")
	if !errors.Is(first.err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want context.Canceled", first.err)
	}

	close(releaseRefresh)
	second := waitRefreshLifecycleResult(t, secondResult, "uncanceled waiter result")
	if second.err != nil {
		t.Fatalf("uncanceled waiter error = %v", second.err)
	}
	if second.report != wantReport {
		t.Fatalf("uncanceled waiter report = %#v, want %#v", second.report, wantReport)
	}
	if got := refreshCalls.Load(); got != 1 {
		t.Fatalf("Refresh callback calls = %d, want 1 for shared round", got)
	}
	if got := reloadCalls.Load(); got != 1 {
		t.Fatalf("Reload callback calls = %d, want 1 for shared round", got)
	}
}

func TestRefreshLifecycleRunContinuesAfterPeriodicError(t *testing.T) {
	periodicErr := errors.New("periodic refresh failed")
	var refreshCalls atomic.Int32
	var reloadCalls atomic.Int32
	firstSuccess := make(chan struct{})
	periodicErrorAttempt := make(chan struct{})
	recoveryAttempt := make(chan struct{})
	var recoveryOnce sync.Once
	periodicErrors := make(chan error, 4)

	lifecycle, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Interval: 10 * time.Millisecond,
		Refresh: func(context.Context) (RefreshReport, error) {
			switch refreshCalls.Add(1) {
			case 1:
				close(firstSuccess)
				return RefreshReport{Changed: true}, nil
			case 2:
				close(periodicErrorAttempt)
				return RefreshReport{}, periodicErr
			default:
				recoveryOnce.Do(func() { close(recoveryAttempt) })
				return RefreshReport{}, nil
			}
		},
		Reload: func(context.Context) error {
			reloadCalls.Add(1)
			return nil
		},
		OnError: func(err error) {
			periodicErrors <- err
		},
	})
	if err != nil {
		t.Fatalf("NewRefreshLifecycle() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- lifecycle.Run(ctx) }()

	waitRefreshLifecycleSignal(t, firstSuccess, "first successful interval refresh")
	waitRefreshLifecycleSignal(t, periodicErrorAttempt, "periodic error refresh")
	waitRefreshLifecycleError(t, periodicErrors, periodicErr, "periodic OnError notification")
	waitRefreshLifecycleSignal(t, recoveryAttempt, "refresh after periodic error")

	cancel()
	timer := time.NewTimer(refreshLifecycleTestTimeout)
	defer timer.Stop()
	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Run() error = %v, want shutdown context cancellation", runErr)
		}
	case <-timer.C:
		t.Fatal("timed out waiting for Run() after shutdown")
	}
	if got := reloadCalls.Load(); got != 1 {
		t.Fatalf("Reload callback calls = %d, want one call for the initial changed snapshot", got)
	}
}

func TestRefreshLifecycleRunReportsReloadError(t *testing.T) {
	reloadErr := errors.New("staged reload failed")
	reloadErrors := make(chan error, 1)
	refreshStarted := make(chan struct{})
	var refreshOnce sync.Once
	var refreshCalls atomic.Int32
	var reloadCalls atomic.Int32

	lifecycle, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Interval: 10 * time.Millisecond,
		Refresh: func(context.Context) (RefreshReport, error) {
			if refreshCalls.Add(1) == 1 {
				refreshOnce.Do(func() { close(refreshStarted) })
				return RefreshReport{Changed: true}, nil
			}
			return RefreshReport{}, nil
		},
		Reload: func(context.Context) error {
			reloadCalls.Add(1)
			return reloadErr
		},
		OnError: func(err error) {
			reloadErrors <- err
		},
	})
	if err != nil {
		t.Fatalf("NewRefreshLifecycle() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- lifecycle.Run(ctx) }()

	waitRefreshLifecycleSignal(t, refreshStarted, "reload-error refresh")
	waitRefreshLifecycleError(t, reloadErrors, reloadErr, "reload OnError notification")
	cancel()

	timer := time.NewTimer(refreshLifecycleTestTimeout)
	defer timer.Stop()
	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Run() error = %v, want shutdown context cancellation", runErr)
		}
	case <-timer.C:
		t.Fatal("timed out waiting for Run() after reload error shutdown")
	}
	if got := reloadCalls.Load(); got != 1 {
		t.Fatalf("Reload callback calls = %d, want 1", got)
	}
}

func TestRefreshLifecycleRunWithZeroIntervalWaitsForShutdown(t *testing.T) {
	var refreshCalls atomic.Int32

	lifecycle, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Interval: 0,
		Refresh: func(context.Context) (RefreshReport, error) {
			refreshCalls.Add(1)
			return RefreshReport{}, nil
		},
		Reload: func(context.Context) error {
			return nil
		},
		OnError: func(error) {},
	})
	if err != nil {
		t.Fatalf("NewRefreshLifecycle() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- lifecycle.Run(ctx) }()

	noRefreshTimer := time.NewTimer(50 * time.Millisecond)
	select {
	case <-noRefreshTimer.C:
	case <-runDone:
		noRefreshTimer.Stop()
		t.Fatal("Run() returned before zero-interval shutdown")
	}
	if got := refreshCalls.Load(); got != 0 {
		t.Fatalf("Refresh callback calls = %d, want 0 for zero interval", got)
	}

	cancel()
	timer := time.NewTimer(refreshLifecycleTestTimeout)
	defer timer.Stop()
	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Run() error = %v, want shutdown context cancellation", runErr)
		}
	case <-timer.C:
		t.Fatal("timed out waiting for zero-interval Run() shutdown")
	}
}

func TestRefreshLifecycleRunCancelsInFlightRefreshOnShutdown(t *testing.T) {
	refreshStarted := make(chan struct{})
	refreshCanceled := make(chan struct{})
	refreshDone := make(chan struct{})
	var startOnce sync.Once
	var cancelOnce sync.Once

	lifecycle, err := NewRefreshLifecycle(RefreshLifecycleConfig{
		Interval: 10 * time.Millisecond,
		Refresh: func(ctx context.Context) (RefreshReport, error) {
			startOnce.Do(func() { close(refreshStarted) })
			defer close(refreshDone)
			select {
			case <-ctx.Done():
				cancelOnce.Do(func() { close(refreshCanceled) })
				return RefreshReport{}, ctx.Err()
			}
		},
		Reload: func(context.Context) error {
			return nil
		},
		OnError: func(error) {},
	})
	if err != nil {
		t.Fatalf("NewRefreshLifecycle() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- lifecycle.Run(ctx) }()
	waitRefreshLifecycleSignal(t, refreshStarted, "in-flight Refresh callback")

	cancel()
	waitRefreshLifecycleSignal(t, refreshCanceled, "in-flight Refresh context cancellation")
	waitRefreshLifecycleSignal(t, refreshDone, "in-flight Refresh callback completion")

	timer := time.NewTimer(refreshLifecycleTestTimeout)
	defer timer.Stop()
	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Run() error = %v, want shutdown context cancellation", runErr)
		}
	case <-timer.C:
		t.Fatal("timed out waiting for in-flight Run() shutdown")
	}
}
