package ruleprovider

import (
	"context"
	"errors"
	"sync"
	"time"
)

// RefreshLifecycleConfig configures a reusable refresh and staged-reload
// lifecycle. The callbacks are deliberately injected so this coordinator stays
// independent of provider storage and any control-plane implementation.
type RefreshLifecycleConfig struct {
	Interval time.Duration
	Refresh  func(context.Context) (RefreshReport, error)
	Reload   func(context.Context) error
	OnError  func(error)
}

// RefreshLifecycle coordinates refresh rounds and optional periodic execution.
type RefreshLifecycle struct {
	interval time.Duration
	refresh  func(context.Context) (RefreshReport, error)
	reload   func(context.Context) error
	onError  func(error)

	mu    sync.Mutex
	round *refreshLifecycleRound
}

type refreshLifecycleRound struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	report  RefreshReport
	err     error
	waiters int
}

// NewRefreshLifecycle constructs a refresh coordinator. A zero interval leaves
// explicit Refresh calls available while disabling periodic execution in Run.
func NewRefreshLifecycle(config RefreshLifecycleConfig) (*RefreshLifecycle, error) {
	if config.Interval < 0 {
		return nil, errors.New("rule provider refresh interval must not be negative")
	}
	if config.Refresh == nil {
		return nil, errors.New("rule provider refresh callback is required")
	}
	if config.Reload == nil {
		config.Reload = func(context.Context) error { return nil }
	}
	if config.OnError == nil {
		config.OnError = func(error) {}
	}

	return &RefreshLifecycle{
		interval: config.Interval,
		refresh:  config.Refresh,
		reload:   config.Reload,
		onError:  config.OnError,
	}, nil
}

// Refresh runs, or joins, one refresh round. Each caller may stop waiting using
// its own context without interrupting a round that still has other waiters.
func (l *RefreshLifecycle) Refresh(ctx context.Context) (RefreshReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	round := l.joinRound()
	select {
	case <-round.done:
		l.leaveRound(round)
		if err := ctx.Err(); err != nil {
			return RefreshReport{}, err
		}
		return round.report, round.err
	case <-ctx.Done():
		l.leaveRound(round)
		return RefreshReport{}, ctx.Err()
	}
}

// Run executes refresh rounds on the configured interval until its context is
// canceled. Periodic refresh failures are reported and do not stop later ticks.
func (l *RefreshLifecycle) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if l.interval == 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_, err := l.Refresh(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				l.onError(err)
			}
		}
	}
}

func (l *RefreshLifecycle) joinRound() *refreshLifecycleRound {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.round == nil {
		operationCtx, cancel := context.WithCancel(context.Background())
		l.round = &refreshLifecycleRound{
			ctx:    operationCtx,
			cancel: cancel,
			done:   make(chan struct{}),
		}
		go l.runRound(l.round)
	}
	l.round.waiters++
	return l.round
}

func (l *RefreshLifecycle) leaveRound(round *refreshLifecycleRound) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.round != round {
		return
	}
	round.waiters--
	if round.waiters == 0 {
		round.cancel()
	}
}

func (l *RefreshLifecycle) runRound(round *refreshLifecycleRound) {
	report, err := l.refresh(round.ctx)
	if err == nil && report.Changed {
		err = l.reload(round.ctx)
	}

	l.mu.Lock()
	round.report = report
	round.err = err
	if l.round == round {
		l.round = nil
	}
	close(round.done)
	l.mu.Unlock()

	round.cancel()
}
