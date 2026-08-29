/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

const (
	// relayHalfCloseTimeout bounds how long a half-closed TCP relay waits
	// for the peer after CloseWrite. 0 disables the bound: production must
	// not cut a server that still has data to send tens of seconds after the
	// client finished. Reload still cancels via ctx. Tests may set
	// halfCloseTimeout > 0 on a relayCore.
	relayHalfCloseTimeout = time.Duration(0)
	// relayIdleTimeout is the optional application-idle bound used only when
	// a relayCore sets idleTimeout > 0 (tests). Production idleTimeout is 0:
	// vanished TCP peers are reaped by kernel keepalive, not this watchdog.
	relayIdleTimeout = 5 * time.Minute
	// relayIdleCheckInterval is the watchdog cadence for idle reclamation.
	relayIdleCheckInterval = 30 * time.Second
)

type relayCore struct {
	left  netproxy.Conn
	right netproxy.Conn

	copyEngine       relayCopyEngine
	halfCloseTimeout time.Duration
	idleTimeout      time.Duration
	idleCheckPeriod  time.Duration
	leftRecord       func(int64)
	rightRecord      func(int64)

	// lastActiveNano is the last time either direction read or wrote data.
	// Guarded by atomic; updated by the copy engines via onActive.
	lastActiveNano atomic.Int64
}

type relayDirection struct {
	name   string
	src    netproxy.Conn
	dst    netproxy.Conn
	record func(int64)
}

type relayResult struct {
	dir string
	err error
}

func newRelayCore(lConn, rConn netproxy.Conn, engine relayCopyEngine, leftRecord func(int64), rightRecord func(int64)) *relayCore {
	return &relayCore{
		left:             lConn,
		right:            rConn,
		copyEngine:       engine,
		halfCloseTimeout: relayHalfCloseTimeout,
		idleTimeout:      0, // 0 disables application-idle force-close
		idleCheckPeriod:  relayIdleCheckInterval,
		leftRecord:       leftRecord,
		rightRecord:      rightRecord,
	}
}

func (c *relayCore) run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	defer close(watchDone)
	defer cancel()

	results := make(chan relayResult, 2)
	var forceCloseOnce sync.Once

	// nudgeReads repeatedly pokes SetReadDeadline on both conns. quic-go
	// (hy2/tuic) may not synchronously unblock a Read after a single
	// SetReadDeadline + Close: the blocked goroutine can remain parked in
	// an internal channel receive. Repeatedly advancing the deadline gives
	// the runtime additional wake-up opportunities without harming already-
	// closed conns (SetReadDeadline on a closed conn returns an error we
	// ignore). TCP conns unblock on the very first nudge, so the loop is
	// a no-op for them thereafter.
	nudgeReads := func() {
		past := time.Unix(1, 0)
		_ = c.left.SetReadDeadline(past)
		_ = c.right.SetReadDeadline(past)
	}

	forceClose := func() {
		forceCloseOnce.Do(func() {
			nudgeReads()
			_ = c.left.Close()
			_ = c.right.Close()
		})
	}

	go func() {
		select {
		case <-ctx.Done():
			forceClose()
		case <-watchDone:
		}
	}()

	// The watchdog stays alive after ctx cancel so quic-go (hy2/tuic) Reads
	// that ignore a single SetReadDeadline/Close still get repeated nudges.
	// Application-idle force-close is optional (idleTimeout > 0); production
	// leaves it off and relies on kernel TCP keepalive.
	c.lastActiveNano.Store(time.Now().UnixNano())
	idleTimeout := c.idleTimeout
	checkPeriod := c.idleCheckPeriod
	if checkPeriod <= 0 {
		checkPeriod = relayIdleCheckInterval
	}
	go func() {
		ctxCanceled := false
		ticker := time.NewTicker(checkPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ctx.Done():
				// ctx was canceled (e.g. reload retired the generation).
				// forceClose was already called by the ctx-watcher, but for
				// QUIC streams the blocked Read may not have woken up yet.
				// Switch to nudge mode: keep poking SetReadDeadline until the
				// relay finishes (watchDone), giving quic-go repeated chances
				// to unblock the parked goroutine.
				ctxCanceled = true
			case <-ticker.C:
				if ctxCanceled {
					// Keep nudging after cancellation — quic-go may need
					// multiple deadline pokes to unblock a parked Read.
					nudgeReads()
					continue
				}
				if idleTimeout > 0 && time.Since(time.Unix(0, c.lastActiveNano.Load())) > idleTimeout {
					// Idle beyond the bound: reclaim the relay. forceClose
					// unblocks both directional reads via deadline + Close.
					cancel()
					forceClose()
					return
				}
			}
		}
	}()

	runDirection := func(dir relayDirection) {
		onActive := func(_ int64) {
			c.lastActiveNano.Store(time.Now().UnixNano())
		}
		_, err := c.copyEngine.Copy(ctx, dir.dst, dir.src, dir.record, onActive)

		if wc, ok := dir.dst.(WriteCloser); ok {
			_ = wc.CloseWrite()
		}

		if err != nil {
			// Any directional copy error is treated as terminal for this relay:
			// cancel shared context and force-close both sides to promptly
			// unblock pending reads/writes in the peer direction.
			cancel()
			forceClose()
		} else if c.halfCloseTimeout > 0 {
			// Test-only half-close bound. Production halfCloseTimeout is 0:
			// do not SetReadDeadline after CloseWrite.
			_ = dir.dst.SetReadDeadline(time.Now().Add(c.halfCloseTimeout))
		}

		results <- relayResult{
			dir: dir.name,
			err: err,
		}
	}

	go runDirection(relayDirection{
		name:   "l2r",
		src:    c.left,
		dst:    c.right,
		record: c.rightRecord,
	})
	go runDirection(relayDirection{
		name:   "r2l",
		src:    c.right,
		dst:    c.left,
		record: c.leftRecord,
	})

	first := <-results
	second := <-results
	return mergeRelayErrors(first.err, second.err)
}

// halfCloseForceClose reports whether a one-sided TCP close has waited
// long enough to force-close the peer. timeout <= 0 disables the bound so
// production Go relay and sockmap keep reading until FIN/RST or ctx cancel.
func halfCloseForceClose(firstClose time.Time, timeout time.Duration, now time.Time) bool {
	if timeout <= 0 || firstClose.IsZero() {
		return false
	}
	return !now.Before(firstClose.Add(timeout))
}

// mergeRelayErrors combines errors from both relay directions.
// Uses errors.Join to preserve both errors for inspection with errors.Is/As.
func mergeRelayErrors(err1, err2 error) error {
	return stderrors.Join(err1, err2)
}
