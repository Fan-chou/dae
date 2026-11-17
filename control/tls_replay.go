/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const (
	tlsReplayMaxBytes    = 32 * 1024
	tlsReplayMaxAttempts = 2
)

type tlsReplayStreamBox struct {
	conn netproxy.Conn
}

// tlsReplayConn transparently buffers the initial TLS ClientHello (0x16 0x03,
// capped at 32 KiB) on multi-candidate proxy TCP flows until the remote sends
// its first response byte. If the initial node resets/EOFs before answering
// (not due to client close, relay cancellation, or caller deadline), it fails
// the dead node over to a backup node via ControlPlane.routeDial and replays
// the buffered ClientHello without stalling first-byte latency or normal relay.
type tlsReplayConn struct {
	flow          *FlowRuntime
	plane         weak.Pointer[ControlPlane]
	createdAtNano int64

	stream           atomic.Pointer[tlsReplayStreamBox]
	pendingReplay    atomic.Pointer[tlsReplayStreamBox]
	closed           atomic.Bool
	answered         atomic.Bool
	disabled         atomic.Bool
	hasSent          atomic.Bool
	readDeadlineNano atomic.Int64
	writeDeadlineSet atomic.Bool

	dialCancelMu sync.Mutex
	dialCancel   context.CancelFunc

	opMu        sync.Mutex
	baseParam   proxyDialParam
	sent        []byte
	writeClosed bool
	attempts    int
	excluded    map[*dialer.Dialer]struct{}
	log         *logrus.Logger
}

func mayStartTLSClientHello(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if b[0] != 0x16 {
		return false
	}
	if len(b) >= 2 && b[1] != 0x03 {
		return false
	}
	return true
}

func (c *ControlPlane) maybeWrapTLSReplay(
	flow *FlowRuntime,
	rConn netproxy.Conn,
	dialParam *proxyDialParam,
	res *proxyDialResult,
	precheckNonTLS bool,
) netproxy.Conn {
	if precheckNonTLS || c == nil || flow == nil || rConn == nil || dialParam == nil || res == nil {
		return rConn
	}
	if !isProxyBackedDialer(res.Dialer) || res.Outbound == nil {
		return rConn
	}
	nt := res.SelectionNetworkTypeObj
	if nt == nil {
		nt = res.OrigNetworkTypeObj
	}
	if !res.Outbound.HasAlternativeDialer(res.Dialer, nt) {
		return rConn
	}

	paramCopy := *dialParam
	paramCopy.captureTrace = nil
	paramCopy.Excluded = nil
	paramCopy.ExcludedSet = nil

	r := &tlsReplayConn{
		flow:          flow,
		plane:         weak.Make(c),
		createdAtNano: time.Now().UnixNano(),
		baseParam:     paramCopy,
		log:           c.log,
	}
	r.storeStream(rConn)
	return r
}

func (r *tlsReplayConn) storeStream(conn netproxy.Conn) {
	r.stream.Store(&tlsReplayStreamBox{conn: conn})
}

func (r *tlsReplayConn) loadStream() netproxy.Conn {
	box := r.stream.Load()
	if box == nil {
		return nil
	}
	return box.conn
}

func (r *tlsReplayConn) setDialCancel(cancel context.CancelFunc) {
	r.dialCancelMu.Lock()
	r.dialCancel = cancel
	// Close or the relay's cancellation deadline can arrive just before the
	// dial registers its cancel function. Do not miss that cancellation.
	canceled := cancel != nil && (r.closed.Load() || !r.readDeadlineAllowsReplay())
	r.dialCancelMu.Unlock()
	if canceled {
		cancel()
	}
}

func (r *tlsReplayConn) cancelActiveDial() {
	r.dialCancelMu.Lock()
	cancel := r.dialCancel
	r.dialCancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *tlsReplayConn) disableLocked() {
	r.disabled.Store(true)
	r.hasSent.Store(false)
	r.sent = nil
	r.excluded = nil
	r.baseParam = proxyDialParam{}
	r.plane = weak.Pointer[ControlPlane]{}
}

func (r *tlsReplayConn) markAnswered() {
	if !r.answered.CompareAndSwap(false, true) {
		return
	}
	r.opMu.Lock()
	r.disableLocked()
	r.opMu.Unlock()
}

func (r *tlsReplayConn) readDeadlineAllowsReplay() bool {
	dl := r.readDeadlineNano.Load()
	return dl == 0 || dl > r.createdAtNano
}

func isReplayTimeoutError(err error) bool {
	var netErr net.Error
	return stderrors.As(err, &netErr) && netErr.Timeout()
}

func (r *tlsReplayConn) shouldReplayReadError(err error) bool {
	if err == nil || r.closed.Load() || r.answered.Load() || r.disabled.Load() || !r.hasSent.Load() {
		return false
	}
	if r.flow == nil || r.flow.Context().Err() != nil {
		return false
	}
	if !r.readDeadlineAllowsReplay() {
		return false
	}
	if isReplayTimeoutError(err) && r.readDeadlineNano.Load() != 0 {
		return false
	}
	return true
}

func (r *tlsReplayConn) Read(b []byte) (int, error) {
	if r.answered.Load() || r.disabled.Load() {
		return r.loadStream().Read(b)
	}
	for {
		s := r.loadStream()
		if s == nil {
			return 0, net.ErrClosed
		}
		n, err := s.Read(b)
		if n > 0 {
			r.markAnswered()
			return n, err
		}
		if err == nil {
			continue
		}
		if !r.shouldReplayReadError(err) {
			return 0, err
		}
		r.opMu.Lock()
		if r.loadStream() != s {
			// Concurrent Write already switched stream cleanly.
			r.opMu.Unlock()
			continue
		}
		if !r.shouldReplayReadError(err) || len(r.sent) < 2 {
			r.opMu.Unlock()
			return 0, err
		}
		ok := r.replayLocked(s, err)
		r.opMu.Unlock()
		if !ok {
			return 0, err
		}
	}
}

func (r *tlsReplayConn) Write(p []byte) (int, error) {
	if r.answered.Load() || r.disabled.Load() {
		return r.loadStream().Write(p)
	}
	r.opMu.Lock()
	s := r.loadStream()
	if s == nil {
		r.opMu.Unlock()
		return 0, net.ErrClosed
	}
	if r.answered.Load() || r.disabled.Load() {
		r.opMu.Unlock()
		return s.Write(p)
	}

	if len(p) > 0 {
		canBuffer := false
		switch len(r.sent) {
		case 0:
			canBuffer = mayStartTLSClientHello(p)
		case 1:
			canBuffer = p[0] == 0x03
		default:
			canBuffer = true
		}
		if !canBuffer || len(r.sent)+len(p) > tlsReplayMaxBytes {
			r.disableLocked()
			r.opMu.Unlock()
			return s.Write(p)
		}
		// Record sent bytes and publish hasSent before s.Write(p) so a
		// fast remote close/RST racing with s.Write return cannot observe
		// hasSent == false in concurrent Read().
		r.sent = append(r.sent, p...)
		if len(r.sent) >= 2 {
			r.hasSent.Store(true)
		}
	}

	n, err := s.Write(p)
	if err == nil {
		r.opMu.Unlock()
		return n, nil
	}

	if len(p) > 0 && len(r.sent) >= 2 &&
		!r.closed.Load() && !r.answered.Load() &&
		r.flow != nil && r.flow.Context().Err() == nil &&
		r.readDeadlineAllowsReplay() &&
		!(isReplayTimeoutError(err) && r.writeDeadlineSet.Load()) {
		if r.replayLocked(s, err) {
			r.opMu.Unlock()
			return len(p), nil
		}
	}
	r.disableLocked()
	r.opMu.Unlock()
	return n, err
}

func (r *tlsReplayConn) replayLocked(failedStream netproxy.Conn, triggerErr error) bool {
	if r.attempts >= tlsReplayMaxAttempts {
		r.disableLocked()
		return false
	}
	c := r.plane.Value()
	if c == nil || r.closed.Load() || r.flow.Context().Err() != nil {
		r.disableLocked()
		return false
	}

	sentCopy := append([]byte(nil), r.sent...)
	wasWriteClosed := r.writeClosed
	oldBinding := r.flow.Binding()
	if r.excluded == nil {
		r.excluded = make(map[*dialer.Dialer]struct{}, tlsReplayMaxAttempts+1)
	}
	if oldBinding.Egress.Dialer != nil {
		r.excluded[oldBinding.Egress.Dialer] = struct{}{}
	}

	_ = failedStream.Close()
	failEarlyReplayBinding(oldBinding, triggerErr)

	// Guard against stale relay stream pointer between rebinds; only the very
	// first replacement tracks expectedOld inside FlowRuntime.
	expectedFlowStream := r.flow.Egress()
	for r.attempts < tlsReplayMaxAttempts {
		if r.closed.Load() || r.flow.Context().Err() != nil || !r.readDeadlineAllowsReplay() {
			r.disableLocked()
			return false
		}
		r.attempts++

		param := r.baseParam
		param.ExcludedSet = maps.Clone(r.excluded)
		if len(r.excluded) == 1 {
			for d := range r.excluded {
				param.Excluded = d
			}
		}

		dialCtx, dialCancel := context.WithCancel(r.flow.Context())
		r.setDialCancel(dialCancel)
		newConn, newRes, dialErr := c.routeDial(dialCtx, &param)
		r.setDialCancel(nil)
		dialCancel()

		if dialErr != nil || newConn == nil || newRes == nil {
			if newConn != nil {
				_ = newConn.Close()
			}
			if newRes != nil {
				newRes.Quality.Abandon()
				newRes.SelectPath.RecoveryAbandon()
			}
			r.disableLocked()
			return false
		}
		// Publish ownership before the first replay write so Close can interrupt
		// it even though the flow is not rebound until replay succeeds.
		pending := &tlsReplayStreamBox{conn: newConn}
		r.pendingReplay.Store(pending)
		if r.closed.Load() || r.flow.Context().Err() != nil || !r.readDeadlineAllowsReplay() {
			r.pendingReplay.CompareAndSwap(pending, nil)
			_ = newConn.Close()
			newRes.Quality.Abandon()
			newRes.SelectPath.RecoveryAbandon()
			r.disableLocked()
			return false
		}

		if writeErr := writeTLSReplayPayload(newConn, sentCopy, wasWriteClosed); writeErr != nil {
			r.pendingReplay.CompareAndSwap(pending, nil)
			_ = newConn.Close()
			if r.closed.Load() || r.flow.Context().Err() != nil || !r.readDeadlineAllowsReplay() {
				newRes.Quality.Abandon()
				newRes.SelectPath.RecoveryAbandon()
				r.disableLocked()
				return false
			}
			if newRes.Dialer != nil {
				r.excluded[newRes.Dialer] = struct{}{}
			}
			newRes.SelectPath.RecoveryFinish()
			newRes.Quality.Fail()
			if newRes.Outbound != nil {
				newRes.Outbound.FailSitePath(pinSiteSubject(newRes.StickySite, newRes.SniffedDomain), newRes.Dialer, newRes.SelectPath)
			}
			notifyProxyDialerHealthCheck(newRes.Dialer, consts.L4ProtoStr_TCP, writeErr)
			continue
		}

		if !r.flow.rebindAfterEarlyReplay(c.PolicyEpoch(), expectedFlowStream, newConn, c.egressRuntime, newRes) {
			r.pendingReplay.CompareAndSwap(pending, nil)
			_ = newConn.Close()
			newRes.Quality.Abandon()
			newRes.SelectPath.RecoveryAbandon()
			r.disableLocked()
			return false
		}

		r.stream.Store(pending)
		r.pendingReplay.CompareAndSwap(pending, nil)
		// Synchronize against concurrent Close() or SetReadDeadline(): if either
		// arrived while swapping streams, propagate immediately so no handle leaks.
		if dl := r.readDeadlineNano.Load(); dl != 0 {
			_ = newConn.SetReadDeadline(time.Unix(0, dl))
		}
		if r.closed.Load() {
			_ = newConn.Close()
			r.disableLocked()
			return false
		}
		if r.log != nil && r.log.IsLevelEnabled(logrus.DebugLevel) && newRes.Dialer != nil && newRes.Dialer.Property() != nil {
			r.log.WithFields(logrus.Fields{
				"attempt": r.attempts,
				"dialer":  newRes.Dialer.Property().Name,
				"target":  newRes.DialTarget,
				"bytes":   len(sentCopy),
			}).Debug("TLS ClientHello early failure replayed onto backup dialer")
		}
		return true
	}

	r.disableLocked()
	return false
}

func failEarlyReplayBinding(binding TcpFlowBinding, err error) {
	binding.Egress.SelectPath.RecoveryFinish()
	binding.Egress.Quality.Fail()
	if binding.Egress.Outbound != nil && binding.Egress.Dialer != nil {
		binding.Egress.Outbound.FailSitePath(
			pinSiteSubject(binding.Egress.StickySite, binding.Egress.SniffedDomain),
			binding.Egress.Dialer,
			binding.Egress.SelectPath,
		)
	}
	if binding.Egress.Dialer != nil {
		l4 := binding.Egress.NetworkType.L4Proto
		if l4 == "" {
			l4 = consts.L4ProtoStr_TCP
		}
		notifyProxyDialerHealthCheck(binding.Egress.Dialer, l4, err)
	}
}

func writeTLSReplayPayload(conn netproxy.Conn, payload []byte, closeWrite bool) error {
	if len(payload) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(consts.DefaultDialTimeout))
		written := 0
		for written < len(payload) {
			n, err := conn.Write(payload[written:])
			if n > 0 {
				written += n
			}
			if err != nil {
				_ = conn.SetWriteDeadline(time.Time{})
				return err
			}
			if n == 0 {
				_ = conn.SetWriteDeadline(time.Time{})
				return stderrors.New("short TLS replay write")
			}
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
	if closeWrite {
		closeWriteRelayConn(conn)
	}
	return nil
}

func (r *tlsReplayConn) Close() error {
	if r == nil {
		return nil
	}
	r.closed.Store(true)
	r.cancelActiveDial()
	pending := r.pendingReplay.Swap(nil)
	if pending != nil {
		_ = pending.conn.Close()
	}
	if current := r.stream.Load(); current != nil && current != pending {
		return current.conn.Close()
	}
	return nil
}

func (r *tlsReplayConn) CloseWrite() error {
	if r == nil {
		return nil
	}
	if !r.answered.Load() && !r.disabled.Load() {
		r.opMu.Lock()
		if !r.answered.Load() && !r.disabled.Load() {
			r.writeClosed = true
		}
		s := r.loadStream()
		r.opMu.Unlock()
		closeWriteRelayConn(s)
		return nil
	}
	closeWriteRelayConn(r.loadStream())
	return nil
}

func (r *tlsReplayConn) SetDeadline(t time.Time) error {
	if r == nil {
		return nil
	}
	r.storeReadDeadline(t)
	r.writeDeadlineSet.Store(!t.IsZero())
	if s := r.loadStream(); s != nil {
		return s.SetDeadline(t)
	}
	return nil
}

func (r *tlsReplayConn) SetReadDeadline(t time.Time) error {
	if r == nil {
		return nil
	}
	r.storeReadDeadline(t)
	if s := r.loadStream(); s != nil {
		return s.SetReadDeadline(t)
	}
	return nil
}

func (r *tlsReplayConn) SetWriteDeadline(t time.Time) error {
	if r == nil {
		return nil
	}
	r.writeDeadlineSet.Store(!t.IsZero())
	if s := r.loadStream(); s != nil {
		return s.SetWriteDeadline(t)
	}
	return nil
}

func (r *tlsReplayConn) storeReadDeadline(t time.Time) {
	var nano int64
	if !t.IsZero() {
		nano = t.UnixNano()
		if nano == 0 {
			nano = 1
		}
	}
	r.readDeadlineNano.Store(nano)
	if nano != 0 && nano <= r.createdAtNano {
		r.cancelActiveDial()
		if pending := r.pendingReplay.Swap(nil); pending != nil {
			_ = pending.conn.Close()
		}
	}
}

func (r *tlsReplayConn) LocalAddr() net.Addr {
	if c, ok := r.loadStream().(net.Conn); ok {
		return c.LocalAddr()
	}
	return nil
}

func (r *tlsReplayConn) RemoteAddr() net.Addr {
	if c, ok := r.loadStream().(net.Conn); ok {
		return c.RemoteAddr()
	}
	return nil
}
