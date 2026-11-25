/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
)

// DefaultPooledUDPResolverIdleTimeout stays below common 30s proxy/NAT UDP
// session idle timeouts so idle sockets are closed cleanly before silent expiry.
const DefaultPooledUDPResolverIdleTimeout = 25 * time.Second

const pooledUDPWriteQueueSize = 64

var errPooledWriteSkipped = errors.New("pooled udp write skipped")

type pooledPendingQuery struct {
	ch    chan dnsResolveResult
	fqdn  string
	qtype uint16
}

type pooledWriteItem struct {
	payload []byte
	errCh   chan error      // buffered(1) for initial send; nil for best-effort resends
	ctx     context.Context // optional caller ctx to skip writing if already cancelled
}

func isNetTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type pooledUDPConn struct {
	conn      netproxy.Conn
	gen       uint64
	retired   bool // detached from r.active; draining remaining pending queries before closing
	closed    bool
	lastReply time.Time
	consecTO  int
	pending   map[uint16]pooledPendingQuery
	idleTimer *time.Timer

	writeCh   chan pooledWriteItem
	writeStop chan struct{}
	stopOnce  sync.Once
	closeOnce sync.Once
}

func (pc *pooledUDPConn) stopWrites() {
	pc.stopOnce.Do(func() {
		close(pc.writeStop)
	})
}

func (pc *pooledUDPConn) closeConn() {
	pc.stopWrites()
	pc.closeOnce.Do(func() {
		_ = pc.conn.Close()
	})
}

// PooledUDPResolver multiplexes concurrent UDP DNS queries for a single
// (dialer, dns, network) tuple over one lazily dialed, persistent PacketConn/Conn
// using the 16-bit DNS transaction ID. Concurrent cold queries serialize onto a
// single DialContext call, writes execute on a per-connection writer goroutine so
// slow/blocking writes never stall other callers past their context deadline,
// timed-out sockets retire for draining without aborting active waiters, and
// Reset tears down sockets on WAN changes for lazy redial.
type PooledUDPResolver struct {
	dialer      netproxy.Dialer
	dns         netip.AddrPort
	network     string
	idleTimeout time.Duration

	closeCtx    context.Context
	closeCancel context.CancelFunc

	mu         sync.Mutex
	closed     bool
	dialing    bool
	dialDone   chan struct{}
	dialCancel context.CancelFunc
	resetGen   uint64
	active     *pooledUDPConn
	conns      map[*pooledUDPConn]struct{}
	nextGen    uint64
	connWG     sync.WaitGroup
}

// NewPooledUDPResolver creates a PooledUDPResolver with the default idle timeout.
func NewPooledUDPResolver(d netproxy.Dialer, dns netip.AddrPort, network string) *PooledUDPResolver {
	return NewPooledUDPResolverWithIdle(d, dns, network, DefaultPooledUDPResolverIdleTimeout)
}

// NewPooledUDPResolverWithIdle creates a PooledUDPResolver with an explicit idle timeout.
func NewPooledUDPResolverWithIdle(d netproxy.Dialer, dns netip.AddrPort, network string, idleTimeout time.Duration) *PooledUDPResolver {
	if idleTimeout <= 0 {
		idleTimeout = DefaultPooledUDPResolverIdleTimeout
	}
	closeCtx, closeCancel := context.WithCancel(context.Background())
	return &PooledUDPResolver{
		dialer:      d,
		dns:         dns,
		network:     network,
		idleTimeout: idleTimeout,
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
	}
}

// ResolveTTL resolves host and typ via the shared UDP socket, returning the
// matching addresses, minimum answer TTL, whether an existing/shared socket or
// in-flight dial was reused, and any lookup error.
func (r *PooledUDPResolver) ResolveTTL(ctx context.Context, host string, typ uint16) (addrs []netip.Addr, ttl time.Duration, reused bool, err error) {
	if r == nil || r.dialer == nil {
		return nil, 0, false, fmt.Errorf("nil dialer")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ans, ok := parseLiteralIPAnswer(host, typ); ok {
		addrs, ttl, err = extractNetipTTL(ans, typ)
		return addrs, ttl, false, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, false, wrapResolveCtxErr(err)
	}

	fqdn := dnsmessage.CanonicalName(host)
	sentAt := time.Now()
	pc, id, respCh, reused, payload, err := r.acquireAndSend(ctx, fqdn, typ)
	if err != nil {
		return nil, 0, reused, err
	}

	ticker := time.NewTicker(consts.ResolveDNSUDPResendInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				r.handleTimeout(pc, id, respCh, reused, sentAt)
			} else {
				r.unregisterPending(pc, id, respCh)
			}
			return nil, 0, reused, wrapResolveCtxErr(ctx.Err())
		case res := <-respCh:
			if res.err != nil {
				return nil, 0, reused, res.err
			}
			addrs, ttl, err := extractNetipTTL(res.ans, typ)
			return addrs, ttl, reused, err
		case <-ticker.C:
			// Non-blocking enqueue onto the per-connection writer; never stalls
			// this caller's select loop or blocks past ctx.Done().
			select {
			case pc.writeCh <- pooledWriteItem{payload: payload, ctx: ctx}:
			case <-pc.writeStop:
			default:
			}
		}
	}
}

func (r *PooledUDPResolver) acquireAndSend(ctx context.Context, fqdn string, typ uint16) (pc *pooledUDPConn, id uint16, respCh chan dnsResolveResult, reused bool, payload []byte, err error) {
	allowStaleRetry := true
	for {
		pc, reused, err = r.acquireConn(ctx)
		if err != nil {
			return nil, 0, nil, reused, nil, err
		}
		id, respCh, ok, err := r.registerPending(pc, fqdn, typ)
		if err != nil {
			return nil, 0, nil, reused, nil, err
		}
		if !ok {
			// Connection rotated right before registration; re-acquire.
			continue
		}
		payload, err = packDNSQuery(fqdn, typ, id, true)
		if err != nil {
			r.unregisterPending(pc, id, respCh)
			return nil, 0, nil, reused, nil, err
		}

		errCh := make(chan error, 1)
		item := pooledWriteItem{payload: payload, errCh: errCh, ctx: ctx}
		var werr error
		select {
		case pc.writeCh <- item:
			select {
			case werr = <-errCh:
			case <-pc.writeStop:
				werr = net.ErrClosed
			case <-ctx.Done():
				r.unregisterPending(pc, id, respCh)
				if !errors.Is(ctx.Err(), context.Canceled) {
					r.retireStalledConn(pc)
				}
				return nil, 0, nil, reused, nil, wrapResolveCtxErr(ctx.Err())
			}
		case <-pc.writeStop:
			werr = net.ErrClosed
		case <-ctx.Done():
			r.unregisterPending(pc, id, respCh)
			if !errors.Is(ctx.Err(), context.Canceled) {
				r.retireStalledConn(pc)
			}
			return nil, 0, nil, reused, nil, wrapResolveCtxErr(ctx.Err())
		}
		if werr == nil {
			return pc, id, respCh, reused, payload, nil
		}
		r.unregisterPending(pc, id, respCh)
		if errors.Is(werr, errPooledWriteSkipped) {
			if ctx.Err() != nil {
				if !errors.Is(ctx.Err(), context.Canceled) {
					r.retireStalledConn(pc)
				}
				return nil, 0, nil, reused, nil, wrapResolveCtxErr(ctx.Err())
			}
			return nil, 0, nil, reused, nil, werr
		}
		if errors.Is(werr, context.Canceled) {
			return nil, 0, nil, reused, nil, wrapResolveCtxErr(werr)
		}
		if isNetTimeoutErr(werr) {
			r.retireStalledConn(pc)
		} else {
			r.dropConn(pc, werr)
		}
		if reused && allowStaleRetry && ctx.Err() == nil && !r.isClosed() {
			allowStaleRetry = false
			continue
		}
		return nil, 0, nil, reused, nil, werr
	}
}

func (r *PooledUDPResolver) acquireConn(ctx context.Context) (*pooledUDPConn, bool, error) {
	for {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return nil, false, net.ErrClosed
		}
		if r.active != nil && !r.active.closed && !r.active.retired {
			pc := r.active
			r.mu.Unlock()
			return pc, true, nil
		}
		if r.dialing {
			done := r.dialDone
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, true, wrapResolveCtxErr(ctx.Err())
			case <-r.closeCtx.Done():
				return nil, true, net.ErrClosed
			case <-done:
				continue
			}
		}

		done := make(chan struct{})
		dialCtx, dialCancel := context.WithCancel(ctx)
		startResetGen := r.resetGen
		r.dialing = true
		r.dialDone = done
		r.dialCancel = dialCancel
		r.mu.Unlock()

		stopClose := context.AfterFunc(r.closeCtx, dialCancel)
		c, err := r.dialer.DialContext(dialCtx, r.network, r.dns.String())
		stopClose()
		dialCancel()

		r.mu.Lock()
		r.dialing = false
		r.dialDone = nil
		r.dialCancel = nil
		discardLateConn := func(late netproxy.Conn) {
			if late == nil {
				return
			}
			// Register with r.connWG BEFORE close(done) so any concurrent Close()
			// waiting on <-done strictly observes this Add before connWG.Wait().
			r.connWG.Add(1)
			go func() {
				defer r.connWG.Done()
				_ = late.Close()
			}()
		}
		if r.closed {
			discardLateConn(c)
			close(done)
			r.mu.Unlock()
			return nil, false, net.ErrClosed
		}
		if r.resetGen != startResetGen {
			discardLateConn(c)
			close(done)
			r.mu.Unlock()
			if ctx.Err() != nil {
				return nil, false, wrapResolveCtxErr(ctx.Err())
			}
			continue
		}
		if err != nil {
			discardLateConn(c)
			close(done)
			r.mu.Unlock()
			if ctx.Err() != nil {
				return nil, false, wrapResolveCtxErr(ctx.Err())
			}
			return nil, false, err
		}
		if c == nil {
			close(done)
			r.mu.Unlock()
			return nil, false, fmt.Errorf("nil conn from dialer")
		}
		r.nextGen++
		pc := &pooledUDPConn{
			conn:      c,
			gen:       r.nextGen,
			pending:   make(map[uint16]pooledPendingQuery),
			writeCh:   make(chan pooledWriteItem, pooledUDPWriteQueueSize),
			writeStop: make(chan struct{}),
		}
		if r.conns == nil {
			r.conns = make(map[*pooledUDPConn]struct{})
		}
		r.active = pc
		r.conns[pc] = struct{}{}
		r.armIdleTimerLocked(pc)
		r.connWG.Add(2)
		close(done)
		r.mu.Unlock()

		go r.readLoop(pc)
		go r.writeLoop(pc)
		return pc, false, nil
	}
}

func (r *PooledUDPResolver) registerPending(pc *pooledUDPConn, fqdn string, qtype uint16) (uint16, chan dnsResolveResult, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, nil, false, net.ErrClosed
	}
	if r.active != pc || pc.closed || pc.retired {
		return 0, nil, false, nil
	}
	if pc.pending == nil {
		pc.pending = make(map[uint16]pooledPendingQuery)
	}
	if len(pc.pending) >= math.MaxUint16 {
		return 0, nil, false, fmt.Errorf("too many concurrent DNS queries")
	}
	r.stopIdleTimerLocked(pc)

	base := uint16(fastrand.Intn(math.MaxUint16 + 1))
	var id uint16
	found := false
	for i := 0; i <= math.MaxUint16; i++ {
		cand := base + uint16(i)
		if _, exists := pc.pending[cand]; !exists {
			id = cand
			found = true
			break
		}
	}
	if !found {
		if len(pc.pending) == 0 && r.active == pc && !pc.closed && !r.closed {
			r.armIdleTimerLocked(pc)
		}
		return 0, nil, false, fmt.Errorf("no free DNS transaction id")
	}
	ch := make(chan dnsResolveResult, 1)
	pc.pending[id] = pooledPendingQuery{ch: ch, fqdn: fqdn, qtype: qtype}
	return id, ch, true, nil
}

func (r *PooledUDPResolver) unregisterPending(pc *pooledUDPConn, id uint16, respCh chan dnsResolveResult) {
	r.mu.Lock()
	cur, ok := pc.pending[id]
	if !ok || cur.ch != respCh {
		r.mu.Unlock()
		return
	}
	delete(pc.pending, id)
	closeNow := r.maybeCloseOrArmIdleLocked(pc)
	r.mu.Unlock()
	if closeNow {
		// r.connWG was already incremented under r.mu inside maybeCloseOrArmIdleLocked.
		go r.finishCloseConn(pc)
	}
}

func (r *PooledUDPResolver) handleTimeout(pc *pooledUDPConn, id uint16, respCh chan dnsResolveResult, reused bool, sentAt time.Time) {
	r.mu.Lock()
	cur, ok := pc.pending[id]
	if !ok || cur.ch != respCh {
		r.mu.Unlock()
		return
	}
	delete(pc.pending, id)
	pc.consecTO++
	// When no reply has arrived since this query was sent and either a reused
	// socket is now idle or consecutive timeouts occurred, retire the socket so
	// subsequent queries redial cleanly. Any other in-flight waiters on pc keep
	// draining until their own reply or deadline; pc closes once pending empties.
	shouldRetire := !pc.closed && !r.closed && !pc.lastReply.After(sentAt) &&
		((reused && len(pc.pending) == 0) || pc.consecTO >= 2)
	if shouldRetire {
		if r.active == pc {
			r.active = nil
		}
		pc.retired = true
	}
	closeNow := r.maybeCloseOrArmIdleLocked(pc)
	r.mu.Unlock()
	if closeNow {
		// r.connWG was already incremented under r.mu inside maybeCloseOrArmIdleLocked.
		go r.finishCloseConn(pc)
	}
}

func (r *PooledUDPResolver) retireStalledConn(pc *pooledUDPConn) {
	r.mu.Lock()
	if r.active == pc {
		r.active = nil
	}
	pc.retired = true
	closeNow := r.maybeCloseOrArmIdleLocked(pc)
	r.mu.Unlock()
	if closeNow {
		// r.connWG was already incremented under r.mu inside maybeCloseOrArmIdleLocked.
		go r.finishCloseConn(pc)
	}
}

// maybeCloseOrArmIdleLocked marks pc closed and reserves a connWG slot for
// asynchronous teardown when pc is retired/closing and has no remaining pending
// queries; otherwise re-arms the idle timer if pc is still active.
// Caller must hold r.mu; if it returns true, caller must launch `go r.finishCloseConn(pc)` unlocked.
func (r *PooledUDPResolver) maybeCloseOrArmIdleLocked(pc *pooledUDPConn) bool {
	if pc.closed || len(pc.pending) > 0 {
		return false
	}
	if pc.retired || r.closed || r.active != pc {
		pc.closed = true
		if r.active == pc {
			r.active = nil
		}
		delete(r.conns, pc)
		r.stopIdleTimerLocked(pc)
		pc.pending = nil
		r.connWG.Add(1)
		return true
	}
	r.armIdleTimerLocked(pc)
	return false
}

func (r *PooledUDPResolver) finishCloseConn(pc *pooledUDPConn) {
	defer r.connWG.Done()
	pc.closeConn()
}

func (r *PooledUDPResolver) isClosed() bool {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	return closed
}

func (r *PooledUDPResolver) isConnClosed(pc *pooledUDPConn) bool {
	r.mu.Lock()
	closed := r.closed || pc.closed
	r.mu.Unlock()
	return closed
}

func (r *PooledUDPResolver) writeLoop(pc *pooledUDPConn) {
	defer r.connWG.Done()
	target := r.dns.String()
	for {
		select {
		case <-pc.writeStop:
			return
		case item := <-pc.writeCh:
			if r.isConnClosed(pc) {
				if item.errCh != nil {
					item.errCh <- net.ErrClosed
				}
				return
			}
			if item.ctx != nil && item.ctx.Err() != nil {
				if item.errCh != nil {
					item.errCh <- errPooledWriteSkipped
				}
				continue
			}
			_ = pc.conn.SetWriteDeadline(time.Now().Add(consts.ResolveDNSUDPResendInterval))
			_, err := WriteUDPConn(pc.conn, target, item.payload)
			if item.errCh != nil {
				item.errCh <- err
			}
			if err != nil {
				if isNetTimeoutErr(err) {
					// A write timeout does not invalidate the read side for queries
					// already sent on pc; retire pc for new queries and let active
					// waiters finish draining on readLoop.
					r.retireStalledConn(pc)
					continue
				}
				r.dropConn(pc, err)
				return
			}
		}
	}
}

func (r *PooledUDPResolver) readLoop(pc *pooledUDPConn) {
	defer r.connWG.Done()
	// Allocate a full-legal-DNS buffer once per pooled socket to match
	// ResolveNetipTTL semantics without per-query allocations.
	buf := pool.GetFullCap(maxDNSMessageSize)
	defer buf.Put()

	for {
		n, err := ReadUDPConn(pc.conn, buf)
		if err != nil {
			r.dropConn(pc, err)
			return
		}
		if n < 2 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[:2])

		r.mu.Lock()
		var pq pooledPendingQuery
		var found bool
		if !r.closed && !pc.closed && pc.pending != nil {
			pq, found = pc.pending[id]
		}
		r.mu.Unlock()

		if !found {
			continue
		}

		var msg dnsmessage.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		res, matched := decodeUnpackedAnswer(&msg, id, pq.fqdn, pq.qtype)
		if !matched {
			continue
		}

		r.mu.Lock()
		var ch chan dnsResolveResult
		closeNow := false
		if !r.closed && !pc.closed && pc.pending != nil {
			if cur, ok := pc.pending[id]; ok && cur.ch == pq.ch {
				ch = cur.ch
				delete(pc.pending, id)
				pc.lastReply = time.Now()
				pc.consecTO = 0
				closeNow = r.maybeCloseOrArmIdleLocked(pc)
			}
		}
		r.mu.Unlock()

		if ch != nil {
			ch <- res
		}
		if closeNow {
			go r.finishCloseConn(pc)
			return
		}
	}
}

func (r *PooledUDPResolver) armIdleTimerLocked(pc *pooledUDPConn) {
	if r.closed || pc.closed || pc.retired || r.active != pc || r.idleTimeout <= 0 {
		return
	}
	if pc.idleTimer != nil {
		pc.idleTimer.Stop()
	}
	pc.idleTimer = time.AfterFunc(r.idleTimeout, func() {
		r.onIdleTimeout(pc)
	})
}

func (r *PooledUDPResolver) stopIdleTimerLocked(pc *pooledUDPConn) {
	if pc.idleTimer != nil {
		pc.idleTimer.Stop()
		pc.idleTimer = nil
	}
}

func (r *PooledUDPResolver) onIdleTimeout(pc *pooledUDPConn) {
	r.mu.Lock()
	if r.closed || pc.closed || r.active != pc || len(pc.pending) > 0 {
		r.mu.Unlock()
		return
	}
	r.active = nil
	pc.closed = true
	pc.pending = nil
	pc.idleTimer = nil
	delete(r.conns, pc)
	r.connWG.Add(1)
	r.mu.Unlock()
	r.finishCloseConn(pc)
}

func (r *PooledUDPResolver) dropConn(pc *pooledUDPConn, err error) {
	if err == nil {
		err = net.ErrClosed
	}
	r.mu.Lock()
	if pc.closed {
		r.mu.Unlock()
		return
	}
	pending, timer := r.detachConnLocked(pc)
	r.connWG.Add(1)
	r.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	pc.stopWrites()
	for _, pq := range pending {
		pq.ch <- dnsResolveResult{err: err}
	}
	go r.finishCloseConn(pc)
}

func (r *PooledUDPResolver) detachConnLocked(pc *pooledUDPConn) (map[uint16]pooledPendingQuery, *time.Timer) {
	pc.closed = true
	if r.active == pc {
		r.active = nil
	}
	delete(r.conns, pc)
	pending := pc.pending
	pc.pending = nil
	timer := pc.idleTimer
	pc.idleTimer = nil
	return pending, timer
}

// Reset drops all active and draining pooled UDP sockets (e.g. on WAN change)
// and cancels any in-flight dial while leaving the resolver ready to lazily
// redial on the next lookup. Waiters are notified immediately and underlying
// socket closes run asynchronously under r.connWG so slow Close() calls never
// block Reset() or query callers. Returns true if any socket or dial was reset.
func (r *PooledUDPResolver) Reset() bool {
	if r == nil {
		return false
	}
	type dropped struct {
		pc      *pooledUDPConn
		pending map[uint16]pooledPendingQuery
		timer   *time.Timer
	}

	r.mu.Lock()
	r.resetGen++
	dialCancel := r.dialCancel
	if len(r.conns) == 0 {
		r.mu.Unlock()
		if dialCancel != nil {
			dialCancel()
			return true
		}
		return false
	}
	toDrop := make([]dropped, 0, len(r.conns))
	for pc := range r.conns {
		pending, timer := r.detachConnLocked(pc)
		r.connWG.Add(1)
		toDrop = append(toDrop, dropped{pc: pc, pending: pending, timer: timer})
	}
	r.mu.Unlock()

	if dialCancel != nil {
		dialCancel()
	}
	for _, d := range toDrop {
		if d.timer != nil {
			d.timer.Stop()
		}
		d.pc.stopWrites()
		for _, pq := range d.pending {
			pq.ch <- dnsResolveResult{err: net.ErrClosed}
		}
		go r.finishCloseConn(d.pc)
	}
	return true
}

// Close permanently shuts down the pooled resolver, cancels any in-flight dial,
// immediately unblocks pending waiters, closes all active and draining sockets,
// and waits for all read/write/close tasks to exit.
func (r *PooledUDPResolver) Close() error {
	if r == nil {
		return nil
	}
	type dropped struct {
		pc      *pooledUDPConn
		pending map[uint16]pooledPendingQuery
		timer   *time.Timer
	}

	r.mu.Lock()
	if r.closed {
		done := r.dialDone
		r.mu.Unlock()
		if done != nil {
			<-done
		}
		r.connWG.Wait()
		return nil
	}
	r.closed = true
	r.closeCancel()
	done := r.dialDone
	toDrop := make([]dropped, 0, len(r.conns))
	for pc := range r.conns {
		pending, timer := r.detachConnLocked(pc)
		r.connWG.Add(1)
		toDrop = append(toDrop, dropped{pc: pc, pending: pending, timer: timer})
	}
	r.mu.Unlock()

	for _, d := range toDrop {
		if d.timer != nil {
			d.timer.Stop()
		}
		d.pc.stopWrites()
		for _, pq := range d.pending {
			pq.ch <- dnsResolveResult{err: net.ErrClosed}
		}
		go r.finishCloseConn(d.pc)
	}
	if done != nil {
		<-done
	}
	r.connWG.Wait()
	return nil
}

func wrapResolveCtxErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrResolveTimeout, err)
	}
	return fmt.Errorf("timeout: %w", err)
}
