/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/common/netutils"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

// Flows accepted by a user-space inbound (section "inbound") do not pass
// through the eBPF datapath, so nothing is known about them in the kernel.
// They are routed entirely in user space: the dial parameters carry
// OutboundControlPlaneRouting plus the consts.InboundID of the inbound, which
// makes chooseProxyDialer run the ordinary routing section with inbound()
// predicates enabled.

// activeControlPlane returns the published (serving) control plane, or nil
// before the first generation is published.
func activeControlPlane() *ControlPlane {
	return activeControlPlanePublication.plane.Load()
}

// InboundTarget is the destination a client asked for: a domain name that dae
// still has to resolve, or an IP address.
type InboundTarget struct {
	Domain string
	IP     netip.Addr
	Port   uint16
}

// String returns host:port.
func (t InboundTarget) String() string {
	host := t.Domain
	if host == "" {
		host = t.IP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(t.Port)))
}

// key identifies the target inside one UDP association.
func (t InboundTarget) key() string {
	if t.Domain != "" {
		return strings.ToLower(strings.TrimSuffix(t.Domain, ".")) + ":" + strconv.Itoa(int(t.Port))
	}
	return netip.AddrPortFrom(t.IP.Unmap(), t.Port).String()
}

// InboundDialError reports that a flow could not be established. The caller
// maps Err to a protocol-level failure reply.
type InboundDialError struct{ Err error }

func (e *InboundDialError) Error() string { return e.Err.Error() }
func (e *InboundDialError) Unwrap() error { return e.Err }

var errInboundUnavailable = errors.New("control plane is not accepting connections")

// resolveInboundTarget turns a client-requested target into the destination
// used for routing and dialing. A domain keeps its name for domain() rules and
// domain dialing; the IP is looked up through dae's own DNS controller so the
// dns section (and its routing) applies.
//
// With deferred set, a domain is not resolved here: the result is a name-only
// flow (see inbound_nameonly.go) whose destination is the placeholder and
// whose address is looked up later, only if routing or a direct dial needs it.
func (c *ControlPlane) resolveInboundTarget(ctx context.Context, t InboundTarget, deferred bool) (dst netip.AddrPort, domain string, nameOnly bool, err error) {
	if t.Domain == "" {
		return common.ConvergeAddrPort(netip.AddrPortFrom(t.IP, t.Port)), "", false, nil
	}
	name := strings.TrimSuffix(t.Domain, ".")
	if ip, perr := netip.ParseAddr(strings.Trim(name, "[]")); perr == nil {
		return common.ConvergeAddrPort(netip.AddrPortFrom(ip, t.Port)), "", false, nil
	}
	if deferred {
		return nameOnlyDest(t.Port), name, true, nil
	}
	// The DNS controller needs a configured dns section (or the asis system
	// resolver). Without one, realIPForNameOnly falls back to the bootstrap
	// resolvers dae already uses for node hosts, so a plain SOCKS5 inbound can
	// still serve domain targets.
	ip, err := c.realIPForNameOnly(ctx, name, netip.IPv4Unspecified())
	if err != nil {
		return netip.AddrPort{}, "", false, err
	}
	return common.ConvergeAddrPort(netip.AddrPortFrom(ip, t.Port)), name, false, nil
}

// resolveInboundViaBootstrap looks name up through the bootstrap resolvers
// with dae's own marked sockets, preferring IPv4.
func (c *ControlPlane) resolveInboundViaBootstrap(ctx context.Context, name string) (netip.Addr, error) {
	ip46, err4, err6 := c.resolveBootstrapIp46(ctx, name, common.MagicNetwork("udp", c.soMarkFromDae, c.mptcp))
	if ip46 != nil {
		if ip46.Ip4.IsValid() {
			return ip46.Ip4, nil
		}
		if ip46.Ip6.IsValid() {
			return ip46.Ip6, nil
		}
	}
	err := err4
	if err == nil {
		err = err6
	}
	if err == nil {
		err = errors.New("no address records")
	}
	return netip.Addr{}, err
}

func (c *ControlPlane) inboundDialParam(inbound string, network string, src, dst netip.AddrPort, domain string, nameOnly bool) *proxyDialParam {
	return &proxyDialParam{
		NameOnly: nameOnly,
		Outbound: consts.OutboundControlPlaneRouting,
		Domain:   domain,
		Src:      src,
		Dest:     dst,
		Network:  network,
		Inbound:  consts.InboundID(inbound),
	}
}

// InboundTCPOptions are the per-inbound knobs of ServeInboundTCP.
type InboundTCPOptions struct {
	// DeferResolve routes a domain target by its name before resolving it.
	DeferResolve bool
	// Sniff allows TLS SNI / HTTP Host sniffing of flows whose target is an
	// IP address with no known name.
	Sniff bool
}

// inboundShouldSniffTCP reports whether a flow to dst should be answered
// before dialing so its first bytes can be sniffed for a name. It follows the
// transparent path's policy (sniffing_timeout, dial_mode, excluded ports) and
// skips targets whose name is already known: a domain the client sent, or a
// FakeIP that still maps back to one.
func (c *ControlPlane) inboundShouldSniffTCP(enabled bool, dst netip.AddrPort, domain string) bool {
	if !enabled || domain != "" {
		return false
	}
	if store := c.fakeIPStore(); store != nil && store.Contains(dst.Addr()) {
		if _, named := store.LookBack(dst.Addr()); named {
			return false
		}
	}
	// The kernel never saw this flow, so there is no routing verdict that
	// could rule sniffing out; ask as for a flow awaiting user-space routing.
	return c.shouldTryTcpSniff(dst, &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)})
}

// sniffInboundTCP reads the start of a flow for a TLS SNI / HTTP Host. It
// always returns a usable relay connection; domain is empty when nothing was
// found. A sniffing miss is never an error.
func (c *ControlPlane) sniffInboundTCP(lConn net.Conn, src, dst netip.AddrPort) (relay net.Conn, domain string, closeFn func(), err error) {
	noop := func() {}
	key := newTcpSniffNegKey(dst, nil)
	now := time.Now()
	if c.shouldSkipTcpSniffByNegativeCache(key, now) {
		return lConn, "", noop, nil
	}
	probeConn, prefetched, ready, err := prefetchForTcpSniff(lConn, c.sniffingTimeout, tcpSniffPrefetchBytes)
	if err != nil {
		return lConn, "", noop, err
	}
	if !ready || !isLikelyHttpOrTLSPrefix(prefetched) {
		c.noteTcpSniffFailure(key, now)
		return probeConn, "", noop, nil
	}
	sniffer := sniffing.NewConnSniffer(probeConn, c.sniffingTimeout, c.log)
	closeFn = func() { _ = sniffer.Close() }
	domain, err = sniffer.SniffTcp()
	if err != nil {
		if !sniffing.IsSniffingError(err) && !daerrors.IsIgnorableConnectionError(err) {
			closeFn()
			return lConn, "", noop, err
		}
		c.noteTcpSniffFailure(key, now)
		return sniffer, "", closeFn, nil
	}
	c.clearTcpSniffNegative(key)
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{"src": src.String(), "dst": dst.String(), "sniffed": domain}).Trace("SOCKS5 inbound sniffed TCP name")
	}
	return sniffer, domain, closeFn, nil
}

// ServeInboundTCP routes, dials and relays one TCP flow accepted by the named
// inbound. established is called once the outbound connection is up and
// before data flows; it is where the protocol layer sends its success reply.
// A failure before that point is returned as *InboundDialError and nothing was
// sent to lConn. When the flow is to be sniffed (see inboundShouldSniffTCP)
// established is called first instead, because the client sends nothing until
// it is answered; failures after that point can only close the connection.
// ServeInboundTCP returns when the relay ends.
func (c *ControlPlane) ServeInboundTCP(ctx context.Context, inbound string, lConn net.Conn, target InboundTarget, opts InboundTCPOptions, established func() error) error {
	lease, ok := c.acquireIncomingConnectionLease(lConn)
	if !ok {
		return &InboundDialError{Err: errInboundUnavailable}
	}
	defer lease.release()

	tcpAddr, ok := lConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return &InboundDialError{Err: fmt.Errorf("unexpected client address type %T", lConn.RemoteAddr())}
	}
	src := common.ConvergeAddrPort(tcpAddr.AddrPort())

	dst, domain, nameOnly, err := c.resolveInboundTarget(ctx, target, opts.DeferResolve)
	if err != nil {
		return &InboundDialError{Err: err}
	}
	// lConn stays the lifecycle connection; relayConn is what is read from,
	// and carries any bytes consumed while sniffing.
	var relayConn net.Conn = lConn
	if c.inboundShouldSniffTCP(opts.Sniff, dst, domain) {
		if established != nil {
			if err := established(); err != nil {
				return err
			}
			established = nil
		}
		var closeSniffer func()
		relayConn, domain, closeSniffer, err = c.sniffInboundTCP(lConn, src, dst)
		defer closeSniffer()
		if err != nil {
			return err
		}
	}
	rConn, res, err := c.routeDial(ctx, c.inboundDialParam(inbound, "tcp", src, dst, domain, nameOnly))
	if err != nil {
		return &InboundDialError{Err: err}
	}
	lease.storePendingEgress(rConn)
	if nameOnly {
		// The flow identity should name the address actually dialed when
		// there is one; a proxy flow routed by name keeps the placeholder.
		if dialed, perr := netip.ParseAddrPort(res.DialTarget); perr == nil {
			dst = common.ConvergeAddrPort(dialed)
		}
	}

	binding := newTcpFlowBinding(c.PolicyEpoch(), res, [6]uint8{})
	flow, err := c.adoptTCPFlow(ctx, lease, lConn, rConn, binding, src, dst)
	if err != nil {
		// Adoption failed locally; the node was never exercised.
		res.Quality.Abandon()
		res.SelectPath.RecoveryAbandon()
		if errors.Is(err, ErrSessionManagerClosed) || errors.Is(err, errRoutingEpochOwnerUnavailable) {
			return &InboundDialError{Err: err}
		}
		return &InboundDialError{Err: fmt.Errorf("adopt inbound TCP flow: %w", err)}
	}
	defer closeEstablishedTCPFlow(rConn, flow)

	if c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"inbound":  inbound,
			"network":  "tcp",
			"outbound": res.Outbound.Name,
			"policy":   res.Outbound.GetSelectionPolicy(),
			"dialer":   res.Dialer.Property().Name,
			"sniffed":  domain,
		}).Debugf("%v <-> %v", src, res.DialTarget)
	}

	if established != nil {
		if err := established(); err != nil {
			return err
		}
	}
	return relayEstablishedTCPFlow(flow, relayConn, rConn, c.log, src, dst)
}

// Limits of one UDP association. They bound what a single authenticated (or
// LAN-local) client can make dae hold open.
const (
	inboundUDPMaxSessions   = 256
	inboundUDPPendingPacket = 16
	// inboundUDPMaxPacket is the largest datagram handled in either direction
	// (DNS with EDNS0, QUIC and games stay far below it). A datagram that fills
	// the buffer may have been truncated and is dropped, never forwarded.
	inboundUDPMaxPacket     = 16 * 1024
	inboundUDPSweepInterval = 10 * time.Second
)

// inboundBudget is a non-blocking counting limit shared by everything one
// inbound owns, so a single client cannot multiply per-association caps into
// unbounded memory on a small router.
type inboundBudget struct {
	n   atomic.Int64
	max int64
}

func newInboundBudget(max int64) *inboundBudget { return &inboundBudget{max: max} }

func (b *inboundBudget) acquire() bool {
	if b == nil {
		return true
	}
	if b.n.Add(1) > b.max {
		b.n.Add(-1)
		return false
	}
	return true
}

func (b *inboundBudget) release() {
	if b != nil {
		b.n.Add(-1)
	}
}

func inboundUDPIdleTimeout(port uint16) time.Duration {
	switch port {
	case 53:
		return DnsNatTimeout
	case 443, 8443:
		return QuicNatTimeout
	default:
		return DefaultNatTimeout
	}
}

// InboundUDPRelay is the outbound half of one UDP association: it keeps one
// outbound packet session per requested target, routes each target on its own
// (so inbound() and domain() rules apply per destination) and hands replies to
// sink. Sessions are symmetric: a reply is only accepted from the target the
// session was opened for.
//
// The relay is not tied to one control plane generation. Every new session is
// dialed through the plane that is active at that moment, so an association
// outlives a reload; sessions of a retired generation die with its outbounds
// and are re-created on the next datagram.
type InboundUDPRelay struct {
	inbound string
	src     netip.AddrPort
	plane   func() *ControlPlane
	sink    func(target InboundTarget, payload []byte)
	// budget, when set, bounds the sessions of every relay of one inbound.
	budget *inboundBudget
	// deferResolve routes domain targets by name before resolving them. Set
	// before the first Send.
	deferResolve bool

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	sessions map[string]*inboundUDPSession
	// failedUntil remembers targets whose session setup just failed, so a
	// stream of datagrams to an unreachable target does not redo DNS and
	// dialing for every packet.
	failedUntil map[string]int64
	closed      bool
}

// inboundUDPFailureBackoff is how long datagrams to a target are dropped after
// its session could not be set up.
const inboundUDPFailureBackoff = 3 * time.Second

// NewInboundUDPRelay creates a relay for the client at src. sink is called
// from session reader goroutines and must not retain payload. budget may be
// nil.
func NewInboundUDPRelay(ctx context.Context, inbound string, src netip.AddrPort, budget *inboundBudget, sink func(target InboundTarget, payload []byte)) *InboundUDPRelay {
	ctx, cancel := context.WithCancel(ctx)
	r := &InboundUDPRelay{
		inbound:  inbound,
		src:      common.ConvergeAddrPort(src),
		plane:    activeControlPlane,
		sink:     sink,
		budget:   budget,
		ctx:      ctx,
		cancel:   cancel,
		sessions: make(map[string]*inboundUDPSession),

		failedUntil: make(map[string]int64),
	}
	go r.sweep()
	return r
}

type inboundUDPSession struct {
	relay  *InboundUDPRelay
	key    string
	target InboundTarget
	idle   time.Duration

	mu         sync.Mutex
	pending    [][]byte
	conn       netproxy.Conn
	dialTarget string
	ready      bool
	closed     bool

	lastActive atomic.Int64
}

func (s *inboundUDPSession) touch() { s.lastActive.Store(time.Now().UnixNano()) }

// Send delivers one client datagram to target, creating the session on first
// use. It never blocks on dialing: datagrams that arrive while the session is
// still being dialed are queued (bounded) and flushed when it is up.
func (r *InboundUDPRelay) Send(target InboundTarget, payload []byte) {
	key := target.key()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	s := r.sessions[key]
	if s == nil {
		if until, failed := r.failedUntil[key]; failed {
			if time.Now().UnixNano() < until {
				r.mu.Unlock()
				return
			}
			delete(r.failedUntil, key)
		}
		if len(r.sessions) >= inboundUDPMaxSessions || !r.budget.acquire() {
			r.mu.Unlock()
			return
		}
		s = &inboundUDPSession{relay: r, key: key, target: target, idle: inboundUDPIdleTimeout(target.Port)}
		s.touch()
		r.sessions[key] = s
		r.mu.Unlock()
		s.queue(payload)
		go s.dial()
		return
	}
	r.mu.Unlock()
	s.touch()
	s.send(payload)
}

func (s *inboundUDPSession) queue(payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.pending) >= inboundUDPPendingPacket {
		return
	}
	s.pending = append(s.pending, append([]byte(nil), payload...))
}

func (s *inboundUDPSession) send(payload []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if !s.ready {
		if len(s.pending) < inboundUDPPendingPacket {
			s.pending = append(s.pending, append([]byte(nil), payload...))
		}
		s.mu.Unlock()
		return
	}
	conn, target := s.conn, s.dialTarget
	s.mu.Unlock()
	s.write(conn, target, payload)
}

func (s *inboundUDPSession) write(conn netproxy.Conn, dialTarget string, payload []byte) {
	if _, err := netutils.WriteUDPConn(conn, dialTarget, payload); err != nil {
		if isUdpEndpointWriteTolerated(err) {
			return
		}
		s.close()
		return
	}
	RecordUploadTraffic(int64(len(payload)))
}

func (s *inboundUDPSession) dial() {
	r := s.relay
	plane := r.plane()
	if plane == nil {
		s.close()
		return
	}
	release, ok := plane.acquireDrainTicketIfAdmitting(plane.acceptsRoutingEpochExecution)
	if !ok {
		s.close()
		return
	}
	defer release()

	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	stop := context.AfterFunc(plane.ctx, cancel)
	defer stop()

	dst, domain, nameOnly, err := plane.resolveInboundTarget(ctx, s.target, r.deferResolve)
	if err != nil {
		plane.logInboundUDPFailure(r.inbound, s.target, err)
		s.fail()
		return
	}
	conn, res, err := plane.routeDial(ctx, plane.inboundDialParam(r.inbound, "udp", r.src, dst, domain, nameOnly))
	if res != nil {
		// No first-byte feedback will arrive for this session; do not record
		// the absence of observation as evidence.
		res.Quality.Abandon()
		res.SelectPath.RecoveryAbandon()
	}
	if err != nil {
		plane.logInboundUDPFailure(r.inbound, s.target, err)
		s.fail()
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.conn, s.dialTarget, s.ready = conn, res.DialTarget, true
	queued := s.pending
	s.pending = nil
	s.mu.Unlock()

	if plane.log.IsLevelEnabled(logrus.DebugLevel) {
		plane.log.WithFields(logrus.Fields{
			"inbound":  r.inbound,
			"network":  "udp",
			"outbound": res.Outbound.Name,
			"dialer":   res.Dialer.Property().Name,
			"sniffed":  domain,
		}).Debugf("%v <-> %v", r.src, res.DialTarget)
	}

	go s.readLoop(conn)
	for _, p := range queued {
		s.write(conn, res.DialTarget, p)
	}
}

func (c *ControlPlane) logInboundUDPFailure(inbound string, target InboundTarget, err error) {
	if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"inbound": inbound,
			"target":  target.String(),
		}).WithError(err).Debug("inbound UDP session setup failed")
	}
}

func (s *inboundUDPSession) readLoop(conn netproxy.Conn) {
	defer s.close()
	buf := make([]byte, inboundUDPMaxPacket)
	for {
		n, err := netutils.ReadUDPConn(conn, buf)
		if err != nil {
			return
		}
		s.touch()
		if n >= len(buf) {
			// May have been truncated; never forward a damaged datagram.
			continue
		}
		RecordDownloadTraffic(int64(n))
		s.relay.sink(s.target, buf[:n])
	}
}

// fail closes a session whose setup failed and blocks the target briefly.
func (s *inboundUDPSession) fail() {
	r := s.relay
	r.mu.Lock()
	if !r.closed {
		r.failedUntil[s.key] = time.Now().Add(inboundUDPFailureBackoff).UnixNano()
	}
	r.mu.Unlock()
	s.close()
}

// close tears the session down and forgets it. Safe to call repeatedly.
func (s *inboundUDPSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conn := s.conn
	s.pending = nil
	s.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	r := s.relay
	// The session counted against the inbound's budget from creation; close
	// runs its body exactly once (guarded by closed above).
	r.budget.release()
	r.mu.Lock()
	if r.sessions[s.key] == s {
		delete(r.sessions, s.key)
	}
	r.mu.Unlock()
}

// sweep closes sessions that have been idle longer than their timeout.
func (r *InboundUDPRelay) sweep() {
	ticker := time.NewTicker(inboundUDPSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-ticker.C:
			var expired []*inboundUDPSession
			r.mu.Lock()
			for key, until := range r.failedUntil {
				if now.UnixNano() >= until {
					delete(r.failedUntil, key)
				}
			}
			for _, s := range r.sessions {
				if now.UnixNano()-s.lastActive.Load() > int64(s.idle) {
					expired = append(expired, s)
				}
			}
			r.mu.Unlock()
			for _, s := range expired {
				s.close()
			}
		}
	}
}

// Close ends the association and closes every session.
func (r *InboundUDPRelay) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	sessions := make([]*inboundUDPSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	r.cancel()
	for _, s := range sessions {
		s.close()
	}
}

// InboundDialErrorKind classifies a failed dial for protocol replies.
type InboundDialErrorKind int

const (
	InboundDialGeneral InboundDialErrorKind = iota
	InboundDialNetworkUnreachable
	InboundDialHostUnreachable
	InboundDialRefused
	InboundDialTimeout
	// InboundDialNotAllowed is a flow the routing rules send to block.
	InboundDialNotAllowed
)

// ClassifyInboundDialError maps a dial failure to a coarse kind.
func ClassifyInboundDialError(err error) InboundDialErrorKind {
	switch {
	case err == nil:
		return InboundDialGeneral
	case errors.Is(err, ob.ErrNoAliveDialer):
		return InboundDialNetworkUnreachable
	case errors.Is(err, ErrUnnamedFakeIP):
		// A FakeIP whose name is gone: the client asked for a host we can no
		// longer identify.
		return InboundDialHostUnreachable
	case errors.Is(err, net.ErrClosed):
		// The block outbound's dialer fails every dial with net.ErrClosed.
		return InboundDialNotAllowed
	case errors.Is(err, context.DeadlineExceeded):
		return InboundDialTimeout
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.HasPrefix(msg, "resolve "):
		// A failed lookup is about the name, even when the resolver itself
		// reports "network is unreachable" for its own socket.
		return InboundDialHostUnreachable
	case strings.Contains(msg, "connection refused"):
		return InboundDialRefused
	case strings.Contains(msg, "network is unreachable"):
		return InboundDialNetworkUnreachable
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "no such host"), strings.Contains(msg, "no real ip"):
		return InboundDialHostUnreachable
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"):
		return InboundDialTimeout
	}
	return InboundDialGeneral
}
