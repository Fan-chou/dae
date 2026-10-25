/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/inbound/socks5"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

const (
	// socksHandshakeTimeout bounds negotiation, authentication and the request,
	// so a client that stalls cannot hold a connection slot.
	socksHandshakeTimeout = 15 * time.Second
	// inboundMaxConns bounds the connections one inbound serves at a time.
	inboundMaxConns = 4096
	// inboundMaxAssociations bounds the UDP associations of one inbound, and
	// inboundMaxUDPSessions all their outbound sessions together. With the
	// per-session buffer they cap the memory a single client can pin.
	inboundMaxAssociations = 256
	inboundMaxUDPSessions  = 2048
)

// InboundManager owns the user-space inbound listeners of the process. It is
// independent of control plane generations: every accepted flow is dispatched
// to the generation that is active at that moment, so a reload never rebinds
// a port whose configuration did not change.
type InboundManager struct {
	log *logrus.Logger

	mu      sync.Mutex
	servers map[string]*inboundServer
	closed  bool
	// desired is the last configuration applied, and failed the bind error of
	// each inbound that is in it but not running.
	desired []config.Inbound
	failed  map[string]string
}

// NewInboundManager creates an empty manager.
func NewInboundManager(log *logrus.Logger) *InboundManager {
	return &InboundManager{log: log, servers: make(map[string]*inboundServer), failed: make(map[string]string)}
}

// Apply reconciles the running listeners with inbounds: new ones are started,
// removed or changed ones are stopped (closing their connections), unchanged
// ones keep running. A listener that cannot bind is logged and retried on the
// next Apply; it never affects the others or the transparent proxy.
func (m *InboundManager) Apply(inbounds []config.Inbound) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.desired = append([]config.Inbound(nil), inbounds...)
	m.failed = make(map[string]string)
	desired := make(map[string]config.Inbound, len(inbounds))
	for _, in := range inbounds {
		desired[in.Name] = in
	}
	for name, s := range m.servers {
		want, ok := desired[name]
		if ok && want == s.cfg {
			continue
		}
		s.stop()
		delete(m.servers, name)
		m.log.Infof("SOCKS5 inbound %q stopped", name)
	}
	for _, in := range inbounds {
		if _, running := m.servers[in.Name]; running {
			continue
		}
		s, err := startInboundServer(m.log, in)
		if err != nil {
			m.failed[in.Name] = err.Error()
			m.log.Errorf("SOCKS5 inbound %q failed to start (other inbounds and tproxy continue): %v", in.Name, err)
			continue
		}
		m.servers[in.Name] = s
		m.log.Infof("SOCKS5 inbound %q listening on %v (udp=%v, auth=%v)", in.Name, in.Listen, in.UDP, in.HasAuth())
	}
}

// Close stops every listener; Apply is a no-op afterwards.
func (m *InboundManager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for name, s := range m.servers {
		s.stop()
		delete(m.servers, name)
	}
}

type inboundServer struct {
	log    *logrus.Logger
	cfg    config.Inbound
	creds  *socks5.Credentials
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	slots  chan struct{}

	assocs      *inboundBudget
	udpSessions *inboundBudget

	accepted atomic.Uint64
	started  time.Time

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	relays map[*InboundUDPRelay]struct{}
}

func startInboundServer(log *logrus.Logger, cfg config.Inbound) (*inboundServer, error) {
	addr, err := cfg.ListenAddrPort()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &inboundServer{
		log:     log,
		cfg:     cfg,
		ln:      ln,
		ctx:     ctx,
		cancel:  cancel,
		slots:   make(chan struct{}, inboundMaxConns),
		conns:   make(map[net.Conn]struct{}),
		relays:  make(map[*InboundUDPRelay]struct{}),
		started: time.Now(),

		assocs:      newInboundBudget(inboundMaxAssociations),
		udpSessions: newInboundBudget(inboundMaxUDPSessions),
	}
	if cfg.HasAuth() {
		s.creds = &socks5.Credentials{Username: cfg.Username, Password: cfg.Password}
	}
	go s.acceptLoop()
	return s, nil
}

func (s *inboundServer) stop() {
	s.cancel()
	_ = s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
}

func (s *inboundServer) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *inboundServer) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *inboundServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warnf("SOCKS5 inbound %q accept: %v", s.cfg.Name, err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		if !s.track(conn) {
			<-s.slots
			_ = conn.Close()
			return
		}
		s.accepted.Add(1)
		go func() {
			defer func() { <-s.slots }()
			s.serveConn(conn)
		}()
	}
}

func (s *inboundServer) serveConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Errorf("SOCKS5 inbound %q: panic serving %v: %v", s.cfg.Name, conn.RemoteAddr(), r)
		}
		s.untrack(conn)
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(socksHandshakeTimeout))
	if err := socks5.Handshake(conn, s.creds); err != nil {
		if s.log.IsLevelEnabled(logrus.DebugLevel) {
			s.log.Debugf("SOCKS5 inbound %q: handshake with %v: %v", s.cfg.Name, conn.RemoteAddr(), err)
		}
		return
	}
	cmd, addr, err := socks5.ReadRequest(conn)
	if err != nil {
		var re *socks5.ReplyError
		if errors.As(err, &re) {
			_ = socks5.WriteReply(conn, re.Code, socks5.Addr{})
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})

	plane := activeControlPlane()
	if plane == nil || !plane.acceptsRoutingEpochExecution() {
		_ = socks5.WriteReply(conn, socks5.ReplyGeneralFailure, socks5.Addr{})
		return
	}
	switch cmd {
	case socks5.CmdConnect:
		s.handleConnect(plane, conn, addr)
	case socks5.CmdUDPAssociate:
		if !s.cfg.UDP {
			_ = socks5.WriteReply(conn, socks5.ReplyCommandNotSupport, socks5.Addr{})
			return
		}
		s.handleAssociate(conn, addr)
	default:
		_ = socks5.WriteReply(conn, socks5.ReplyCommandNotSupport, socks5.Addr{})
	}
}

func inboundTargetFromSocks(a socks5.Addr) InboundTarget {
	return InboundTarget{Domain: a.Domain, IP: a.IP, Port: a.Port}
}

func socksAddrFromTarget(t InboundTarget) socks5.Addr {
	if t.Domain != "" {
		return socks5.Addr{Domain: t.Domain, Port: t.Port}
	}
	return socks5.Addr{IP: t.IP, Port: t.Port}
}

func socksReplyCode(kind InboundDialErrorKind) byte {
	switch kind {
	case InboundDialNetworkUnreachable:
		return socks5.ReplyNetworkUnreachable
	case InboundDialHostUnreachable:
		return socks5.ReplyHostUnreachable
	case InboundDialRefused:
		return socks5.ReplyConnectionRefused
	case InboundDialTimeout:
		return socks5.ReplyTTLExpired
	case InboundDialNotAllowed:
		return socks5.ReplyNotAllowed
	default:
		return socks5.ReplyGeneralFailure
	}
}

func (s *inboundServer) handleConnect(plane *ControlPlane, conn net.Conn, addr socks5.Addr) {
	// The flow ends with the inbound or with the generation that routed it,
	// like a transparent connection ends with its generation.
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	stop := context.AfterFunc(plane.ctx, cancel)
	defer stop()

	replied := false
	err := plane.ServeInboundTCP(ctx, s.cfg.Name, conn, inboundTargetFromSocks(addr), InboundTCPOptions{Sniff: s.cfg.SniffEnabled(), DeferResolve: s.cfg.DeferResolve()}, func() error {
		replied = true
		return socks5.WriteReply(conn, socks5.ReplySucceeded, socks5.Addr{})
	})
	if err == nil {
		return
	}
	var dialErr *InboundDialError
	if !replied {
		code := byte(socks5.ReplyGeneralFailure)
		if errors.As(err, &dialErr) {
			code = socksReplyCode(ClassifyInboundDialError(dialErr.Err))
		}
		_ = socks5.WriteReply(conn, code, socks5.Addr{})
	}
	if errors.As(err, &dialErr) {
		if s.log.IsLevelEnabled(logrus.DebugLevel) {
			s.log.Debugf("SOCKS5 inbound %q: %v -> %v: %v", s.cfg.Name, conn.RemoteAddr(), addr, err)
		}
		return
	}
	s.log.Warnf("SOCKS5 inbound %q: %v -> %v: %v", s.cfg.Name, conn.RemoteAddr(), addr, err)
}

// handleAssociate serves UDP ASSOCIATE: a UDP relay socket is opened on the
// address the client reached us on, and the association lives exactly as long
// as the TCP control connection (RFC 1928 section 6).
func (s *inboundServer) handleAssociate(conn net.Conn, req socks5.Addr) {
	fail := func(code byte) { _ = socks5.WriteReply(conn, code, socks5.Addr{}) }

	if !s.assocs.acquire() {
		fail(socks5.ReplyGeneralFailure)
		return
	}
	defer s.assocs.release()

	local, ok := conn.LocalAddr().(*net.TCPAddr)
	remote, ok2 := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || !ok2 {
		fail(socks5.ReplyGeneralFailure)
		return
	}
	clientIP := remote.AddrPort().Addr().Unmap()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		s.log.Warnf("SOCKS5 inbound %q: open UDP relay: %v", s.cfg.Name, err)
		fail(socks5.ReplyGeneralFailure)
		return
	}
	defer func() { _ = pc.Close() }()

	advertise := local.AddrPort().Addr().Unmap()
	if s.cfg.UDPAdvertise != "" {
		if ip, perr := netip.ParseAddr(s.cfg.UDPAdvertise); perr == nil {
			advertise = ip.Unmap()
		}
	}
	relayPort := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	if err := socks5.WriteReply(conn, socks5.ReplySucceeded, socks5.AddrFromAddrPort(netip.AddrPortFrom(advertise, relayPort))); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	// The TCP connection is the association's lifetime: anything the client
	// writes on it is ignored, and its end ends the association.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		cancel()
	}()
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	var (
		relay  *InboundUDPRelay
		client netip.AddrPort
	)
	defer func() {
		if relay != nil {
			relay.Close()
		}
	}()
	buf := make([]byte, inboundUDPMaxPacket)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if from.Addr().Unmap() != clientIP || n >= len(buf) {
			// Other hosts are ignored; a datagram that fills the buffer may
			// have been truncated and is dropped.
			continue
		}
		if relay == nil {
			if req.Port != 0 && from.Port() != req.Port {
				continue
			}
			client = from
			sink := func(target InboundTarget, payload []byte) {
				pkt := socks5.AppendUDPHeader(make([]byte, 0, 32+len(target.Domain)+len(payload)), socksAddrFromTarget(target))
				pkt = append(pkt, payload...)
				_, _ = pc.WriteToUDPAddrPort(pkt, client)
			}
			relay = NewInboundUDPRelay(ctx, s.cfg.Name, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), s.udpSessions, sink)
			relay.deferResolve = s.cfg.DeferResolve()
			s.addRelay(relay)
			defer s.removeRelay(relay)
		} else if from != client {
			continue
		}
		target, payload, err := socks5.ParseUDPPacket(buf[:n])
		if err != nil || target.Port == 0 {
			continue
		}
		relay.Send(inboundTargetFromSocks(target), payload)
	}
}

// String describes the server for logs.
func (s *inboundServer) String() string {
	return fmt.Sprintf("socks5 inbound %q on %v", s.cfg.Name, s.cfg.Listen)
}
