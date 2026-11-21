/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"
	"sync/atomic"
	"time"
)

// Listener states of an inbound.
const (
	InboundStateListening = "listening"
	InboundStateFailed    = "failed"
)

// InboundStatus is what the admin API reports about one configured inbound.
// It never carries the password.
type InboundStatus struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	Listen       string `json:"listen"`
	Username     string `json:"username,omitempty"`
	HasPassword  bool   `json:"has_password"`
	UDP          bool   `json:"udp"`
	UDPAdvertise string `json:"udp_advertise,omitempty"`
	Sniff        string `json:"sniff"`
	Resolve      string `json:"resolve"`

	// State is "listening", or "failed" with Error when the socket could not
	// be bound; a failed inbound is retried on the next reload.
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// Conns counts open client connections (including the TCP connection that
	// holds a UDP association), Associations the UDP associations and
	// UDPSessions their per-target sessions. Accepted counts every connection
	// since the listener started.
	Conns        int    `json:"conns"`
	Associations int    `json:"associations"`
	UDPSessions  int    `json:"udp_sessions"`
	Accepted     uint64 `json:"accepted"`
	Since        string `json:"since,omitempty"`
}

// activeInboundManager is the manager whose UDP sessions /v1/connections
// lists next to the control plane's flows.
var activeInboundManager atomic.Pointer[InboundManager]

// SetActive makes m the manager that the admin connection list reads.
func (m *InboundManager) SetActive() { activeInboundManager.Store(m) }

// Snapshot reports every configured inbound, in configuration order.
func (m *InboundManager) Snapshot() []InboundStatus {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]InboundStatus, 0, len(m.desired))
	for _, cfg := range m.desired {
		st := InboundStatus{
			Name:         cfg.Name,
			Protocol:     cfg.Protocol,
			Listen:       cfg.Listen,
			Username:     cfg.Username,
			HasPassword:  cfg.Password != "",
			UDP:          cfg.UDP,
			UDPAdvertise: cfg.UDPAdvertise,
			Sniff:        cfg.Sniff,
			Resolve:      cfg.Resolve,
			State:        InboundStateFailed,
			Error:        m.failed[cfg.Name],
		}
		if s := m.servers[cfg.Name]; s != nil {
			st.State, st.Error = InboundStateListening, ""
			st.Conns = s.connCount()
			st.Associations = int(s.assocs.n.Load())
			st.UDPSessions = int(s.udpSessions.n.Load())
			st.Accepted = s.accepted.Load()
			st.Since = s.started.UTC().Format(time.RFC3339)
		}
		out = append(out, st)
	}
	return out
}

func (s *inboundServer) connCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *inboundServer) addRelay(r *InboundUDPRelay) {
	s.mu.Lock()
	s.relays[r] = struct{}{}
	s.mu.Unlock()
}

func (s *inboundServer) removeRelay(r *InboundUDPRelay) {
	s.mu.Lock()
	delete(s.relays, r)
	s.mu.Unlock()
}

// udpConnections lists the UDP sessions of every inbound. Inbound UDP sessions
// are not flows of the control plane's session manager, so the connection list
// would not show them otherwise.
func (m *InboundManager) udpConnections() []AdminConnection {
	return m.collectUDPConnections(func(r *InboundUDPRelay, out []AdminConnection) []AdminConnection {
		return r.appendConnections(out)
	})
}

func (m *InboundManager) accountingUDPConnections() []AdminConnection {
	return m.collectUDPConnections(func(r *InboundUDPRelay, out []AdminConnection) []AdminConnection {
		return r.appendAccountingConnections(out)
	})
}

func (m *InboundManager) collectUDPConnections(collect func(*InboundUDPRelay, []AdminConnection) []AdminConnection) []AdminConnection {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	servers := make([]*inboundServer, 0, len(m.servers))
	for _, s := range m.servers {
		servers = append(servers, s)
	}
	m.mu.Unlock()

	var out []AdminConnection
	for _, s := range servers {
		s.mu.Lock()
		relays := make([]*InboundUDPRelay, 0, len(s.relays))
		for r := range s.relays {
			relays = append(relays, r)
		}
		s.mu.Unlock()
		for _, r := range relays {
			out = collect(r, out)
		}
	}
	return out
}

func (r *InboundUDPRelay) appendConnections(out []AdminConnection) []AdminConnection {
	return r.appendSessionConnections(out, (*inboundUDPSession).adminConnection)
}

func (r *InboundUDPRelay) appendAccountingConnections(out []AdminConnection) []AdminConnection {
	return r.appendSessionConnections(out, (*inboundUDPSession).accountingConnection)
}

func (r *InboundUDPRelay) appendSessionConnections(out []AdminConnection, build func(*inboundUDPSession) (AdminConnection, bool)) []AdminConnection {
	r.mu.Lock()
	sessions := make([]*inboundUDPSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		if item, ok := build(s); ok {
			out = append(out, item)
		}
	}
	return out
}

// adminConnection describes an established session; one still being dialed
// has no outbound to show yet.
func (s *inboundUDPSession) adminConnection() (AdminConnection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready || s.closed || s.closedAccounted.Load() {
		return AdminConnection{}, false
	}
	now := time.Now()
	return s.toAdminConnectionLocked(now), true
}

// accountingConnection returns an established session until RecordClosed has
// accounted for it, preventing gaps or double-counting during concurrent close.
func (s *inboundUDPSession) accountingConnection() (AdminConnection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready || s.closedAccounted.Load() {
		return AdminConnection{}, false
	}
	now := time.Now()
	return s.toAdminConnectionLocked(now), true
}

func (s *inboundUDPSession) toAdminConnectionLocked(now time.Time) AdminConnection {
	srcIP, srcPort := splitAddrPort(s.relay.src)
	var dstIP string
	if s.target.IP.IsValid() {
		dstIP = s.target.IP.Unmap().String()
	}
	target := displayConnectionTarget(s.target.String())
	if dstIP == "" && s.dialTarget != "" {
		if parsed, _ := splitTargetHostPort(s.dialTarget); parsed != "" {
			dstIP = parsed
		}
	}
	return AdminConnection{
		ID:            "in-udp:" + strconv.FormatUint(s.id, 10),
		Network:       "udp",
		Inbound:       s.relay.inbound,
		SrcIP:         srcIP,
		SrcPort:       srcPort,
		DstIP:         dstIP,
		DstPort:       s.target.Port,
		Target:        target,
		Domain:        sanitizeAdminDomain(s.domain),
		SniffedDomain: "",
		Rule:          s.rule,
		Outbound:      s.outbound,
		Dialer:        s.dialer,
		Chain:         buildAdminConnectionChain(s.outbound, "", s.dialer),
		Policy:        s.policy,
		StartTime:     formatFlowStart(s.startUnixNano),
		DurationMs:    flowDurationMs(s.startUnixNano, now),
		Upload:        s.upload.Load(),
		Download:      s.download.Load(),
	}
}

// CloseUDPConnectionByID terminates one established inbound UDP session by id ("in-udp:<n>").
func (m *InboundManager) CloseUDPConnectionByID(id string) bool {
	if m == nil || id == "" {
		return false
	}
	m.mu.Lock()
	servers := make([]*inboundServer, 0, len(m.servers))
	for _, s := range m.servers {
		servers = append(servers, s)
	}
	m.mu.Unlock()

	for _, srv := range servers {
		srv.mu.Lock()
		relays := make([]*InboundUDPRelay, 0, len(srv.relays))
		for r := range srv.relays {
			relays = append(relays, r)
		}
		srv.mu.Unlock()
		for _, r := range relays {
			r.mu.Lock()
			var target *inboundUDPSession
			for _, s := range r.sessions {
				if "in-udp:"+strconv.FormatUint(s.id, 10) == id {
					target = s
					break
				}
			}
			r.mu.Unlock()
			if target != nil {
				target.closeReason.CompareAndSwap(flowCloseNormal, flowCloseAborted)
				target.close()
				return true
			}
		}
	}
	return false
}

// CloseUDPConnectionsWhere terminates inbound UDP sessions satisfying match and returns the closed count.
func (m *InboundManager) CloseUDPConnectionsWhere(match func(AdminConnection) bool) int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	servers := make([]*inboundServer, 0, len(m.servers))
	for _, s := range m.servers {
		servers = append(servers, s)
	}
	m.mu.Unlock()

	var matched []*inboundUDPSession
	for _, srv := range servers {
		srv.mu.Lock()
		relays := make([]*InboundUDPRelay, 0, len(srv.relays))
		for r := range srv.relays {
			relays = append(relays, r)
		}
		srv.mu.Unlock()
		for _, r := range relays {
			r.mu.Lock()
			for _, s := range r.sessions {
				if item, ok := s.adminConnection(); ok && (match == nil || match(item)) {
					matched = append(matched, s)
				}
			}
			r.mu.Unlock()
		}
	}
	for _, s := range matched {
		s.closeReason.CompareAndSwap(flowCloseNormal, flowCloseAborted)
		s.close()
	}
	return len(matched)
}

// CloseUDPConnections terminates inbound UDP sessions matching filter and returns the closed count.
func (m *InboundManager) CloseUDPConnections(filter AdminConnectionFilter) int {
	filter = filter.normalized()
	if filter.IsEmpty() {
		return m.CloseUDPConnectionsWhere(nil)
	}
	return m.CloseUDPConnectionsWhere(func(item AdminConnection) bool {
		return item.matches(filter)
	})
}

var inboundUDPSessionSeq atomic.Uint64

// mergeInboundUDPConnections adds the inbound UDP sessions that pass filter to
// a control plane snapshot, keeping the bounded, heaviest-first shape.
func mergeInboundUDPConnections(snap AdminConnectionsSnapshot, udp []AdminConnection, filter AdminConnectionFilter, limit int) AdminConnectionsSnapshot {
	filter = filter.normalized()
	added := 0
	for _, item := range udp {
		if item.matches(filter) {
			snap.Connections = append(snap.Connections, item)
			added++
		}
	}
	if added == 0 {
		return snap
	}
	snap.Total += added
	sortAdminConnections(snap.Connections)
	if len(snap.Connections) > limit {
		snap.Connections = snap.Connections[:limit]
	}
	snap.Truncated = snap.Total > len(snap.Connections)
	return snap
}
