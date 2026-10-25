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
			out = r.appendConnections(out)
		}
	}
	return out
}

func (r *InboundUDPRelay) appendConnections(out []AdminConnection) []AdminConnection {
	r.mu.Lock()
	sessions := make([]*inboundUDPSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		if item, ok := s.adminConnection(); ok {
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
	if !s.ready || s.closed {
		return AdminConnection{}, false
	}
	return AdminConnection{
		ID:       "i" + strconv.FormatUint(s.id, 10),
		Network:  "udp",
		Src:      formatAddrPort(s.relay.src),
		Dst:      s.target.String(),
		Domain:   s.domain,
		Inbound:  s.relay.inbound,
		Outbound: s.outbound,
		Dialer:   s.dialer,
		Policy:   s.policy,
		Start:    formatFlowStart(s.startUnixNano),
		Upload:   s.upload.Load(),
		Download: s.download.Load(),
	}, true
}

var inboundUDPSessionSeq atomic.Uint64

// mergeInboundUDPConnections adds the inbound UDP sessions that pass filter to
// a control plane snapshot, keeping the bounded, heaviest-first shape.
func mergeInboundUDPConnections(snap AdminConnectionsSnapshot, udp []AdminConnection, filter adminConnectionFilter, limit int) AdminConnectionsSnapshot {
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
