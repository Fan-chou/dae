/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

const (
	adminConnectionsDefaultLimit = 256
	adminConnectionsMaxLimit     = 1024
)

// AdminConnection is one tproxy-captured live flow for GET /v1/connections.
type AdminConnection struct {
	ID       string `json:"id"`
	Network  string `json:"network"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Domain   string `json:"domain,omitempty"`
	Mac      string `json:"mac,omitempty"`
	Outbound string `json:"outbound"`
	Dialer   string `json:"dialer,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Start    string `json:"start,omitempty"`
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}

// AdminConnectionsSnapshot is the bounded live-flow list. It never includes node URIs.
type AdminConnectionsSnapshot struct {
	Total       int               `json:"total"`
	Truncated   bool              `json:"truncated"`
	Connections []AdminConnection `json:"connections"`
}

type adminConnectionFilter struct {
	outbound string
	src      string
	mac      string
}

func clampAdminConnectionLimit(limit int) int {
	if limit <= 0 {
		return adminConnectionsDefaultLimit
	}
	if limit > adminConnectionsMaxLimit {
		return adminConnectionsMaxLimit
	}
	return limit
}

func (c *ControlPlane) AdminConnections(limit int, outbound, src, mac string) AdminConnectionsSnapshot {
	if c == nil {
		return AdminConnectionsSnapshot{Connections: []AdminConnection{}}
	}
	manager, _ := c.controlPlaneSessionManager()
	if manager == nil {
		return AdminConnectionsSnapshot{Connections: []AdminConnection{}}
	}
	return manager.adminConnectionsSnapshot(clampAdminConnectionLimit(limit), adminConnectionFilter{
		outbound: strings.TrimSpace(outbound),
		src:      strings.TrimSpace(src),
		mac:      strings.ToLower(strings.TrimSpace(mac)),
	})
}

func (m *SessionManager) adminConnectionsSnapshot(limit int, filter adminConnectionFilter) AdminConnectionsSnapshot {
	tcp, udp := m.snapshotFlowRuntimes()
	total := 0
	out := make([]AdminConnection, 0, min(limit, len(tcp)+len(udp)))
	appendFiltered := func(item AdminConnection) {
		if !item.matches(filter) {
			return
		}
		total++
		if len(out) < limit {
			out = append(out, item)
		}
	}
	for _, flow := range tcp {
		appendFiltered(adminConnectionFromTCP(flow))
	}
	for _, flow := range udp {
		appendFiltered(adminConnectionFromUDP(flow))
	}
	if out == nil {
		out = []AdminConnection{}
	}
	return AdminConnectionsSnapshot{
		Total:       total,
		Truncated:   total > len(out),
		Connections: out,
	}
}

func (m *SessionManager) snapshotFlowRuntimes() (tcp []*FlowRuntime, udp []*UDPFlowRuntime) {
	if m == nil {
		return nil, nil
	}
	m.mu.RLock()
	tcp = make([]*FlowRuntime, 0, len(m.flows))
	for _, flow := range m.flows {
		tcp = append(tcp, flow)
	}
	udp = make([]*UDPFlowRuntime, 0, len(m.udpFlows))
	for _, flow := range m.udpFlows {
		udp = append(udp, flow)
	}
	m.mu.RUnlock()
	return tcp, udp
}

func adminConnectionFromTCP(flow *FlowRuntime) AdminConnection {
	if flow == nil {
		return AdminConnection{}
	}
	item := AdminConnection{
		ID:       strconv.FormatUint(flow.id, 10),
		Network:  flow.network,
		Src:      flow.src.String(),
		Dst:      flow.dst.String(),
		Mac:      macString(flow.mac),
		Upload:   flow.uploadBytes.Load(),
		Download: flow.downloadBytes.Load(),
		Start:    formatFlowStart(flow.startUnixNano),
	}
	fillAdminConnectionEgress(&item, flow.binding.Egress.Outbound, flow.binding.Egress.Dialer, flow.binding.Egress.SniffedDomain, flow.binding.Egress.Target, flow.binding.Egress.IsDialIp)
	if item.Dst == "" || item.Dst == "invalid AddrPort" {
		item.Dst = flow.binding.Egress.Target
	}
	return item
}

func adminConnectionFromUDP(flow *UDPFlowRuntime) AdminConnection {
	if flow == nil {
		return AdminConnection{}
	}
	item := AdminConnection{
		ID:       strconv.FormatUint(flow.id, 10),
		Network:  flow.network,
		Src:      flow.src.String(),
		Dst:      flow.dst.String(),
		Mac:      macString(flow.mac),
		Upload:   flow.uploadBytes.Load(),
		Download: flow.downloadBytes.Load(),
		Start:    formatFlowStart(flow.startUnixNano),
	}
	fillAdminConnectionEgress(&item, flow.binding.Egress.Outbound, flow.binding.Egress.Dialer, flow.binding.Egress.SniffedDomain, flow.binding.Egress.Target, flow.binding.Egress.IsDialIp)
	return item
}

func fillAdminConnectionEgress(item *AdminConnection, group *outbound.DialerGroup, d *dialer.Dialer, sniffed, target string, isDialIP bool) {
	if group != nil {
		item.Outbound = group.Name
		item.Policy = string(group.GetSelectionPolicy())
	}
	if d != nil && d.Property() != nil {
		item.Dialer = d.Property().Name
	}
	domain := sniffed
	if domain == "" && !isDialIP {
		domain = target
	}
	if strings.Contains(domain, "://") {
		domain = ""
	}
	item.Domain = domain
}

func macString(mac [6]uint8) string {
	if mac == [6]uint8{} {
		return ""
	}
	return Mac2String(mac[:])
}

func formatFlowStart(unixNano int64) string {
	if unixNano <= 0 {
		return ""
	}
	return time.Unix(0, unixNano).UTC().Format(time.RFC3339)
}

func (item AdminConnection) matches(filter adminConnectionFilter) bool {
	if filter.outbound != "" && !strings.EqualFold(item.Outbound, filter.outbound) {
		return false
	}
	if filter.src != "" && !strings.Contains(item.Src, filter.src) {
		return false
	}
	if filter.mac != "" && !strings.Contains(strings.ToLower(item.Mac), filter.mac) {
		return false
	}
	return true
}
