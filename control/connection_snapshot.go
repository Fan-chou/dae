/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
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
	m.flows.Range(func(_, value any) bool { tcp = append(tcp, value.(*FlowRuntime)); return true })
	m.udpFlows.Range(func(_, value any) bool { udp = append(udp, value.(*UDPFlowRuntime)); return true })
	return tcp, udp
}

func adminConnectionFromTCP(flow *FlowRuntime) AdminConnection {
	if flow == nil {
		return AdminConnection{}
	}
	item := AdminConnection{
		ID:       strconv.FormatUint(flow.id, 10),
		Network:  flow.network,
		Src:      formatAddrPort(flow.src),
		Dst:      formatAddrPort(flow.dst),
		Mac:      macString(flow.mac),
		Upload:   flow.uploadBytes.Load(),
		Download: flow.downloadBytes.Load(),
		Start:    formatFlowStart(flow.startUnixNano),
	}
	fillAdminConnectionEgress(&item, flow.binding.Egress.Outbound, flow.binding.Egress.Dialer, flow.binding.Egress.SniffedDomain, flow.binding.Egress.Target, flow.binding.Egress.IsDialIp)
	if item.Dst == "" {
		item.Dst = displayConnectionTarget(flow.binding.Egress.Target)
	}
	return item
}

func adminConnectionFromUDP(flow *UDPFlowRuntime) AdminConnection {
	if flow == nil {
		return AdminConnection{}
	}
	src, dst := udpFlowAddrs(flow)
	sniffed, target, isDialIP := udpFlowSniff(flow)
	item := AdminConnection{
		ID:       strconv.FormatUint(flow.id, 10),
		Network:  flow.network,
		Src:      formatAddrPort(src),
		Dst:      formatAddrPort(dst),
		Mac:      macString(udpFlowMac(flow.endpoint, flow.binding)),
		Upload:   flow.uploadBytes.Load(),
		Download: flow.downloadBytes.Load(),
		Start:    formatFlowStart(flow.startUnixNano),
	}
	if item.Mac == "" {
		item.Mac = macString(flow.mac)
	}
	fillAdminConnectionEgress(&item, flow.binding.Egress.Outbound, flow.binding.Egress.Dialer, sniffed, target, isDialIP)
	if item.Dst == "" {
		item.Dst = displayConnectionTarget(target)
	}
	return item
}

func formatAddrPort(addr netip.AddrPort) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func displayConnectionTarget(target string) string {
	value := strings.TrimSpace(target)
	if value == "" || strings.Contains(value, "://") || value == "invalid AddrPort" {
		return ""
	}
	return value
}

func udpFlowMac(endpoint *UdpEndpoint, binding UdpFlowBinding) [6]uint8 {
	if binding.Mac != [6]uint8{} {
		return binding.Mac
	}
	if endpoint == nil {
		return [6]uint8{}
	}
	if endpoint.poolKey.RouteScope.Mac != [6]uint8{} {
		return endpoint.poolKey.RouteScope.Mac
	}
	endpoint.routingMu.RLock()
	defer endpoint.routingMu.RUnlock()
	if endpoint.hasRoutingCache {
		return endpoint.routingCache.Mac
	}
	return [6]uint8{}
}

func udpFlowAddrs(flow *UDPFlowRuntime) (src, dst netip.AddrPort) {
	if flow == nil {
		return netip.AddrPort{}, netip.AddrPort{}
	}
	src = flow.src
	dst = flow.dst
	if flow.endpoint == nil {
		return src, dst
	}
	if !src.IsValid() {
		src = flow.endpoint.poolKey.Src
	}
	if !dst.IsValid() {
		dst = flow.endpoint.poolKey.Dst
	}
	if !dst.IsValid() {
		if pair := flow.endpoint.udpConnStateLastPair.Load(); pair != nil && pair.dst.IsValid() {
			dst = pair.dst
		}
	}
	if !dst.IsValid() {
		flow.endpoint.routingMu.RLock()
		if flow.endpoint.hasRoutingCache && flow.endpoint.routingCacheDst.IsValid() {
			dst = flow.endpoint.routingCacheDst
		}
		flow.endpoint.routingMu.RUnlock()
	}
	return src, dst
}

func udpFlowSniff(flow *UDPFlowRuntime) (sniffed, target string, isDialIP bool) {
	if flow == nil {
		return "", "", false
	}
	sniffed = flow.binding.Egress.SniffedDomain
	target = flow.binding.Egress.Target
	isDialIP = flow.binding.Egress.IsDialIp
	if flow.endpoint != nil {
		if flow.endpoint.SniffedDomain != "" {
			sniffed = flow.endpoint.SniffedDomain
		}
		if target == "" {
			target = flow.endpoint.DialTarget
		}
		if flow.endpoint.flowBindingSet {
			isDialIP = flow.endpoint.flowBindingDialIP
		}
	}
	return sniffed, target, isDialIP
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
