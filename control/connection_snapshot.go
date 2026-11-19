/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"sort"
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

// AdminConnection is one active flow for GET /api/v1/connections and WS connections.
type AdminConnection struct {
	ID           string           `json:"id"`
	Network      string           `json:"network"`
	Inbound      string           `json:"inbound,omitempty"`
	SrcIP        string           `json:"src_ip"`
	SrcPort      uint16           `json:"src_port"`
	DstIP        string           `json:"dst_ip"`
	DstPort      uint16           `json:"dst_port"`
	Target       string           `json:"target,omitempty"`
	Domain       string           `json:"domain,omitempty"`
	Mac          string           `json:"mac,omitempty"`
	Process      string           `json:"process,omitempty"`
	Rule         *RoutingRuleMeta `json:"rule,omitempty"`
	Outbound     string           `json:"outbound"`
	Dialer       string           `json:"dialer,omitempty"`
	Policy       string           `json:"policy,omitempty"`
	Offloaded    bool             `json:"offloaded,omitempty"`
	StartTime    string           `json:"start_time,omitempty"`
	DurationMs   int64            `json:"duration_ms"`
	Upload       uint64           `json:"upload"`
	Download     uint64           `json:"download"`
	UploadRate   uint64           `json:"upload_rate"`
	DownloadRate uint64           `json:"download_rate"`
}

// AdminConnectionsSnapshot is the bounded live-flow list. It never includes node URIs.
type AdminConnectionsSnapshot struct {
	Scope         string            `json:"scope,omitempty"`
	Total         int               `json:"total"`
	Truncated     bool              `json:"truncated"`
	Connections   []AdminConnection `json:"connections"`
	SnapshotAtMs  int64             `json:"snapshot_at_ms,omitempty"`
	UploadTotal   uint64            `json:"upload_total,omitempty"`
	DownloadTotal uint64            `json:"download_total,omitempty"`
}

// AdminConnectionFilter constrains connection queries, WS streams, and batch closes.
type AdminConnectionFilter struct {
	Network  string `json:"network,omitempty"`
	Outbound string `json:"outbound,omitempty"`
	Dialer   string `json:"dialer,omitempty"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Mac      string `json:"mac,omitempty"`
	Process  string `json:"process,omitempty"`
	Inbound  string `json:"inbound,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Query    string `json:"q,omitempty"`
	All      bool   `json:"all,omitempty"`
}

func (f AdminConnectionFilter) normalized() AdminConnectionFilter {
	f.Network = strings.ToLower(strings.TrimSpace(f.Network))
	f.Outbound = strings.TrimSpace(f.Outbound)
	f.Dialer = strings.TrimSpace(f.Dialer)
	f.SrcIP = strings.TrimSpace(f.SrcIP)
	f.DstIP = strings.TrimSpace(f.DstIP)
	f.Domain = strings.ToLower(strings.TrimSpace(f.Domain))
	f.Mac = strings.ToLower(strings.TrimSpace(f.Mac))
	f.Process = strings.TrimSpace(f.Process)
	f.Inbound = strings.TrimSpace(f.Inbound)
	f.Rule = strings.TrimSpace(f.Rule)
	f.Query = strings.ToLower(strings.TrimSpace(f.Query))
	return f
}

func (f AdminConnectionFilter) IsEmpty() bool {
	return f.Network == "" &&
		f.Outbound == "" &&
		f.Dialer == "" &&
		f.SrcIP == "" &&
		f.DstIP == "" &&
		f.Domain == "" &&
		f.Mac == "" &&
		f.Process == "" &&
		f.Inbound == "" &&
		f.Rule == "" &&
		f.Query == ""
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

func (c *ControlPlane) AdminConnections(limit int, filter AdminConnectionFilter) AdminConnectionsSnapshot {
	if c == nil {
		return AdminConnectionsSnapshot{Connections: []AdminConnection{}}
	}
	manager, _ := c.controlPlaneSessionManager()
	if manager == nil {
		return AdminConnectionsSnapshot{Connections: []AdminConnection{}}
	}
	limit = clampAdminConnectionLimit(limit)
	filter = filter.normalized()
	snap := manager.adminConnectionsSnapshot(limit, filter)
	snap = mergeInboundUDPConnections(snap, activeInboundManager.Load().udpConnections(), filter, limit)
	store := c.runtimeStatsStore()
	snap.UploadTotal = store.uploadTotal.Load()
	snap.DownloadTotal = store.downloadTotal.Load()
	return snap
}

func (m *SessionManager) adminConnectionsSnapshot(limit int, filter AdminConnectionFilter) AdminConnectionsSnapshot {
	filter = filter.normalized()
	now := time.Now()
	tcp, udp := m.snapshotFlowRuntimes()
	total := 0
	out := make([]AdminConnection, 0, min(limit, len(tcp)+len(udp)))
	appendFiltered := func(item AdminConnection) {
		if !item.matches(filter) {
			return
		}
		total++
		out = append(out, item)
	}
	for _, flow := range tcp {
		appendFiltered(adminConnectionFromTCPAt(flow, now))
	}
	for _, flow := range udp {
		appendFiltered(adminConnectionFromUDPAt(flow, now))
	}
	sortAdminConnections(out)
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []AdminConnection{}
	}
	return AdminConnectionsSnapshot{
		Scope:        m.adminSnapshotID,
		Total:        total,
		Truncated:    total > len(out),
		Connections:  out,
		SnapshotAtMs: now.UnixMilli(),
	}
}

func sortAdminConnections(out []AdminConnection) {
	sort.Slice(out, func(i, j int) bool {
		if bi, bj := out[i].Upload+out[i].Download, out[j].Upload+out[j].Download; bi != bj {
			return bi > bj
		}
		if len(out[i].ID) != len(out[j].ID) {
			return len(out[i].ID) < len(out[j].ID)
		}
		return out[i].ID < out[j].ID
	})
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
	return adminConnectionFromTCPAt(flow, time.Now())
}

func adminConnectionFromTCPAt(flow *FlowRuntime, now time.Time) AdminConnection {
	if flow == nil {
		return AdminConnection{}
	}
	binding := flow.Binding()
	srcIP, srcPort := splitAddrPort(flow.src)
	dstIP, dstPort := splitAddrPort(flow.dst)
	target := displayConnectionTarget(binding.Egress.Target)
	if dstIP == "" && dstPort == 0 && target != "" {
		dstIP, dstPort = splitTargetHostPort(target)
	}
	item := AdminConnection{
		ID:         "tcp:" + strconv.FormatUint(flow.id, 10),
		Network:    flow.network,
		Inbound:    binding.Inbound,
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		DstIP:      dstIP,
		DstPort:    dstPort,
		Target:     target,
		Mac:        macString(flow.mac),
		Process:    binding.Process,
		Rule:       binding.Route.Rule,
		Offloaded:  flow.offloaded.Load(),
		StartTime:  formatFlowStart(flow.startUnixNano),
		DurationMs: flowDurationMs(flow.startUnixNano, now),
		Upload:     flow.uploadBytes.Load(),
		Download:   flow.downloadBytes.Load(),
	}
	fillAdminConnectionEgress(&item, binding.Egress.Outbound, binding.Egress.Dialer, binding.Egress.SniffedDomain, binding.Egress.Target, binding.Egress.IsDialIp)
	return item
}

func adminConnectionFromUDP(flow *UDPFlowRuntime) AdminConnection {
	return adminConnectionFromUDPAt(flow, time.Now())
}

func adminConnectionFromUDPAt(flow *UDPFlowRuntime, now time.Time) AdminConnection {
	if flow == nil {
		return AdminConnection{}
	}
	src, dst := udpFlowAddrs(flow)
	sniffed, targetRaw, isDialIP := udpFlowSniff(flow)
	srcIP, srcPort := splitAddrPort(src)
	dstIP, dstPort := splitAddrPort(dst)
	target := displayConnectionTarget(targetRaw)
	if dstIP == "" && dstPort == 0 && target != "" {
		dstIP, dstPort = splitTargetHostPort(target)
	}
	item := AdminConnection{
		ID:         "udp:" + strconv.FormatUint(flow.id, 10),
		Network:    flow.network,
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		DstIP:      dstIP,
		DstPort:    dstPort,
		Target:     target,
		Mac:        macString(udpFlowMac(flow.endpoint, flow.binding)),
		Process:    flow.binding.Process,
		Rule:       flow.binding.Rule,
		StartTime:  formatFlowStart(flow.startUnixNano),
		DurationMs: flowDurationMs(flow.startUnixNano, now),
		Upload:     flow.uploadBytes.Load(),
		Download:   flow.downloadBytes.Load(),
	}
	if item.Mac == "" {
		item.Mac = macString(flow.mac)
	}
	fillAdminConnectionEgress(&item, flow.binding.Egress.Outbound, flow.binding.Egress.Dialer, sniffed, targetRaw, isDialIP)
	return item
}

func splitAddrPort(addr netip.AddrPort) (string, uint16) {
	if !addr.IsValid() {
		return "", 0
	}
	return addr.Addr().Unmap().String(), addr.Port()
}

func splitTargetHostPort(target string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0
	}
	var port uint16
	if p, err := strconv.ParseUint(portStr, 10, 16); err == nil {
		port = uint16(p)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), port
	}
	return "", port
}

func flowDurationMs(startUnixNano int64, now time.Time) int64 {
	if startUnixNano <= 0 {
		return 0
	}
	d := now.UnixMilli() - startUnixNano/int64(time.Millisecond)
	if d < 0 {
		return 0
	}
	return d
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

func matchIPOrCIDR(value string, pattern string) bool {
	if pattern == "" {
		return true
	}
	if value == "" {
		return false
	}
	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		addr, aerr := netip.ParseAddr(value)
		return aerr == nil && prefix.Contains(addr.Unmap())
	}
	if wantAddr, err := netip.ParseAddr(pattern); err == nil {
		gotAddr, aerr := netip.ParseAddr(value)
		return aerr == nil && wantAddr.Unmap() == gotAddr.Unmap()
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
}

func matchNetworkFilter(network string, want string) bool {
	if want == "" {
		return true
	}
	n := strings.ToLower(network)
	if n == want {
		return true
	}
	if want == "tcp" && strings.HasPrefix(n, "tcp") {
		return true
	}
	if want == "udp" && strings.HasPrefix(n, "udp") {
		return true
	}
	return false
}

// Matches reports whether item satisfies filter.
func (item AdminConnection) Matches(filter AdminConnectionFilter) bool {
	return item.matches(filter.normalized())
}

func (item AdminConnection) matches(filter AdminConnectionFilter) bool {
	if !matchNetworkFilter(item.Network, filter.Network) {
		return false
	}
	if filter.Outbound != "" && !strings.EqualFold(item.Outbound, filter.Outbound) {
		return false
	}
	if filter.Dialer != "" && !strings.EqualFold(item.Dialer, filter.Dialer) {
		return false
	}
	if !matchIPOrCIDR(item.SrcIP, filter.SrcIP) {
		return false
	}
	if !matchIPOrCIDR(item.DstIP, filter.DstIP) {
		return false
	}
	if filter.Domain != "" && !strings.Contains(strings.ToLower(item.Domain), filter.Domain) {
		return false
	}
	if filter.Mac != "" && !strings.Contains(strings.ToLower(item.Mac), filter.Mac) {
		return false
	}
	if filter.Process != "" && !strings.EqualFold(item.Process, filter.Process) {
		return false
	}
	if filter.Inbound != "" && !strings.EqualFold(item.Inbound, filter.Inbound) {
		return false
	}
	if filter.Rule != "" {
		if item.Rule == nil {
			return false
		}
		if strconv.Itoa(item.Rule.Index) != filter.Rule &&
			!strings.Contains(strings.ToLower(item.Rule.Raw), strings.ToLower(filter.Rule)) {
			return false
		}
	}
	if filter.Query != "" {
		ruleRaw := ""
		if item.Rule != nil {
			ruleRaw = strings.ToLower(item.Rule.Raw)
		}
		if !strings.Contains(strings.ToLower(item.Domain), filter.Query) &&
			!strings.Contains(strings.ToLower(item.Target), filter.Query) &&
			!strings.Contains(strings.ToLower(item.SrcIP), filter.Query) &&
			!strings.Contains(strings.ToLower(item.DstIP), filter.Query) &&
			!strings.Contains(strings.ToLower(item.Process), filter.Query) &&
			!strings.Contains(strings.ToLower(item.Outbound), filter.Query) &&
			!strings.Contains(strings.ToLower(item.Dialer), filter.Query) &&
			!strings.Contains(strings.ToLower(item.Mac), filter.Query) &&
			!strings.Contains(strings.ToLower(item.Inbound), filter.Query) &&
			!strings.Contains(ruleRaw, filter.Query) {
			return false
		}
	}
	return true
}
