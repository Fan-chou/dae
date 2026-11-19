/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

var processStartedAt = time.Now().UTC()

// AdminStatus is the JSON body kept for internal/diagnostic metrics helpers.
// It never includes node URIs or credentials.
type AdminStatus struct {
	Version           string                   `json:"version"`
	Running           bool                     `json:"running"`
	LanInterface      []string                 `json:"lan_interface"`
	WanInterface      []string                 `json:"wan_interface"`
	UploadRate        uint64                   `json:"upload_rate"`
	DownloadRate      uint64                   `json:"download_rate"`
	UploadTotal       uint64                   `json:"upload_total"`
	DownloadTotal     uint64                   `json:"download_total"`
	ActiveConnections int                      `json:"active_connections"`
	UDPSessions       int                      `json:"udp_sessions"`
	RssBytes          uint64                   `json:"rss_bytes"`
	FdCount           int                      `json:"fd_count"`
	TrafficSamples    []AdminTrafficSample     `json:"traffic_samples,omitempty"`
	UDPReplyDrought   *UDPReplyDroughtSnapshot `json:"udp_reply_drought,omitempty"`
}

// AdminBpfOverflow reports eBPF map overflow counters.
type AdminBpfOverflow struct {
	UDP uint64 `json:"udp"`
	TCP uint64 `json:"tcp"`
}

// AdminSystemInfo is the slow-changing runtime environment metadata for GET /api/v1/system.
type AdminSystemInfo struct {
	Version       string   `json:"version"`
	Running       bool     `json:"running"`
	Hostname      string   `json:"hostname,omitempty"`
	GoVersion     string   `json:"go_version"`
	OS            string   `json:"os"`
	Arch          string   `json:"arch"`
	NumCPU        int      `json:"num_cpu"`
	StartedAt     string   `json:"started_at"`
	UptimeSec     int64    `json:"uptime_sec"`
	DialMode      string   `json:"dial_mode,omitempty"`
	LanInterface  []string `json:"lan_interface"`
	WanInterface  []string `json:"wan_interface"`
	EBPFEnabled   bool     `json:"ebpf_enabled"`
	LogLevel      string   `json:"log_level,omitempty"`
	InboundsCount int      `json:"inbounds_count"`
	GroupsCount   int      `json:"groups_count"`
	PolicyEpoch   uint64   `json:"policy_epoch,omitempty"`
	PolicyHash    string   `json:"policy_hash,omitempty"`
}

// AdminMetricsSnapshot is the real-time O(1) runtime metrics payload for GET /api/v1/metrics and WS metrics.
type AdminUDPReplyDroughtSummary struct {
	Mode       string               `json:"mode"`
	Generation uint64               `json:"generation"`
	Group      string               `json:"group,omitempty"`
	Client     string               `json:"client,omitempty"`
	Contract   string               `json:"contract,omitempty"`
	Stats      UDPReplyDroughtStats `json:"stats"`
	Excluded   map[string]int       `json:"excluded,omitempty"`
}

type AdminMetricsSnapshot struct {
	TimestampMs       int64                        `json:"ts"`
	UploadRate        uint64                       `json:"upload_rate"`
	DownloadRate      uint64                       `json:"download_rate"`
	UploadTotal       uint64                       `json:"upload_total"`
	DownloadTotal     uint64                       `json:"download_total"`
	ActiveConnections int                          `json:"active_connections"`
	TCPConnections    int                          `json:"tcp_connections"`
	UDPSessions       int                          `json:"udp_sessions"`
	OffloadedTCP      int64                        `json:"offloaded_tcp"`
	RssBytes          uint64                       `json:"rss_bytes"`
	HeapBytes         uint64                       `json:"heap_bytes"`
	FdCount           int                          `json:"fd_count"`
	Goroutines        int                          `json:"goroutines"`
	DNS               AdminDNSStats                `json:"dns"`
	FakeIP            *AdminFakeIPStats            `json:"fakeip,omitempty"`
	BpfOverflow       AdminBpfOverflow             `json:"bpf_overflow"`
	TCPConnPanicCount uint64                       `json:"tcp_conn_panic_count"`
	UDPReplyDrought   *AdminUDPReplyDroughtSummary `json:"udp_reply_drought,omitempty"`
}

// AdminTrafficSample is one overview chart point. Rates are bytes/sec.
type AdminTrafficSample struct {
	TimestampMs  int64  `json:"ts"`
	UploadRate   uint64 `json:"up"`
	DownloadRate uint64 `json:"down"`
}

// AdminProbeHealth describes a per-transport health probe observation without credentials.
type AdminProbeHealth struct {
	Alive     bool   `json:"alive"`
	LatencyMs *int32 `json:"latency_ms,omitempty"`
	Admission string `json:"admission,omitempty"`
	Reason    string `json:"reason,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// AdminGroupMember is one selectable or observed member. Name is the logical
// identity persisted by SetGroupSelection; node links are never exposed.
type AdminGroupMember struct {
	Name        string                       `json:"name"`
	DisplayName string                       `json:"display_name,omitempty"`
	Kind        string                       `json:"kind,omitempty"`
	Protocol    string                       `json:"protocol,omitempty"`
	Endpoint    string                       `json:"endpoint,omitempty"`
	Alive       bool                         `json:"alive"`
	LatencyMs   *int32                       `json:"latency_ms,omitempty"`
	Admission   string                       `json:"admission,omitempty"`
	Reason      string                       `json:"reason,omitempty"`
	CheckedAt   string                       `json:"checked_at,omitempty"`
	Probes      map[string]*AdminProbeHealth `json:"probes,omitempty"`
}

// AdminGroup is one outbound group for the management API.
type AdminGroup struct {
	Name             string             `json:"name"`
	Selectable       bool               `json:"selectable"`
	Policy           string             `json:"policy"`
	Selected         string             `json:"selected"`
	IsolateTransport bool               `json:"isolate_transport,omitempty"`
	SelectionMembers []string           `json:"selection_members"`
	Members          []AdminGroupMember `json:"members"`
}

func sanitizeSafeEndpoint(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" || strings.Contains(v, "://") || strings.Contains(v, "@") {
		return ""
	}
	return v
}

// AdminGroups lists user-defined outbound groups. Built-in direct/block are
// omitted. Member identities are names only; node links are never copied.
func (c *ControlPlane) AdminGroups() []AdminGroup {
	if c == nil {
		return nil
	}
	groups := make([]AdminGroup, 0, len(c.outbounds))
	for _, group := range c.outbounds {
		if group == nil || isBuiltinAdminGroup(group.Name) {
			continue
		}
		members := append([]string(nil), c.groupSelectionMembers[group.Name]...)
		if len(members) == 0 {
			members = adminMemberNamesFromDialers(group.Dialers)
		}
		policy := group.CurrentSelectionPolicy()
		selected := ""
		if policy.Policy == consts.DialerSelectionPolicy_Fixed &&
			policy.FixedIndex >= 0 && policy.FixedIndex < len(members) {
			// Live FixedIndex is the data-plane authority. Apply() may have
			// fallen back after a persisted member disappeared without rewriting
			// the store snapshot.
			selected = members[policy.FixedIndex]
		}
		item := AdminGroup{
			Name:             group.Name,
			Selectable:       len(c.groupSelectionMembers[group.Name]) > 0,
			Policy:           string(policy.Policy),
			Selected:         selected,
			IsolateTransport: group.IsolateTransport,
			SelectionMembers: append([]string(nil), members...),
			Members:          make([]AdminGroupMember, 0, len(members)),
		}
		for _, name := range members {
			member := AdminGroupMember{Name: name}
			if sample, ok := adminSampleForGroupMember(group, name); ok {
				member.Kind = sample.Kind
				member.Protocol = sample.Protocol
				member.Endpoint = sample.Endpoint
				member.Alive = sample.Alive
				member.LatencyMs = sample.LatencyMs
				member.Admission = sample.Admission
				member.Reason = sample.Reason
				member.CheckedAt = sample.CheckedAt
				member.Probes = sample.Probes
			}
			item.Members = append(item.Members, member)
		}
		if item.Selected == "" {
			if live := adminPeekSelected(group, policy.Policy); live != "" {
				item.Selected = live
			} else {
				item.Selected = adminInferredSelected(policy.Policy, item.Members)
			}
		}
		groups = append(groups, item)
	}
	return groups
}

// AdminSystemInfo returns static/slow-changing daemon system info for GET /api/v1/system.
func (c *ControlPlane) AdminSystemInfo(version string) AdminSystemInfo {
	hostname, _ := os.Hostname()
	now := time.Now().UTC()
	uptime := int64(now.Sub(processStartedAt).Seconds())
	if uptime < 0 {
		uptime = 0
	}
	info := AdminSystemInfo{
		Version:       version,
		Running:       c != nil,
		Hostname:      hostname,
		GoVersion:     runtime.Version(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		NumCPU:        runtime.NumCPU(),
		StartedAt:     processStartedAt.Format(time.RFC3339),
		UptimeSec:     uptime,
		InboundsCount: len(activeInboundManager.Load().Snapshot()),
	}
	if c == nil {
		info.LanInterface = []string{}
		info.WanInterface = []string{}
		return info
	}
	info.DialMode = string(c.dialMode)
	info.LanInterface = append([]string(nil), c.lanInterface...)
	info.WanInterface = append([]string(nil), c.wanInterface...)
	if info.LanInterface == nil {
		info.LanInterface = []string{}
	}
	if info.WanInterface == nil {
		info.WanInterface = []string{}
	}
	info.EBPFEnabled = c.core != nil && c.core.bpf.Load() != nil
	if c.log != nil {
		info.LogLevel = c.log.GetLevel().String()
	}
	for _, g := range c.outbounds {
		if g != nil && !isBuiltinAdminGroup(g.Name) {
			info.GroupsCount++
		}
	}
	info.PolicyEpoch = uint64(c.policyIdentity.Epoch())
	if hash := c.policyIdentity.Hash(); hash != ([32]byte{}) {
		info.PolicyHash = hex.EncodeToString(hash[:])
	}
	return info
}

// AdminMetricsSnapshot returns fast O(1) runtime metrics for GET /api/v1/metrics and WS metrics.
func (c *ControlPlane) AdminMetricsSnapshot() AdminMetricsSnapshot {
	now := time.Now()
	proc := readSelfProcessStats()
	snap := AdminMetricsSnapshot{
		TimestampMs: now.UnixMilli(),
		OffloadedTCP: tcpOffloadActive.Load(),
		RssBytes:    proc.RSSBytes,
		HeapBytes:   proc.HeapBytes,
		FdCount:     proc.FDCount,
		Goroutines:  proc.Goroutines,
	}
	if c == nil {
		return snap
	}
	stats := c.SnapshotRuntimeScalars()
	snap.UploadRate = stats.UploadRate
	snap.DownloadRate = stats.DownloadRate
	snap.UploadTotal = stats.UploadTotal
	snap.DownloadTotal = stats.DownloadTotal
	snap.ActiveConnections = stats.ActiveConnections
	snap.TCPConnections = c.ActiveTCPConnections()
	snap.UDPSessions = stats.UDPSessions
	snap.TCPConnPanicCount = c.tcpConnPanicCount.Load()

	if dns := c.ActiveDnsController(); dns != nil {
		snap.DNS = dns.AdminStats()
	}
	if fake := c.fakeIPStore(); fake != nil {
		fs := fake.AdminStats()
		snap.FakeIP = &fs
	}
	if c.core != nil {
		if objs := c.core.bpf.Load(); objs != nil && objs.BpfStatsMap != nil {
			udpOv, tcpOv := c.readMapOverflowCounters(objs.BpfStatsMap)
			snap.BpfOverflow = AdminBpfOverflow{UDP: udpOv, TCP: tcpOv}
		}
	}
	if drought := c.udpReplyDrought.snapshot(now); drought != nil {
		snap.UDPReplyDrought = &AdminUDPReplyDroughtSummary{
			Mode:       drought.Mode,
			Generation: drought.Generation,
			Group:      drought.Group,
			Client:     drought.Client,
			Contract:   drought.Contract,
			Stats:      drought.Stats,
			Excluded:   drought.Excluded,
		}
	}
	return snap
}

// AdminMetricsHistory returns downsampled rate history buckets for GET /api/v1/metrics/history.
func (c *ControlPlane) AdminMetricsHistory(windowSec, maxPoints int) []AdminTrafficSample {
	if c == nil {
		return []AdminTrafficSample{}
	}
	stats := c.SnapshotRuntimeHistory(windowSec, maxPoints)
	out := make([]AdminTrafficSample, 0, len(stats.Samples))
	for _, sample := range stats.Samples {
		out = append(out, AdminTrafficSample{
			TimestampMs:  sample.Timestamp.UnixMilli(),
			UploadRate:   sample.UploadRate,
			DownloadRate: sample.DownloadRate,
		})
	}
	return out
}

// AdminStatusSnapshot returns process-local status for internal tests/compatibility helpers.
func (c *ControlPlane) AdminStatusSnapshot(version string) AdminStatus {
	status := AdminStatus{
		Version: version,
		Running: c != nil,
	}
	if c == nil {
		return status
	}
	status.LanInterface = append([]string(nil), c.lanInterface...)
	status.WanInterface = append([]string(nil), c.wanInterface...)
	stats := c.SnapshotRuntimeStats(defaultRuntimeWindowSec, 48)
	status.UploadRate = stats.UploadRate
	status.DownloadRate = stats.DownloadRate
	status.UploadTotal = stats.UploadTotal
	status.DownloadTotal = stats.DownloadTotal
	status.ActiveConnections = stats.ActiveConnections
	status.UDPSessions = stats.UDPSessions
	status.UDPReplyDrought = c.udpReplyDrought.snapshot(time.Now())
	status.RssBytes, status.FdCount = readSelfRSSAndFDs()
	if len(stats.Samples) > 0 {
		status.TrafficSamples = make([]AdminTrafficSample, 0, len(stats.Samples))
		for _, sample := range stats.Samples {
			status.TrafficSamples = append(status.TrafficSamples, AdminTrafficSample{
				TimestampMs:  sample.Timestamp.UnixMilli(),
				UploadRate:   sample.UploadRate,
				DownloadRate: sample.DownloadRate,
			})
		}
	}
	return status
}

func isBuiltinAdminGroup(name string) bool {
	switch name {
	case consts.OutboundDirect.String(), consts.OutboundBlock.String(), consts.OutboundMustRules.String():
		return true
	default:
		return false
	}
}

func adminMemberNamesFromDialers(dialers []*dialer.Dialer) []string {
	names := make([]string, 0, len(dialers))
	seen := make(map[string]struct{}, len(dialers))
	for _, d := range dialers {
		if d == nil || d.Property() == nil {
			continue
		}
		name := d.Property().Name
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

type adminLatencySample struct {
	Kind      string
	Protocol  string
	Endpoint  string
	Alive     bool
	LatencyMs *int32
	Admission string
	Reason    string
	CheckedAt string
	Probes    map[string]*AdminProbeHealth
}

func adminSampleFromDialer(d *dialer.Dialer, kind string) adminLatencySample {
	if d == nil {
		return adminLatencySample{Kind: kind, Admission: dialer.AdmissionDead.String(), Reason: "not_alive"}
	}
	snapshot := bestNodeLatencySnapshotForDialer(d)
	admission, reason := adminAdmissionForDialer(d)
	alive := snapshot.Alive
	if admission != "" && admission != dialer.AdmissionDead.String() {
		alive = true
	}
	if admission == dialer.AdmissionDead.String() {
		alive = false
	}
	protocol := ""
	endpoint := ""
	if kind == "node" && d.Property() != nil {
		protocol = d.Property().Protocol
		endpoint = sanitizeSafeEndpoint(d.Property().Address)
	}
	probes, checkedAt := adminProbeMapForDialer(d)
	return adminLatencySample{
		Kind:      kind,
		Protocol:  protocol,
		Endpoint:  endpoint,
		Alive:     alive,
		LatencyMs: snapshot.LatencyMs,
		Admission: admission,
		Reason:    reason,
		CheckedAt: checkedAt,
		Probes:    probes,
	}
}

func adminProbeMapForDialer(d *dialer.Dialer) (map[string]*AdminProbeHealth, string) {
	if d == nil {
		return nil, ""
	}
	specs := []struct {
		key string
		nt  *dialer.NetworkType
	}{
		{key: "tcp4", nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}},
		{key: "tcp6", nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6}},
		{key: "dns4", nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, IsDns: true, UdpHealthDomain: dialer.UdpHealthDomainDns}},
		{key: "dns6", nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, IsDns: true, UdpHealthDomain: dialer.UdpHealthDomainDns}},
	}
	var probes map[string]*AdminProbeHealth
	var maxChecked time.Time
	for _, spec := range specs {
		obs := d.SnapshotLastProbe(spec.nt)
		lastLat, hasLat := d.MustGetLatencies10(spec.nt).LastLatency()
		alive := d.MustGetAlive(spec.nt)
		if obs.CheckedAt.IsZero() && !obs.HasLatency && !hasLat {
			continue
		}
		if probes == nil {
			probes = make(map[string]*AdminProbeHealth, 4)
		}
		var latMs *int32
		if obs.HasLatency {
			ms := int32(obs.Latency.Milliseconds())
			latMs = &ms
		} else if hasLat {
			ms := int32(lastLat.Milliseconds())
			latMs = &ms
		}
		checkedAtStr := ""
		if !obs.CheckedAt.IsZero() {
			checkedAtStr = obs.CheckedAt.UTC().Format(time.RFC3339)
			if obs.CheckedAt.After(maxChecked) {
				maxChecked = obs.CheckedAt
			}
		}
		probes[spec.key] = &AdminProbeHealth{
			Alive:     alive,
			LatencyMs: latMs,
			Admission: d.AdmissionState(spec.nt).String(),
			Reason:    d.AdmissionReason(spec.nt),
			CheckedAt: checkedAtStr,
		}
	}
	if maxChecked.IsZero() {
		return probes, ""
	}
	return probes, maxChecked.UTC().Format(time.RFC3339)
}

func adminSampleForGroupMember(group *outbound.DialerGroup, name string) (adminLatencySample, bool) {
	if group == nil || name == "" {
		return adminLatencySample{}, false
	}
	if child := group.NestedGroupNamed(name); child != nil {
		return adminSampleForNestedMember(group, child), true
	}
	if d := group.DialerNamed(name); d != nil {
		return adminSampleFromDialer(d, "node"), true
	}
	return adminLatencySample{}, false
}

func adminSampleForNestedMember(parent, child *outbound.DialerGroup) adminLatencySample {
	if child == nil {
		return adminLatencySample{Kind: "group", Admission: dialer.AdmissionDead.String(), Reason: "not_alive"}
	}
	for _, nt := range adminTCPNetworkTypes() {
		var d *dialer.Dialer
		var err error
		if parent != nil {
			d, err = parent.PeekSelectNestedMember(child, nt)
		} else {
			d, err = child.PeekSelect(nt)
		}
		if err != nil || d == nil {
			continue
		}
		if parent != nil {
			d = parent.HealthViewOf(d)
		}
		return adminSampleFromDialer(d, "group")
	}
	return adminLatencySample{Kind: "group", Admission: dialer.AdmissionDead.String(), Reason: "not_alive"}
}

func adminTCPNetworkTypes() []*dialer.NetworkType {
	return []*dialer.NetworkType{
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6},
	}
}

func adminAdmissionForDialer(d *dialer.Dialer) (state, reason string) {
	if d == nil {
		return dialer.AdmissionDead.String(), "not_alive"
	}
	foundProbed := false
	bestProbed := dialer.AdmissionDead
	probedReason := "not_alive"

	foundAny := false
	worstUnprobed := dialer.AdmissionAlive
	unprobedReason := "ok"

	for _, nt := range adminTCPNetworkTypes() {
		obs := d.SnapshotLastProbe(nt)
		_, hasLat := d.MustGetLatencies10(nt).LastLatency()
		alive := d.MustGetAlive(nt)
		st := d.AdmissionState(nt)
		r := d.AdmissionReason(nt)

		probed := obs.HasLatency || hasLat || (!obs.CheckedAt.IsZero() && !obs.Alive) || !alive
		if probed {
			if !foundProbed || st < bestProbed {
				foundProbed = true
				bestProbed = st
				probedReason = r
			}
			continue
		}
		if !foundAny || st > worstUnprobed {
			foundAny = true
			worstUnprobed = st
			unprobedReason = r
		}
	}
	if foundProbed {
		return bestProbed.String(), probedReason
	}
	if foundAny {
		return worstUnprobed.String(), unprobedReason
	}
	nt := adminTCPNetworkTypes()[0]
	return d.AdmissionState(nt).String(), d.AdmissionReason(nt)
}

func adminPeekSelected(group *outbound.DialerGroup, policy consts.DialerSelectionPolicy) string {
	switch policy {
	case consts.DialerSelectionPolicy_Fallback, consts.DialerSelectionPolicy_UrlTest:
	default:
		return ""
	}
	if group == nil {
		return ""
	}
	for _, nt := range adminTCPNetworkTypes() {
		d, nested, err := group.PeekSelectPath(nt)
		if err != nil || d == nil || d.Property() == nil {
			continue
		}
		if nested != "" {
			return nested
		}
		if name := d.Property().Name; name != "" {
			return name
		}
	}
	return ""
}

func adminInferredSelected(policy consts.DialerSelectionPolicy, members []AdminGroupMember) string {
	switch policy {
	case consts.DialerSelectionPolicy_Fallback, consts.DialerSelectionPolicy_UrlTest:
		// Group-level live pick is filled by adminPeekSelected. Do not guess
		// from first-alive / raw latency; that disagrees with admission.
		return ""
	case consts.DialerSelectionPolicy_FirstAlive:
		for _, member := range members {
			if member.Alive {
				return member.Name
			}
		}
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		var best string
		var bestMs int32
		found := false
		for _, member := range members {
			if !member.Alive || member.LatencyMs == nil {
				continue
			}
			if !found || *member.LatencyMs < bestMs {
				best = member.Name
				bestMs = *member.LatencyMs
				found = true
			}
		}
		return best
	}
	return ""
}

// AdminQuality is a bounded diagnostics snapshot, independent of group-level selected.
func (c *ControlPlane) AdminQuality(group, host string) []map[string]any {
	result := make([]map[string]any, 0)
	if c == nil {
		return result
	}
	for _, g := range c.outbounds {
		if g != nil && (group == "" || g.Name == group) {
			result = append(result, g.QualityStatus(host, 256-len(result))...)
			if len(result) >= 256 {
				break
			}
		}
	}
	return result
}

func (c *ControlPlane) AdminRecoveryDiagnostics() []outbound.RecoveryDiagnostics {
	result := make([]outbound.RecoveryDiagnostics, 0)
	if c == nil {
		return result
	}
	now := time.Now()
	for _, g := range c.outbounds {
		if g != nil && usesAdminRecoveryGroup(g) {
			s := g.RecoveryDiagnostics(now)
			s.PolicyEpoch = uint64(c.PolicyEpoch())
			result = append(result, s)
			if len(result) == 256 {
				break
			}
		}
	}
	return result
}

func usesAdminRecoveryGroup(g *outbound.DialerGroup) bool {
	p := g.GetSelectionPolicy()
	return p == consts.DialerSelectionPolicy_Fallback || p == consts.DialerSelectionPolicy_UrlTest
}
