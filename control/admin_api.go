/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/hex"
	"fmt"
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
	ResolveDNS        *AdminResolveDNSStats        `json:"resolve_dns,omitempty"`
	BpfOverflow       AdminBpfOverflow             `json:"bpf_overflow"`
	TCPConnPanicCount uint64                       `json:"tcp_conn_panic_count"`
	UDPReplyDrought   *AdminUDPReplyDroughtSummary `json:"udp_reply_drought,omitempty"`
}

// AdminResolveDNSStats exposes per-generation node resolve_dns cache, fallback,
// circuit-breaker fail-open, and pooling counters for GET /api/v1/metrics.
type AdminResolveDNSStats struct {
	CacheEntries     int    `json:"cache_entries"`
	Hits             uint64 `json:"hits"`
	StaleHits        uint64 `json:"stale_hits"`
	Misses           uint64 `json:"misses"`
	NegativeHits     uint64 `json:"negative_hits"`
	PrefetchStarted  uint64 `json:"prefetch_started"`
	PrefetchConsumed uint64 `json:"prefetch_consumed"`
	Timeouts         uint64 `json:"timeouts"`
	Failures         uint64 `json:"failures"`
	FailOpen         uint64 `json:"fail_open"`
	PassivePins      uint64 `json:"passive_pins"`
	PooledDials      uint64 `json:"pooled_dials"`
	PooledReuses     uint64 `json:"pooled_reuses"`
}

// AdminTrafficSample is one overview chart point. Rates are bytes/sec.
type AdminTrafficSample struct {
	TimestampMs  int64  `json:"ts"`
	UploadRate   uint64 `json:"up"`
	DownloadRate uint64 `json:"down"`
}

// AdminProbeHealth describes a per-transport health probe observation without credentials.
type AdminProbeHealth struct {
	Alive             bool     `json:"alive"`
	LatencyMs         *int32   `json:"latency_ms,omitempty"`
	BaselineMs        *int32   `json:"baseline_ms,omitempty"`
	QualityScoreMs    *int32   `json:"quality_score_ms,omitempty"`
	LossRate          *float64 `json:"loss_rate,omitempty"`
	RecentLatenciesMs []int32  `json:"recent_latencies_ms,omitempty"`
	Congested         bool     `json:"congested,omitempty"`
	FailStreak        int      `json:"fail_streak,omitempty"`
	PenaltyLevel      int      `json:"penalty_level,omitempty"`
	Admission         string   `json:"admission,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	CheckedAt         string   `json:"checked_at,omitempty"`
}

// AdminGroupMember is one selectable or observed member. Name is the logical
// identity persisted by SetGroupSelection; node links are never exposed.
type AdminGroupMember struct {
	Name              string                           `json:"name"`
	DisplayName       string                           `json:"display_name,omitempty"`
	Kind              string                           `json:"kind,omitempty"`
	ResolvedLeaf      string                           `json:"resolved_leaf,omitempty"`
	Protocol          string                           `json:"protocol,omitempty"`
	Endpoint          string                           `json:"endpoint,omitempty"`
	Alive             bool                             `json:"alive"`
	LatencyMs         *int32                           `json:"latency_ms,omitempty"`
	BaselineMs        *int32                           `json:"baseline_ms,omitempty"`
	QualityScoreMs    *int32                           `json:"quality_score_ms,omitempty"`
	LossRate          *float64                         `json:"loss_rate,omitempty"`
	RecentLatenciesMs []int32                          `json:"recent_latencies_ms,omitempty"`
	Load              *dialer.LoadContext              `json:"load,omitempty"`
	Admission         string                           `json:"admission,omitempty"`
	Reason            string                           `json:"reason,omitempty"`
	CheckedAt         string                           `json:"checked_at,omitempty"`
	Probes            map[string]*AdminProbeHealth     `json:"probes,omitempty"`
	ResolveDNS        *dialer.ResolveDNSHealthSnapshot `json:"resolve_dns,omitempty"`
}

// AdminGroup is one outbound group for the management API.
type AdminGroup struct {
	Name             string             `json:"name"`
	DisplayName      string             `json:"display_name,omitempty"`
	Origin           string             `json:"origin,omitempty"`
	Wrapper          bool               `json:"wrapper,omitempty"`
	Selectable       bool               `json:"selectable"`
	Policy           string             `json:"policy"`
	Selected         string             `json:"selected"`
	IsolateTransport bool               `json:"isolate_transport,omitempty"`
	QualityMode      string             `json:"quality_mode,omitempty"`
	CheckToleranceMs int64              `json:"check_tolerance_ms,omitempty"`
	Lazy             bool               `json:"lazy,omitempty"`
	StickyCount      int                `json:"sticky_count,omitempty"`
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
			QualityMode:      group.QualityMode(),
			CheckToleranceMs: group.CheckToleranceMs(),
			Lazy:             group.LazyCheck(),
			StickyCount:      group.StickyCount(),
			SelectionMembers: append([]string(nil), members...),
			Members:          make([]AdminGroupMember, 0, len(members)),
		}
		for _, name := range members {
			member := AdminGroupMember{Name: name}
			if sample, ok := adminSampleForGroupMember(group, name); ok {
				member.Kind = sample.Kind
				member.ResolvedLeaf = sample.ResolvedLeaf
				member.Protocol = sample.Protocol
				member.Endpoint = sample.Endpoint
				member.Alive = sample.Alive
				member.LatencyMs = sample.LatencyMs
				member.BaselineMs = sample.BaselineMs
				member.QualityScoreMs = sample.QualityScoreMs
				member.LossRate = sample.LossRate
				member.RecentLatenciesMs = sample.RecentLatenciesMs
				member.Load = sample.Load
				member.Admission = sample.Admission
				member.Reason = sample.Reason
				member.CheckedAt = sample.CheckedAt
				member.Probes = sample.Probes
				member.ResolveDNS = sample.ResolveDNS
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
		TimestampMs:  now.UnixMilli(),
		OffloadedTCP: tcpOffloadActive.Load(),
		RssBytes:     proc.RSSBytes,
		HeapBytes:    proc.HeapBytes,
		FdCount:      proc.FDCount,
		Goroutines:   proc.Goroutines,
	}
	if c == nil {
		return snap
	}
	tcpConnections := c.ActiveTCPConnections()
	stats := c.SnapshotRuntimeScalars()
	snap.UploadRate = stats.UploadRate
	snap.DownloadRate = stats.DownloadRate
	snap.UploadTotal = stats.UploadTotal
	snap.DownloadTotal = stats.DownloadTotal
	snap.TCPConnections = tcpConnections
	snap.UDPSessions = stats.UDPSessions
	snap.ActiveConnections = snap.TCPConnections + snap.UDPSessions
	snap.TCPConnPanicCount = c.tcpConnPanicCount.Load()

	if dns := c.ActiveDnsController(); dns != nil {
		snap.DNS = dns.AdminStats()
	}
	if fake := c.fakeIPStore(); fake != nil {
		fs := fake.AdminStats()
		snap.FakeIP = &fs
	}
	if c.hasResolveDNSNode() {
		rs := c.adminResolveDNSStats()
		snap.ResolveDNS = &rs
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
	Kind              string
	ResolvedLeaf      string
	Protocol          string
	Endpoint          string
	Alive             bool
	LatencyMs         *int32
	BaselineMs        *int32
	QualityScoreMs    *int32
	LossRate          *float64
	RecentLatenciesMs []int32
	Load              *dialer.LoadContext
	Admission         string
	Reason            string
	CheckedAt         string
	Probes            map[string]*AdminProbeHealth
	ResolveDNS        *dialer.ResolveDNSHealthSnapshot
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
	var loadCtx *dialer.LoadContext
	if kind == "node" && d.Property() != nil {
		protocol = d.Property().Protocol
		endpoint = sanitizeSafeEndpoint(d.Property().Address)
		lc := d.LoadContext(time.Now())
		if lc.Class != "" && (lc.Class != "unobserved" || lc.Active > 0) {
			loadCopy := lc
			loadCtx = &loadCopy
		}
	}
	probes, checkedAt := adminProbeMapForDialer(d)
	repProbe := selectRepresentativeAdminProbe(probes)
	sample := adminLatencySample{
		Kind:       kind,
		Protocol:   protocol,
		Endpoint:   endpoint,
		Alive:      alive,
		LatencyMs:  snapshot.LatencyMs,
		Load:       loadCtx,
		Admission:  admission,
		Reason:     reason,
		CheckedAt:  checkedAt,
		Probes:     probes,
		ResolveDNS: d.SnapshotResolveDNSHealth(time.Now()),
	}
	if repProbe != nil {
		sample.BaselineMs = repProbe.BaselineMs
		sample.QualityScoreMs = repProbe.QualityScoreMs
		sample.LossRate = repProbe.LossRate
		sample.RecentLatenciesMs = repProbe.RecentLatenciesMs
	}
	return sample
}

func selectRepresentativeAdminProbe(probes map[string]*AdminProbeHealth) *AdminProbeHealth {
	p4 := probes["tcp4"]
	p6 := probes["tcp6"]
	if p4 == nil {
		return p6
	}
	if p6 == nil {
		return p4
	}
	if p4.Alive != p6.Alive {
		if p4.Alive {
			return p4
		}
		return p6
	}
	if (p4.LatencyMs != nil) != (p6.LatencyMs != nil) {
		if p4.LatencyMs != nil {
			return p4
		}
		return p6
	}
	if p4.LatencyMs != nil && p6.LatencyMs != nil && *p4.LatencyMs != *p6.LatencyMs {
		if *p4.LatencyMs < *p6.LatencyMs {
			return p4
		}
		return p6
	}
	return p4
}

func adminProbeMapForDialer(d *dialer.Dialer) (map[string]*AdminProbeHealth, string) {
	if d == nil {
		return nil, ""
	}
	specs := []struct {
		key       string
		isDataUDP bool
		nt        *dialer.NetworkType
	}{
		{key: "tcp4", nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}},
		{key: "tcp6", nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6}},
		{key: "dns4", nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, IsDns: true, UdpHealthDomain: dialer.UdpHealthDomainDns}},
		{key: "dns6", nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, IsDns: true, UdpHealthDomain: dialer.UdpHealthDomainDns}},
		{key: "udp4", isDataUDP: true, nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: dialer.UdpHealthDomainData}},
		{key: "udp6", isDataUDP: true, nt: &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, UdpHealthDomain: dialer.UdpHealthDomainData}},
	}
	var probes map[string]*AdminProbeHealth
	var maxChecked time.Time
	for _, spec := range specs {
		obs := d.SnapshotLastProbe(spec.nt)
		lastLat, hasLat := d.MustGetLatencies10(spec.nt).LastLatency()
		alive := d.MustGetAlive(spec.nt)
		admission := d.AdmissionState(spec.nt)
		detail := d.HealthSlotDetail(spec.nt)
		if spec.isDataUDP {
			if detail.TestSampleCount == 0 && alive && admission == dialer.AdmissionAlive && obs.CheckedAt.IsZero() && !obs.HasLatency && !hasLat {
				continue
			}
		} else if obs.CheckedAt.IsZero() && !obs.HasLatency && !hasLat {
			continue
		}
		if probes == nil {
			probes = make(map[string]*AdminProbeHealth, 6)
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
			Alive:             alive,
			LatencyMs:         latMs,
			BaselineMs:        detail.BaselineMs,
			QualityScoreMs:    detail.QualityScoreMs,
			LossRate:          detail.LossRate,
			RecentLatenciesMs: detail.RecentLatenciesMs,
			Congested:         detail.Congested,
			FailStreak:        detail.FailStreak,
			PenaltyLevel:      detail.PenaltyLevel,
			Admission:         admission.String(),
			Reason:            d.AdmissionReason(spec.nt),
			CheckedAt:         checkedAtStr,
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
		resolvedLeaf := ""
		if d.Property() != nil {
			resolvedLeaf = d.Property().Name
		}
		if parent != nil {
			d = parent.HealthViewOf(d)
		}
		sample := adminSampleFromDialer(d, "group")
		sample.ResolvedLeaf = resolvedLeaf
		return sample
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

func (c *ControlPlane) findAdminGroup(name string) (*outbound.DialerGroup, error) {
	if c == nil {
		return nil, fmt.Errorf("control plane is not ready")
	}
	name = strings.TrimSpace(name)
	if name == "" || isBuiltinAdminGroup(name) {
		return nil, fmt.Errorf("invalid group")
	}
	for _, g := range c.outbounds {
		if g != nil && g.Name == name {
			return g, nil
		}
	}
	return nil, fmt.Errorf("unknown group")
}

// AdminGroupSticky returns active per-site sticky pins for a group.
func (c *ControlPlane) AdminGroupSticky(groupName, network, query string, limit int) ([]outbound.SiteStickyEntrySnapshot, int, error) {
	group, err := c.findAdminGroup(groupName)
	if err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	entries, total := group.SnapshotSiteSticky(network, query, limit)
	return entries, total, nil
}

// AdminClearGroupSticky removes one site pin (if site != "") or all pins on groupName.
func (c *ControlPlane) AdminClearGroupSticky(groupName, site, network string) (int, error) {
	group, err := c.findAdminGroup(groupName)
	if err != nil {
		return 0, err
	}
	return group.ClearSiteSticky(site, network), nil
}
