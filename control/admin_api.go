/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// AdminStatus is the JSON body for GET /v1/status. It never includes node
// URIs or credentials.
type AdminStatus struct {
	Version           string               `json:"version"`
	Running           bool                 `json:"running"`
	LanInterface      []string             `json:"lan_interface"`
	WanInterface      []string             `json:"wan_interface"`
	UploadRate        uint64               `json:"upload_rate"`
	DownloadRate      uint64               `json:"download_rate"`
	UploadTotal       uint64               `json:"upload_total"`
	DownloadTotal     uint64               `json:"download_total"`
	ActiveConnections int                  `json:"active_connections"`
	UDPSessions       int                  `json:"udp_sessions"`
	RssBytes          uint64               `json:"rss_bytes"`
	FdCount           int                  `json:"fd_count"`
	TrafficSamples    []AdminTrafficSample `json:"traffic_samples,omitempty"`
}

// AdminTrafficSample is one overview chart point. Rates are bytes/sec.
type AdminTrafficSample struct {
	TimestampMs  int64  `json:"ts"`
	UploadRate   uint64 `json:"up"`
	DownloadRate uint64 `json:"down"`
}

// AdminGroupMember is one selectable or observed member. Name is the logical
// identity persisted by SetGroupSelection; latency is optional.
type AdminGroupMember struct {
	Name      string `json:"name"`
	Alive     bool   `json:"alive"`
	LatencyMs *int32 `json:"latency_ms,omitempty"`
	// Admission is alive | degraded | dead. It is the userspace three-state
	// health shown on fallback / url_test groups; omitted when unknown.
	Admission string `json:"admission,omitempty"`
	// Reason is a machine-readable cause: ok, not_alive, fail, rtt,
	// congestion, or a comma-joined combination.
	Reason string `json:"reason,omitempty"`
}

// AdminGroup is one outbound group for the management UI.
type AdminGroup struct {
	Name             string             `json:"name"`
	Selectable       bool               `json:"selectable"`
	Policy           string             `json:"policy"`
	Selected         string             `json:"selected"`
	SelectionMembers []string           `json:"selection_members"`
	Members          []AdminGroupMember `json:"members"`
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
			SelectionMembers: append([]string(nil), members...),
			Members:          make([]AdminGroupMember, 0, len(members)),
		}
		for _, name := range members {
			member := AdminGroupMember{Name: name}
			if sample, ok := adminSampleForGroupMember(group, name); ok {
				member.Alive = sample.Alive
				member.LatencyMs = sample.LatencyMs
				member.Admission = sample.Admission
				member.Reason = sample.Reason
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

// AdminStatusSnapshot returns process-local status for GET /v1/status.
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
	Alive     bool
	LatencyMs *int32
	Admission string
	Reason    string
}

func adminSampleFromDialer(d *dialer.Dialer) adminLatencySample {
	if d == nil {
		return adminLatencySample{Admission: dialer.AdmissionDead.String(), Reason: "not_alive"}
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
	return adminLatencySample{
		Alive:     alive,
		LatencyMs: snapshot.LatencyMs,
		Admission: admission,
		Reason:    reason,
	}
}

func adminSampleForGroupMember(group *outbound.DialerGroup, name string) (adminLatencySample, bool) {
	if group == nil || name == "" {
		return adminLatencySample{}, false
	}
	if child := group.NestedGroupNamed(name); child != nil {
		return adminSampleForNestedMember(group, child), true
	}
	if d := group.DialerNamed(name); d != nil {
		return adminSampleFromDialer(d), true
	}
	return adminLatencySample{}, false
}

func adminSampleForNestedMember(parent, child *outbound.DialerGroup) adminLatencySample {
	if child == nil {
		return adminLatencySample{Admission: dialer.AdmissionDead.String(), Reason: "not_alive"}
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
		return adminSampleFromDialer(d)
	}
	return adminLatencySample{Admission: dialer.AdmissionDead.String(), Reason: "not_alive"}
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
	found := false
	worst := dialer.AdmissionAlive
	reason = "ok"
	for _, nt := range adminTCPNetworkTypes() {
		obs := d.SnapshotLastProbe(nt)
		if obs.CheckedAt.IsZero() && d.MustGetAlive(nt) {
			continue
		}
		st := d.AdmissionState(nt)
		if !found || st > worst {
			found = true
			worst = st
			reason = d.AdmissionReason(nt)
		}
	}
	if !found {
		nt := adminTCPNetworkTypes()[0]
		return d.AdmissionState(nt).String(), d.AdmissionReason(nt)
	}
	return worst.String(), reason
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
		d, err := group.PeekSelect(nt)
		if err != nil || d == nil || d.Property() == nil {
			continue
		}
		if nested := group.NestedMemberNameFor(d, nt); nested != "" {
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
