/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestAdminGroupsOmitsBuiltinAndNodeLinks(t *testing.T) {
	t.Parallel()
	d := newTestEndpointDialer()
	t.Cleanup(func() { _ = d.Close() })
	group := newTestFixedOutboundGroup(d)
	t.Cleanup(func() { group.Close() })
	store := outbound.NewGroupSelectionStore(t.TempDir() + "/state.json")
	if err := store.Set(group.Name, "Cherry_Proxy"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	direct := &outbound.DialerGroup{Name: consts.OutboundDirect.String()}
	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds:           []*outbound.DialerGroup{direct, group},
			groupSelectionStore: store,
			groupSelectionMembers: map[string][]string{
				group.Name: {"Cherry_Proxy", "Other"},
			},
		},
	}
	groups := c.AdminGroups()
	if len(groups) != 1 {
		t.Fatalf("groups = %#v, want 1 user group", groups)
	}
	if groups[0].Name != group.Name || !groups[0].Selectable || groups[0].Selected != "Cherry_Proxy" {
		t.Fatalf("group = %#v", groups[0])
	}
	body, err := json.Marshal(groups)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(body)), "://") || strings.Contains(string(body), "ss://") {
		t.Fatalf("admin groups JSON leaked a node URI: %s", body)
	}
}

func TestAdminInferredSelectedFirstAlive(t *testing.T) {
	t.Parallel()
	ms := int32(20)
	got := adminInferredSelected(consts.DialerSelectionPolicy_FirstAlive, []AdminGroupMember{
		{Name: "dead", Alive: false},
		{Name: "live", Alive: true, LatencyMs: &ms},
	})
	if got != "live" {
		t.Fatalf("selected = %q, want live", got)
	}
	if adminInferredSelected(consts.DialerSelectionPolicy_FirstAlive, []AdminGroupMember{{Name: "dead", Alive: false}}) != "" {
		t.Fatal("want empty selected when no member is alive")
	}
}

func TestAdminInferredSelectedSkipsFallbackAndUrlTest(t *testing.T) {
	t.Parallel()
	ms := int32(20)
	members := []AdminGroupMember{
		{Name: "a", Alive: true, LatencyMs: &ms},
		{Name: "b", Alive: true},
	}
	if got := adminInferredSelected(consts.DialerSelectionPolicy_Fallback, members); got != "" {
		t.Fatalf("fallback selected = %q, want empty (per-site, not global)", got)
	}
	if got := adminInferredSelected(consts.DialerSelectionPolicy_UrlTest, members); got != "" {
		t.Fatalf("url_test selected = %q, want empty (quality + per-site)", got)
	}
}

func TestAdminGroupsReportsLiveFallbackLeaf(t *testing.T) {
	t.Parallel()
	a := newNamedTestEndpointDialer("hk-1")
	b := newNamedTestEndpointDialer("us-1")
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	group := newTestOutboundGroup(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, a, b)
	t.Cleanup(func() { group.Close() })
	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{group},
			groupSelectionMembers: map[string][]string{
				group.Name: {"hk-1", "us-1"},
			},
		},
	}
	groups := c.AdminGroups()
	if len(groups) != 1 {
		t.Fatalf("groups = %#v, want 1", groups)
	}
	if groups[0].Selected != "hk-1" {
		t.Fatalf("selected = %q, want live fallback leaf hk-1", groups[0].Selected)
	}
}

func TestAdminGroupsIgnoresStaleSelectionAfterPolicyChange(t *testing.T) {
	t.Parallel()
	a := newTestEndpointDialer()
	b := newTestEndpointDialer()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	group := newTestOutboundGroup(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, a, b)
	t.Cleanup(func() { group.Close() })

	store := outbound.NewGroupSelectionStore(t.TempDir() + "/state.json")
	if err := store.Set(group.Name, "Cherry_Proxy"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds:           []*outbound.DialerGroup{group},
			groupSelectionStore: store,
			groupSelectionMembers: map[string][]string{
				group.Name: {"Cherry_Proxy", "Other"},
			},
		},
	}
	groups := c.AdminGroups()
	if len(groups) != 1 {
		t.Fatalf("groups = %#v, want 1", groups)
	}
	if groups[0].Policy != string(consts.DialerSelectionPolicy_Fallback) {
		t.Fatalf("policy = %q, want fallback", groups[0].Policy)
	}
	if groups[0].Selected != "" {
		t.Fatalf("selected = %q, want empty after select→fallback leftover store value", groups[0].Selected)
	}
}

func TestAdminGroupsUsesLiveFixedIndexWhenPersistedMemberGone(t *testing.T) {
	t.Parallel()
	d := newTestEndpointDialer()
	t.Cleanup(func() { _ = d.Close() })
	group := newTestFixedOutboundGroup(d)
	t.Cleanup(func() { group.Close() })

	store := outbound.NewGroupSelectionStore(t.TempDir() + "/state.json")
	if err := store.Set(group.Name, "Cherry_Proxy"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds:           []*outbound.DialerGroup{group},
			groupSelectionStore: store,
			groupSelectionMembers: map[string][]string{
				group.Name: {"Other", "Next"},
			},
		},
	}
	groups := c.AdminGroups()
	if len(groups) != 1 {
		t.Fatalf("groups = %#v, want 1", groups)
	}
	if groups[0].Selected != "Other" {
		t.Fatalf("selected = %q, want live FixedIndex member Other, not stale Cherry_Proxy", groups[0].Selected)
	}
}

func TestAdminStatusSnapshotCopiesInterfaces(t *testing.T) {
	t.Parallel()
	c := &ControlPlane{
		lanInterface: []string{"br-lan", "Home"},
		wanInterface: nil,
		runtimeStats: newRuntimeStats(),
	}
	c.recordUploadTraffic(4096)
	c.recordDownloadTraffic(2048)
	status := c.AdminStatusSnapshot("test-version")
	if status.Version != "test-version" || !status.Running {
		t.Fatalf("status = %#v", status)
	}
	if len(status.LanInterface) != 2 || status.LanInterface[0] != "br-lan" {
		t.Fatalf("lan = %#v", status.LanInterface)
	}
	status.LanInterface[0] = "mutated"
	if c.lanInterface[0] != "br-lan" {
		t.Fatal("AdminStatusSnapshot must copy lan_interface")
	}
	if status.UploadTotal != 4096 || status.DownloadTotal != 2048 {
		t.Fatalf("totals up=%d down=%d", status.UploadTotal, status.DownloadTotal)
	}
	if status.RssBytes == 0 || status.FdCount == 0 {
		t.Fatalf("process metrics rss=%d fd=%d", status.RssBytes, status.FdCount)
	}
	body, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "://") {
		t.Fatalf("status JSON leaked a URI: %s", body)
	}
}

func TestTriggerLatencyChecksForGroupRejectsUnknownAndBuiltin(t *testing.T) {
	t.Parallel()
	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{{Name: "AI"}},
		},
	}
	if err := c.TriggerLatencyChecksForGroup("direct"); err == nil {
		t.Fatal("builtin group should be rejected")
	}
	if err := c.TriggerLatencyChecksForGroup("missing"); err == nil {
		t.Fatal("unknown group should be rejected")
	}
	if err := c.TriggerLatencyChecksForGroup("AI"); err != nil {
		t.Fatalf("AI group: %v", err)
	}
}

func TestAdminGroupsReportsAdmissionStates(t *testing.T) {
	t.Parallel()
	a := newNamedTestEndpointDialer("hk-1")
	b := newNamedTestEndpointDialer("us-1")
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	typ := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	a.SetFailDegradedForTest(typ, true)
	group := newTestOutboundGroup(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, a, b)
	t.Cleanup(func() { group.Close() })
	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{group},
			groupSelectionMembers: map[string][]string{
				group.Name: {"hk-1", "us-1"},
			},
		},
	}
	groups := c.AdminGroups()
	if len(groups) != 1 || len(groups[0].Members) != 2 {
		t.Fatalf("groups = %#v", groups)
	}
	byName := map[string]AdminGroupMember{}
	for _, member := range groups[0].Members {
		byName[member.Name] = member
	}
	hk := byName["hk-1"]
	if hk.Admission != "degraded" {
		t.Fatalf("hk-1 admission = %q, want degraded", hk.Admission)
	}
	if !strings.Contains(hk.Reason, "fail") {
		t.Fatalf("hk-1 reason = %q, want fail", hk.Reason)
	}
	us := byName["us-1"]
	if us.Admission != "alive" && us.Admission != "" {
		t.Fatalf("us-1 admission = %q, want alive", us.Admission)
	}
	body, err := json.Marshal(groups)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"admission":"degraded"`) {
		t.Fatalf("JSON missing degraded admission: %s", body)
	}
}

func TestAdminGroupsResolvesNestedMemberHealthAndSelection(t *testing.T) {
	t.Parallel()
	a := newNamedTestEndpointDialer("hk-1")
	b := newNamedTestEndpointDialer("us-1")
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	option := &componentdialer.GlobalOption{Log: logger, CheckInterval: time.Second}
	annos := []*componentdialer.Annotation{{}, {}}
	child := outbound.NewDialerGroup(option, "proxy-child", []*componentdialer.Dialer{a, b}, annos, outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *componentdialer.NetworkType, bool) {})
	t.Cleanup(func() { child.Close() })
	parent, err := outbound.NewNestedDialerGroup(option, "stream", []outbound.NestedDialerGroupMember{{Group: child}}, outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive}, func(bool, *componentdialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("NewNestedDialerGroup() error = %v", err)
	}
	t.Cleanup(func() { parent.Close() })

	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{parent, child},
			groupSelectionMembers: map[string][]string{
				parent.Name: {child.Name},
				child.Name:  {"hk-1", "us-1"},
			},
		},
	}
	groups := c.AdminGroups()
	byName := map[string]AdminGroup{}
	for _, group := range groups {
		byName[group.Name] = group
	}
	stream, ok := byName["stream"]
	if !ok {
		t.Fatalf("groups = %#v, want stream parent", groups)
	}
	if len(stream.Members) != 1 || stream.Members[0].Name != "proxy-child" {
		t.Fatalf("stream members = %#v, want nested child name", stream.Members)
	}
	if !stream.Members[0].Alive {
		t.Fatalf("nested child shown dead: %#v", stream.Members[0])
	}
	if stream.Selected != "proxy-child" {
		t.Fatalf("stream selected = %q, want proxy-child", stream.Selected)
	}
}

func TestAdminGroupsParentHealthRetryKeepsNestedChildAlive(t *testing.T) {
	t.Parallel()
	a := newNamedTestEndpointDialer("hk-1")
	b := newNamedTestEndpointDialer("us-1")
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	childOption := &componentdialer.GlobalOption{
		Log:               logger,
		CheckInterval:     time.Second,
		TcpCheckOptionRaw: componentdialer.TcpCheckOptionRaw{Raw: []string{"https://child.example/check"}},
	}
	parentOption := &componentdialer.GlobalOption{
		Log:               logger,
		CheckInterval:     time.Second,
		TcpCheckOptionRaw: componentdialer.TcpCheckOptionRaw{Raw: []string{"https://parent.example/check"}},
	}
	annos := []*componentdialer.Annotation{{}, {}}
	child := outbound.NewDialerGroup(childOption, "proxy-child", []*componentdialer.Dialer{a, b}, annos, outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *componentdialer.NetworkType, bool) {})
	t.Cleanup(func() { child.Close() })
	parent, err := outbound.NewNestedDialerGroupWithRuntimeOptions(parentOption, "stream", []outbound.NestedDialerGroupMember{{Group: child}}, outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive}, func(bool, *componentdialer.NetworkType, bool) {}, outbound.DialerGroupRuntimeOptions{HealthCheckEnabled: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	t.Cleanup(func() { parent.Close() })
	t.Cleanup(func() {
		for _, view := range parent.ParentHealthViewDialers() {
			_ = view.Close()
		}
	})

	firstView := parent.HealthViewOf(a)
	if firstView == nil || firstView == a {
		t.Fatal("parent health clone for first child leaf is required")
	}
	snapshot := firstView.HealthSnapshot()
	for i := range snapshot.Collections {
		snapshot.Collections[i].Alive = false
	}
	firstView.RestoreHealthSnapshot(snapshot)

	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{parent, child},
			groupSelectionMembers: map[string][]string{
				parent.Name: {child.Name},
				child.Name:  {"hk-1", "us-1"},
			},
		},
	}
	groups := c.AdminGroups()
	byName := map[string]AdminGroup{}
	for _, group := range groups {
		byName[group.Name] = group
	}
	stream, ok := byName["stream"]
	if !ok {
		t.Fatalf("groups = %#v, want stream parent", groups)
	}
	if len(stream.Members) != 1 || !stream.Members[0].Alive {
		t.Fatalf("nested child shown dead after parent retry should admit second leaf: %#v", stream)
	}
}

func TestAdminGroupsIPv4OnlyNodeRemainsAliveWithLatencyWhenIPv6Fails(t *testing.T) {
	t.Parallel()
	d := newNamedTestEndpointDialer("hk-v4-only")
	t.Cleanup(func() { _ = d.Close() })

	tcp4 := &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	now := time.Now()
	snap := d.HealthSnapshot()
	snap.Collections[componentdialer.IdxTcp4].Alive = true
	snap.Collections[componentdialer.IdxTcp4].MovingAverage = 42 * time.Millisecond
	snap.Collections[componentdialer.IdxTcp4].LastProbe = componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  now,
		Alive:      true,
		Latency:    42 * time.Millisecond,
		HasLatency: true,
	}
	snap.Collections[componentdialer.IdxTcp6].Alive = false
	snap.Collections[componentdialer.IdxTcp6].LastProbe = componentdialer.DialerProbeObservationSnapshot{
		CheckedAt: now,
		Alive:     false,
		Message:   "timeout",
	}
	d.RestoreHealthSnapshot(snap)

	group := newTestOutboundGroup(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, d)
	t.Cleanup(func() { group.Close() })
	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{group},
			groupSelectionMembers: map[string][]string{
				group.Name: {"hk-v4-only"},
			},
		},
	}

	checkMember := func() AdminGroupMember {
		t.Helper()
		groups := c.AdminGroups()
		if len(groups) != 1 || len(groups[0].Members) != 1 {
			t.Fatalf("groups = %#v, want 1 group with 1 member", groups)
		}
		return groups[0].Members[0]
	}

	m := checkMember()
	if !m.Alive || m.Admission != "alive" || m.Reason != "ok" {
		t.Fatalf("IPv4-only member status = %#v, want Alive=true Admission=alive Reason=ok", m)
	}
	if m.LatencyMs == nil || *m.LatencyMs != 42 {
		t.Fatalf("IPv4-only member latency = %v, want 42", m.LatencyMs)
	}

	d.SetFailDegradedForTest(tcp4, true)
	m = checkMember()
	if !m.Alive || m.Admission != "degraded" || !strings.Contains(m.Reason, "fail") {
		t.Fatalf("degraded IPv4 + dead IPv6 member = %#v, want Alive=true Admission=degraded fail reason", m)
	}
	if m.LatencyMs == nil || *m.LatencyMs != 42 {
		t.Fatalf("degraded IPv4 member latency = %v, want 42", m.LatencyMs)
	}

	d.SetFailDegradedForTest(tcp4, false)
	snap = d.HealthSnapshot()
	snap.Collections[componentdialer.IdxTcp4].Alive = false
	snap.Collections[componentdialer.IdxTcp4].LastProbe = componentdialer.DialerProbeObservationSnapshot{
		CheckedAt: now,
		Alive:     false,
		Message:   "timeout",
	}
	d.RestoreHealthSnapshot(snap)
	m = checkMember()
	if m.Alive || m.Admission != "dead" {
		t.Fatalf("all-dead member = %#v, want Alive=false Admission=dead", m)
	}
}

func TestAdminMetricsSnapshotIncludesTCPAndUDP(t *testing.T) {
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })

	directGroup := &outbound.DialerGroup{Name: consts.OutboundDirect.String()}
	_, err := manager.adoptTCP(
		&memoryLayoutConn{id: 1001},
		nil,
		TcpFlowBinding{
			Egress: TcpEgressBinding{Outbound: directGroup, Target: "1.1.1.1:443"},
		},
		runtime,
		nil,
		netip.MustParseAddrPort("192.168.1.50:55001"),
		netip.MustParseAddrPort("1.1.1.1:443"),
	)
	if err != nil {
		t.Fatal(err)
	}

	key := UdpEndpointKey{
		Src: netip.MustParseAddrPort("192.168.1.50:55002"),
		Dst: netip.MustParseAddrPort("8.8.8.8:53"),
	}
	ue := &UdpEndpoint{poolRef: DefaultUdpEndpointPool, poolKey: key, NatTimeout: time.Minute}
	ue.RefreshTtl()
	shard := DefaultUdpEndpointPool.shardFor(key)
	shard.mu.Lock()
	DefaultUdpEndpointPool.setShardEntryLocked(shard, key, ue)
	shard.mu.Unlock()
	t.Cleanup(func() {
		shard := DefaultUdpEndpointPool.shardFor(key)
		shard.mu.Lock()
		DefaultUdpEndpointPool.deleteShardEntryLocked(shard, key)
		shard.mu.Unlock()
	})

	c := &ControlPlane{runtimeStats: newRuntimeStats()}
	if err := c.AttachSessionManager(manager); err != nil {
		t.Fatal(err)
	}

	snap := c.AdminMetricsSnapshot()
	if snap.TCPConnections != 1 {
		t.Fatalf("TCPConnections = %d, want 1", snap.TCPConnections)
	}
	if snap.UDPSessions < 1 {
		t.Fatalf("UDPSessions = %d, want >= 1", snap.UDPSessions)
	}
	if snap.ActiveConnections != snap.TCPConnections+snap.UDPSessions {
		t.Fatalf("ActiveConnections = %d, want TCP(%d)+UDP(%d)=%d",
			snap.ActiveConnections, snap.TCPConnections, snap.UDPSessions, snap.TCPConnections+snap.UDPSessions)
	}

	scalars := c.SnapshotRuntimeScalars()
	if scalars.ActiveConnections != snap.TCPConnections+scalars.UDPSessions {
		t.Fatalf("SnapshotRuntimeScalars ActiveConnections = %d, want %d",
			scalars.ActiveConnections, snap.TCPConnections+scalars.UDPSessions)
	}
}

func TestAdminGroupsP0RichHealthQualityScoreDataUDPAndSticky(t *testing.T) {
	t.Parallel()
	d := newNamedTestEndpointDialer("hk-rich")
	t.Cleanup(func() { _ = d.Close() })

	tcp4 := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	udp4 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}

	// Feed real probes via HealthSnapshot + HealthSlotDetail path and trigger data-UDP failure.
	snap := d.HealthSnapshot()
	snap.Collections[componentdialer.IdxTcp4].Alive = true
	snap.Collections[componentdialer.IdxTcp4].MovingAverage = 55 * time.Millisecond
	snap.Collections[componentdialer.IdxTcp4].LastProbe = componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  time.Now(),
		Alive:      true,
		Latency:    55 * time.Millisecond,
		HasLatency: true,
	}
	d.RestoreHealthSnapshot(snap)
	d.ObserveSilentFailure(udp4)
	d.SetFailDegradedForTest(udp4, true)
	d.SetFailDegradedForTest(tcp4, true)

	child := newTestOutboundGroup(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, d)
	t.Cleanup(func() { child.Close() })

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	parent, err := outbound.NewNestedDialerGroupWithRuntimeOptions(
		&componentdialer.GlobalOption{Log: logger, CheckTolerance: 80 * time.Millisecond},
		"proxy-parent",
		[]outbound.NestedDialerGroupMember{{Group: child}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_UrlTest},
		func(bool, *componentdialer.NetworkType, bool) {},
		outbound.DialerGroupRuntimeOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { parent.Close() })

	child.PinSite("sub.youtube.com", d, false)

	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{parent, child},
			groupSelectionMembers: map[string][]string{
				parent.Name: {child.Name},
				child.Name:  {"hk-rich"},
			},
		},
	}

	groups := c.AdminGroups()
	byName := map[string]AdminGroup{}
	for _, g := range groups {
		byName[g.Name] = g
	}

	p := byName["proxy-parent"]
	if p.CheckToleranceMs != 80 {
		t.Fatalf("CheckToleranceMs = %d, want 80", p.CheckToleranceMs)
	}
	if len(p.Members) != 1 || p.Members[0].ResolvedLeaf != "hk-rich" {
		t.Fatalf("parent member = %+v, want ResolvedLeaf=hk-rich", p.Members)
	}

	ch := byName[child.Name]
	if ch.StickyCount != 1 {
		t.Fatalf("StickyCount = %d, want 1", ch.StickyCount)
	}
	m := ch.Members[0]
	if m.QualityScoreMs == nil || *m.QualityScoreMs <= 55 {
		t.Fatalf("QualityScoreMs = %v, expected > 55 with degraded penalty", m.QualityScoreMs)
	}
	if m.Probes["udp4"] == nil || m.Probes["udp4"].Admission != "degraded" {
		t.Fatalf("expected degraded udp4 data-UDP slot, got %+v", m.Probes)
	}

	entries, total, err := c.AdminGroupSticky(child.Name, "tcp", "youtube", 10)
	if err != nil || total != 1 || len(entries) != 1 || entries[0].Site != "youtube.com" || entries[0].Leaf != "hk-rich" {
		t.Fatalf("AdminGroupSticky err=%v total=%d entries=%+v", err, total, entries)
	}
	cleared, err := c.AdminClearGroupSticky(child.Name, "youtube.com", "tcp")
	if err != nil || cleared != 1 {
		t.Fatalf("AdminClearGroupSticky err=%v cleared=%d", err, cleared)
	}
	if got := child.StickyCount(); got != 0 {
		t.Fatalf("StickyCount after clear = %d, want 0", got)
	}
}

func TestTriggerLatencyChecksForMemberNotifiesParentHealthViews(t *testing.T) {
	t.Parallel()
	a := newNamedTestEndpointDialer("hk-1")
	t.Cleanup(func() { _ = a.Close() })
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	childOption := &componentdialer.GlobalOption{
		Log:               logger,
		CheckInterval:     time.Second,
		TcpCheckOptionRaw: componentdialer.TcpCheckOptionRaw{Raw: []string{"https://child.example/check"}},
	}
	parentOption := &componentdialer.GlobalOption{
		Log:               logger,
		CheckInterval:     time.Second,
		TcpCheckOptionRaw: componentdialer.TcpCheckOptionRaw{Raw: []string{"https://parent.example/check"}},
	}
	child := outbound.NewDialerGroup(childOption, "proxy-child", []*componentdialer.Dialer{a}, []*componentdialer.Annotation{{}}, outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *componentdialer.NetworkType, bool) {})
	t.Cleanup(func() { child.Close() })
	parent, err := outbound.NewNestedDialerGroupWithRuntimeOptions(parentOption, "stream", []outbound.NestedDialerGroupMember{{Group: child}}, outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *componentdialer.NetworkType, bool) {}, outbound.DialerGroupRuntimeOptions{HealthCheckEnabled: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	t.Cleanup(func() { parent.Close() })
	t.Cleanup(func() {
		for _, view := range parent.ParentHealthViewDialers() {
			_ = view.Close()
		}
	})

	parentView := parent.HealthViewOf(a)
	if parentView == nil || parentView == a {
		t.Fatal("expected distinct parent health view clone")
	}

	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{parent, child},
		},
	}
	if err := c.TriggerLatencyChecksForMember(parent.Name, child.Name); err != nil {
		t.Fatalf("TriggerLatencyChecksForMember() error = %v", err)
	}
	if !parentView.HasPendingCheckForTest() {
		t.Fatal("expected parent health view check notification to be queued")
	}
	if !a.HasPendingCheckForTest() {
		t.Fatal("expected child concrete dialer check notification to be queued")
	}
}

func TestAdminGroupsRepresentativeProbeUsesAliveIPv6WhenIPv4Dead(t *testing.T) {
	t.Parallel()
	d := newNamedTestEndpointDialer("hk-v6-only")
	t.Cleanup(func() { _ = d.Close() })

	tcp4 := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	now := time.Now()
	// Seed tcp4 as dead with its own failure stats, and tcp6 as alive with distinct latency stats.
	snap := d.HealthSnapshot()
	snap.Collections[componentdialer.IdxTcp4].Alive = false
	snap.Collections[componentdialer.IdxTcp4].LastProbe = componentdialer.DialerProbeObservationSnapshot{
		CheckedAt: now,
		Alive:     false,
		Message:   "timeout",
	}
	snap.Collections[componentdialer.IdxTcp6].Alive = true
	snap.Collections[componentdialer.IdxTcp6].MovingAverage = 35 * time.Millisecond
	snap.Collections[componentdialer.IdxTcp6].LastProbe = componentdialer.DialerProbeObservationSnapshot{
		CheckedAt:  now,
		Alive:      true,
		Latency:    35 * time.Millisecond,
		HasLatency: true,
	}
	snap.Health[componentdialer.IdxTcp4] = componentdialer.NodeHealthSlotSnapshot{
		Baseline:            999 * time.Millisecond,
		BaselineSamples:     3,
		RecentSuccessDelays: []time.Duration{999 * time.Millisecond},
		LastSampleRTT:       999 * time.Millisecond,
		Degraded:            true,
	}
	snap.Health[componentdialer.IdxTcp6] = componentdialer.NodeHealthSlotSnapshot{
		Baseline:            30 * time.Millisecond,
		BaselineSamples:     3,
		RecentSuccessDelays: []time.Duration{32 * time.Millisecond, 35 * time.Millisecond},
		LastSampleRTT:       35 * time.Millisecond,
	}
	d.RestoreHealthSnapshot(snap)
	d.ObserveSilentFailure(tcp4)

	sample := adminSampleFromDialer(d, "node")
	if !sample.Alive || sample.LatencyMs == nil || *sample.LatencyMs != 35 {
		t.Fatalf("sample top-level = alive:%v lat:%v, want alive=true lat=35", sample.Alive, sample.LatencyMs)
	}
	if sample.BaselineMs == nil || *sample.BaselineMs != 30 {
		t.Fatalf("BaselineMs = %v, want 30 from tcp6 (not tcp4)", sample.BaselineMs)
	}
	if p4 := sample.Probes["tcp4"]; p4 == nil || p4.LossRate == nil || *p4.LossRate != 1 {
		t.Fatalf("tcp4 probe LossRate = %v, want 1.0", sample.Probes["tcp4"])
	}
	if sample.LossRate != nil {
		t.Fatalf("LossRate = %v, want nil from tcp6 (not tcp4's 1.0)", *sample.LossRate)
	}
	if len(sample.RecentLatenciesMs) != 2 || sample.RecentLatenciesMs[0] != 32 || sample.RecentLatenciesMs[1] != 35 {
		t.Fatalf("RecentLatenciesMs = %v, want [32 35] from tcp6", sample.RecentLatenciesMs)
	}
	if sample.QualityScoreMs == nil || *sample.QualityScoreMs != 35 {
		t.Fatalf("QualityScoreMs = %v, want 35 from tcp6", sample.QualityScoreMs)
	}
}

func TestAdminCloseGroupOtherConnections(t *testing.T) {
	t.Parallel()
	hk01 := newNamedTestEndpointDialer("hk-01")
	sg01 := newNamedTestEndpointDialer("sg-01")
	us01 := newNamedTestEndpointDialer("us-01")
	sharedLeaf := newNamedTestEndpointDialer("shared-leaf")
	t.Cleanup(func() {
		_ = hk01.Close()
		_ = sg01.Close()
		_ = us01.Close()
		_ = sharedLeaf.Close()
	})

	autoHK := newTestOutboundGroup(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, hk01, sharedLeaf)
	autoHK.Name = "auto-hk"
	t.Cleanup(func() { autoHK.Close() })
	autoJP := newTestOutboundGroup(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, sharedLeaf)
	autoJP.Name = "auto-jp"
	t.Cleanup(func() { autoJP.Close() })

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	proxy, err := outbound.NewNestedDialerGroupWithRuntimeOptions(
		&componentdialer.GlobalOption{Log: logger},
		"proxy",
		[]outbound.NestedDialerGroupMember{
			{Dialer: hk01},
			{Dialer: sg01},
			{Dialer: us01},
			{Group: autoHK},
			{Group: autoJP},
		},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *componentdialer.NetworkType, bool) {},
		outbound.DialerGroupRuntimeOptions{},
	)
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	t.Cleanup(func() { proxy.Close() })

	otherGroup := newTestOutboundGroup(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed}, us01)
	otherGroup.Name = "other"
	t.Cleanup(func() { otherGroup.Close() })

	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })

	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: []*outbound.DialerGroup{proxy, otherGroup, autoHK, autoJP},
		},
	}
	if err := c.AttachSessionManager(manager); err != nil {
		t.Fatal(err)
	}

	var nextID uint64
	var nextPort uint16 = 41000
	adopt := func(out *outbound.DialerGroup, d *componentdialer.Dialer, nested string) *FlowRuntime {
		nextID++
		nextPort++
		flow, aerr := manager.adoptTCP(
			&memoryLayoutConn{id: nextID},
			nil,
			TcpFlowBinding{
				Egress: TcpEgressBinding{
					Outbound:   out,
					Dialer:     d,
					Target:     "example.com:443",
					SelectPath: outbound.SelectPath{NestedMember: nested},
				},
			},
			runtime,
			nil,
			netip.AddrPortFrom(netip.MustParseAddr("192.168.1.2"), nextPort),
			netip.MustParseAddrPort("93.184.216.34:443"),
		)
		if aerr != nil {
			t.Fatal(aerr)
		}
		return flow
	}

	activeIDs := func() map[uint64]bool {
		res := make(map[uint64]bool)
		tcp, _ := manager.snapshotFlowRuntimes()
		for _, f := range tcp {
			if f != nil && !f.closedAccounted.Load() {
				res[f.id] = true
			}
		}
		return res
	}

	// 1. Re-selecting current node (hk-01 -> hk-01) spares hk-01, closes stale us-01, spares otherGroup.
	fHK := adopt(proxy, hk01, "")
	fStaleUS := adopt(proxy, us01, "")
	fOther := adopt(otherGroup, us01, "")
	if closed := c.AdminCloseGroupOtherConnections("proxy", "hk-01"); closed != 1 {
		t.Fatalf("re-select hk-01 closed = %d, want 1 (stale us-01)", closed)
	}
	if closed := c.AdminCloseGroupOtherConnections("proxy", "hk-01"); closed != 0 {
		t.Fatalf("repeat re-select hk-01 closed = %d, want 0", closed)
	}
	ids := activeIDs()
	if !ids[fHK.id] || ids[fStaleUS.id] || !ids[fOther.id] {
		t.Fatalf("unexpected active IDs after hk-01 re-select: %+v", ids)
	}

	// 2. Node-to-node (hk-01 -> sg-01) closes hk-01 and spares newly dialed sg-01.
	fSG := adopt(proxy, sg01, "")
	if closed := c.AdminCloseGroupOtherConnections("proxy", "sg-01"); closed != 1 {
		t.Fatalf("node-to-node sg-01 closed = %d, want 1", closed)
	}
	ids = activeIDs()
	if ids[fHK.id] || !ids[fSG.id] || !ids[fOther.id] {
		t.Fatalf("unexpected active IDs after node-to-node: %+v", ids)
	}

	// 3. Nested-to-node (auto-hk -> sg-01) closes auto-hk leaves and spares sg-01.
	fAutoHK := adopt(proxy, hk01, "auto-hk")
	if closed := c.AdminCloseGroupOtherConnections("proxy", "sg-01"); closed != 1 {
		t.Fatalf("nested-to-node sg-01 closed = %d, want 1", closed)
	}
	ids = activeIDs()
	if ids[fAutoHK.id] || !ids[fSG.id] {
		t.Fatalf("unexpected active IDs after nested-to-node: %+v", ids)
	}

	// 4. Node-to-nested and nested-to-nested (even sharing shared-leaf) keep only Chain[1] == auto-jp.
	fAutoHKShared := adopt(proxy, sharedLeaf, "auto-hk")
	fAutoJPShared := adopt(proxy, sharedLeaf, "auto-jp")
	if closed := c.AdminCloseGroupOtherConnections("proxy", "auto-jp"); closed != 2 {
		t.Fatalf("switch to auto-jp closed = %d, want 2 (sg-01 + auto-hk)", closed)
	}
	ids = activeIDs()
	if ids[fSG.id] || ids[fAutoHKShared.id] || !ids[fAutoJPShared.id] || !ids[fOther.id] {
		t.Fatalf("unexpected active IDs after nested-to-nested: %+v", ids)
	}

	// 5. Nested fallback when SelectPath.NestedMember is absent (len(Chain) < 3):
	// TCP flow on child leaf hk-01 must be kept when keepMember is auto-hk, while us-01 is closed.
	fTCPChildLeafNoPath := adopt(proxy, hk01, "")
	fTCPNonChildNoPath := adopt(proxy, us01, "")
	if closed := c.AdminCloseGroupOtherConnections("proxy", "auto-hk"); closed != 2 {
		t.Fatalf("nested fallback closed = %d, want 2 (fAutoJPShared + fTCPNonChildNoPath)", closed)
	}
	ids = activeIDs()
	if !ids[fTCPChildLeafNoPath.id] || ids[fTCPNonChildNoPath.id] || !ids[fOther.id] {
		t.Fatalf("unexpected active IDs after nested fallback close: %+v", ids)
	}
}
