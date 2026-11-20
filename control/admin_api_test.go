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
