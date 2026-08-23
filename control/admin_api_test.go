/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
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
