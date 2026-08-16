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
)

func TestAdminGroupsOmitsBuiltinAndNodeLinks(t *testing.T) {
	t.Parallel()
	store := outbound.NewGroupSelectionStore(t.TempDir() + "/state.json")
	if err := store.Set("proxy", "Cherry_Proxy"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	group := &outbound.DialerGroup{Name: "proxy"}
	direct := &outbound.DialerGroup{Name: consts.OutboundDirect.String()}
	c := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds:             []*outbound.DialerGroup{direct, group},
			groupSelectionStore:   store,
			groupSelectionMembers: map[string][]string{"proxy": {"Cherry_Proxy", "Other"}},
		},
	}
	groups := c.AdminGroups()
	if len(groups) != 1 {
		t.Fatalf("groups = %#v, want 1 user group", groups)
	}
	if groups[0].Name != "proxy" || !groups[0].Selectable || groups[0].Selected != "Cherry_Proxy" {
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
