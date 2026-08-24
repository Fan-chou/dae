/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestSiteKey_ETLDPlusOne(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"www.youtube.com", "youtube.com"},
		{"m.youtube.com.", "youtube.com"},
		{"YOUTUBE.COM", "youtube.com"},
		{"a.b.google.co.uk", "google.co.uk"},
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:443", "1.2.3.4"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"::ffff:8.8.8.8", "8.8.8.8"},
		{"127.0.0.1", ""},
		{"::1", ""},
		{"0.0.0.0", ""},
		{"169.254.1.1", ""},
		{"example.com:443", "example.com"},
		{"localhost", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := SiteKey(tt.host); got != tt.want {
			t.Fatalf("SiteKey(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}

func TestDialerGroup_SiteStickyKeepsDegradedPin(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}

	g.PinSite("www.youtube.com", dialers[0], false)
	dialers[0].SetDegradedForTest(TestNetworkType, true)

	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "m.youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() error = %v", err)
	}
	if selected != dialers[0] {
		t.Fatalf("sticky site selected %p, want degraded pin %p", selected, dialers[0])
	}

	selected, _, err = g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() without site error = %v", err)
	}
	if selected != dialers[0] {
		t.Fatalf("group-level selected %p, want RTT-degraded first member %p", selected, dialers[0])
	}

	dialers[0].SetFailDegradedForTest(TestNetworkType, true)
	selected, _, _, err = g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "m.youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after fail-degrade error = %v", err)
	}
	if selected != dialers[0] {
		t.Fatalf("sticky site selected %p, want fail-degraded pin %p", selected, dialers[0])
	}
	selected, _, err = g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() after fail-degrade error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("group-level selected %p, want later Alive dialer %p after fail-degrade", selected, dialers[1])
	}
}

func TestDialerGroup_SiteStickyLeavesDeadPin(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}

	g.PinSite("youtube.com", dialers[0], false)
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[0], false)

	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after dead pin error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected %p, want next member after dead pin", selected)
	}
}

func TestDialerGroup_SiteStickyExcludedAndHoldDownAvoidFlap(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}

	now := time.Unix(1_700_000_000, 0)
	g.nowFn = func() time.Time { return now }

	g.PinSite("youtube.com", dialers[0], false)
	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, dialers[0], "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() excluded pin error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("excluded pin selected %p, want %p", selected, dialers[1])
	}

	g.FailSite("youtube.com", dialers[0])
	g.PinSite("youtube.com", dialers[1], false)

	dialers[0].SetDegradedForTest(TestNetworkType, false)
	selected, _, _, err = g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after failover error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected %p after A recovered, want held pin %p (no A↔B flap)", selected, dialers[1])
	}

	now = now.Add(siteStickyHoldDown + time.Second)
	selected, _, _, err = g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after hold-down error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected %p after hold-down, want dwell pin %p", selected, dialers[1])
	}
}

func TestDialerGroup_FallbackStickyReclaimsHigherPriority(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}

	now := time.Unix(1_700_000_000, 0)
	g.nowFn = func() time.Time { return now }

	g.PinSite("youtube.com", dialers[1], false)
	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after pin error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected %p before reclaim, want pin %p", selected, dialers[1])
	}

	now = now.Add(siteStickyReclaimAfter - time.Second)
	selected, _, _, err = g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() just before reclaim error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected %p just before reclaim, want pin %p", selected, dialers[1])
	}

	now = now.Add(2 * time.Second)
	selected, _, _, err = g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after reclaim error = %v", err)
	}
	if selected != dialers[0] {
		t.Fatalf("selected %p after reclaim, want higher-priority %p", selected, dialers[0])
	}
}

func TestDialerGroup_FallbackStickyDoesNotReclaimAfterSlowProbe(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}

	now := time.Unix(1_700_000_000, 0)
	g.nowFn = func() time.Time { return now }

	g.PinSite("youtube.com", dialers[0], false)
	now = now.Add(siteStickyMinDwell + time.Second)
	g.PinSite("youtube.com", dialers[0], true)
	g.PinSite("youtube.com", dialers[0], true)

	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after slow probe error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected %p after slow probe, want alt %p", selected, dialers[1])
	}
	g.PinSite("youtube.com", selected, false)

	now = now.Add(siteStickyReclaimAfter + time.Second)
	selected, _, _, err = g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after reclaim window error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected %p after slow-probe window, want to stay on alt %p", selected, dialers[1])
	}
}

func TestDialerGroup_SiteStickyPinsIPAndIgnoresFirstAlive(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}
	g.PinSite("1.2.3.4", dialers[0], false)
	dialers[0].SetFailDegradedForTest(TestNetworkType, true)
	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "1.2.3.4:443")
	if err != nil {
		t.Fatalf("SelectForSite(ip) error = %v", err)
	}
	if selected != dialers[0] {
		t.Fatalf("IP site selected %p, want fail-degraded pin %p", selected, dialers[0])
	}

	first, firstDialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive})
	defer first.Close()
	for _, d := range firstDialers {
		defer d.Close()
	}
	first.PinSite("youtube.com", firstDialers[1], false)
	selected, _, _, err = first.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("first_alive SelectForSite() error = %v", err)
	}
	if selected != firstDialers[0] {
		t.Fatalf("first_alive selected %p, want declaration order %p", selected, firstDialers[0])
	}
}

func TestDialerGroup_SiteStickyNestedParentPinsConcreteLeaf(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	a := namedNoopDialer(option, "proxy-a")
	b := namedNoopDialer(option, "proxy-b")
	defer a.Close()
	defer b.Close()

	childA, err := NewNestedDialerGroup(option, "child-a", []NestedDialerGroupMember{
		{Dialer: a},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("child-a: %v", err)
	}
	defer childA.Close()
	childB, err := NewNestedDialerGroup(option, "child-b", []NestedDialerGroupMember{
		{Dialer: b},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("child-b: %v", err)
	}
	defer childB.Close()

	parent, err := NewNestedDialerGroup(option, "parent", []NestedDialerGroupMember{
		{Group: childA},
		{Group: childB},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	parent.PinSite("youtu.be", a, false)
	a.SetDegradedForTest(TestNetworkType, true)
	selected, _, _, err := parent.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "www.youtu.be")
	if err != nil {
		t.Fatalf("nested SelectForSite() error = %v", err)
	}
	if selected != a {
		t.Fatalf("nested selected %p, want pinned concrete leaf %p", selected, a)
	}
}

func TestDialerGroup_NestedFixedChildHonorsParentHoldDown(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	a := namedNoopDialer(option, "proxy-a")
	b := namedNoopDialer(option, "proxy-b")
	defer a.Close()
	defer b.Close()

	childA, err := NewNestedDialerGroup(option, "child-a", []NestedDialerGroupMember{
		{Dialer: a},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("child-a: %v", err)
	}
	defer childA.Close()
	childB, err := NewNestedDialerGroup(option, "child-b", []NestedDialerGroupMember{
		{Dialer: b},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("child-b: %v", err)
	}
	defer childB.Close()

	parent, err := NewNestedDialerGroup(option, "parent", []NestedDialerGroupMember{
		{Group: childA},
		{Group: childB},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	now := time.Unix(1_700_000_000, 0)
	parent.nowFn = func() time.Time { return now }
	parent.FailSite("youtube.com", a)

	selected, _, _, err := parent.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("nested SelectForSite() after FailSite error = %v", err)
	}
	if selected != b {
		t.Fatalf("nested selected %p, want next fixed child %p", selected, b)
	}
}

func TestDialerGroup_NestedFallbackLastResortIgnoresChildHoldDown(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	leaf := namedNoopDialer(option, "only-leaf")
	defer leaf.Close()

	child, err := NewNestedDialerGroup(option, "child-fallback", []NestedDialerGroupMember{
		{Dialer: leaf},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	defer child.Close()
	parent, err := NewNestedDialerGroup(option, "parent-fallback", []NestedDialerGroupMember{
		{Group: child},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	now := time.Unix(1_700_000_000, 0)
	parent.nowFn = func() time.Time { return now }
	parent.FailSite("youtube.com", leaf)

	selected, _, _, err := parent.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("last-resort nested SelectForSite() error = %v, want the only healthy leaf", err)
	}
	if selected != leaf {
		t.Fatalf("nested last-resort selected %p, want hold-down leaf %p", selected, leaf)
	}
}

func TestDialerGroup_KernelFastPathDirectMinSiblingStickyStaysUserspace(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	directDialer := newDirectDialer(option, false)
	proxyDialer := namedNoopDialer(option, "sibling-proxy")
	defer directDialer.Close()
	defer proxyDialer.Close()

	directChild := NewDialerGroup(option, "direct-child", []*dialer.Dialer{directDialer}, newEmptyAnnotations(1), DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer directChild.Close()
	proxyChild := NewDialerGroup(option, "proxy-child", []*dialer.Dialer{proxyDialer}, newEmptyAnnotations(1), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fallback,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer proxyChild.Close()
	parent, err := NewNestedDialerGroup(option, "min-parent", []NestedDialerGroupMember{
		{Group: directChild},
		{Group: proxyChild},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	directDialer.MustGetLatencies10(TestNetworkType).AppendLatency(time.Millisecond)
	proxyDialer.MustGetLatencies10(TestNetworkType).AppendLatency(50 * time.Millisecond)
	parent.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(directDialer, true)
	parent.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(proxyDialer, true)

	if parent.KernelFastPathDirect(TestNetworkType) {
		t.Fatal("min parent must stay userspace while a sticky sibling still admits a proxy")
	}
}

func TestDialerGroup_KernelFastPathDirectFixedIgnoresUnselectedStickySibling(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	directDialer := newDirectDialer(option, false)
	proxyDialer := namedNoopDialer(option, "unused-proxy")
	defer directDialer.Close()
	defer proxyDialer.Close()

	directChild := NewDialerGroup(option, "direct-child", []*dialer.Dialer{directDialer}, newEmptyAnnotations(1), DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer directChild.Close()
	proxyChild := NewDialerGroup(option, "unused-fallback", []*dialer.Dialer{proxyDialer}, newEmptyAnnotations(1), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fallback,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer proxyChild.Close()
	parent, err := NewNestedDialerGroup(option, "fixed-parent", []NestedDialerGroupMember{
		{Group: directChild},
		{Group: proxyChild},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	if !parent.KernelFastPathDirect(TestNetworkType) {
		t.Fatal("fixed parent selecting DIRECT must keep kernel DIRECT despite an unused sticky sibling")
	}
}

func TestDialerGroup_KernelFastPathDirectFirstAliveIgnoresSharedDirectStickySibling(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	directDialer := newDirectDialer(option, false)
	proxyDialer := namedNoopDialer(option, "unused-proxy")
	defer directDialer.Close()
	defer proxyDialer.Close()

	directChild := NewDialerGroup(option, "direct-child", []*dialer.Dialer{directDialer}, newEmptyAnnotations(1), DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer directChild.Close()
	proxyChild := NewDialerGroup(option, "unused-fallback", []*dialer.Dialer{directDialer, proxyDialer}, newEmptyAnnotations(2), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fallback,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer proxyChild.Close()
	parent, err := NewNestedDialerGroup(option, "first-alive-parent", []NestedDialerGroupMember{
		{Group: directChild},
		{Group: proxyChild},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	if !parent.KernelFastPathDirect(TestNetworkType) {
		t.Fatal("first_alive parent selecting DIRECT must keep kernel DIRECT despite an unused sibling that shares the same DIRECT pointer")
	}
	if parent.HasSiteStickyFor(directDialer, TestNetworkType) {
		t.Fatal("first_alive path through fixed DIRECT must not inherit sticky from an unused fallback sibling that shares the same leaf")
	}
	if got := parent.NestedMemberNameFor(directDialer, TestNetworkType); got != "direct-child" {
		t.Fatalf("NestedMemberNameFor() = %q, want direct-child not the unused sticky sibling", got)
	}
}

func TestDialerGroup_KernelFastPathDirectFallbackStaysUserspaceWhileProxyAdmitted(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	proxy := namedNoopDialer(option, "proxy")
	direct := newDirectDialer(option, false)
	defer proxy.Close()
	defer direct.Close()

	g := NewDialerGroup(option, "fallback", []*dialer.Dialer{proxy, direct}, newEmptyAnnotations(2), DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	defer g.Close()

	if g.KernelFastPathDirect(TestNetworkType) {
		t.Fatal("fallback with admitted proxy must stay in userspace for site sticky")
	}
	proxy.SetDegradedForTest(TestNetworkType, true)
	if g.KernelFastPathDirect(TestNetworkType) {
		t.Fatal("degraded proxy must still keep fallback off kernel DIRECT")
	}
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(proxy, false)
	if !g.KernelFastPathDirect(TestNetworkType) {
		t.Fatal("fallback with only DIRECT admitted should allow kernel DIRECT")
	}
}

func TestDialerGroup_HoldDownSkipsAllFailedLeaves(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "fallback-3", dialers, newEmptyAnnotations(3), DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}

	now := time.Unix(1_700_000_000, 0)
	g.nowFn = func() time.Time { return now }

	g.FailSite("youtube.com", dialers[0])
	g.FailSite("youtube.com", dialers[1])

	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after A,B hold-down error = %v", err)
	}
	if selected != dialers[2] {
		t.Fatalf("selected %p, want healthy C %p (not A↔B flap)", selected, dialers[2])
	}
}

func TestDialerGroup_SnapshotPinSharesLiveTable(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_UrlTest})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}
	snap := g.SnapshotForEstablishedFlow(dialers[0])
	snap.PinSite("music.youtube.com", dialers[0], false)
	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after snapshot pin error = %v", err)
	}
	if selected != dialers[0] {
		t.Fatalf("selected %p, want snapshot-pinned leaf %p", selected, dialers[0])
	}
}

func TestDialerGroup_KernelFastPathDirectNestedFallbackStaysUserspace(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	proxy := namedNoopDialer(option, "proxy")
	direct := newDirectDialer(option, false)
	defer proxy.Close()
	defer direct.Close()

	child := NewDialerGroup(option, "auto", []*dialer.Dialer{proxy, direct}, newEmptyAnnotations(2), DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	defer child.Close()
	parent, err := NewNestedDialerGroup(option, "select", []NestedDialerGroupMember{{Group: child}}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	proxy.SetDegradedForTest(TestNetworkType, true)
	if parent.KernelFastPathDirect(TestNetworkType) {
		t.Fatal("fixed parent wrapping fallback must stay userspace while the child still admits a proxy")
	}
	child.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(proxy, false)
	if !parent.KernelFastPathDirect(TestNetworkType) {
		t.Fatal("fixed parent wrapping fallback may take kernel DIRECT once the proxy is Dead")
	}
}

func TestDialerGroup_SnapshotPinKeepsSiblingDwell(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}
	now := time.Unix(1_700_000_000, 0)
	g.nowFn = func() time.Time { return now }

	g.PinSite("youtube.com", dialers[0], false)
	snap := g.SnapshotForEstablishedFlow(dialers[1])
	snap.nowFn = g.nowFn
	snap.PinSite("youtube.com", dialers[1], false)

	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after sibling snapshot pin error = %v", err)
	}
	if selected != dialers[0] {
		t.Fatalf("selected %p, want dwell-locked pin %p (snapshot must not yank within 30s)", selected, dialers[0])
	}
}

func TestDialerGroup_FailureOnlyStickyExpiresAfterHoldDown(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}
	now := time.Unix(1_700_000_000, 0)
	g.nowFn = func() time.Time { return now }

	g.FailSite("youtube.com", dialers[0])
	g.siteSticky.mu.Lock()
	if _, ok := g.siteSticky.entries[SiteKey("youtube.com")]; !ok {
		g.siteSticky.mu.Unlock()
		t.Fatal("FailSite should insert a hold-down entry")
	}
	g.siteSticky.mu.Unlock()

	now = now.Add(siteStickyHoldDown + time.Second)
	if g.siteHoldDownActive("youtube.com", dialers[0]) {
		t.Fatal("hold-down should have expired")
	}
	g.siteSticky.mu.Lock()
	_, ok := g.siteSticky.entries[SiteKey("youtube.com")]
	g.siteSticky.mu.Unlock()
	if ok {
		t.Fatal("failure-only sticky entry should be deleted once hold-down expires")
	}
}

func TestSiteStickyEvictsFailureOnlyBeforeLivePins(t *testing.T) {
	table := newSiteStickyTable()
	now := time.Unix(1_700_000_000, 0)
	leaf := &dialer.Dialer{}
	still := func(*dialer.Dialer) bool { return true }
	for i := 0; i < siteStickyMaxEntries-1; i++ {
		table.pin(fmt.Sprintf("n%d.com", i), leaf, now, false, still)
	}
	other := &dialer.Dialer{}
	table.fail("oldfail.com", other, now.Add(-time.Minute))
	if len(table.entries) != siteStickyMaxEntries {
		t.Fatalf("entries = %d, want %d before evict", len(table.entries), siteStickyMaxEntries)
	}
	table.pin("newest.com", leaf, now, false, still)
	if _, ok := table.entries[SiteKey("oldfail.com")]; ok {
		t.Fatal("failure-only entry should be evicted before a live pin")
	}
	if _, ok := table.entries[SiteKey("newest.com")]; !ok {
		t.Fatal("newest pin should survive eviction")
	}
}

func TestDialerGroup_FailSiteHoldDownSurvivesLastSuccessTTL(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}
	now := time.Unix(1_700_000_000, 0)
	g.nowFn = func() time.Time { return now }

	g.PinSite("youtube.com", dialers[0], false)
	now = now.Add(siteStickyTTL - time.Second)
	g.FailSite("youtube.com", dialers[0])
	now = now.Add(2 * time.Second)

	if !g.siteHoldDownActive("youtube.com", dialers[0]) {
		t.Fatal("hold-down written near lastSuccess TTL must still be active")
	}
	selected, _, _, err := g.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectForSite() after TTL-boundary FailSite error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected %p, want next member %p while A is held down", selected, dialers[1])
	}
}

func TestDialerGroup_SharedChildStickyTableDedupesPin(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	a := namedNoopDialer(option, "proxy-a")
	b := namedNoopDialer(option, "proxy-b")
	defer a.Close()
	defer b.Close()

	auto := NewDialerGroup(option, "auto", []*dialer.Dialer{a, b}, newEmptyAnnotations(2), DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	defer auto.Close()
	stream, err := NewNestedDialerGroup(option, "stream", []NestedDialerGroupMember{{Group: auto}}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer stream.Close()
	parent, err := NewNestedDialerGroup(option, "final", []NestedDialerGroupMember{
		{Group: stream},
		{Group: auto},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	if got := parent.collectStickyTablesContaining(a); len(got) != 1 {
		t.Fatalf("collected %d sticky tables, want 1 unique auto table", len(got))
	}

	now := time.Unix(1_700_000_000, 0)
	parent.nowFn = func() time.Time { return now }
	auto.nowFn = parent.nowFn
	parent.PinSite("youtube.com", a, false)
	now = now.Add(siteStickyMinDwell + time.Second)
	parent.PinSite("youtube.com", a, true)

	auto.siteSticky.mu.Lock()
	entry := auto.siteSticky.entries[SiteKey("youtube.com")]
	slow := 0
	armed := false
	if entry != nil {
		slow = entry.consecutiveSlow
		armed = entry.probeNext
	}
	auto.siteSticky.mu.Unlock()
	if slow != 1 {
		t.Fatalf("consecutiveSlow = %d, want 1 after a single slow pin through a diamond", slow)
	}
	if armed {
		t.Fatal("one slow sample must not arm the site-unfriendly probe")
	}
}

func TestDialerGroup_SnapshotOmitsSiblingDialers(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}
	snap := g.SnapshotForEstablishedFlow(dialers[0])
	if got := snap.nestedConcreteDialers(); len(got) != 1 || got[0] != dialers[0] {
		t.Fatalf("snapshot members = %v, want only selected leaf", got)
	}
}

func TestDialerGroupCloseDetachesStickyFromSnapshots(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback})
	for _, d := range dialers {
		defer d.Close()
	}

	g.PinSite("youtube.com", dialers[0], false)
	snap := g.SnapshotForEstablishedFlow(dialers[0])
	if err := g.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	snap.FailSite("youtube.com", dialers[0])
	snap.PinSite("other.com", dialers[0], false)
	if g.siteSticky.holdDownActive("youtube.com", dialers[0], time.Now()) {
		t.Fatal("detached sticky table must ignore FailSite from an established-flow snapshot")
	}
}

func TestDialerGroup_SelectPathKeepsStickyWhenEmptySiteWouldReselect(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	a := namedNoopDialer(option, "proxy-a")
	b := namedNoopDialer(option, "proxy-b")
	defer a.Close()
	defer b.Close()
	child := NewDialerGroup(option, "inner-fallback", []*dialer.Dialer{a, b}, newEmptyAnnotations(2), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fallback,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer child.Close()
	parent, err := NewNestedDialerGroup(option, "fixed-parent", []NestedDialerGroupMember{
		{Group: child},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	child.PinSite("youtube.com", b, false)
	selected, _, _, path, err := parent.SelectWithPath(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectWithPath() error = %v", err)
	}
	if selected != b {
		t.Fatalf("selected %p, want pinned inner leaf %p", selected, b)
	}
	if !path.HasSiteSticky() {
		t.Fatal("recorded path must keep inner fallback sticky so a slow handshake can still switch")
	}
	if parent.HasSiteStickyFor(selected, TestNetworkType) {
		t.Fatal("empty-site reconstruction must not report sticky: it reselects A and misses the pin to B")
	}
}

func TestDialerGroup_SnapshotPathDoesNotPinUnusedFallbackSibling(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	leafA := namedNoopDialer(option, "shared-a")
	leafB := namedNoopDialer(option, "leaf-b")
	defer leafA.Close()
	defer leafB.Close()
	fixedChild := NewDialerGroup(option, "direct-child", []*dialer.Dialer{leafA}, newEmptyAnnotations(1), DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer fixedChild.Close()
	fallbackChild := NewDialerGroup(option, "unused-fallback", []*dialer.Dialer{leafB, leafA}, newEmptyAnnotations(2), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fallback,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer fallbackChild.Close()
	parent, err := NewNestedDialerGroup(option, "first-alive-parent", []NestedDialerGroupMember{
		{Group: fixedChild},
		{Group: fallbackChild},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	selected, _, _, path, err := parent.SelectWithPath(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectWithPath() error = %v", err)
	}
	if selected != leafA {
		t.Fatalf("selected %p, want shared leaf via fixed child %p", selected, leafA)
	}
	if path.HasSiteSticky() {
		t.Fatal("first_alive path through a non-sticky child must not record unused fallback sticky")
	}
	if path.NestedMember != "direct-child" {
		t.Fatalf("NestedMember = %q, want direct-child", path.NestedMember)
	}

	snap := parent.SnapshotForEstablishedFlowPath(selected, path)
	snap.PinSite("youtube.com", leafA, false)
	got, _, _, err := fallbackChild.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("unused fallback SelectForSite() error = %v", err)
	}
	if got != leafB {
		t.Fatalf("unused fallback selected %p, want B %p (recorded-path snapshot must not pin the sibling table)", got, leafB)
	}
}

func TestDialerGroup_PeekSelectPathRecordsNestedMember(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	a := namedNoopDialer(option, "proxy-a")
	b := namedNoopDialer(option, "proxy-b")
	defer a.Close()
	defer b.Close()
	childA, err := NewNestedDialerGroup(option, "child-a", []NestedDialerGroupMember{
		{Dialer: a},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("child-a: %v", err)
	}
	defer childA.Close()
	childB, err := NewNestedDialerGroup(option, "child-b", []NestedDialerGroupMember{
		{Dialer: b},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("child-b: %v", err)
	}
	defer childB.Close()
	parent, err := NewNestedDialerGroup(option, "parent", []NestedDialerGroupMember{
		{Group: childA},
		{Group: childB},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	defer parent.Close()

	d, nested, err := parent.PeekSelectPath(TestNetworkType)
	if err != nil {
		t.Fatalf("PeekSelectPath() error = %v", err)
	}
	if d != a {
		t.Fatalf("peek leaf %p, want child-a leaf %p", d, a)
	}
	if nested != "child-a" {
		t.Fatalf("PeekSelectPath nested = %q, want child-a from the same peek", nested)
	}
	if n := len(parent.internedSelectPaths); n != 0 {
		t.Fatalf("PeekSelectPath interned %d paths, want none (admin peek does not need a flow token)", n)
	}
	if _, _, _, err := parent.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com"); err != nil {
		t.Fatalf("SelectWithExclusionResultForSite() error = %v", err)
	}
	if n := len(parent.internedSelectPaths); n != 0 {
		t.Fatalf("SelectWithExclusionResultForSite interned %d paths, want none (handshake retry does not store a token)", n)
	}
	if _, _, _, _, err := parent.SelectWithPath(TestNetworkType, true, nil, "youtube.com"); err != nil {
		t.Fatalf("SelectWithPath() error = %v", err)
	}
	if n := len(parent.internedSelectPaths); n != 1 {
		t.Fatalf("SelectWithPath interned %d paths, want 1", n)
	}
}

func TestDialerGroup_SelectPathRecordsNineNestedStickyTables(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	a := namedNoopDialer(option, "proxy-a")
	b := namedNoopDialer(option, "proxy-b")
	defer a.Close()
	defer b.Close()

	inner := NewDialerGroup(option, "inner", []*dialer.Dialer{a, b}, newEmptyAnnotations(2), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fallback,
	}, func(bool, *dialer.NetworkType, bool) {})
	defer inner.Close()
	parent := inner
	for i := range 8 {
		next, err := NewNestedDialerGroup(option, fmt.Sprintf("wrap-%d", i), []NestedDialerGroupMember{
			{Group: parent},
		}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, func(bool, *dialer.NetworkType, bool) {})
		if err != nil {
			t.Fatalf("wrap-%d: %v", i, err)
		}
		defer next.Close()
		parent = next
	}

	selected, _, _, path, err := parent.SelectWithPath(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectWithPath() error = %v", err)
	}
	if selected != a {
		t.Fatalf("selected %p, want inner first leaf %p", selected, a)
	}
	if got := len(path.stickyTables()); got != 9 {
		t.Fatalf("sticky tables = %d, want 9 (must not truncate at 8)", got)
	}

	_, _, _, path2, err := parent.SelectWithPath(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("second SelectWithPath() error = %v", err)
	}
	if path != path2 {
		t.Fatal("the same nested path must intern to one comparable token")
	}
	if n := len(parent.internedSelectPaths); n != 1 {
		t.Fatalf("interned paths = %d, want 1 unique 9-deep token", n)
	}
	allocs := testing.AllocsPerRun(200, func() {
		_, _, _, got, err := parent.SelectWithPath(TestNetworkType, true, nil, "youtube.com")
		if err != nil {
			t.Fatal(err)
		}
		if got != path2 {
			t.Fatal("intern hit returned a different token")
		}
	})
	if allocs > 90 {
		t.Fatalf("intern-hit SelectWithPath allocs = %.1f, want <= 90 (must not recopy interned tables each select)", allocs)
	}
	if n := len(parent.internedSelectPaths); n != 1 {
		t.Fatalf("interned paths = %d after intern hits, want 1", n)
	}

	snap := parent.SnapshotForEstablishedFlowPath(selected, path)
	snap.PinSite("youtube.com", b, false)
	got, _, _, err := inner.SelectWithExclusionResultForSite(TestNetworkType, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("inner SelectForSite() after 9-deep pin error = %v", err)
	}
	if got != b {
		t.Fatal("recorded 9-deep path must pin the innermost sticky table, not drop it at cap 8")
	}
}

func TestInternSelectPathSharesTablesAcrossNestedMembers(t *testing.T) {
	g := &DialerGroup{}
	table := &siteStickyTable{}
	var a, b selectPathBuilder
	a.NestedMember = "child-a"
	b.NestedMember = "child-b"
	a.addTable(table)
	b.addTable(table)
	pa := internSelectPath(g, a)
	pb := internSelectPath(g, b)
	if pa.NestedMember != "child-a" || pb.NestedMember != "child-b" {
		t.Fatalf("NestedMember a=%q b=%q", pa.NestedMember, pb.NestedMember)
	}
	if pa == pb {
		t.Fatal("different NestedMember must keep distinct SelectPath tokens")
	}
	if pa.p == nil || pa.p != pb.p {
		t.Fatal("sibling leaves sharing one sticky table must reuse the interned slice")
	}
	if n := len(g.internedSelectPaths); n != 1 {
		t.Fatalf("interned paths = %d, want 1 shared table sequence", n)
	}
}

func TestInternSelectPathIndexesByLastTable(t *testing.T) {
	g := &DialerGroup{}
	shared := &siteStickyTable{}
	const n = 64
	var first [n]SelectPath
	for i := 0; i < n; i++ {
		var b selectPathBuilder
		b.NestedMember = "child"
		b.addTable(shared)
		b.addTable(&siteStickyTable{})
		first[i] = internSelectPath(g, b)
		again := internSelectPath(g, b)
		if again != first[i] {
			t.Fatalf("path %d intern hit returned a different token", i)
		}
	}
	if got := len(g.internedSelectPaths); got != n {
		t.Fatalf("interned paths = %d, want %d distinct last tables", got, n)
	}
	if got := len(g.internedByLastTable); got != n {
		t.Fatalf("last-table index size = %d, want %d", got, n)
	}
}

func TestInternSelectPathSkipsEmptyTables(t *testing.T) {
	g := &DialerGroup{}
	p := internSelectPath(g, selectPathBuilder{NestedMember: "child-a"})
	if p.NestedMember != "child-a" || p.p != nil {
		t.Fatalf("empty-table path = %+v, want NestedMember only", p)
	}
	if n := len(g.internedSelectPaths); n != 0 {
		t.Fatalf("interned %d paths, want none for NestedMember-only tokens", n)
	}
}
