/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/sirupsen/logrus"
)

const (
	testTcpCheckUrl = "https://connectivitycheck.gstatic.com/generate_204"
	testUdpCheckDns = "https://connectivitycheck.gstatic.com/generate_204"
)

var TestNetworkType = &dialer.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
	IsDns:     false,
}

var TestDnsUdp4NetworkType = &dialer.NetworkType{
	L4Proto:         consts.L4ProtoStr_UDP,
	IpVersion:       consts.IpVersionStr_4,
	IsDns:           true,
	UdpHealthDomain: dialer.UdpHealthDomainDns,
}

var TestDataUdp4NetworkType = &dialer.NetworkType{
	L4Proto:         consts.L4ProtoStr_UDP,
	IpVersion:       consts.IpVersionStr_4,
	UdpHealthDomain: dialer.UdpHealthDomainData,
}

var log = logrus.New()

func init() {
	logger.SetLogger(log, "trace", false, nil)
}

func newDirectDialer(option *dialer.GlobalOption, fullcone bool) *dialer.Dialer {
	_d, p := dialer.NewDirectDialer(option, true)
	d := dialer.NewDialer(_d, option, dialer.InstanceOption{DisableCheck: false}, p)
	return d
}

func newBuiltinBlockDialer(option *dialer.GlobalOption) *dialer.Dialer {
	underlay, property := dialer.NewBlockDialer(option, func() {})
	return dialer.NewDialer(underlay, option, dialer.InstanceOption{DisableCheck: true}, property)
}

func newEmptyAnnotations(n int) []*dialer.Annotation {
	annotations := make([]*dialer.Annotation, n)
	for i := range annotations {
		annotations[i] = &dialer.Annotation{}
	}
	return annotations
}

type noopTestDialer struct{}

func (noopTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("not implemented")
}

func newNoopDialer(option *dialer.GlobalOption) *dialer.Dialer {
	return dialer.NewDialer(
		noopTestDialer{},
		option,
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{},
	)
}

func dialerSignalLen(t *testing.T, d *dialer.Dialer, field string) int {
	t.Helper()

	v := reflect.ValueOf(d).Elem().FieldByName(field)
	if !v.IsValid() {
		t.Fatalf("field %q not found", field)
	}
	if v.Kind() != reflect.Chan {
		t.Fatalf("field %q kind = %v, want chan", field, v.Kind())
	}
	return v.Len()
}

func newTestGroupForSelection(policy DialerSelectionPolicy) (*DialerGroup, []*dialer.Dialer) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	group := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)), policy, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	return group, dialers
}

func markDialersDead(set *dialer.AliveDialerSet, dialers ...*dialer.Dialer) {
	for _, d := range dialers {
		set.NotifyLatencyChange(d, false)
	}
}

func TestDialerGroup_Select_Fixed(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
		CheckDnsTcp:       false,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, true),
		newDirectDialer(option, false),
	}
	fixedIndex := 1
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: fixedIndex,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	for range 10 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}

	fixedIndex = 0
	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: fixedIndex,
	})
	for range 10 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}
}

func TestDialerGroup_FixedHealthOverrideKeepsHealthState(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{newDirectDialer(option, false), newDirectDialer(option, false)}
	g := NewDialerGroupWithRuntimeOptions(
		option,
		"fixed-health",
		dialers,
		newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 1},
		func(bool, *dialer.NetworkType, bool) {},
		DialerGroupRuntimeOptions{HealthCheckEnabled: true},
	)
	defer g.Close()
	for _, d := range dialers {
		defer d.Close()
	}
	if g.MustGetAliveDialerSet(TestNetworkType) == nil {
		t.Fatal("fixed group with explicit health options must retain alive-state sets")
	}
	selected, _, err := g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if selected != dialers[1] {
		t.Fatalf("selected dialer = %p, want fixed dialer %p", selected, dialers[1])
	}
}

func TestDialerGroup_LazyCheckActivatesOnFirstSelection(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newDirectDialer(option, false)
	g := NewDialerGroupWithRuntimeOptions(
		option,
		"lazy-health",
		[]*dialer.Dialer{d},
		newEmptyAnnotations(1),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *dialer.NetworkType, bool) {},
		DialerGroupRuntimeOptions{HealthCheckEnabled: true, Lazy: true},
	)
	defer g.Close()
	defer d.Close()
	checkActivated := func() bool {
		return reflect.ValueOf(d).Elem().FieldByName("checkActivated").Bool()
	}
	if checkActivated() {
		t.Fatal("lazy group activated health check during construction")
	}
	if !g.IsLazyCheck() {
		t.Fatal("group did not retain lazy runtime option")
	}
	if _, _, err := g.Select(TestNetworkType, true); err != nil {
		t.Fatalf("first Select() error = %v", err)
	}
	if !checkActivated() {
		t.Fatal("first selection did not activate health check")
	}
	if _, _, err := g.Select(TestNetworkType, true); err != nil {
		t.Fatalf("second Select() error = %v", err)
	}
}

func TestDialerGroup_NestedActivationRespectsChildLazyCheck(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newDirectDialer(option, false)
	child := NewDialerGroupWithRuntimeOptions(
		option,
		"lazy-child",
		[]*dialer.Dialer{d},
		newEmptyAnnotations(1),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *dialer.NetworkType, bool) {},
		DialerGroupRuntimeOptions{HealthCheckEnabled: true, Lazy: true},
	)
	parent, err := NewNestedDialerGroup(option, "parent", []NestedDialerGroupMember{{Group: child}}, DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("NewNestedDialerGroup() error = %v", err)
	}
	defer parent.Close()
	defer child.Close()
	defer d.Close()

	checkActivated := func() bool {
		return reflect.ValueOf(d).Elem().FieldByName("checkActivated").Bool()
	}
	parent.ActivateCheck()
	if checkActivated() {
		t.Fatal("parent activation bypassed child's lazy health check")
	}
	if _, _, err := parent.Select(TestNetworkType, true); err != nil {
		t.Fatalf("parent.Select() error = %v", err)
	}
	if !checkActivated() {
		t.Fatal("child selection did not activate lazy health check")
	}
}

func TestDialerGroup_NestedParentHealthViewRetriesChildAlternative(t *testing.T) {
	childOption := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	parentOption := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{"https://parent.example/check"}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     30 * time.Second,
	}
	leaves := []*dialer.Dialer{newDirectDialer(childOption, false), newDirectDialer(childOption, false)}
	child := NewDialerGroup(childOption, "child", leaves, newEmptyAnnotations(len(leaves)), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	}, func(bool, *dialer.NetworkType, bool) {})
	parent, err := NewNestedDialerGroupWithRuntimeOptions(parentOption, "parent", []NestedDialerGroupMember{{Group: child}}, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	}, func(bool, *dialer.NetworkType, bool) {}, DialerGroupRuntimeOptions{HealthCheckEnabled: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	defer child.Close()
	for _, view := range parent.ParentHealthViewDialers() {
		defer view.Close()
	}
	for _, leaf := range leaves {
		defer leaf.Close()
	}

	firstView := parent.parentHealthViews[leaves[0]]
	if firstView == nil {
		t.Fatal("parent did not create a health view for the first child leaf")
	}
	if firstView == leaves[0] || firstView.GlobalOption != parentOption {
		t.Fatal("parent health view did not retain the parent-specific health option")
	}
	if leaves[0].GlobalOption != childOption {
		t.Fatal("parent health view overwrote the child leaf health option")
	}
	snapshot := firstView.HealthSnapshot()
	for i := range snapshot.Collections {
		snapshot.Collections[i].Alive = false
	}
	firstView.RestoreHealthSnapshot(snapshot)

	selected, _, err := parent.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("parent.Select() error = %v", err)
	}
	if selected != leaves[1] {
		t.Fatalf("selected dialer = %p, want child alternative %p", selected, leaves[1])
	}
}

func TestDialerGroup_NestedParentHealthViewPreservesFixedSelection(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	leaf := newDirectDialer(option, false)
	parent, err := NewNestedDialerGroupWithRuntimeOptions(option, "fixed-parent", []NestedDialerGroupMember{{Dialer: leaf}}, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {}, DialerGroupRuntimeOptions{HealthCheckEnabled: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	for _, view := range parent.ParentHealthViewDialers() {
		defer view.Close()
	}
	defer leaf.Close()

	view := parent.parentHealthViews[leaf]
	snapshot := view.HealthSnapshot()
	for i := range snapshot.Collections {
		snapshot.Collections[i].Alive = false
	}
	view.RestoreHealthSnapshot(snapshot)

	selected, _, err := parent.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("parent.Select() error = %v", err)
	}
	if selected != leaf {
		t.Fatalf("selected dialer = %p, want fixed dialer %p", selected, leaf)
	}
}

func TestDialerGroup_NestedParentHealthViewEnablesExplicitCheckForDisabledMember(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	underlay, property := dialer.NewDirectDialer(option, true)
	leaf := dialer.NewDialer(underlay, option, dialer.InstanceOption{DisableCheck: true}, property)
	parent, err := NewNestedDialerGroupWithRuntimeOptions(option, "disabled-member-parent", []NestedDialerGroupMember{{Dialer: leaf}}, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {}, DialerGroupRuntimeOptions{HealthCheckEnabled: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	defer leaf.Close()

	view := parent.parentHealthViews[leaf]
	if view == nil {
		t.Fatal("parent did not create a health view for the disabled member")
	}
	if view.DisableCheck {
		t.Fatal("explicit parent health view inherited DisableCheck and cannot run its own check")
	}
}

func TestDialerGroup_NestedParentMinLatencyUsesParentHealthView(t *testing.T) {
	childOption := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	parentOption := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{"https://parent.example/check"}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     30 * time.Second,
	}
	leaves := []*dialer.Dialer{newDirectDialer(childOption, false), newDirectDialer(childOption, false)}
	leaves[0].MustGetLatencies10(TestNetworkType).AppendLatency(10 * time.Millisecond)
	leaves[1].MustGetLatencies10(TestNetworkType).AppendLatency(100 * time.Millisecond)
	parent, err := NewNestedDialerGroupWithRuntimeOptions(parentOption, "min-parent", []NestedDialerGroupMember{
		{Dialer: leaves[0]}, {Dialer: leaves[1]},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinAverage10Latencies}, func(bool, *dialer.NetworkType, bool) {}, DialerGroupRuntimeOptions{HealthCheckEnabled: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	for _, leaf := range leaves {
		defer leaf.Close()
	}

	parent.parentHealthViews[leaves[0]].MustGetLatencies10(TestNetworkType).AppendLatency(100 * time.Millisecond)
	parent.parentHealthViews[leaves[1]].MustGetLatencies10(TestNetworkType).AppendLatency(10 * time.Millisecond)

	selected, _, err := parent.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("parent.Select() error = %v", err)
	}
	if selected != leaves[1] {
		t.Fatalf("selected dialer = %p, want parent-health fastest leaf %p", selected, leaves[1])
	}
}

func TestDialerGroup_EnsureReloadSelectionFloorMapsConcreteFallbackToParentView(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	leaf := newDirectDialer(option, false)
	child := NewDialerGroup(option, "reload-child", []*dialer.Dialer{leaf}, newEmptyAnnotations(1), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {})
	parent, err := NewNestedDialerGroupWithRuntimeOptions(option, "reload-parent", []NestedDialerGroupMember{{Group: child}}, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	}, func(bool, *dialer.NetworkType, bool) {}, DialerGroupRuntimeOptions{HealthCheckEnabled: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	defer child.Close()
	defer leaf.Close()

	view := parent.parentHealthViews[leaf]
	if view == nil {
		t.Fatal("parent did not create a health view for the concrete leaf")
	}
	fallback := parent.CaptureReloadSelectionFallback()
	if got := fallback[TestNetworkType.Index()]; got != leaf {
		t.Fatalf("reload fallback = %p, want concrete leaf %p", got, leaf)
	}

	set := parent.MustGetAliveDialerSet(TestNetworkType)
	set.NotifyLatencyChange(view, false)
	if set.Len() != 0 {
		t.Fatalf("parent alive set length before floor = %d, want 0", set.Len())
	}

	parent.EnsureReloadSelectionFloor(fallback)
	if !set.IsAlive(view) {
		t.Fatal("reload floor did not mark the parent health view alive")
	}
	if set.IsAlive(leaf) {
		t.Fatal("parent alive set unexpectedly admitted the concrete leaf instead of its view")
	}
}

func TestDialerGroup_NestedLazyParentActivatesOnlyParentViewUntilChildSelection(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	leaf := newDirectDialer(option, false)
	child := NewDialerGroupWithRuntimeOptions(
		option,
		"lazy-child",
		[]*dialer.Dialer{leaf},
		newEmptyAnnotations(1),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *dialer.NetworkType, bool) {},
		DialerGroupRuntimeOptions{HealthCheckEnabled: true, Lazy: true},
	)
	parent, err := NewNestedDialerGroupWithRuntimeOptions(option, "lazy-parent", []NestedDialerGroupMember{{Group: child}}, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {}, DialerGroupRuntimeOptions{HealthCheckEnabled: true, Lazy: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	defer child.Close()
	for _, view := range parent.ParentHealthViewDialers() {
		defer view.Close()
	}
	defer leaf.Close()

	parentView := parent.parentHealthViews[leaf]
	checkActivated := func(d *dialer.Dialer) bool {
		return reflect.ValueOf(d).Elem().FieldByName("checkActivated").Bool()
	}
	parent.ActivateCheck()
	if checkActivated(parentView) || checkActivated(leaf) {
		t.Fatal("lazy parent activation started parent view or lazy child")
	}
	if _, _, err := parent.Select(TestNetworkType, true); err != nil {
		t.Fatalf("parent.Select() error = %v", err)
	}
	if !checkActivated(parentView) {
		t.Fatal("first parent selection did not activate the parent health view")
	}
	if !checkActivated(leaf) {
		t.Fatal("parent selection did not activate the selected lazy child")
	}
}

func TestDialerGroup_CaptureReloadSelectionFallbackDoesNotActivateCheck(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	leaf := newDirectDialer(option, false)
	child := NewDialerGroupWithRuntimeOptions(
		option,
		"lazy-child",
		[]*dialer.Dialer{leaf},
		newEmptyAnnotations(1),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *dialer.NetworkType, bool) {},
		DialerGroupRuntimeOptions{HealthCheckEnabled: true, Lazy: true},
	)
	parent, err := NewNestedDialerGroupWithRuntimeOptions(option, "lazy-parent", []NestedDialerGroupMember{{Group: child}}, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	}, func(bool, *dialer.NetworkType, bool) {}, DialerGroupRuntimeOptions{HealthCheckEnabled: true, Lazy: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	defer child.Close()
	for _, view := range parent.ParentHealthViewDialers() {
		defer view.Close()
	}
	defer leaf.Close()

	checkActivated := func(d *dialer.Dialer) bool {
		return reflect.ValueOf(d).Elem().FieldByName("checkActivated").Bool()
	}
	view := parent.parentHealthViews[leaf]
	fallback := parent.CaptureReloadSelectionFallback()
	if got := fallback[TestNetworkType.Index()]; got != leaf {
		t.Fatalf("reload fallback = %p, want concrete leaf %p", got, leaf)
	}
	if checkActivated(leaf) {
		t.Fatal("fallback sampling activated the concrete leaf probe")
	}
	if view != nil && checkActivated(view) {
		t.Fatal("fallback sampling activated the parent health view")
	}
}

func TestDialerGroup_Select_MinLastLatency(t *testing.T) {

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
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	// Test 1000 times.
	for range 1000 {
		var minLatency time.Duration
		jMinLatency := -1
		for j, d := range dialers {
			// Simulate a latency test.
			var (
				latency time.Duration
				alive   bool
			)
			// 20% chance for timeout.
			if fastrand.Intn(5) == 0 {
				// Simulate a timeout test.
				latency = 1000 * time.Millisecond
				alive = false
			} else {
				// Simulate a normal test.
				latency = time.Duration(fastrand.Int63n(int64(1000 * time.Millisecond)))
				alive = true
			}
			d.MustGetLatencies10(TestNetworkType).AppendLatency(latency)
			if alive && (jMinLatency == -1 || latency < minLatency) {
				jMinLatency = j
				minLatency = latency
			}
			g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(d, alive)
		}
		d, _, err := g.Select(TestNetworkType, true)
		if jMinLatency == -1 {
			if !errors.Is(err, ErrNoAliveDialer) {
				t.Fatalf("expected ErrNoAliveDialer, got: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[jMinLatency] {
			// Get index of d.
			indexD := -1
			for j := range dialers {
				if d == dialers[j] {
					indexD = j
					break
				}
			}
			t.Errorf("dialers[%v] expected, but dialers[%v] selected", jMinLatency, indexD)
		}
	}
}

func TestDialerGroup_Select_Random(t *testing.T) {

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
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	count := make([]int, len(dialers))
	for range 100 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
}

func TestDialerGroup_Resuscitate_UDPTriggersDnsUdpAndTcp(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newNoopDialer(option)
	g := &DialerGroup{
		Dialers: []*dialer.Dialer{d},
	}

	g.resuscitate(TestDataUdp4NetworkType)

	if got := dialerSignalLen(t, d, "checkDnsUdpCh"); got != 1 {
		t.Fatalf("DNS-UDP resuscitation signals = %d, want 1", got)
	}
	if got := dialerSignalLen(t, d, "checkTcpCh"); got != 1 {
		t.Fatalf("TCP resuscitation signals = %d, want 1", got)
	}
}

func TestDialerGroup_Resuscitate_TCPTriggersOnlyTcp(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newNoopDialer(option)
	g := &DialerGroup{
		Dialers: []*dialer.Dialer{d},
	}

	g.resuscitate(TestNetworkType)

	if got := dialerSignalLen(t, d, "checkDnsUdpCh"); got != 0 {
		t.Fatalf("DNS-UDP resuscitation signals = %d, want 0", got)
	}
	if got := dialerSignalLen(t, d, "checkTcpCh"); got != 1 {
		t.Fatalf("TCP resuscitation signals = %d, want 1", got)
	}
}

func TestDialerGroup_SetAlive(t *testing.T) {

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
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	zeroTarget := 3
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[zeroTarget], false)
	count := make([]int, len(dialers))
	for range 100 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 && i != zeroTarget {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
	if count[zeroTarget] != 0 {
		t.Fail()
	}
}

func TestDialerGroup_SetSelectionPolicy_FixedToRandomCreatesAliveState(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	if got := g.MustGetAliveDialerSet(TestNetworkType); got != nil {
		t.Fatal("fixed policy should not eagerly allocate alive-state sets")
	}

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	set := g.MustGetAliveDialerSet(TestNetworkType)
	if set == nil {
		t.Fatal("random policy should allocate alive-state sets on demand")
	}
	if got := set.Len(); got != len(dialers) {
		t.Fatalf("alive dialer count = %d, want %d", got, len(dialers))
	}
}

func TestDialerGroup_SetSelectionPolicy_FixedToRandomPreservesAliveState(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	dialers[1].ReportUnavailableForced(TestNetworkType, errors.New("forced dead for policy switch"))

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	set := g.MustGetAliveDialerSet(TestNetworkType)
	if set == nil {
		t.Fatal("random policy should allocate alive-state sets")
	}
	if got := set.Len(); got != 1 {
		t.Fatalf("alive dialer count = %d, want 1", got)
	}

	selected, _, err := g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() error after preserving alive state: %v", err)
	}
	if selected != dialers[0] {
		t.Fatal("expected selection to skip dialer that was already dead before policy switch")
	}
}

func TestDialerGroup_SetSelectionPolicy_RecomputesMinLatencyOrdering(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(90 * time.Millisecond)
	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(80 * time.Millisecond)
	dialers[1].MustGetLatencies10(TestNetworkType).AppendLatency(50 * time.Millisecond)
	dialers[1].MustGetLatencies10(TestNetworkType).AppendLatency(40 * time.Millisecond)

	set := g.MustGetAliveDialerSet(TestNetworkType)
	set.NotifyLatencyChange(dialers[0], true)
	set.NotifyLatencyChange(dialers[1], true)

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinAverage10Latencies,
	})

	selected, _, err := g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() error after policy update: %v", err)
	}
	if selected != dialers[1] {
		t.Fatal("expected lower-average-latency dialer after policy recompute")
	}
}

func TestDialerGroup_Select_DataUdpFallsBackToDnsUdp(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	markDialersDead(g.MustGetAliveDialerSet(TestDataUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestDnsUdp4NetworkType), dialers[0])
	markDialersDead(g.MustGetAliveDialerSet(TestNetworkType), dialers...)

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[1] {
		t.Fatalf("expected DNS UDP fallback to select dialers[1], got another dialer")
	}
}

func TestDialerGroup_Select_DataUdpFallsBackToTcp(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	markDialersDead(g.MustGetAliveDialerSet(TestDataUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestDnsUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestNetworkType), dialers[1])

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[0] {
		t.Fatalf("expected TCP fallback to select dialers[0], got another dialer")
	}
}

func TestDialerGroup_Select_DataUdpFixedPolicyDoesNotFallback(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 1,
	})

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[1] {
		t.Fatalf("expected fixed policy to keep selecting dialers[1], got another dialer")
	}
}

func TestDialerGroup_Select_FirstAlivePreservesDeclarationOrder(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	})
	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(2 * time.Second)
	dialers[1].MustGetLatencies10(TestNetworkType).AppendLatency(time.Millisecond)

	for range 20 {
		d, latency, err := g.Select(TestNetworkType, true)
		if err != nil {
			t.Fatalf("Select() error = %v", err)
		}
		if d != dialers[0] {
			t.Fatalf("selected dialer = %p, want first declared dialer %p", d, dialers[0])
		}
		if latency != 0 {
			t.Fatalf("selection latency = %v, want 0 for first_alive", latency)
		}
	}
}

func TestDialerGroup_Select_FirstAliveSkipsDeadAndReturnsNoAlive(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	})
	set := g.MustGetAliveDialerSet(TestNetworkType)
	set.NotifyLatencyChange(dialers[0], false)

	d, _, err := g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() after first dialer failure = %v", err)
	}
	if d != dialers[1] {
		t.Fatalf("selected dialer = %p, want second declared alive dialer %p", d, dialers[1])
	}

	set.NotifyLatencyChange(dialers[1], false)
	if _, _, err := g.Select(TestNetworkType, true); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("Select() with no alive dialers error = %v, want ErrNoAliveDialer", err)
	}
}

func TestDialerGroup_Select_FirstAliveSingleDeadDoesNotForceSelection(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	d := newDirectDialer(option, false)
	g := NewDialerGroup(option, "single-first-alive", []*dialer.Dialer{d}, newEmptyAnnotations(1), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	}, func(bool, *dialer.NetworkType, bool) {})
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(d, false)

	if _, _, err := g.Select(TestNetworkType, true); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("Select() with one dead dialer error = %v, want ErrNoAliveDialer", err)
	}
}

func TestDialerGroup_Select_FirstAliveEmptyReturnsNoAlive(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	g := NewDialerGroup(option, "empty-first-alive", nil, nil, DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	}, func(bool, *dialer.NetworkType, bool) {})

	if _, _, err := g.Select(TestNetworkType, true); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("Select() with empty group error = %v, want ErrNoAliveDialer", err)
	}
}

func TestDialerGroup_Select_FirstAliveFallsBackToOtherIPFamily(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	})
	for _, d := range dialers {
		d.ReportUnavailableForced(TestNetworkType, errors.New("forced IPv4 failure"))
	}

	d, _, selectedNetworkType, err := g.SelectWithExclusionResult(TestNetworkType, false, nil)
	if err != nil {
		t.Fatalf("SelectWithExclusionResult() error = %v", err)
	}
	if d != dialers[0] {
		t.Fatalf("selected dialer = %p, want first declared IPv6-alive dialer %p", d, dialers[0])
	}
	if selectedNetworkType == nil || selectedNetworkType.IpVersion != consts.IpVersionStr_6 {
		t.Fatalf("selected network type = %#v, want IPv6 fallback", selectedNetworkType)
	}
}

func TestDialerGroup_Select_FirstAliveNestedSkipsFailedChildAndUsesBuiltinSibling(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	for _, builtinName := range []string{"direct", "block"} {
		t.Run(builtinName, func(t *testing.T) {
			childDialers := []*dialer.Dialer{
				newDirectDialer(option, false),
				newDirectDialer(option, false),
			}
			child := NewDialerGroup(option, "failed-child", childDialers, newEmptyAnnotations(len(childDialers)), DialerSelectionPolicy{
				Policy: consts.DialerSelectionPolicy_FirstAlive,
			}, func(bool, *dialer.NetworkType, bool) {})
			childSet := child.MustGetAliveDialerSet(TestNetworkType)
			for _, d := range childDialers {
				childSet.NotifyLatencyChange(d, false)
			}

			builtinDialer := newDirectDialer(option, false)
			builtin := NewDialerGroup(option, builtinName, []*dialer.Dialer{builtinDialer}, newEmptyAnnotations(1), DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, func(bool, *dialer.NetworkType, bool) {})
			parent, err := NewNestedDialerGroup(option, "parent", []NestedDialerGroupMember{
				{Group: child},
				{Group: builtin},
			}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive}, func(bool, *dialer.NetworkType, bool) {})
			if err != nil {
				t.Fatalf("NewNestedDialerGroup() error = %v", err)
			}

			selected, _, err := parent.Select(TestNetworkType, true)
			if err != nil {
				t.Fatalf("Select() error = %v", err)
			}
			if selected != builtinDialer {
				t.Fatalf("selected dialer = %p, want %s builtin sibling %p", selected, builtinName, builtinDialer)
			}
		})
	}
}

func TestDialerGroup_Select_FirstAliveNestedHealthKeepsBlockFallback(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	policies := []DialerSelectionPolicy{
		{Policy: consts.DialerSelectionPolicy_FirstAlive},
		{Policy: consts.DialerSelectionPolicy_MinAverage10Latencies},
	}
	for _, policy := range policies {
		t.Run(string(policy.Policy), func(t *testing.T) {
			childDialers := []*dialer.Dialer{
				newDirectDialer(option, false),
				newDirectDialer(option, false),
			}
			child := NewDialerGroup(option, "failed-child", childDialers, newEmptyAnnotations(len(childDialers)), DialerSelectionPolicy{
				Policy: consts.DialerSelectionPolicy_FirstAlive,
			}, func(bool, *dialer.NetworkType, bool) {})
			childSet := child.MustGetAliveDialerSet(TestNetworkType)
			for _, d := range childDialers {
				childSet.NotifyLatencyChange(d, false)
			}

			blockDialer := newBuiltinBlockDialer(option)
			if !skipsParentHealthAdmission(blockDialer) {
				t.Fatalf("builtin block dialer name=%q link=%q disableCheck=%v should skip parent health admission", blockDialer.Property().Name, blockDialer.Property().Link, blockDialer.DisableCheck)
			}
			block := NewDialerGroup(option, consts.OutboundBlock.String(), []*dialer.Dialer{blockDialer}, newEmptyAnnotations(1), DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, func(bool, *dialer.NetworkType, bool) {})
			sawKernelDead := false
			parent, err := NewNestedDialerGroupWithRuntimeOptions(option, "parent", []NestedDialerGroupMember{
				{Group: child},
				{Group: block},
			}, policy, func(alive bool, _ *dialer.NetworkType, isInit bool) {
				if !alive && !isInit {
					sawKernelDead = true
				}
			}, DialerGroupRuntimeOptions{HealthCheckEnabled: true})
			if err != nil {
				t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
			}
			defer parent.Close()
			defer child.Close()
			defer block.Close()
			defer blockDialer.Close()
			for _, view := range parent.ParentHealthViewDialers() {
				defer view.Close()
			}
			for _, d := range childDialers {
				defer d.Close()
			}

			if view := parent.parentHealthViews[blockDialer]; view != nil {
				t.Fatal("parent created a health view for REJECT/block; probes would mark the fallback dead")
			}
			for _, leaf := range childDialers {
				if parent.parentHealthViews[leaf] == nil {
					t.Fatal("parent omitted a health view for a probeable child leaf")
				}
				snapshot := parent.parentHealthViews[leaf].HealthSnapshot()
				for i := range snapshot.Collections {
					snapshot.Collections[i].Alive = false
				}
				parent.parentHealthViews[leaf].RestoreHealthSnapshot(snapshot)
			}

			set := parent.MustGetAliveDialerSet(TestNetworkType)
			if set == nil {
				t.Fatal("parent has no alive set")
			}
			if got := set.Len(); got != 0 {
				t.Fatalf("parent probe set length = %d, want 0 after all health views died", got)
			}
			if !parent.KernelOutboundAlive(TestNetworkType) {
				t.Fatal("kernel outbound alive = false; REJECT fallback would be unreachable from BPF")
			}
			if sawKernelDead {
				t.Fatal("alive callback reported the group dead; BPF would drop new connections before REJECT")
			}

			selected, _, err := parent.Select(TestNetworkType, true)
			if err != nil {
				t.Fatalf("Select() error = %v", err)
			}
			if selected != blockDialer {
				t.Fatalf("selected dialer = %p, want builtin block fallback %p", selected, blockDialer)
			}
		})
	}
}

func TestDialerGroup_KernelOutboundAliveWithoutBlockFollowsProbeSet(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	childDialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	child := NewDialerGroup(option, "failed-child", childDialers, newEmptyAnnotations(len(childDialers)), DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_FirstAlive,
	}, func(bool, *dialer.NetworkType, bool) {})
	sawKernelDead := false
	parent, err := NewNestedDialerGroupWithRuntimeOptions(option, "parent", []NestedDialerGroupMember{
		{Group: child},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinAverage10Latencies}, func(alive bool, _ *dialer.NetworkType, isInit bool) {
		if !alive && !isInit {
			sawKernelDead = true
		}
	}, DialerGroupRuntimeOptions{HealthCheckEnabled: true})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	defer child.Close()
	for _, view := range parent.ParentHealthViewDialers() {
		defer view.Close()
	}
	for _, d := range childDialers {
		defer d.Close()
	}

	for _, leaf := range childDialers {
		view := parent.parentHealthViews[leaf]
		if view == nil {
			t.Fatal("parent omitted a health view for a probeable child leaf")
		}
		snapshot := view.HealthSnapshot()
		for i := range snapshot.Collections {
			snapshot.Collections[i].Alive = false
		}
		view.RestoreHealthSnapshot(snapshot)
	}

	set := parent.MustGetAliveDialerSet(TestNetworkType)
	if set == nil {
		t.Fatal("parent has no alive set")
	}
	if got := set.Len(); got != 0 {
		t.Fatalf("parent probe set length = %d, want 0 after all health views died", got)
	}
	if parent.KernelOutboundAlive(TestNetworkType) {
		t.Fatal("kernel outbound alive = true, want false when every probeable member is dead")
	}
	if !sawKernelDead {
		t.Fatal("alive callback did not report the group dead after every probeable member died")
	}
}
