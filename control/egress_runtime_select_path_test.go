/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestAcquireEgressKeepsDeepStickyPathsDistinct(t *testing.T) {
	a := newTestEndpointDialer()
	b := newTestEndpointDialer()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	option := &componentdialer.GlobalOption{Log: logger, CheckInterval: time.Second}
	fixedChild := ob.NewDialerGroup(option, "fixed-child", []*componentdialer.Dialer{a}, []*componentdialer.Annotation{{}}, ob.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}, func(bool, *componentdialer.NetworkType, bool) {})
	t.Cleanup(func() { _ = fixedChild.Close() })
	fallbackChild := ob.NewDialerGroup(option, "fallback-child", []*componentdialer.Dialer{a, b}, []*componentdialer.Annotation{{}, {}}, ob.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fallback,
	}, func(bool, *componentdialer.NetworkType, bool) {})
	t.Cleanup(func() { _ = fallbackChild.Close() })
	middle, err := ob.NewNestedDialerGroup(option, "middle", []ob.NestedDialerGroupMember{
		{Group: fixedChild},
		{Group: fallbackChild},
	}, ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *componentdialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("middle: %v", err)
	}
	t.Cleanup(func() { _ = middle.Close() })
	parent, err := ob.NewNestedDialerGroup(option, "root", []ob.NestedDialerGroupMember{
		{Group: middle},
	}, ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(bool, *componentdialer.NetworkType, bool) {})
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	t.Cleanup(func() { _ = parent.Close() })

	nt := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	selected1, _, _, path1, err := parent.SelectWithPath(nt, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectWithPath fixed grandchild: %v", err)
	}
	if selected1 != a || path1.HasSiteSticky() || path1.NestedMember != "middle" {
		t.Fatalf("fixed grandchild path selected=%p sticky=%v member=%q", selected1, path1.HasSiteSticky(), path1.NestedMember)
	}

	middle.SetSelectionPolicy(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 1})
	selected2, _, _, path2, err := parent.SelectWithPath(nt, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("SelectWithPath fallback grandchild: %v", err)
	}
	if selected2 != a || !path2.HasSiteSticky() || path2.NestedMember != "middle" {
		t.Fatalf("fallback grandchild path selected=%p sticky=%v member=%q", selected2, path2.HasSiteSticky(), path2.NestedMember)
	}

	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })
	runtime.configureResources([]*ob.DialerGroup{parent}, []*componentdialer.Dialer{a, b}, nil)

	_, snap1, ok := runtime.acquireEgress(selected1, parent, path1)
	if !ok || snap1 == nil {
		t.Fatal("acquireEgress non-sticky path failed")
	}
	_, snap2, ok := runtime.acquireEgress(selected2, parent, path2)
	if !ok || snap2 == nil {
		t.Fatal("acquireEgress sticky path failed")
	}
	if snap1 == snap2 {
		t.Fatal("acquireEgress reused one snapshot for deep paths that share NestedMember but not sticky tables")
	}

	snap1.PinSite("other.com", b, false)
	got, _, _, err := fallbackChild.SelectWithExclusionResultForSite(nt, true, nil, "other.com")
	if err != nil {
		t.Fatalf("fallback SelectForSite other.com: %v", err)
	}
	if got != a {
		t.Fatal("non-sticky snapshot must not pin the unused fallback table")
	}

	snap2.PinSite("youtube.com", b, false)
	got, _, _, err = fallbackChild.SelectWithExclusionResultForSite(nt, true, nil, "youtube.com")
	if err != nil {
		t.Fatalf("fallback SelectForSite youtube.com: %v", err)
	}
	if got != b {
		t.Fatal("sticky-path snapshot must still pin its own fallback table")
	}
}
