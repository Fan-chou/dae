/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestHealthDialerCacheReusesSameNodeAndOption(t *testing.T) {
	base := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     30 * time.Second,
	}
	override := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     5 * time.Minute,
	}
	src := newDirectDialer(base, false)
	defer src.Close()
	cache := &HealthDialerCache{}
	first, created := cache.ReuseOrClone(src, override)
	if !created || first == nil || first == src {
		t.Fatalf("first clone created=%v first=%p src=%p", created, first, src)
	}
	defer first.Close()
	second, created := cache.ReuseOrClone(src, override)
	if created || second != first {
		t.Fatalf("second clone created=%v second=%p want %p", created, second, first)
	}
	same, created := cache.ReuseOrClone(src, base)
	if created || same != src {
		t.Fatalf("matching option should return src, created=%v same=%p", created, same)
	}
}

func TestNestedSelectWithoutProbeSettingsDoesNotCloneLeaves(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	leaf := newDirectDialer(option, false)
	child := NewDialerGroupWithRuntimeOptions(
		option,
		"heart",
		[]*dialer.Dialer{leaf},
		newEmptyAnnotations(1),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive},
		func(bool, *dialer.NetworkType, bool) {},
		DialerGroupRuntimeOptions{HealthCheckEnabled: true},
	)
	parent, err := NewNestedDialerGroupWithRuntimeOptions(option, "select", []NestedDialerGroupMember{
		{Group: child},
		{Dialer: leaf},
	}, DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}, func(bool, *dialer.NetworkType, bool) {}, DialerGroupRuntimeOptions{
		HealthCheckEnabled: false,
		Lazy:               false,
	})
	if err != nil {
		t.Fatalf("NewNestedDialerGroupWithRuntimeOptions() error = %v", err)
	}
	defer parent.Close()
	defer child.Close()
	defer leaf.Close()
	if len(parent.parentHealthViews) != 0 {
		t.Fatalf("select group without probe settings created %d parent health views", len(parent.parentHealthViews))
	}
}
