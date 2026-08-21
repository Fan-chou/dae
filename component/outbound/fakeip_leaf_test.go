/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func testFakeIPLeafOption() *dialer.GlobalOption {
	return &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
}

func TestDialerGroup_FakeIPLeafIsProxy_BuiltinDirect(t *testing.T) {
	option := testFakeIPLeafOption()
	g := NewDialerGroup(option, consts.OutboundDirect.String(),
		[]*dialer.Dialer{newDirectDialer(option, true)}, newEmptyAnnotations(1),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
		func(bool, *dialer.NetworkType, bool) {})
	if g.FakeIPLeafIsProxy() {
		t.Fatal("builtin direct group must not be a FakeIP proxy leaf")
	}
}

func TestDialerGroup_FakeIPLeafIsProxy_FixedFollowsSelection(t *testing.T) {
	option := testFakeIPLeafOption()
	directGroup := NewDialerGroup(option, consts.OutboundDirect.String(),
		[]*dialer.Dialer{newDirectDialer(option, true)}, newEmptyAnnotations(1),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
		func(bool, *dialer.NetworkType, bool) {})
	node := newNoopDialer(option)
	parent, err := NewNestedDialerGroup(option, "CN_CN", []NestedDialerGroupMember{
		{Group: directGroup},
		{Dialer: node},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatal(err)
	}
	if parent.FakeIPLeafIsProxy() {
		t.Fatal("fixed(0)=direct must be DIRECT")
	}
	parent.SetSelectionPolicy(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 1})
	if !parent.FakeIPLeafIsProxy() {
		t.Fatal("switching CN_CN to a node must be PROXY")
	}
}

func TestDialerGroup_FakeIPLeafIsProxy_MinAnyNodeIsProxy(t *testing.T) {
	option := testFakeIPLeafOption()
	directGroup := NewDialerGroup(option, consts.OutboundDirect.String(),
		[]*dialer.Dialer{newDirectDialer(option, true)}, newEmptyAnnotations(1),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
		func(bool, *dialer.NetworkType, bool) {})
	parent, err := NewNestedDialerGroup(option, "Apple_Proxy", []NestedDialerGroupMember{
		{Group: directGroup},
		{Dialer: newNoopDialer(option)},
	}, DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {})
	if err != nil {
		t.Fatal(err)
	}
	if !parent.FakeIPLeafIsProxy() {
		t.Fatal("url-test/min with a node member must be PROXY without Select()")
	}
}
