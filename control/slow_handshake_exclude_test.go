/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestCanExcludeSlowHandshake_FixedKeepsSameDialer(t *testing.T) {
	a := newTestEndpointDialer()
	b := newTestEndpointDialer()
	defer a.Close()
	defer b.Close()
	g := newTestFixedOutboundGroup(a, b)
	defer g.Close()

	cp := &ControlPlane{}
	res := &proxyDialResult{
		Outbound:                g,
		Dialer:                  a,
		SelectionNetworkTypeObj: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
	}
	if cp.canExcludeSlowHandshake(res) {
		t.Fatal("fixed policy must not auto-switch after a slow handshake")
	}
}

func TestCanExcludeSlowHandshake_NestedFixedSwitchesInnerFallback(t *testing.T) {
	a := newTestEndpointDialer()
	b := newTestEndpointDialer()
	defer a.Close()
	defer b.Close()
	child := newTestOutboundGroup(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, a, b)
	defer child.Close()

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	parent, err := ob.NewNestedDialerGroup(
		&componentdialer.GlobalOption{Log: logger, CheckInterval: time.Second},
		"fixed-parent",
		[]ob.NestedDialerGroupMember{{Group: child}},
		ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
	if err != nil {
		t.Fatalf("NewNestedDialerGroup() error = %v", err)
	}
	defer parent.Close()

	cp := &ControlPlane{}
	res := &proxyDialResult{
		Outbound:                parent,
		Dialer:                  a,
		SelectionNetworkTypeObj: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
	}
	if !cp.canExcludeSlowHandshake(res) {
		t.Fatal("outer fixed wrapping fallback must still exclude a slow inner leaf")
	}
}

func TestCanExcludeSlowHandshake_FallbackSwitchesDialer(t *testing.T) {
	a := newTestEndpointDialer()
	b := newTestEndpointDialer()
	defer a.Close()
	defer b.Close()
	g := newTestOutboundGroup(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback}, a, b)
	defer g.Close()

	cp := &ControlPlane{}
	res := &proxyDialResult{
		Outbound:                g,
		Dialer:                  a,
		SelectionNetworkTypeObj: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
	}
	if !cp.canExcludeSlowHandshake(res) {
		t.Fatal("fallback should exclude the slow handshake dialer when another leaf is alive")
	}
}

func TestCanExcludeSlowHandshake_FirstAliveDoesNotSwitch(t *testing.T) {
	a := newTestEndpointDialer()
	b := newTestEndpointDialer()
	defer a.Close()
	defer b.Close()
	g := newTestOutboundGroup(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_FirstAlive}, a, b)
	defer g.Close()

	cp := &ControlPlane{}
	res := &proxyDialResult{
		Outbound:                g,
		Dialer:                  a,
		SelectionNetworkTypeObj: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
	}
	if cp.canExcludeSlowHandshake(res) {
		t.Fatal("first_alive must not close a successful handshake to redial another leaf")
	}
}

func TestCanExcludeSlowHandshake_MinLastDoesNotSwitch(t *testing.T) {
	a := newTestEndpointDialer()
	b := newTestEndpointDialer()
	defer a.Close()
	defer b.Close()
	g := newTestOutboundGroup(ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, a, b)
	defer g.Close()

	cp := &ControlPlane{}
	res := &proxyDialResult{
		Outbound:                g,
		Dialer:                  a,
		SelectionNetworkTypeObj: &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
	}
	if cp.canExcludeSlowHandshake(res) {
		t.Fatal("min policy must not close a successful handshake to redial another leaf")
	}
}

func TestSiteFailDomainPrefersSniffed(t *testing.T) {
	if got := siteFailDomain(&proxyDialResult{SniffedDomain: "youtube.com"}, ""); got != "youtube.com" {
		t.Fatalf("siteFailDomain sniffed = %q, want youtube.com", got)
	}
	if got := siteFailDomain(&proxyDialResult{StickySite: "8.8.8.8", SniffedDomain: "nas"}, "nas"); got != "8.8.8.8" {
		t.Fatalf("siteFailDomain sticky = %q, want dest IP pin key", got)
	}
	if got := siteFailDomain(&proxyDialResult{}, "example.com"); got != "example.com" {
		t.Fatalf("siteFailDomain fallback = %q, want example.com", got)
	}
}

func TestStickySelectHostUsesUnicastIPWhenNoDomain(t *testing.T) {
	dst := netip.MustParseAddr("8.8.8.8")
	if got := stickySelectHost("", dst, false); got != "8.8.8.8" {
		t.Fatalf("stickySelectHost(ip-only) = %q, want 8.8.8.8", got)
	}
	if got := stickySelectHost("www.youtube.com", dst, false); got != "www.youtube.com" {
		t.Fatalf("stickySelectHost(domain) = %q, want sniffed domain", got)
	}
	if got := stickySelectHost("nas", dst, false); got != "8.8.8.8" {
		t.Fatalf("stickySelectHost(single-label) = %q, want dest IP sticky key, not a domain rewrite", got)
	}
	if got := stickySelectHost("", dst, true); got != "" {
		t.Fatalf("stickySelectHost(fakeip) = %q, want empty", got)
	}
	if got := stickySelectHost("", netip.MustParseAddr("127.0.0.1"), false); got != "" {
		t.Fatalf("stickySelectHost(loopback) = %q, want empty", got)
	}
}
