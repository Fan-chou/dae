/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func tcp6NetworkType() *NetworkType {
	return &NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_6,
	}
}

func udp6DnsNetworkType() *NetworkType {
	return &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		IsDns:           true,
		UdpHealthDomain: UdpHealthDomainDns,
	}
}

func TestParseTcpCheckOption_V4OnlyPinnedIPsOmitIp6(t *testing.T) {
	opt, err := ParseTcpCheckOption(context.Background(), []string{
		"http://cp.cloudflare.com/generate_204",
		"1.1.1.1",
	}, "HEAD", "udp")
	if err != nil {
		t.Fatalf("ParseTcpCheckOption() error = %v", err)
	}
	if !opt.Ip4.IsValid() {
		t.Fatal("expected pinned IPv4")
	}
	if opt.Ip6.IsValid() {
		t.Fatalf("Ip6 = %v, want invalid for a v4-only pin list", opt.Ip6)
	}
}

func TestDialer_Check_NoApplicableIPPreservesAlive(t *testing.T) {
	d := newNamedTestDialer(t, "v4-only-probe")
	typ := tcp6NetworkType()
	if !d.MustGetAlive(typ) {
		t.Fatal("new dialer Tcp6 should start alive")
	}

	set := NewAliveDialerSet(
		d.Log,
		"probe-skip",
		typ,
		0,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		[]*Dialer{d},
		[]*Annotation{{}},
		func(bool) {},
		true,
	)
	d.RegisterAliveDialerSet(set)
	t.Cleanup(func() { d.UnregisterAliveDialerSet(set) })

	ok, err := d.Check(&CheckOption{
		networkType: typ,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			return false, fmt.Errorf("wrapped: %w", ErrNoApplicableIP)
		},
	})
	if err != nil {
		t.Fatalf("Check() error = %v, want nil skip", err)
	}
	if ok {
		t.Fatal("Check() ok = true, want skip")
	}
	if !d.MustGetAlive(typ) {
		t.Fatal("Tcp6 liveness flipped after a missing probe address")
	}
	if snap := d.HealthSnapshot().Collections[IdxTcp6]; snap.FailCount != 0 {
		t.Fatalf("Tcp6 failCount = %d, want 0", snap.FailCount)
	}
	if !set.IsAlive(d) || set.Len() != 1 {
		t.Fatalf("alive set len=%d isAlive=%v, want the dialer kept", set.Len(), set.IsAlive(d))
	}
	probe := d.SnapshotLastProbe(typ)
	if probe.Alive != true {
		t.Fatalf("LastProbe.Alive = %v, want preserved true", probe.Alive)
	}
	if !strings.Contains(probe.Message, ErrNoApplicableIP.Error()) {
		t.Fatalf("LastProbe.Message = %q, want it to mention %q", probe.Message, ErrNoApplicableIP.Error())
	}
}

func TestDialer_Check_NoApplicableIPDoesNotReviveOrKill(t *testing.T) {
	d := newNamedTestDialer(t, "already-dead")
	typ := tcp6NetworkType()
	d.ReportUnavailableForced(typ, errors.New("real v6 timeout"))
	if d.MustGetAlive(typ) {
		t.Fatal("forced failure should mark Tcp6 dead")
	}

	ok, err := d.Check(&CheckOption{
		networkType: typ,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			return false, ErrNoApplicableIP
		},
	})
	if err != nil || ok {
		t.Fatalf("Check() = (%v, %v), want skip", ok, err)
	}
	if d.MustGetAlive(typ) {
		t.Fatal("missing probe address revived a dead Tcp6 collection")
	}
}

func TestDialer_Check_RealFailureStillMarksDead(t *testing.T) {
	d := newNamedTestDialer(t, "real-timeout")
	typ := tcp6NetworkType()
	set := NewAliveDialerSet(
		d.Log,
		"probe-fail",
		typ,
		0,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		[]*Dialer{d},
		[]*Annotation{{}},
		func(bool) {},
		true,
	)
	d.RegisterAliveDialerSet(set)
	t.Cleanup(func() { d.UnregisterAliveDialerSet(set) })

	ok, err := d.Check(&CheckOption{
		networkType: typ,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			return false, errors.New("timeout")
		},
	})
	if err == nil || ok {
		t.Fatalf("Check() = (%v, %v), want timeout error", ok, err)
	}
	if d.MustGetAlive(typ) {
		t.Fatal("real probe timeout should mark Tcp6 dead")
	}
	if set.IsAlive(d) {
		t.Fatal("alive set kept a dialer after a real Tcp6 timeout")
	}
}

func TestDialer_Check_NoApplicableIPSkipsUdp6(t *testing.T) {
	d := newNamedTestDialer(t, "udp6-skip")
	typ := udp6DnsNetworkType()
	ok, err := d.Check(&CheckOption{
		networkType: typ,
		CheckFunc: func(context.Context, *NetworkType) (bool, error) {
			return false, ErrNoApplicableIP
		},
	})
	if err != nil || ok {
		t.Fatalf("Check() = (%v, %v), want skip", ok, err)
	}
	if !d.MustGetAlive(typ) {
		t.Fatal("Udp6 DNS liveness flipped after a missing probe address")
	}
}
