/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
)

func TestInboundBudget(t *testing.T) {
	b := newInboundBudget(2)
	if !b.acquire() || !b.acquire() {
		t.Fatal("budget refused within its limit")
	}
	if b.acquire() {
		t.Fatal("budget granted beyond its limit")
	}
	b.release()
	if !b.acquire() {
		t.Fatal("budget did not free a slot on release")
	}
	var nilBudget *inboundBudget
	if !nilBudget.acquire() {
		t.Fatal("nil budget must be unlimited")
	}
	nilBudget.release()
}

func TestInboundTargetKeyIsCaseAndDotInsensitive(t *testing.T) {
	a := InboundTarget{Domain: "Example.COM.", Port: 443}
	b := InboundTarget{Domain: "example.com", Port: 443}
	if a.key() != b.key() {
		t.Fatalf("%q != %q", a.key(), b.key())
	}
	ip4 := InboundTarget{IP: netip.MustParseAddr("1.2.3.4"), Port: 53}
	mapped := InboundTarget{IP: netip.MustParseAddr("::ffff:1.2.3.4"), Port: 53}
	if ip4.key() != mapped.key() {
		t.Fatalf("%q != %q", ip4.key(), mapped.key())
	}
	if (InboundTarget{Domain: "example.com", Port: 80}).key() == a.key() {
		t.Fatal("different ports share a key")
	}
}

func TestInboundUDPIdleTimeout(t *testing.T) {
	if inboundUDPIdleTimeout(53) != DnsNatTimeout {
		t.Fatal("DNS timeout")
	}
	if inboundUDPIdleTimeout(443) != QuicNatTimeout {
		t.Fatal("QUIC timeout")
	}
	if inboundUDPIdleTimeout(12345) != DefaultNatTimeout {
		t.Fatal("default timeout")
	}
}

func TestClassifyInboundDialError(t *testing.T) {
	cases := []struct {
		err  error
		want InboundDialErrorKind
	}{
		{nil, InboundDialGeneral},
		{ob.ErrNoAliveDialer, InboundDialNetworkUnreachable},
		{errors.New("dial tcp 1.2.3.4:80: connect: connection refused"), InboundDialRefused},
		{errors.New("connect: network is unreachable"), InboundDialNetworkUnreachable},
		{errors.New("resolve example.com: dns routing is not configured"), InboundDialHostUnreachable},
		{errors.New("resolve x.example: no real IP (bootstrap resolvers: write udp: sendto: network is unreachable)"), InboundDialHostUnreachable},
		{context.DeadlineExceeded, InboundDialTimeout},
		{errors.New("i/o timeout"), InboundDialTimeout},
		{fmt.Errorf("%w 198.18.0.9", ErrUnnamedFakeIP), InboundDialHostUnreachable},
		{net.ErrClosed, InboundDialNotAllowed},
		{fmt.Errorf("dial: %w", net.ErrClosed), InboundDialNotAllowed},
		{errors.New("something else"), InboundDialGeneral},
	}
	for _, tc := range cases {
		if got := ClassifyInboundDialError(tc.err); got != tc.want {
			t.Errorf("ClassifyInboundDialError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// With no published control plane every datagram's session setup fails; the
// relay must stay bounded and closable.
func TestInboundUDPRelayWithoutPlaneDropsAndCloses(t *testing.T) {
	var delivered int
	r := NewInboundUDPRelay(context.Background(), "s1", netip.MustParseAddrPort("192.0.2.1:5000"), newInboundBudget(4), func(InboundTarget, []byte) { delivered++ })
	r.plane = func() *ControlPlane { return nil }
	for i := 0; i < 10; i++ {
		r.Send(InboundTarget{IP: netip.MustParseAddr("8.8.8.8"), Port: uint16(1000 + i)}, []byte("x"))
	}
	r.Close()
	r.Send(InboundTarget{IP: netip.MustParseAddr("8.8.8.8"), Port: 53}, []byte("x"))
	if delivered != 0 {
		t.Fatalf("delivered %d datagrams without a control plane", delivered)
	}
	if n := r.budget.n.Load(); n != 0 {
		// Dial goroutines close failed sessions asynchronously; give them a
		// moment before declaring a leak.
		waitForBudget(t, r.budget)
	}
}

func waitForBudget(t *testing.T, b *inboundBudget) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if b.n.Load() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("budget leaked %d slots after the relay closed", b.n.Load())
}

func inboundTestSniffPlane(timeout time.Duration, mode consts.DialMode) *ControlPlane {
	cp := &ControlPlane{}
	cp.sniffingTimeout = timeout
	cp.dialMode = mode
	return cp
}

func TestInboundShouldSniffTCP(t *testing.T) {
	https := netip.MustParseAddrPort("203.0.113.10:443")
	ssh := netip.MustParseAddrPort("203.0.113.10:22")
	plane := inboundTestSniffPlane(30*time.Millisecond, consts.DialMode_Domain)

	cases := []struct {
		name    string
		plane   *ControlPlane
		enabled bool
		dst     netip.AddrPort
		domain  string
		want    bool
	}{
		{"ip target on https", plane, true, https, "", true},
		{"inbound has sniff off", plane, false, https, "", false},
		{"client already sent a name", plane, true, https, "example.com", false},
		{"excluded port", plane, true, ssh, "", false},
		{"sniffing_timeout is zero", inboundTestSniffPlane(0, consts.DialMode_Domain), true, https, "", false},
		{"dial_mode ip", inboundTestSniffPlane(30*time.Millisecond, consts.DialMode_Ip), true, https, "", false},
	}
	for _, tc := range cases {
		if got := tc.plane.inboundShouldSniffTCP(tc.enabled, tc.dst, tc.domain); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
