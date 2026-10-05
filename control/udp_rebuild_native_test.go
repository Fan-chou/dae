// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestUDPRebuildNativePeerWithMappingEnabled(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			store := openCrossFamilyTestStore(t, t.TempDir())
			f := newRebuildFixtureWithStore(t, kind, "enforce", false, store)
			if f.old.crossFamily != store {
				t.Fatal("fixture did not retain enabled global mapping")
			}
			f.qualify(t)
			slot := f.old.rebuildPeer(f.b)
			waitRebuild(t, func() bool { return slot.owner.Load().endpoint != f.old })
			next := slot.owner.Load().endpoint
			if next.crossFamily != store || f.old.dead.Load() {
				t.Fatal("native recovery lost mapping view or shared ancestor")
			}
			f.relay.mu.Lock()
			original := f.relay.first
			f.relay.mu.Unlock()
			oldA, oldB := f.relay.mapping(original, f.a), f.relay.mapping(original, f.b)
			for i := 0; i < 3; i++ {
				f.send(t, f.old, f.a, fmt.Sprintf("A/native/%d", i), true)
				r := f.send(t, f.old, f.b, fmt.Sprintf("B/native/%d", i), true)
				if r.endpoint != next {
					t.Fatal("native B bypassed successor")
				}
			}
			snap := f.m.udpRebuild.Load().snapshot(time.Now())
			if snap.Counts["committed"] != 1 || snap.Counts["recovered"] != 1 || snap.AttemptsInWindow != 1 {
				t.Fatalf("native recovery: %+v", snap)
			}
			if f.relay.mapping(original, f.a) != oldA {
				t.Fatal("native A mapping changed")
			}
			f.relay.mu.Lock()
			fresh := false
			for key, c := range f.relay.mappings {
				if key != original.String()+"/"+f.a.String() && c.LocalAddr().String() != oldB.String() {
					fresh = true
				}
			}
			f.relay.mu.Unlock()
			if !fresh {
				t.Fatal("native B did not obtain a new mapping")
			}
			f.old.TrackUdpConnStateTuplePair(f.old.poolKey.Src, f.b)
			f.m.udpStateMu.Lock()
			defer f.m.udpStateMu.Unlock()
			for _, peer := range []netip.AddrPort{f.a, f.b} {
				for _, pair := range [][2]netip.AddrPort{{f.old.poolKey.Src, peer}, {peer, f.old.poolKey.Src}} {
					if refs := f.m.pinnedUDP[bpfTuplesKeyFromAddrPorts(pair[0], pair[1], 17)]; refs != 1 {
						t.Errorf("tuple %v refs=%d", pair, refs)
					}
				}
			}
		})
	}
}

func TestUDPRebuildPeerAliasEligibility(t *testing.T) {
	store := openCrossFamilyTestStore(t, t.TempDir())
	v4 := netip.MustParseAddrPort("192.0.2.1:27015")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:27015")
	client4 := netip.MustParseAddrPort("192.0.2.201:32000")
	client6 := netip.MustParseAddrPort("[2001:db8::201]:32000")
	alias, err := store.reply(v6, client4)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                       string
		src, peer, fixed, original netip.AddrPort
		target                     string
		view                       *UDPCrossFamilyStore
		reject                     bool
	}{
		{name: "native v4", src: client4, peer: v4, target: v4.String(), view: store},
		{name: "native v6", src: client6, peer: v6, target: v6.String(), view: store},
		{name: "native mapped v4", src: netip.MustParseAddrPort("[::ffff:192.0.2.201]:32000"), peer: v4, target: v4.String(), view: store},
		{name: "native no store", src: client4, peer: v4, target: v4.String()},
		{name: "foreign", src: client4, peer: v6, target: v6.String(), view: store, reject: true},
		{name: "foreign without store", src: client4, peer: v6, target: v6.String(), reject: true},
		{name: "allocated alias", src: client4, peer: alias, target: alias.String(), view: store, reject: true},
		{name: "unallocated alias", src: client4, peer: netip.MustParseAddrPort("198.19.0.250:27015"), target: v4.String(), view: store, reject: true},
		{name: "fixed alias", src: client4, peer: v6, fixed: alias, target: v6.String(), view: store, reject: true},
		{name: "alias dial target", src: client4, peer: v4, target: alias.String(), view: store, reject: true},
		{name: "fixed other peer", src: client4, peer: v4, fixed: netip.MustParseAddrPort("192.0.2.2:27015"), target: v4.String(), view: store, reject: true},
		{name: "different original", src: client4, peer: v4, original: netip.MustParseAddrPort("192.0.2.2:27015"), target: v4.String(), view: store, reject: true},
		{name: "unknown source", peer: v4, target: v4.String(), view: store, reject: true},
		{name: "missing store", src: client4, peer: v4, target: v4.String(), view: &UDPCrossFamilyStore{}, reject: true},
		{name: "unopened store", src: client4, peer: v4, target: v4.String(), view: NewUDPCrossFamilyStore(t.TempDir(), "closed"), reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ue := &UdpEndpoint{poolKey: UdpEndpointKey{Src: tc.src, Dst: tc.fixed}, DialTarget: tc.target, crossFamily: tc.view}
			if tc.original.IsValid() {
				ue.installRebuildPeer(tc.peer, &udpRebuildPeer{original: tc.original})
			}
			if got := udpRebuildPeerUsesAlias(ue, tc.peer); got != tc.reject {
				t.Fatalf("alias=%v want %v", got, tc.reject)
			}
		})
	}
	f := newRebuildFixtureWithStore(t, "shadowsocks", "enforce", false, store)
	x := f.o.execution.Load()
	f.old.SniffedDomain = "example.com"
	if got := x.exclusion(f.old, f.b); got != "peer_alias_unsupported" {
		t.Fatalf("domain exclusion=%s", got)
	}
	f.old.SniffedDomain = ""
	f.old.resolveDNSState = &udpResolveDNSState{}
	if got := x.exclusion(f.old, f.b); got != "peer_alias_unsupported" {
		t.Fatalf("resolveDNS exclusion=%s", got)
	}
}
