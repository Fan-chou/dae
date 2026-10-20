//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// The resolver reads the datapath's own association maps. Use the real map
// definitions from the compiled object so a mismatch between the Go structs
// and the C layout fails here instead of silently yielding no MACs.
func TestKernelMacResolverReadsRealAssociationMaps(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create BPF maps")
	}
	spec, err := ebpf.LoadCollectionSpec("bpf_bpfel.o")
	if err != nil {
		t.Skipf("generated BPF object unavailable: %v", err)
	}
	newMap := func(name string) *ebpf.Map {
		ms := spec.Maps[name]
		if ms == nil {
			t.Fatalf("object has no map %q", name)
		}
		cp := ms.Copy()
		cp.Pinning = ebpf.PinNone
		m, err := ebpf.NewMap(cp)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	ipMac, macAssoc := newMap("ip_mac_assoc_map"), newMap("mac_assoc_map")

	mac := [6]byte{0x3e, 0x0a, 0xa5, 0xde, 0xae, 0xa3}
	v4 := netip.MustParseAddr("192.168.124.200")
	v6 := netip.MustParseAddr("2409:8a55:358e:c970::1")
	for _, a := range []netip.Addr{v4, v6} {
		if err := ipMac.Put(&bpfIpMacAssocKey{Ip: a.As16()}, &bpfMacAssocKey{Mac: mac}); err != nil {
			t.Fatal(err)
		}
	}
	var entry bpfMacAssocEntry
	entry.Ips[0].Ip = v4.As16() // as the datapath stores it: IPv4 is v4-mapped
	entry.Ips[1].Ip = v6.As16()
	if err := macAssoc.Put(&bpfMacAssocKey{Mac: mac}, &entry); err != nil {
		t.Fatal(err)
	}

	r := newKernelMacResolverFromMaps(ipMac, macAssoc)
	if r == nil {
		t.Fatal("resolver not built")
	}
	for _, a := range []netip.Addr{v4, v6} {
		got, ok := r.macOf(a)
		if !ok || got != mac {
			t.Fatalf("macOf(%v) = %x, %v", a, got, ok)
		}
	}
	if _, ok := r.macOf(netip.MustParseAddr("192.168.124.201")); ok {
		t.Fatal("unknown address resolved")
	}
	addrs := r.addrsOf(mac)
	if len(addrs) != 2 || addrs[0] != v4 || addrs[1] != v6 {
		t.Fatalf("addrsOf = %v", addrs)
	}
	if got := r.addrsOf([6]byte{1, 2, 3, 4, 5, 6}); len(got) != 0 {
		t.Fatalf("unknown mac resolved: %v", got)
	}
	if newKernelMacResolverFromMaps(nil, macAssoc) != nil {
		t.Fatal("resolver built without its maps")
	}
}
