//go:build linux && !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Real wildcard sockets plus production LAN ingress, inside an isolated netns.
// No traffic, routes, listeners or BPF hooks on the gateway are changed.
func TestLocalUDPServiceKernel(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	ns, err := netns.New()
	if errors.Is(err, unix.EPERM) {
		t.Skipf("requires CAP_SYS_ADMIN: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Fatal(err)
		}
	}()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"192.168.124.223/32", "fd00::223/128"} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(lo, addr); err != nil {
			t.Fatal(err)
		}
	}
	for _, network := range []string{"udp4", "udp6"} {
		for _, port := range []int{53, 5353} {
			conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
		}
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	// Limit verifier work to the actual production entry under test.
	for name := range spec.Programs {
		if name != "tproxy_lan_ingress_l2" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	if err := spec.Variables["PARAM"].Set(bpfDaeParam{Dae0Ifindex: uint32(lo.Attrs().Index), DatapathGeneration: 41}); err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load production LAN ingress: %+v", err)
	}
	defer coll.Close()
	bpf := &bpfObjects{}
	bpf.LocalAddrMap = coll.Maps["local_addr_map"]
	release, err := acquireLocalAddressWatcher(bpf, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	secondRelease, err := acquireLocalAddressWatcher(bpf, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	// Releasing a candidate must not stop the active generation's writer.
	secondRelease()
	secondRelease()
	update := func(name string, key, value interface{}) {
		t.Helper()
		if err := coll.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	update("routing_meta_map", uint32(0), uint32(1))
	rule := bpfMatchSet{Type: uint8(consts.MatchType_Fallback)}
	update("routing_map", uint32(0), rule)
	port := uint16(53)
	check := func(name, dest string, want uint32) {
		t.Helper()
		t.Log(name)
		func() {
			packet := localUDPTestPacket(netip.MustParseAddr(dest), port)
			ctx := make([]byte, 192)
			binary.NativeEndian.PutUint32(ctx[36:40], uint32(lo.Attrs().Index))
			binary.NativeEndian.PutUint32(ctx[40:44], uint32(lo.Attrs().Index))
			got, err := coll.Programs["tproxy_lan_ingress_l2"].Run(&ebpf.RunOptions{Data: packet, Context: ctx})
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("LAN action = %d, want %d (0=local/direct, 7=DNS redirect)", got, want)
			}
		}()
	}
	check("public_ipv4_dns", "119.29.29.29", 7)
	check("public_ipv6_dns", "2001:4860:4860::8888", 7)
	check("local_ipv4_service", "192.168.124.223", 0)
	check("local_ipv6_service", "fd00::223", 0)
	rule.Must = 1
	update("routing_map", uint32(0), rule)
	check("must_direct_ipv4", "119.29.29.29", 0)
	check("must_direct_ipv6", "2001:4860:4860::8888", 0)
	rule.Must = 0
	update("routing_map", uint32(0), rule)
	// The bug is not specific to DNS: a wildcard listener must not bypass a
	// routing block for a remote UDP destination on any port.
	port = 5353
	rule.Outbound = uint8(consts.OutboundBlock)
	update("routing_map", uint32(0), rule)
	check("remote_ipv4_udp_block", "119.29.29.29", 2)
	check("remote_ipv6_udp_block", "2001:4860:4860::8888", 2)
	check("local_ipv4_udp_service", "192.168.124.223", 0)
	check("local_ipv6_udp_service", "fd00::223", 0)
	port = 53
	rule.Outbound = uint8(consts.OutboundDirect)
	update("routing_map", uint32(0), rule)

	// Verify notifications survive a shared-generation release and reflect actual
	// address deletion/re-addition before exercising the same wildcard listener.
	for _, ip := range []string{"192.168.124.223/32", "fd00::223/128"} {
		addr, _ := netlink.ParseAddr(ip)
		addr.Flags = unix.IFA_F_NODAD
		key := netip.MustParseAddr(addr.IP.String()).As16()
		if err := netlink.AddrDel(lo, addr); err != nil {
			t.Fatal(err)
		}
		waitLocalAddressMap(t, bpf.LocalAddrMap, key, false)
		check("removed_"+ip, addr.IP.String(), 7)
		if err := netlink.AddrAdd(lo, addr); err != nil {
			t.Fatal(err)
		}
		waitLocalAddressMap(t, bpf.LocalAddrMap, key, true)
		check("restored_"+ip, addr.IP.String(), 0)
	}
	// Last release joins the writer and clears an ejected object's old state;
	// reacquiring that same object initializes a fresh authoritative snapshot.
	release()
	key := netip.MustParseAddr("192.168.124.223").As16()
	waitLocalAddressMap(t, bpf.LocalAddrMap, key, false)
	reacquiredRelease, err := acquireLocalAddressWatcher(bpf, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	defer reacquiredRelease()
	waitLocalAddressMap(t, bpf.LocalAddrMap, key, true)
	check("reacquired_local_service", "192.168.124.223", 0)
}

func waitLocalAddressMap(t *testing.T, m *ebpf.Map, key [16]byte, present bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var value uint8
		err := m.Lookup(key, &value)
		if (present && err == nil && value == 1) || (!present && errors.Is(err, ebpf.ErrKeyNotExist)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("address presence did not become %v", present)
}

func localUDPTestPacket(dest netip.Addr, port uint16) []byte {
	iplen := 20
	if dest.Is6() {
		iplen = 40
	}
	packet := make([]byte, 14+iplen+8+12)
	copy(packet[:12], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	ip := packet[14:]
	if dest.Is4() {
		binary.BigEndian.PutUint16(packet[12:14], 0x0800)
		ip[0], ip[8], ip[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
		copy(ip[12:16], netip.MustParseAddr("192.168.124.220").AsSlice())
		copy(ip[16:20], dest.AsSlice())
	} else {
		binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
		ip[0], ip[6], ip[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(ip)-40))
		copy(ip[8:24], netip.MustParseAddr("fd00::220").AsSlice())
		copy(ip[24:40], dest.AsSlice())
	}
	udp := ip[iplen:]
	binary.BigEndian.PutUint16(udp[0:2], 53197)
	binary.BigEndian.PutUint16(udp[2:4], port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	return packet
}
