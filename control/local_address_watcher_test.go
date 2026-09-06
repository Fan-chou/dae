/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type memoryLocalAddresses struct {
	values map[[16]byte]uint8
	fail   bool
}

func (m *memoryLocalAddresses) Update(k, v interface{}, _ ebpf.MapUpdateFlags) error {
	if m.fail {
		return errors.New("map unavailable")
	}
	m.values[k.([16]byte)] = v.(uint8)
	return nil
}
func (m *memoryLocalAddresses) Delete(k interface{}) error {
	if m.fail {
		return errors.New("map unavailable")
	}
	delete(m.values, k.([16]byte))
	return nil
}
func testHostAddress(ip string, index, flags int) netlink.Addr {
	addr := netip.MustParseAddr(ip)
	return netlink.Addr{IPNet: &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())}, LinkIndex: index, Flags: flags}
}
func TestLocalAddressesSnapshot(t *testing.T) {
	m := &memoryLocalAddresses{values: make(map[[16]byte]uint8)}
	s := &localAddressSet{target: m, installed: make(map[[16]byte]struct{})}
	a := testHostAddress("192.168.124.223", 1, 0)
	duplicate := testHostAddress("192.168.124.223", 2, 0)
	v6 := testHostAddress("fd00::223", 2, 0)
	if err := s.replace([]netlink.Addr{a, duplicate, v6, testHostAddress("fd00::224", 2, unix.IFA_F_TENTATIVE), testHostAddress("fd00::225", 2, unix.IFA_F_DADFAILED), testHostAddress("0.0.0.0", 1, 0), testHostAddress("ff02::1", 1, 0)}); err != nil {
		t.Fatal(err)
	}
	if len(m.values) != 2 {
		t.Fatalf("snapshot = %v", m.values)
	}
	if err := s.replace([]netlink.Addr{duplicate, v6}); err != nil {
		t.Fatal(err)
	}
	if len(m.values) != 2 {
		t.Fatal("removing one interface removed a shared local address")
	}
	if err := s.replace([]netlink.Addr{v6}); err != nil {
		t.Fatal(err)
	}
	if len(m.values) != 1 || m.values[netip.MustParseAddr("fd00::223").As16()] != 1 {
		t.Fatal("stale IPv4 address survived removal")
	}
	if err := s.replace(nil); err != nil {
		t.Fatal(err)
	}
	if len(m.values) != 0 {
		t.Fatal("failed to clear stale permissions")
	}
}
func TestLocalAddressesRetryMapFailures(t *testing.T) {
	m := &memoryLocalAddresses{values: make(map[[16]byte]uint8), fail: true}
	s := &localAddressSet{target: m, installed: make(map[[16]byte]struct{})}
	a := []netlink.Addr{testHostAddress("192.168.124.223", 1, 0)}
	if err := s.replace(a); err == nil {
		t.Fatal("lost update error")
	}
	m.fail = false
	if err := s.replace(a); err != nil {
		t.Fatal(err)
	}
	if len(m.values) != 1 {
		t.Fatal("failed update was not retried")
	}
	m.fail = true
	if err := s.replace(nil); err == nil {
		t.Fatal("lost deletion error")
	}
	m.fail = false
	if err := s.replace(nil); err != nil {
		t.Fatal(err)
	}
	if len(m.values) != 0 {
		t.Fatal("failed deletion was not retried")
	}
}
