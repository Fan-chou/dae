//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

type icmpRawSender struct {
	mu    sync.Mutex
	fd    int
	open  bool
	inet6 bool
	bound netip.Addr
	mark  uint32
}

var (
	icmp4AdminSender = icmpRawSender{}
	icmp6AdminSender = icmpRawSender{inet6: true}
)

func sendICMPAdminProhibited(udpPayload []byte, client, dest netip.AddrPort, soMark uint32) error {
	if !client.IsValid() || !dest.IsValid() {
		return fmt.Errorf("invalid addr: client=%v dest=%v", client, dest)
	}
	clientAddr := client.Addr().Unmap()
	destAddr := dest.Addr().Unmap()
	if clientAddr.Is4() && destAddr.Is4() {
		return icmp4AdminSender.send(udpPayload, netip.AddrPortFrom(clientAddr, client.Port()), netip.AddrPortFrom(destAddr, dest.Port()), soMark)
	}
	if clientAddr.Is6() && destAddr.Is6() {
		return icmp6AdminSender.send(udpPayload, netip.AddrPortFrom(clientAddr, client.Port()), netip.AddrPortFrom(destAddr, dest.Port()), soMark)
	}
	return fmt.Errorf("icmp admin-prohibited requires same address family: client=%v dest=%v", client, dest)
}

func (s *icmpRawSender) send(udpPayload []byte, client, dest netip.AddrPort, soMark uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLocked(soMark); err != nil {
		return err
	}
	if err := s.bindLocked(dest.Addr()); err != nil {
		s.resetLocked()
		if err := s.ensureLocked(soMark); err != nil {
			return err
		}
		if err := s.bindLocked(dest.Addr()); err != nil {
			return err
		}
	}
	var msg []byte
	var sa unix.Sockaddr
	if s.inet6 {
		msg = buildIPv6ICMPAdminProhibited(client, dest, udpPayload)
		var dstAddr unix.SockaddrInet6
		clientIP := client.Addr().As16()
		copy(dstAddr.Addr[:], clientIP[:])
		sa = &dstAddr
	} else {
		msg = buildIPv4ICMPAdminProhibited(client, dest, udpPayload)
		var dstAddr unix.SockaddrInet4
		clientIP := client.Addr().As4()
		copy(dstAddr.Addr[:], clientIP[:])
		sa = &dstAddr
	}
	if err := unix.Sendto(s.fd, msg, 0, sa); err != nil {
		s.resetLocked()
		return fmt.Errorf("send ICMP admin-prohibited to %v: %w", client, err)
	}
	return nil
}

func (s *icmpRawSender) ensureLocked(soMark uint32) error {
	if s.open {
		if s.mark != soMark {
			if err := unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_MARK, int(soMark)); err != nil {
				s.resetLocked()
				return fmt.Errorf("set SO_MARK on ICMP socket: %w", err)
			}
			s.mark = soMark
		}
		return nil
	}
	domain := unix.AF_INET
	proto := unix.IPPROTO_ICMP
	if s.inet6 {
		domain = unix.AF_INET6
		proto = unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(domain, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return fmt.Errorf("create raw ICMP socket: %w", err)
	}
	if s.inet6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("enable IPV6_TRANSPARENT on ICMPv6 socket: %w", err)
		}
	} else if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("enable IP_TRANSPARENT on ICMPv4 socket: %w", err)
	}
	if soMark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(soMark)); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("set SO_MARK on ICMP socket: %w", err)
		}
	}
	s.fd = fd
	s.open = true
	s.mark = soMark
	s.bound = netip.Addr{}
	return nil
}

func (s *icmpRawSender) bindLocked(addr netip.Addr) error {
	if s.bound.IsValid() && s.bound == addr {
		return nil
	}
	if s.inet6 {
		var bindAddr unix.SockaddrInet6
		ip := addr.As16()
		copy(bindAddr.Addr[:], ip[:])
		if err := unix.Bind(s.fd, &bindAddr); err != nil {
			return fmt.Errorf("bind ICMPv6 socket to %v: %w", addr, err)
		}
	} else {
		var bindAddr unix.SockaddrInet4
		ip := addr.As4()
		copy(bindAddr.Addr[:], ip[:])
		if err := unix.Bind(s.fd, &bindAddr); err != nil {
			return fmt.Errorf("bind ICMPv4 socket to %v: %w", addr, err)
		}
	}
	s.bound = addr
	return nil
}

func (s *icmpRawSender) resetLocked() {
	if s.open {
		_ = unix.Close(s.fd)
	}
	s.fd = 0
	s.open = false
	s.bound = netip.Addr{}
	s.mark = 0
}
