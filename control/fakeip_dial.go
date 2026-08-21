/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

func (c *ControlPlane) resolveFakeIPDomain(domain string, dst netip.Addr) (string, error) {
	store := c.fakeIPStore()
	if store == nil || !store.Contains(dst) {
		return domain, nil
	}
	if domain != "" {
		if _, err := netip.ParseAddr(strings.Trim(domain, "[]")); err == nil {
			domain = ""
		}
	}
	if domain != "" {
		return strings.TrimSuffix(domain, "."), nil
	}
	name, ok := store.LookBack(dst)
	if !ok {
		return "", fmt.Errorf("unnamed FakeIP %s", dst)
	}
	return strings.TrimSuffix(name, "."), nil
}

func (c *ControlPlane) guardFakeIPOutbound(outbound consts.OutboundIndex, dst netip.Addr) error {
	store := c.fakeIPStore()
	if store == nil || !store.Contains(dst) {
		return nil
	}
	if outbound == consts.OutboundDirect {
		return fmt.Errorf("refusing FakeIP %s via direct; waiting for client TTL", dst)
	}
	return nil
}

func (c *ControlPlane) rewriteFakeIPDialTarget(ctx context.Context, domain string, dst netip.AddrPort, network, dialTarget string, dialIp bool) (string, bool, error) {
	store := c.fakeIPStore()
	if store == nil {
		return dialTarget, dialIp, nil
	}
	if addr, err := parseDialTargetIP(dialTarget); err == nil && store.Contains(addr) {
		wantV6 := dst.Addr().Is6() && !dst.Addr().Is4In6()
		if network != "udp" && domain != "" {
			return net.JoinHostPort(domain, strconv.Itoa(int(dst.Port()))), false, nil
		}
		realIP, err := c.lookupRealIPForFakeIP(ctx, domain, wantV6)
		if err != nil {
			return "", false, err
		}
		if store.Contains(realIP) {
			return "", false, fmt.Errorf("refusing to dial FakeIP %s", realIP)
		}
		return netip.AddrPortFrom(realIP, dst.Port()).String(), true, nil
	}
	if store.Contains(dst.Addr()) && network == "udp" {
		wantV6 := dst.Addr().Is6() && !dst.Addr().Is4In6()
		realIP, err := c.lookupRealIPForFakeIP(ctx, domain, wantV6)
		if err != nil {
			return "", false, err
		}
		if store.Contains(realIP) {
			return "", false, fmt.Errorf("refusing to dial FakeIP %s", realIP)
		}
		return netip.AddrPortFrom(realIP, dst.Port()).String(), true, nil
	}
	return dialTarget, dialIp, nil
}

func udpDialTarget(c *ControlPlane, realDst netip.AddrPort, pinned, selected string) string {
	if c != nil {
		if store := c.fakeIPStore(); store != nil && store.Contains(realDst.Addr()) && selected != "" {
			return selected
		}
	}
	return pinned
}

func parseDialTargetIP(target string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(target); err == nil {
		return addr, nil
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(host)
}

func (c *ControlPlane) lookupRealIPForFakeIP(ctx context.Context, domain string, ipv6 bool) (netip.Addr, error) {
	if c == nil || domain == "" {
		return netip.Addr{}, fmt.Errorf("empty FakeIP name")
	}
	dns := c.ActiveDnsController()
	if dns == nil {
		return netip.Addr{}, fmt.Errorf("dns controller is not ready")
	}
	qtype := uint16(dnsmessage.TypeA)
	if ipv6 {
		qtype = dnsmessage.TypeAAAA
	}
	if ip := realIPFromAnswers(dns.LookupCacheAnswers(domain, qtype), ipv6); ip.IsValid() {
		return ip, nil
	}
	if err := dns.EnsureRealAnswers(ctx, domain, qtype); err != nil {
		return netip.Addr{}, fmt.Errorf("resolve real IP for FakeIP name %s: %w", domain, err)
	}
	if ip := realIPFromAnswers(dns.LookupCacheAnswers(domain, qtype), ipv6); ip.IsValid() {
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("no real IP for FakeIP name %s", domain)
}

func realIPFromAnswers(answers []dnsmessage.RR, ipv6 bool) netip.Addr {
	for _, rr := range answers {
		ip, ok := dnsAnswerIP(rr)
		if !ok {
			continue
		}
		if ipv6 && ip.Is6() && !ip.Is4In6() {
			return ip
		}
		if !ipv6 && (ip.Is4() || ip.Is4In6()) {
			return ip
		}
	}
	return netip.Addr{}
}
