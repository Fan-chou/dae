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
	"github.com/daeuniverse/dae/common/netutils"
	dnsmessage "github.com/miekg/dns"
)

// resolveIPViaDialer is the UDP DNS lookup used by resolve_dns pinning.
// Tests replace it to avoid a real network round-trip.
var resolveIPViaDialer = netutils.ResolveNetip

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

func (c *ControlPlane) rewriteFakeIPDialTarget(domain string, dst netip.AddrPort, dialTarget string, dialIp bool) (string, bool, error) {
	store := c.fakeIPStore()
	if store == nil {
		return dialTarget, dialIp, nil
	}
	fakeDest := store.Contains(dst.Addr())
	fakeTarget := false
	if addr, err := parseDialTargetIP(dialTarget); err == nil && store.Contains(addr) {
		fakeTarget = true
	}
	if !fakeDest && !fakeTarget {
		return dialTarget, dialIp, nil
	}
	if domain == "" {
		return "", false, fmt.Errorf("unnamed FakeIP %s", dst.Addr())
	}
	return net.JoinHostPort(domain, strconv.Itoa(int(dst.Port()))), false, nil
}

func udpDialTarget(selected, pinned string) string {
	if selected != "" {
		return selected
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

func (c *ControlPlane) applyProxyResolveDNS(ctx context.Context, p *proxyDialParam, res *proxyDialResult) error {
	if res == nil || p == nil || p.Network != "udp" {
		return nil
	}
	domain := strings.TrimSuffix(res.SniffedDomain, ".")
	if domain == "" || isIPLikeDomain(domain) {
		return nil
	}
	if res.Dialer == nil {
		return nil
	}
	dns := res.Dialer.ResolveDNS()
	if !dns.IsValid() {
		return nil
	}
	wantV6 := p.Dest.Addr().Is6() && !p.Dest.Addr().Is4In6()
	qtype := uint16(dnsmessage.TypeA)
	if wantV6 {
		qtype = uint16(dnsmessage.TypeAAAA)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer cancel()
	network := res.Network
	if network == "" {
		network = "udp"
	}
	addrs, err := resolveIPViaDialer(dialCtx, res.Dialer, dns, domain, qtype, network)
	if err != nil {
		return fmt.Errorf("resolve %s via %s: %w", domain, dns, err)
	}
	ip, err := pickResolvedDialIP(addrs, wantV6, c.fakeIPStore())
	if err != nil {
		return fmt.Errorf("no real IP for %s via %s: %w", domain, dns, err)
	}
	res.DialTarget = netip.AddrPortFrom(ip, p.Dest.Port()).String()
	res.IsDialIp = true
	return nil
}

func pickResolvedDialIP(addrs []netip.Addr, wantV6 bool, store *FakeIPStore) (netip.Addr, error) {
	for _, ip := range addrs {
		if store != nil && store.Contains(ip) {
			continue
		}
		if wantV6 && ip.Is6() && !ip.Is4In6() {
			return ip, nil
		}
		if !wantV6 && (ip.Is4() || ip.Is4In6()) {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no matching address family")
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
