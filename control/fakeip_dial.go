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
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// resolveIPViaDialer is the UDP DNS lookup used by resolve_dns pinning.
// Tests replace it to avoid a real network round-trip.
var resolveIPViaDialer = netutils.ResolveNetip

func (c *ControlPlane) destIsFakeIP(addr netip.Addr) bool {
	store := c.fakeIPStore()
	return store != nil && store.Contains(addr)
}

// realIPForFakeIPRoute looks up the on-wire destination for FakeIP rematch.
// DnsCache keeps the real A/AAAA; the client dest (28.x / 198.18) must not
// feed geoip/ip(). Cache miss re-resolves; still missing is a hard error.
func (c *ControlPlane) realIPForFakeIPRoute(ctx context.Context, domain string, fake netip.Addr) (netip.Addr, error) {
	if domain == "" {
		return netip.Addr{}, fmt.Errorf("unnamed FakeIP %s", fake)
	}
	preferV6 := fake.Is6() && !fake.Is4In6()
	if ip := c.realIPFromDnsCache(domain, preferV6); ip.IsValid() {
		return ip, nil
	}
	dns := c.ActiveDnsController()
	if dns == nil {
		return netip.Addr{}, fmt.Errorf("no real IP for FakeIP %s (%s)", fake, domain)
	}
	// Re-resolve only when DNS routing is live. Unit tests seed DnsCache
	// without a resolver; a missing real RR is then a hard error.
	if rt := dns.runtime(); rt != nil && rt.routing != nil {
		qtypes := [2]uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}
		if preferV6 {
			qtypes[0], qtypes[1] = dnsmessage.TypeAAAA, dnsmessage.TypeA
		}
		var lastErr error
		for _, qtype := range qtypes {
			if err := dns.EnsureRealAnswers(ctx, domain, qtype); err != nil {
				lastErr = err
				continue
			}
			if ip := c.realIPFromDnsCache(domain, preferV6); ip.IsValid() {
				return ip, nil
			}
		}
		if lastErr != nil {
			return netip.Addr{}, fmt.Errorf("no real IP for FakeIP %s (%s): %w", fake, domain, lastErr)
		}
	}
	return netip.Addr{}, fmt.Errorf("no real IP for FakeIP %s (%s)", fake, domain)
}

func (c *ControlPlane) realIPFromDnsCache(domain string, preferV6 bool) netip.Addr {
	dns := c.ActiveDnsController()
	if dns == nil || domain == "" {
		return netip.Addr{}
	}
	qtypes := [2]uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	if preferV6 {
		qtypes[0], qtypes[1] = dnsmessage.TypeAAAA, dnsmessage.TypeA
	}
	var addrs []netip.Addr
	for _, qtype := range qtypes {
		addrs = append(addrs, ipsFromAnswers(dns.LookupCacheAnswers(domain, qtype))...)
	}
	ip, err := pickResolvedDialIP(addrs, preferV6, c.fakeIPStore())
	if err != nil {
		return netip.Addr{}
	}
	return ip
}

func ipsFromAnswers(answers []dnsmessage.RR) []netip.Addr {
	var addrs []netip.Addr
	for _, rr := range answers {
		ip, ok := dnsAnswerIP(rr)
		if !ok {
			continue
		}
		addrs = append(addrs, ip)
	}
	return addrs
}

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

const resolveDNSPinCacheMax = 1024

type proxyResolveDNSPin struct {
	ip      netip.Addr
	expires time.Time
}

type proxyResolveDNSPinCache struct {
	mu      sync.Mutex
	entries map[string]proxyResolveDNSPin
}

func proxyResolveDNSPinKey(d *dialer.Dialer, dns netip.AddrPort, domain string, preferV6 bool) string {
	fam := byte('4')
	if preferV6 {
		fam = '6'
	}
	return fmt.Sprintf("%p\x00%s\x00%s\x00%c", d, dns.String(), domain, fam)
}

func (c *proxyResolveDNSPinCache) lookup(key string, now time.Time) (netip.Addr, bool) {
	if c == nil {
		return netip.Addr{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.entries[key]
	if !ok || now.After(ent.expires) || !ent.ip.IsValid() {
		if ok {
			delete(c.entries, key)
		}
		return netip.Addr{}, false
	}
	return ent.ip, true
}

func (c *proxyResolveDNSPinCache) store(key string, ip netip.Addr, now time.Time) {
	if c == nil || !ip.IsValid() || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]proxyResolveDNSPin)
	}
	if len(c.entries) >= resolveDNSPinCacheMax {
		for k, ent := range c.entries {
			if now.After(ent.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= resolveDNSPinCacheMax {
			c.entries = make(map[string]proxyResolveDNSPin)
		}
	}
	c.entries[key] = proxyResolveDNSPin{ip: ip, expires: now.Add(consts.ResolveDNSCacheTTL)}
}

func (c *ControlPlane) pinProxyResolveDNSTarget(res *proxyDialResult, ip netip.Addr, port uint16) {
	res.DialTarget = netip.AddrPortFrom(ip, port).String()
	res.IsDialIp = true
	if !isDirectResolveDNSDial(res) {
		// Proxy dials reuse MagicNetwork.IPVersion for the outer hop to the
		// node (sticky IP, Shadowsocks/SOCKS base dial). The inner UDP dest
		// family is already expressed by DialTarget; rewriting Network here
		// would reconnect the proxy over the wrong family without re-selecting.
		return
	}
	ipVer := consts.IpVersionFromAddr(ip)
	mptcp := false
	if c != nil {
		mptcp = c.mptcp
	}
	res.Network = common.MagicNetworkWithIPVersion("udp", res.Mark, mptcp, string(ipVer))
	if res.SelectionNetworkTypeObj != nil && res.SelectionNetworkTypeObj.IpVersion != ipVer {
		nt := *res.SelectionNetworkTypeObj
		nt.IpVersion = ipVer
		res.SelectionNetworkTypeObj = &nt
		res.SelectionNetworkType = nt.StringWithoutDns()
	}
}

func isDirectResolveDNSDial(res *proxyDialResult) bool {
	if res == nil {
		return false
	}
	if res.OutboundIndex == consts.OutboundDirect {
		return true
	}
	return res.Outbound != nil && strings.EqualFold(res.Outbound.Name, consts.OutboundDirect.String())
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
	preferV6 := p.Dest.Addr().Is6() && !p.Dest.Addr().Is4In6()
	key := proxyResolveDNSPinKey(res.Dialer, dns, domain, preferV6)
	now := time.Now()
	if ip, ok := c.resolveDNSPins.lookup(key, now); ok {
		c.pinProxyResolveDNSTarget(res, ip, p.Dest.Port())
		return nil
	}
	qtypes := [2]uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	if preferV6 {
		qtypes[0], qtypes[1] = dnsmessage.TypeAAAA, dnsmessage.TypeA
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dnsCtx, cancel := context.WithTimeout(ctx, consts.ResolveDNSTimeout)
	defer cancel()
	lookupNet := res.Network
	if lookupNet == "" {
		lookupNet = "udp"
	}
	store := c.fakeIPStore()
	var lastErr error
	for _, qtype := range qtypes {
		addrs, err := resolveIPViaDialer(dnsCtx, res.Dialer, dns, domain, qtype, lookupNet)
		if err != nil {
			lastErr = err
			continue
		}
		ip, err := pickResolvedDialIP(addrs, preferV6, store)
		if err != nil {
			lastErr = err
			continue
		}
		c.pinProxyResolveDNSTarget(res, ip, p.Dest.Port())
		c.resolveDNSPins.store(key, ip, now)
		if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
			dialerName := ""
			if prop := res.Dialer.Property(); prop != nil {
				dialerName = prop.Name
			}
			c.log.WithFields(logrus.Fields{
				"domain": domain,
				"dns":    dns.String(),
				"dialer": dialerName,
				"target": res.DialTarget,
			}).Debug("pinned UDP dest via resolve_dns")
		}
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("resolve %s via %s: %w", domain, dns, lastErr)
	}
	return fmt.Errorf("no real IP for %s via %s", domain, dns)
}

func pickResolvedDialIP(addrs []netip.Addr, preferV6 bool, store *FakeIPStore) (netip.Addr, error) {
	var fallback netip.Addr
	for _, ip := range addrs {
		if store != nil && store.Contains(ip) {
			continue
		}
		isV6 := ip.Is6() && !ip.Is4In6()
		if preferV6 == isV6 {
			return ip, nil
		}
		if !fallback.IsValid() {
			fallback = ip
		}
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	return netip.Addr{}, fmt.Errorf("no real IP")
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
