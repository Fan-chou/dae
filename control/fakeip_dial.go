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
	"golang.org/x/sync/singleflight"
)

// resolveIPViaDialer is the UDP DNS lookup used by resolve_dns pinning.
// Tests replace it to avoid a real network round-trip.
var resolveIPViaDialer = netutils.ResolveNetipTTL

func (c *ControlPlane) destIsFakeIP(addr netip.Addr) bool {
	store := c.fakeIPStore()
	return store != nil && store.Contains(addr)
}

// fakeIPDialSkipResolve reports whether a decisive FakeIP match can dial
// without looking up the real dest IP. Block and a user group whose current
// leaf is a proxy node only need the name. Builtin direct and a group that
// currently selects a direct leaf still need a real address (system resolve
// of domain:port can bounce back into the FakeIP pool).
func fakeIPDialSkipResolve(m *RoutingMatcher, outbound consts.OutboundIndex) bool {
	if outbound == consts.OutboundBlock {
		return true
	}
	return m.fakeIPOutboundIsProxy(outbound)
}

func (c *ControlPlane) fakeIPShouldPinRealDest(outbound consts.OutboundIndex) bool {
	if outbound == consts.OutboundDirect {
		return true
	}
	if outbound.IsReserved() {
		return false
	}
	if c == nil || c.routingMatcher == nil {
		return false
	}
	return !c.routingMatcher.fakeIPOutboundIsProxy(outbound)
}

func (c *ControlPlane) routeFakeIP(
	ctx context.Context,
	src, dst netip.AddrPort,
	domain string,
	l4proto consts.L4ProtoType,
	routingResult *bpfRoutingResult,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, realIP netip.Addr, err error) {
	if c == nil || c.routingMatcher == nil {
		return 0, 0, false, netip.Addr{}, fmt.Errorf("nil routing matcher")
	}
	if routingResult == nil {
		routingResult = &bpfRoutingResult{}
	}
	var ipVersion consts.IpVersionType
	if dst.Addr().Is4() || dst.Addr().Is4In6() {
		ipVersion = consts.IpVersion_4
	} else {
		ipVersion = consts.IpVersion_6
	}
	var mac16 [16]uint8
	copy(mac16[10:], routingResult.Mac[:])
	bSrc := src.Addr().As16()
	bDst := dst.Addr().As16()

	if len(c.routingMatcher.orderedRules) > 0 {
		facts, factErr := c.routingMatcher.newFacts(bSrc, bDst, src.Port(), dst.Port(), ipVersion, l4proto, domain, routingResult.Pname, routingResult.Dscp, mac16)
		if factErr != nil {
			return 0, 0, false, netip.Addr{}, factErr
		}
		attempted := false
		var resolved netip.Addr
		var resolveErr error
		lookup := func() (netip.Addr, error) {
			if !attempted {
				attempted = true
				resolved, resolveErr = c.realIPForFakeIPRoute(ctx, domain, dst.Addr())
			}
			return resolved, resolveErr
		}
		out, routeMark, routeMust, real, routeErr := c.routingMatcher.matchOrderedFakeIP(facts, lookup)
		if routeErr != nil {
			return 0, 0, false, netip.Addr{}, routeErr
		}
		if !real.IsValid() && !fakeIPDialSkipResolve(c.routingMatcher, out) {
			real, routeErr = lookup()
		}
		return out, routeMark, routeMust, real, routeErr
	}
	outboundIndex, mark, must, needsDestIP, err := c.routingMatcher.MatchDeferringDestIP(
		bSrc,
		bDst,
		src.Port(),
		dst.Port(),
		ipVersion,
		l4proto,
		domain,
		routingResult.Pname,
		routingResult.Dscp,
		mac16,
	)
	if err != nil {
		return 0, 0, false, netip.Addr{}, err
	}
	if !needsDestIP && fakeIPDialSkipResolve(c.routingMatcher, outboundIndex) {
		return outboundIndex, mark, must, netip.Addr{}, nil
	}
	realIP, realErr := c.realIPForFakeIPRoute(ctx, domain, dst.Addr())
	if realErr != nil {
		return 0, 0, false, netip.Addr{}, realErr
	}
	outboundIndex, mark, must, err = c.Route(src, netip.AddrPortFrom(realIP, dst.Port()), domain, l4proto, routingResult)
	return outboundIndex, mark, must, realIP, err
}

// realIPForFakeIPRoute looks up the on-wire destination for FakeIP rematch.
// DnsCache keeps the real A/AAAA; the client dest (28.x / 198.18) must not
// feed geoip/ip(). Cache miss re-resolves; still missing is a hard error.
func (c *ControlPlane) realIPForFakeIPRoute(ctx context.Context, domain string, fake netip.Addr) (netip.Addr, error) {
	if domain == "" {
		return netip.Addr{}, unnamedFakeIPError(fake)
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
		addrs = append(addrs, dns.freshAnswerIPs(domain, qtype)...)
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
		return "", unnamedFakeIPError(dst)
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
		return "", false, unnamedFakeIPError(dst.Addr())
	}
	return net.JoinHostPort(domain, strconv.Itoa(int(dst.Port()))), false, nil
}

func udpDialTarget(selected, pinned string) string {
	if selected != "" {
		return selected
	}
	return pinned
}

// ensureUdpDialTargetIP makes UDP DialTarget something the leaf can send.
//
// resolve_dns: applyProxyResolveDNS already pinned an IP (and its cache);
// leave that IP alone.
// No resolve_dns: direct keeps the real IP; proxies pass domain:port (Hy2/TUIC accept
// host:port on the wire). No name: pass the packet dest IP. FakeIP 28.x
// is never dialed — rewriteFakeIPDialTarget must have produced a domain.
func (c *ControlPlane) ensureUdpDialTargetIP(ctx context.Context, p *proxyDialParam, res *proxyDialResult) error {
	if res == nil || p == nil || p.Network != "udp" {
		return nil
	}
	if res.ResolveDNSPinned || udpDialTargetPinnedByResolveDNS(res) {
		return nil
	}
	dest := p.Dest.Addr()
	fake := dest.IsValid() && c.destIsFakeIP(dest)
	domain := udpDialDomain(res)
	// FakeIP direct pin: keep the resolved real IP. Rewriting to domain:port
	// would let a direct leaf resolve via the system and bounce into 28.x.
	if res.PinnedFakeIPRealDest || isDirectResolveDNSDial(res) {
		if _, err := parseDialTargetIP(res.DialTarget); err == nil {
			return nil
		}
	}
	if domain != "" {
		c.setUdpDialTargetDomain(res, domain, p.Dest.Port())
		return nil
	}
	if _, err := parseDialTargetIP(res.DialTarget); err == nil {
		return nil
	}
	if dest.IsValid() && !fake {
		c.pinProxyResolveDNSTarget(res, dest, p.Dest.Port())
		return nil
	}
	return fmt.Errorf("udp dial target is not an IP: %s", res.DialTarget)
}

func (c *ControlPlane) setUdpDialTargetDomain(res *proxyDialResult, domain string, port uint16) {
	if res == nil || domain == "" {
		return
	}
	res.DialTarget = net.JoinHostPort(domain, strconv.Itoa(int(port)))
	res.IsDialIp = false
}

func udpDialDomain(res *proxyDialResult) string {
	if res == nil {
		return ""
	}
	domain := strings.TrimSuffix(res.SniffedDomain, ".")
	if domain == "" || isIPLikeDomain(domain) {
		if host, _, err := net.SplitHostPort(res.DialTarget); err == nil {
			domain = host
		}
	}
	if domain == "" || isIPLikeDomain(domain) {
		return ""
	}
	return domain
}

func udpDialTargetPinnedByResolveDNS(res *proxyDialResult) bool {
	if res == nil || res.Dialer == nil || !res.Dialer.ResolveDNS().IsValid() {
		return false
	}
	_, err := parseDialTargetIP(res.DialTarget)
	return err == nil
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
	ip          netip.Addr
	expires     time.Time
	staleUntil  time.Time
	refreshing  bool
	speculative bool
}

type proxyResolveDNSPinCache struct {
	mu              sync.Mutex
	entries         map[string]proxyResolveDNSPin
	sf              singleflight.Group
	background      map[string]bool
	backgroundNodes map[*dialer.Dialer]int
}

func proxyResolveDNSPinKey(d *dialer.Dialer, dns netip.AddrPort, domain string, preferV6 bool) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	fam := byte('4')
	if preferV6 {
		fam = '6'
	}
	return fmt.Sprintf("%p\x00%s\x00%s\x00%c", d, dns.String(), domain, fam)
}

func (c *proxyResolveDNSPinCache) lookupFreshOrStale(key string, now time.Time) (ip netip.Addr, stale bool, ok bool) {
	if c == nil {
		return netip.Addr{}, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.entries[key]
	if !ok || !ent.ip.IsValid() {
		return netip.Addr{}, false, false
	}
	if !now.After(ent.expires) {
		return ent.ip, false, true
	}
	if now.After(ent.staleUntil) {
		delete(c.entries, key)
		return netip.Addr{}, false, false
	}
	return ent.ip, true, true
}

func (c *proxyResolveDNSPinCache) tryMarkStaleRefresh(key string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.entries[key]
	if !ok || ent.refreshing || !ent.ip.IsValid() {
		return false
	}
	ent.refreshing = true
	c.entries[key] = ent
	return true
}

func (c *proxyResolveDNSPinCache) clearRefreshing(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.entries[key]
	if !ok {
		return
	}
	ent.refreshing = false
	c.entries[key] = ent
}

func (c *proxyResolveDNSPinCache) store(key string, ip netip.Addr, now time.Time, ttl time.Duration) {
	c.storeCandidate(key, ip, now, ttl, false)
}

func (c *proxyResolveDNSPinCache) storeCandidate(key string, ip netip.Addr, now time.Time, ttl time.Duration, speculative bool) {
	if c == nil || !ip.IsValid() || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]proxyResolveDNSPin)
	}
	if old, exists := c.entries[key]; exists {
		speculative = speculative && old.speculative
	} else if len(c.entries) >= resolveDNSPinCacheMax {
		for k, ent := range c.entries {
			if now.After(ent.staleUntil) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= resolveDNSPinCacheMax {
			var victim string
			var earliest time.Time
			candidateSpec := false
			for k, ent := range c.entries {
				if speculative && !ent.speculative && !now.After(ent.expires) {
					continue
				}
				if victim == "" || (ent.speculative && !candidateSpec) || (ent.speculative == candidateSpec && ent.expires.Before(earliest)) {
					victim, earliest, candidateSpec = k, ent.expires, ent.speculative
				}
			}
			if victim == "" {
				return
			}
			delete(c.entries, victim)
		}
	}
	fresh := clampResolveDNSPinTTL(ttl)
	c.entries[key] = proxyResolveDNSPin{
		ip:          ip,
		speculative: speculative,
		expires:     now.Add(fresh),
		staleUntil:  now.Add(fresh + consts.ResolveDNSStaleTTL),
	}
}

func clampResolveDNSPinTTL(ttl time.Duration) time.Duration {
	if ttl < consts.ResolveDNSCacheTTLMin {
		return consts.ResolveDNSCacheTTLMin
	}
	if ttl > consts.ResolveDNSCacheTTLMax {
		return consts.ResolveDNSCacheTTLMax
	}
	return ttl
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
	if c != nil && c.udpCrossFamily != nil {
		res.Network = common.MagicNetwork("udp", res.Mark, mptcp)
	} else {
		res.Network = common.MagicNetworkWithIPVersion("udp", res.Mark, mptcp, string(ipVer))
	}
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
	if res.Dialer != nil {
		p := res.Dialer.Property()
		return p != nil && p.Address == "" && p.Name == "direct"
	}
	return res.Outbound != nil && strings.EqualFold(res.Outbound.Name, consts.OutboundDirect.String())
}

func resolveDNSLookupNetwork(mark uint32, mptcp bool) string {
	// No IPVersion: the family would force the outer hop to the node
	// (SS/stickyip), not the resolver address. Health checks do the same.
	return common.MagicNetwork("udp", mark, mptcp)
}

func (c *ControlPlane) applyProxyResolveDNS(ctx context.Context, p *proxyDialParam, res *proxyDialResult) error {
	if res == nil || p == nil || p.Network != "udp" {
		return nil
	}
	domain := strings.ToLower(strings.TrimSuffix(res.SniffedDomain, "."))
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
	ip, err := c.lookupProxyResolveDNSPin(ctx, res, domain, preferV6)
	if err != nil {
		return err
	}
	c.pinProxyResolveDNSTarget(res, ip, p.Dest.Port())
	res.ResolveDNSPinned = true
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

func (c *ControlPlane) lookupProxyResolveDNSPin(ctx context.Context, res *proxyDialResult, domain string, preferV6 bool) (netip.Addr, error) {
	key := resolveDNSResultKey(res, domain, preferV6)
	c.resolveDNSPins.consume(key)
	if ip, stale, ok := c.resolveDNSPins.lookupFreshOrStale(key, time.Now()); ok {
		if stale && c.resolveDNSPins.tryMarkStaleRefresh(key) {
			c.refreshProxyResolveDNSResult(res, domain, preferV6)
		}
		return ip, nil
	}
	result := c.resolveDNSPins.sf.DoChan(key, func() (any, error) {
		if ip, stale, ok := c.resolveDNSPins.lookupFreshOrStale(key, time.Now()); ok && !stale {
			return ip, nil
		}
		ip, ttl, err := c.lookupProxyResolveDNSUncached(res, domain, preferV6)
		if err != nil {
			return nil, err
		}
		c.resolveDNSPins.store(key, ip, time.Now(), ttl)
		return ip, nil
	})
	// A shared, bounded refresh can outlive this waiter. Endpoint creation
	// must still return as soon as its own dial budget is cancelled.
	var v any
	select {
	case <-ctx.Done():
		return netip.Addr{}, ctx.Err()
	case r := <-result:
		if r.Err != nil {
			return netip.Addr{}, r.Err
		}
		v = r.Val
	}
	ip, _ := v.(netip.Addr)
	if !ip.IsValid() {
		return netip.Addr{}, fmt.Errorf("no real IP for %s via %s", domain, res.Dialer.ResolveDNS())
	}
	c.resolveDNSPins.consume(key)
	return ip, nil
}

func (c *ControlPlane) refreshProxyResolveDNSPin(d *dialer.Dialer, mark uint32, domain string, preferV6 bool) {
	c.refreshProxyResolveDNSResult(&proxyDialResult{Dialer: d, Mark: mark}, domain, preferV6)
}

func (c *ControlPlane) refreshProxyResolveDNSResult(res *proxyDialResult, domain string, preferV6 bool) {
	key := resolveDNSResultKey(res, domain, preferV6)
	if !c.resolveDNSPins.startBackground(key, res.Dialer) {
		c.resolveDNSPins.clearRefreshing(key)
		return
	}
	copyRes := *res
	go func() {
		defer c.resolveDNSPins.finishBackground(key, res.Dialer)
		defer c.resolveDNSPins.clearRefreshing(key)
		_, _, _ = c.resolveDNSPins.sf.Do(key, func() (any, error) {
			if ip, stale, ok := c.resolveDNSPins.lookupFreshOrStale(key, time.Now()); ok && !stale {
				return ip, nil
			}
			ip, ttl, err := c.lookupProxyResolveDNSUncached(&copyRes, domain, preferV6)
			if err == nil {
				c.resolveDNSPins.store(key, ip, time.Now(), ttl)
			}
			return ip, err
		})
	}()
}

func (c *ControlPlane) lookupProxyResolveDNSUncached(res *proxyDialResult, domain string, preferV6 bool) (netip.Addr, time.Duration, error) {
	dns := res.Dialer.ResolveDNS()
	qtypes := [2]uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	if preferV6 {
		qtypes[0], qtypes[1] = dnsmessage.TypeAAAA, dnsmessage.TypeA
	}
	// Independent of the caller's ctx so prefetch and the first packet share
	// one in-flight lookup instead of cancelling each other.
	dnsCtx, cancel := context.WithTimeout(context.Background(), consts.ResolveDNSTimeout)
	defer cancel()
	lookupNet := resolveDNSLookupNetwork(res.Mark, c.mptcp)
	store := c.fakeIPStore()
	type answer struct {
		ip  netip.Addr
		ttl time.Duration
		err error
	}
	results := make(chan answer, 2)
	queryDialer := resolveDNSQueryDialer(res)
	resolver := resolveIPViaDialer
	launch := func(qtype uint16) {
		go func() {
			addrs, ttl, err := resolver(dnsCtx, queryDialer, dns, domain, qtype, lookupNet)
			var ip netip.Addr
			if err == nil {
				ip, err = pickResolvedDialIP(addrs, preferV6, store)
			}
			results <- answer{ip, ttl, err}
		}()
	}
	launch(qtypes[0])
	timer := time.NewTimer(consts.ResolveDNSFallbackDelay)
	defer timer.Stop()
	second := false
	remaining := 1
	var lastErr error
	for remaining > 0 {
		select {
		case <-dnsCtx.Done():
			return netip.Addr{}, 0, fmt.Errorf("resolve %s via %s: %w", domain, dns, dnsCtx.Err())
		case <-timer.C:
			if !second {
				second = true
				remaining++
				launch(qtypes[1])
			}
		case ans := <-results:
			remaining--
			if ans.err == nil {
				return ans.ip, ans.ttl, nil
			}
			lastErr = ans.err
			if !second {
				second = true
				remaining++
				timer.Stop()
				launch(qtypes[1])
			}
		}
	}
	return netip.Addr{}, 0, fmt.Errorf("resolve %s via %s: %w", domain, dns, lastErr)
}

func (c *ControlPlane) hasResolveDNSNode() bool {
	if c == nil {
		return false
	}
	for _, out := range c.outbounds {
		if out == nil {
			continue
		}
		for _, d := range out.Dialers {
			if d != nil && d.ResolveDNS().IsValid() {
				return true
			}
		}
	}
	return false
}

func (c *ControlPlane) prefetchResolveDNSFromDNS(qname string, qtype uint16, req *udpRequest, fakeDestination bool) {
	preferV6 := qtype == dnsmessage.TypeAAAA
	var src netip.AddrPort
	var mac [6]uint8
	var mark uint32
	var pname [16]uint8
	if req != nil {
		src = req.realSrc
		if req.routingResult != nil {
			mac = req.routingResult.Mac
			mark = req.routingResult.Mark
			pname = req.routingResult.Pname
		}
	}
	c.prefetchProxyResolveDNS(qname, preferV6, src, mac, mark, pname, fakeDestination)
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
