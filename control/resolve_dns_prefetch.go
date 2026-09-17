package control

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

// The selected node remains the cache identity. A transport class and mark
// distinguish DNS queries that actually leave through different paths.
func resolveDNSResultKey(res *proxyDialResult, domain string, v6 bool) string {
	key := proxyResolveDNSPinKey(res.Dialer, res.Dialer.ResolveDNS(), domain, v6)
	class := ""
	if res.Outbound != nil && res.Outbound.IsolateTransport {
		class = res.Outbound.Name
	}
	if res.Mark != 0 || class != "" {
		key += fmt.Sprintf("\x00%d\x00%s", res.Mark, class)
	}
	return key
}

type resolveDNSClassDialer struct{ res *proxyDialResult }

func (d resolveDNSClassDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	return d.res.Outbound.DialContextWithSelected(ctx, d.res.Dialer, network, address)
}
func resolveDNSQueryDialer(res *proxyDialResult) netproxy.Dialer {
	if res.Outbound != nil && res.Outbound.IsolateTransport {
		return resolveDNSClassDialer{res}
	}
	return res.Dialer
}

func (c *proxyResolveDNSPinCache) consume(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ent, ok := c.entries[key]; ok && ent.speculative {
		ent.speculative = false
		c.entries[key] = ent
	}
	if _, ok := c.background[key]; ok {
		c.background[key] = false
	}
}
func (c *proxyResolveDNSPinCache) startBackground(key string, d *dialer.Dialer) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.background[key]; ok {
		return false
	}
	if len(c.background) >= 8 || c.backgroundNodes[d] >= 2 {
		return false
	}
	if c.background == nil {
		c.background = make(map[string]bool)
		c.backgroundNodes = make(map[*dialer.Dialer]int)
	}
	c.background[key] = true
	c.backgroundNodes[d]++
	return true
}
func (c *proxyResolveDNSPinCache) finishBackground(key string, d *dialer.Dialer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.background, key)
	c.backgroundNodes[d]--
	if c.backgroundNodes[d] == 0 {
		delete(c.backgroundNodes, d)
	}
}
func (c *proxyResolveDNSPinCache) storePrefetch(key string, ip netip.Addr, ttl time.Duration) {
	// storeCandidate preserves an already-consumed entry. A racing demand also
	// calls consume after receiving the shared result.
	c.mu.Lock()
	speculative := c.background[key]
	c.mu.Unlock()
	c.storeCandidate(key, ip, time.Now(), ttl, speculative)
}

func (c *ControlPlane) prefetchProxyResolveDNS(domain string, preferV6 bool, src netip.AddrPort, mac [6]uint8, _ uint32, _ [16]uint8, fakeDestination ...bool) {
	if c == nil || c.routingMatcher == nil || !src.IsValid() {
		return
	}
	if c.ctx != nil && c.ctx.Err() != nil {
		return
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" || isIPLikeDomain(domain) {
		return
	}
	index, mark, _, ok := c.routingMatcher.resolveDNSPrefetchRoute(domain, preferV6, src.Addr(), mac, len(fakeDestination) > 0 && fakeDestination[0])
	if !ok || index.IsReserved() || int(index) >= len(c.outbounds) {
		return
	}
	group := c.outbounds[index]
	if group == nil {
		return
	}
	version := consts.IpVersionStr_4
	if preferV6 {
		version = consts.IpVersionStr_6
	}
	nt := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: version, UdpHealthDomain: dialer.UdpHealthDomainData}
	d, err := group.PeekResolveDNSCandidate(nt)
	if err != nil || d == nil || !d.ResolveDNS().IsValid() {
		return
	}
	res := &proxyDialResult{OutboundIndex: index, Outbound: group, Dialer: d, Mark: mark}
	if isDirectResolveDNSDial(res) || c.shouldRejectProxiedQuic(d, true) {
		return
	}
	if res.Mark == 0 {
		res.Mark = c.soMarkFromDae
	}
	key := resolveDNSResultKey(res, domain, preferV6)
	if _, _, hit := c.resolveDNSPins.lookupFreshOrStale(key, time.Now()); hit {
		return
	}
	if !c.resolveDNSPins.startBackground(key, d) {
		return
	}
	go func() {
		defer c.resolveDNSPins.finishBackground(key, d)
		_, err, _ := c.resolveDNSPins.sf.Do(key, func() (any, error) {
			if ip, _, hit := c.resolveDNSPins.lookupFreshOrStale(key, time.Now()); hit {
				return ip, nil
			}
			ip, ttl, err := c.lookupProxyResolveDNSUncached(res, domain, preferV6)
			if err == nil {
				c.resolveDNSPins.storePrefetch(key, ip, ttl)
			}
			return ip, err
		})
		if err == nil && c.log != nil {
			c.log.WithField("domain", domain).Debug("resolve_dns prefetch completed")
		}
	}()
}

func (c *ControlPlane) resolveDNSPrefetchCallback() func(string, uint16, *udpRequest, bool) {
	if c == nil || !c.hasResolveDNSNode() {
		return nil
	}
	return c.prefetchResolveDNSFromDNS
}
