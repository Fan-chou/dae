package control

import (
	"context"
	stderrors "errors"
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

func (d resolveDNSClassDialer) ResolveDNSLookup(ctx context.Context, dns netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, time.Duration, bool, error) {
	if d.res == nil || d.res.Dialer == nil {
		return nil, 0, false, fmt.Errorf("nil dialer")
	}
	class := ""
	if d.res.Outbound != nil && d.res.Outbound.IsolateTransport {
		class = d.res.Outbound.Name
	}
	return d.res.Dialer.ResolveDNSLookupForClass(ctx, dns, host, typ, network, class)
}
func resolveDNSQueryDialer(res *proxyDialResult) netproxy.Dialer {
	if res.Outbound != nil && res.Outbound.IsolateTransport {
		return resolveDNSClassDialer{res}
	}
	return res.Dialer
}

func (c *proxyResolveDNSPinCache) consume(key string) {
	_ = c.consumeAndReport(key)
}

func (c *proxyResolveDNSPinCache) consumeAndReport(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	consumed := false
	if ent, ok := c.entries[key]; ok && ent.speculative {
		ent.speculative = false
		c.entries[key] = ent
		consumed = true
	}
	if spec, ok := c.background[key]; ok && spec {
		c.background[key] = false
		consumed = true
	}
	return consumed
}
func (c *proxyResolveDNSPinCache) startBackground(key string, d *dialer.Dialer) bool {
	return c.startBackgroundTask(key, d, true)
}
func (c *proxyResolveDNSPinCache) startBackgroundTask(key string, d *dialer.Dialer, speculative bool) bool {
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
	c.background[key] = speculative
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

func (c *ControlPlane) prefetchProxyResolveDNSForResult(res *proxyDialResult, domain string, preferV6 bool) {
	if c == nil || res == nil || res.Dialer == nil {
		return
	}
	if c.ctx != nil && c.ctx.Err() != nil {
		return
	}
	if !res.Dialer.ResolveDNS().IsValid() || res.Dialer.IsResolveDNSCircuitOpen(time.Now()) {
		return
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" || isIPLikeDomain(domain) {
		return
	}
	if isDirectResolveDNSDial(res) || c.shouldRejectProxiedQuic(res.Dialer, true) {
		return
	}
	copyRes := *res
	if copyRes.Mark == 0 {
		copyRes.Mark = c.soMarkFromDae
	}
	key := resolveDNSResultKey(&copyRes, domain, preferV6)
	if _, _, hit, _ := c.resolveDNSPins.lookupPin(key, time.Now()); hit {
		return
	}
	d := copyRes.Dialer
	if !c.resolveDNSPins.startBackgroundTask(key, d, true) {
		return
	}
	c.resolveDNSPins.metrics.prefetchStarted.Add(1)
	go func() {
		defer c.resolveDNSPins.finishBackground(key, d)
		_, err, _ := c.resolveDNSPins.sf.Do(key, func() (any, error) {
			if ip, _, hit, _ := c.resolveDNSPins.lookupPin(key, time.Now()); hit {
				return resolveDNSFlightResult{ip: ip, queried: false, healthRecorded: false}, nil
			}
			ip, ttl, healthRecorded, err := c.executeResolveDNSLookup(&copyRes, domain, preferV6)
			if err == nil {
				c.resolveDNSPins.storePrefetch(key, ip, ttl)
			} else if stderrors.Is(err, errResolveDNSNegative) {
				c.resolveDNSPins.storeNegative(key, time.Now(), consts.ResolveDNSNegativeTTL)
			}
			return resolveDNSFlightResult{ip: ip, queried: true, healthRecorded: healthRecorded}, err
		})
		if err == nil && c.log != nil {
			c.log.WithField("domain", domain).Debug("resolve_dns prefetch completed")
		}
	}()
}
