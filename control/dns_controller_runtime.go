/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

// lookupSystemDns is the AsIs destination for internal EnsureReal queries,
// which have no client packet. Tests replace it.
var lookupSystemDns = netutils.SystemDns

type dnsControllerRuntimeState struct {
	routing                *dns.Dns
	lifecycleCtx           context.Context
	cacheAccessCallback    func(cache *DnsCache) (err error)
	cacheDeleteCallback    func(cacheKey string, cache *DnsCache) (err error)
	newCache               func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	routeProjectionEpoch   uint64
	routeProjectionHash    [32]byte
	projectCacheRoute      func(cache *DnsCache) []uint32
	bestDialerChooser      func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *dns.Upstream) (*dialArgument, error)
	timeoutExceedCallback  func(dialArgument *dialArgument, err error)
	fixedDomainTtl         map[string]int
	qtypePrefer            uint16
	optimisticCacheEnabled bool
	optimisticCacheTtl     int
	maxCacheSize           int
	fakeIPPolicy           *FakeIPPolicy
	prefetchResolveDNS     func(qname string, qtype uint16, req *udpRequest)
}

func normalizeDnsRuntimeBehavior(option *DnsControllerOption) (qtypePrefer uint16, optimisticCacheEnabled bool, optimisticCacheTtl int, maxCacheSize int, err error) {
	if option == nil {
		option = &DnsControllerOption{}
	}
	qtypePrefer, err = parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return 0, false, 0, 0, err
	}
	optimisticCacheTtl = option.OptimisticCacheTtl
	maxCacheSize = option.MaxCacheSize
	if optimisticCacheTtl == 0 && maxCacheSize == 0 {
		optimisticCacheTtl = 60
	}
	return qtypePrefer, option.OptimisticCache, optimisticCacheTtl, maxCacheSize, nil
}

func (c *DnsController) currentQtypePrefer() uint16 {
	rt := c.runtime()
	if rt == nil {
		return 0
	}
	return rt.qtypePrefer
}

func (c *DnsController) currentOptimisticCacheConfig() (enabled bool, ttl int, maxCacheSize int) {
	rt := c.runtime()
	if rt == nil {
		return false, 0, 0
	}
	return rt.optimisticCacheEnabled, rt.optimisticCacheTtl, rt.maxCacheSize
}

// ReuseForReload updates the current facade to the replacement generation's
// runtime and returns a fresh facade that shares the same long-lived store.
// The shared store carries DNS cache, forwarders, janitors, async BPF workers,
// and the current runtime/config across reloads. The old control plane publishes
// the new facade as a handoff bridge so ActiveDnsController observes the
// replacement runtime without a nil window during reload retirement.
func (c *DnsController) ReuseForReload(option *DnsControllerOption, routing *dns.Dns) (*DnsController, error) {
	if c == nil {
		return nil, nil
	}
	c.ensureStoreForReload()
	previousRuntime := c.runtime()
	projectionUnchanged := previousRuntime != nil && option != nil &&
		option.RouteProjectionHash != ([32]byte{}) &&
		previousRuntime.routeProjectionHash == option.RouteProjectionHash
	if projectionUnchanged {
		// Projection epochs identify bitmap content, not control-plane lifetime.
		// Keeping the old epoch makes every existing cache wrapper valid for the
		// replacement runtime, avoiding an O(cache size) reload walk.
		adjustedOption := *option
		adjustedOption.RouteProjectionEpoch = previousRuntime.routeProjectionEpoch
		option = &adjustedOption
	}
	if err := c.TryUpdateRuntime(option, routing); err != nil {
		return nil, err
	}
	if !projectionUnchanged {
		c.reprojectCachedRoutes(c.runtime())
	}
	if err := c.ResetDnsForwarders(); err != nil && c.log != nil {
		c.log.WithError(err).Warn("failed to retire stale DNS forwarders during reload reuse")
	}
	return c.sharedStoreFacade(), nil
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func (c *DnsController) updateRuntime(option *DnsControllerOption, routing *dns.Dns) error {
	if c == nil {
		return nil
	}
	c.requireStore()
	if option == nil {
		option = &DnsControllerOption{}
	}
	qtypePrefer, optimisticCacheEnabled, optimisticCacheTtl, maxCacheSize, err := normalizeDnsRuntimeBehavior(option)
	if err != nil {
		return err
	}
	// c.log is deliberately NOT reassigned here: the controller is published
	// while request handlers and the janitor run, and an unlocked field write
	// would be a data race. Reloads never introduce a new logger instance
	// anyway — the daemon mutates the single shared logger in place (see
	// cmd/run_reload_worker.go logger.SetLogger), so the construction-time
	// pointer stays correct across generations.
	lifecycleCtx := option.LifecycleContext
	if lifecycleCtx == nil {
		lifecycleCtx = context.Background()
	}
	runtimeState := &dnsControllerRuntimeState{
		routing:                routing,
		lifecycleCtx:           lifecycleCtx,
		cacheAccessCallback:    option.CacheAccessCallback,
		cacheDeleteCallback:    option.CacheDeleteCallback,
		newCache:               option.NewCache,
		routeProjectionEpoch:   option.RouteProjectionEpoch,
		routeProjectionHash:    option.RouteProjectionHash,
		projectCacheRoute:      option.ProjectCacheRoute,
		bestDialerChooser:      option.BestDialerChooser,
		timeoutExceedCallback:  option.TimeoutExceedCallback,
		fixedDomainTtl:         option.FixedDomainTtl,
		qtypePrefer:            qtypePrefer,
		optimisticCacheEnabled: optimisticCacheEnabled,
		optimisticCacheTtl:     optimisticCacheTtl,
		maxCacheSize:           maxCacheSize,
		fakeIPPolicy:           option.FakeIPPolicy,
		prefetchResolveDNS:     option.PrefetchResolveDNS,
	}
	c.runtimeMu.Lock()
	c.runtimeState.Store(runtimeState)
	c.runtimeMu.Unlock()
	if maxCacheSize > 0 && c.dnsCacheSize.Load() > int64(maxCacheSize) {
		c.cacheProjectionMu.Lock()
		c.trimDnsCacheToSizeLocked(maxCacheSize)
		c.cacheProjectionMu.Unlock()
	}
	return nil
}

func (c *DnsController) fakeIPPolicy() *FakeIPPolicy {
	rt := c.runtime()
	if rt == nil {
		return nil
	}
	return rt.fakeIPPolicy
}

func fakeIPClientFromReq(req *udpRequest) (netip.Addr, [6]byte) {
	var mac [6]byte
	if req == nil {
		return netip.Addr{}, mac
	}
	if req.routingResult != nil {
		mac = req.routingResult.Mac
	}
	if req.realSrc.IsValid() {
		return req.realSrc.Addr(), mac
	}
	return netip.Addr{}, mac
}

func (c *DnsController) rewriteClientPacked(qname string, qtype uint16, packed []byte, req *udpRequest) []byte {
	policy := c.fakeIPPolicy()
	if policy == nil {
		c.maybePrefetchResolveDNS(qname, qtype, req)
		return packed
	}
	src, mac := fakeIPClientFromReq(req)
	out, err := policy.PackedOrReal(qname, qtype, packed, src, mac)
	if err != nil {
		if c.log != nil {
			c.log.WithError(err).Warn("fakeip packed rewrite failed; sending real response")
		}
		c.maybePrefetchResolveDNS(qname, qtype, req)
		return packed
	}
	c.maybePrefetchResolveDNS(qname, qtype, req)
	return out
}

func (c *DnsController) rewriteClientMsg(msg *dnsmessage.Msg, req *udpRequest) {
	policy := c.fakeIPPolicy()
	if policy == nil || msg == nil {
		if msg != nil && len(msg.Question) > 0 {
			c.maybePrefetchResolveDNS(msg.Question[0].Name, msg.Question[0].Qtype, req)
		}
		return
	}
	src, mac := fakeIPClientFromReq(req)
	if err := policy.RewriteMsg(msg, src, mac); err != nil && c.log != nil {
		c.log.WithError(err).Warn("fakeip message rewrite failed; sending real response")
	}
	if len(msg.Question) > 0 {
		c.maybePrefetchResolveDNS(msg.Question[0].Name, msg.Question[0].Qtype, req)
	}
}

func (c *DnsController) maybePrefetchResolveDNS(qname string, qtype uint16, req *udpRequest) {
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return
	}
	rt := c.runtime()
	if rt == nil || rt.prefetchResolveDNS == nil {
		return
	}
	rt.prefetchResolveDNS(qname, qtype, req)
}

func (c *DnsController) LookupCacheAnswers(qname string, qtype uint16) []dnsmessage.RR {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	key := c.cacheKey(qname, qtype)
	if v, ok := c.dnsCache.Load(key); ok {
		if cache, _ := v.(*DnsCache); cache != nil {
			return cache.Answer
		}
	}
	prefix := key + "|"
	var answers []dnsmessage.RR
	c.dnsCache.Range(func(k, value any) bool {
		ks, ok := k.(string)
		if !ok || (ks != key && !strings.HasPrefix(ks, prefix)) {
			return true
		}
		cache, _ := value.(*DnsCache)
		if cache == nil || len(cache.Answer) == 0 {
			return true
		}
		answers = cache.Answer
		return false
	})
	return answers
}

func (c *DnsController) cacheHasRealIP(qname string, qtype uint16) bool {
	preferV6 := qtype == dnsmessage.TypeAAAA
	store := c.fakeIPAnswerStore()
	for _, cache := range c.lookupDnsCacheEntries(qname, qtype) {
		ip, err := pickResolvedDialIP(ipsFromAnswers(cache.Answer), preferV6, store)
		if err == nil && ip.IsValid() {
			return true
		}
	}
	return false
}

const ensureRealAnswersMissTTL = 2 * time.Second

type ensureRealMissEntry struct {
	until time.Time
	err   error
}

func ensureRealFlightKey(cacheKey string) string {
	return "ensure-real:" + cacheKey
}

func dnsCacheFresh(cache *DnsCache, now time.Time) bool {
	if cache == nil {
		return false
	}
	if n := cache.deadlineNano.Load(); n > 0 {
		return now.UnixNano() < n
	}
	if cache.Deadline.IsZero() {
		return true
	}
	return now.Before(cache.Deadline)
}

func dnsCacheFreshUpstream(cache *DnsCache, now time.Time) bool {
	if cache == nil {
		return false
	}
	if !cache.OriginalDeadline.IsZero() {
		return now.Before(cache.OriginalDeadline)
	}
	return dnsCacheFresh(cache, now)
}

func (c *DnsController) lookupDnsCacheEntries(qname string, qtype uint16) []*DnsCache {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	key := c.cacheKey(qname, qtype)
	prefix := key + "|"
	var caches []*DnsCache
	if v, ok := c.dnsCache.Load(key); ok {
		if cache, _ := v.(*DnsCache); cache != nil {
			caches = append(caches, cache)
		}
	}
	c.dnsCache.Range(func(k, value any) bool {
		ks, ok := k.(string)
		if !ok || !strings.HasPrefix(ks, prefix) {
			return true
		}
		cache, _ := value.(*DnsCache)
		if cache == nil {
			return true
		}
		caches = append(caches, cache)
		return true
	})
	return caches
}

func (c *DnsController) freshAnswerIPs(qname string, qtype uint16) []netip.Addr {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	now := time.Now()
	var addrs []netip.Addr
	for _, cache := range c.lookupDnsCacheEntries(qname, qtype) {
		if !dnsCacheFreshUpstream(cache, now) {
			continue
		}
		addrs = append(addrs, ipsFromAnswers(cache.Answer)...)
	}
	return addrs
}

func (c *DnsController) fakeIPAnswerStore() *FakeIPStore {
	if p := c.fakeIPPolicy(); p != nil {
		return p.store
	}
	return nil
}

// cacheNeedsRealRefresh is true when EnsureRealAnswers should query upstream.
// A real A/AAAA or NODATA still inside the upstream TTL is served from cache.
// Past that TTL, or FakeIP-only leftovers, we look up again.
func (c *DnsController) cacheNeedsRealRefresh(qname string, qtype uint16) bool {
	preferV6 := qtype == dnsmessage.TypeAAAA
	store := c.fakeIPAnswerStore()
	now := time.Now()
	hasFreshFakeOnly := false
	hasFreshEmpty := false
	expiredReal := false
	for _, cache := range c.lookupDnsCacheEntries(qname, qtype) {
		addrs := ipsFromAnswers(cache.Answer)
		ip, err := pickResolvedDialIP(addrs, preferV6, store)
		hasReal := err == nil && ip.IsValid()
		fresh := dnsCacheFreshUpstream(cache, now)
		if hasReal {
			if fresh {
				return false
			}
			expiredReal = true
			continue
		}
		if !fresh {
			continue
		}
		if len(addrs) > 0 {
			hasFreshFakeOnly = true
			continue
		}
		hasFreshEmpty = true
	}
	if hasFreshFakeOnly || expiredReal {
		return true
	}
	return !hasFreshEmpty
}

func (c *DnsController) loadEnsureRealMiss(cacheKey string) (error, bool) {
	if c == nil || c.dnsControllerStore == nil || cacheKey == "" {
		return nil, false
	}
	v, ok := c.ensureRealMiss.Load(cacheKey)
	if !ok {
		return nil, false
	}
	ent, ok := v.(ensureRealMissEntry)
	if !ok || time.Now().After(ent.until) {
		c.ensureRealMiss.Delete(cacheKey)
		return nil, false
	}
	return ent.err, true
}

func (c *DnsController) storeEnsureRealMiss(cacheKey string, err error) {
	if c == nil || c.dnsControllerStore == nil || cacheKey == "" || err == nil {
		return
	}
	c.ensureRealMiss.Store(cacheKey, ensureRealMissEntry{
		until: time.Now().Add(ensureRealAnswersMissTTL),
		err:   err,
	})
}

func dnsAnswerIPSet(answers []dnsmessage.RR) map[netip.Addr]struct{} {
	out := make(map[netip.Addr]struct{})
	for _, rr := range answers {
		ip, ok := dnsAnswerIP(rr)
		if !ok || !ip.IsValid() {
			continue
		}
		out[ip] = struct{}{}
	}
	return out
}

func dnsAnswerIPsEqual(a, b []dnsmessage.RR) bool {
	left := dnsAnswerIPSet(a)
	right := dnsAnswerIPSet(b)
	if len(left) != len(right) {
		return false
	}
	for ip := range left {
		if _, ok := right[ip]; !ok {
			return false
		}
	}
	return true
}

func (c *DnsController) existingAnswerRRs(qname string, qtype uint16) []dnsmessage.RR {
	var answers []dnsmessage.RR
	for _, cache := range c.lookupDnsCacheEntries(qname, qtype) {
		if cache == nil {
			continue
		}
		answers = append(answers, cache.Answer...)
	}
	return answers
}

func (c *DnsController) ensureRealStoreKey(qname string, qtype uint16, responseCacheKey string) string {
	base := c.cacheKey(qname, qtype)
	if _, ok := c.dnsCache.Load(base); ok {
		return base
	}
	if responseCacheKey != "" {
		return responseCacheKey
	}
	return base
}

func (c *DnsController) queryAndMaybeStoreRealAnswers(ctx context.Context, qname string, qtype uint16) error {
	rt := c.runtime()
	if rt == nil || rt.routing == nil {
		return fmt.Errorf("dns routing is not configured")
	}
	qname = dnsmessage.CanonicalName(qname)
	upstreamIndex, upstream, err := rt.routing.RequestSelect(ctx, qname, qtype)
	if err != nil {
		return err
	}
	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		return fmt.Errorf("dns request rejected")
	}
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(qname, qtype)
	msg.RecursionDesired = true
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	req, err := c.ensureRealUpstreamRequest(upstream)
	if err != nil {
		return err
	}
	resolution, err := c.resolveDNSUpstream(ctx, 0, req, data, upstream)
	if err != nil {
		return err
	}
	if resolution == nil || resolution.response == nil {
		return fmt.Errorf("empty DNS response")
	}
	resp := resolution.response
	if resp.Rcode != dnsmessage.RcodeSuccess {
		return dnsResponseRcodeError(resp.Rcode)
	}
	if len(c.lookupDnsCacheEntries(qname, qtype)) > 0 && dnsAnswerIPsEqual(c.existingAnswerRRs(qname, qtype), resp.Answer) {
		c.refreshExistingDnsCacheTTL(qname, qtype, dnsMessageAnswerTTL(resp))
		return nil
	}
	baseKey := c.cacheKey(qname, qtype)
	storeKey := c.ensureRealStoreKey(qname, qtype, c.responseCacheKey(baseKey, req, upstreamIndex, upstream))
	return c.NormalizeAndCacheDnsResp_(resp, storeKey)
}

// ensureRealUpstreamRequest synthesizes a dest for AsIs. Named upstreams
// do not need a client packet; AsIs does (resolveDNSUpstream uses realDst).
func (c *DnsController) ensureRealUpstreamRequest(upstream *dns.Upstream) (*udpRequest, error) {
	if upstream != nil {
		return nil, nil
	}
	dst, err := lookupSystemDns()
	if err != nil {
		return nil, fmt.Errorf("asis DNS lookup requires a destination: %w", err)
	}
	if !dst.IsValid() {
		return nil, fmt.Errorf("asis DNS lookup requires a destination")
	}
	return &udpRequest{realDst: dst}, nil
}

func dnsResponseRcodeError(rcode int) error {
	if name := dnsmessage.RcodeToString[rcode]; name != "" {
		return fmt.Errorf("DNS %s", name)
	}
	return fmt.Errorf("DNS rcode %d", rcode)
}

func dnsMessageAnswerTTL(msg *dnsmessage.Msg) uint32 {
	if msg == nil || len(msg.Answer) == 0 {
		return minFirefoxCacheTtl
	}
	ttl := msg.Answer[0].Header().Ttl
	if ttl > 31536000 {
		return 31536000
	}
	if ttl == 0 {
		return minFirefoxCacheTtl
	}
	return ttl
}

func (c *DnsController) refreshExistingDnsCacheTTL(qname string, qtype uint16, ttl uint32) {
	now := time.Now()
	host := strings.TrimSuffix(dnsmessage.CanonicalName(qname), ".")
	originalDeadline := now.Add(time.Duration(ttl) * time.Second)
	deadline := originalDeadline
	if rt := c.runtime(); rt != nil {
		if fixedTtl, ok := rt.fixedDomainTtl[host]; ok {
			deadline = now.Add(time.Duration(fixedTtl) * time.Second)
		}
	}
	c.forEachDnsCacheEntry(qname, qtype, func(key string, cache *DnsCache) {
		if cache == nil {
			return
		}
		next := cache.cloneWithDeadlines(deadline, originalDeadline)
		if next == nil {
			return
		}
		if next.RouteOwnerKey == "" {
			next.RouteOwnerKey = key
		}
		// Swap the published object so Deadline/OriginalDeadline are never
		// written in place. CAS loses to a concurrent full replace, which
		// already carries its own TTL.
		_ = c.dnsCache.CompareAndSwap(key, cache, next)
	})
	c.rememberDnsKnowledge(c.cacheKey(qname, qtype), originalDeadline, false)
}

func (c *DnsController) forEachDnsCacheEntry(qname string, qtype uint16, fn func(key string, cache *DnsCache)) {
	if c == nil || c.dnsControllerStore == nil || fn == nil {
		return
	}
	key := c.cacheKey(qname, qtype)
	prefix := key + "|"
	if v, ok := c.dnsCache.Load(key); ok {
		if cache, _ := v.(*DnsCache); cache != nil {
			fn(key, cache)
		}
	}
	c.dnsCache.Range(func(k, value any) bool {
		ks, ok := k.(string)
		if !ok || !strings.HasPrefix(ks, prefix) {
			return true
		}
		cache, _ := value.(*DnsCache)
		if cache != nil {
			fn(ks, cache)
		}
		return true
	})
}

func (c *DnsController) EnsureRealAnswers(ctx context.Context, qname string, qtype uint16) error {
	if c == nil || qname == "" {
		return fmt.Errorf("dns controller is not ready")
	}
	c.requireStore()
	if !c.cacheNeedsRealRefresh(qname, qtype) {
		return nil
	}
	cacheKey := c.cacheKey(qname, qtype)
	if err, ok := c.loadEnsureRealMiss(cacheKey); ok {
		return err
	}
	_, err, _ := c.sf.Do(ensureRealFlightKey(cacheKey), func() (any, error) {
		if !c.cacheNeedsRealRefresh(qname, qtype) {
			c.ensureRealMiss.Delete(cacheKey)
			return nil, nil
		}
		if err, ok := c.loadEnsureRealMiss(cacheKey); ok {
			return nil, err
		}
		workCtx, cancel := c.newWorkContext(5 * time.Second)
		defer cancel()
		err := c.queryAndMaybeStoreRealAnswers(workCtx, qname, qtype)
		if err != nil {
			c.storeEnsureRealMiss(cacheKey, err)
			return nil, err
		}
		c.ensureRealMiss.Delete(cacheKey)
		return nil, nil
	})
	return err
}

func (c *DnsController) runtime() *dnsControllerRuntimeState {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	return c.runtimeState.Load()
}

// TryUpdateRuntime updates generation-local DNS runtime state and reports
// invalid behavior config via error.
func (c *DnsController) TryUpdateRuntime(option *DnsControllerOption, routing *dns.Dns) error {
	return c.updateRuntime(option, routing)
}
