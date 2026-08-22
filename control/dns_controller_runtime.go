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

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type dnsControllerRuntimeState struct {
	routing               *dns.Dns
	lifecycleCtx          context.Context
	cacheAccessCallback   func(cache *DnsCache) (err error)
	cacheRemoveCallback   func(cache *DnsCache) (err error)
	cacheDeleteCallback   func(cacheKey string, cache *DnsCache) (err error)
	newCache              func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	routeProjectionEpoch  uint64
	routeProjectionHash   [32]byte
	projectCacheRoute     func(cache *DnsCache) []uint32
	bestDialerChooser     func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *dns.Upstream) (*dialArgument, error)
	timeoutExceedCallback func(dialArgument *dialArgument, err error)
	fixedDomainTtl        map[string]int
	fakeIPPolicy          *FakeIPPolicy
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
	if c == nil {
		return 0
	}
	return uint16(c.qtypePrefer.Load())
}

func (c *DnsController) currentOptimisticCacheConfig() (enabled bool, ttl int, maxCacheSize int) {
	if c == nil {
		return false, 0, 0
	}
	return c.optimisticCacheEnabled.Load(), int(c.optimisticCacheTtl.Load()), int(c.maxCacheSize.Load())
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
	c.qtypePrefer.Store(uint32(qtypePrefer))
	c.optimisticCacheEnabled.Store(optimisticCacheEnabled)
	c.optimisticCacheTtl.Store(int64(optimisticCacheTtl))
	c.maxCacheSize.Store(int64(maxCacheSize))
	c.log = option.Log
	lifecycleCtx := option.LifecycleContext
	if lifecycleCtx == nil {
		lifecycleCtx = context.Background()
	}
	runtimeState := &dnsControllerRuntimeState{
		routing:               routing,
		lifecycleCtx:          lifecycleCtx,
		cacheAccessCallback:   option.CacheAccessCallback,
		cacheRemoveCallback:   option.CacheRemoveCallback,
		cacheDeleteCallback:   option.CacheDeleteCallback,
		newCache:              option.NewCache,
		routeProjectionEpoch:  option.RouteProjectionEpoch,
		routeProjectionHash:   option.RouteProjectionHash,
		projectCacheRoute:     option.ProjectCacheRoute,
		bestDialerChooser:     option.BestDialerChooser,
		timeoutExceedCallback: option.TimeoutExceedCallback,
		fixedDomainTtl:        option.FixedDomainTtl,
		fakeIPPolicy:          option.FakeIPPolicy,
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
		return packed
	}
	src, mac := fakeIPClientFromReq(req)
	out, err := policy.PackedOrReal(qname, qtype, packed, src, mac)
	if err != nil {
		if c.log != nil {
			c.log.WithError(err).Warn("fakeip packed rewrite failed; sending real response")
		}
		return packed
	}
	return out
}

func (c *DnsController) rewriteClientMsg(msg *dnsmessage.Msg, req *udpRequest) {
	policy := c.fakeIPPolicy()
	if policy == nil || msg == nil {
		return
	}
	src, mac := fakeIPClientFromReq(req)
	if err := policy.RewriteMsg(msg, src, mac); err != nil && c.log != nil {
		c.log.WithError(err).Warn("fakeip message rewrite failed; sending real response")
	}
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

func (c *DnsController) EnsureRealAnswers(ctx context.Context, qname string, qtype uint16) error {
	if c == nil || qname == "" {
		return fmt.Errorf("dns controller is not ready")
	}
	if len(c.LookupCacheAnswers(qname, qtype)) > 0 {
		return nil
	}
	if ctx == nil {
		ctx = c.baseContext()
	}
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(dnsmessage.CanonicalName(qname), qtype)
	msg.RecursionDesired = true
	return c.handleWithResponseWriter_(ctx, msg, nil, false, nil, 0, nil, "", "")
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

// UpdateRuntime preserves the historical panic-on-invalid-input API for
// external callers. New internal code should use TryUpdateRuntime.
func (c *DnsController) UpdateRuntime(option *DnsControllerOption, routing *dns.Dns) {
	if err := c.TryUpdateRuntime(option, routing); err != nil {
		panic(err)
	}
}
