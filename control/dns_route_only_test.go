/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestDNSRouteOnlyProjectionLifecycle(t *testing.T) {
	for _, mode := range []string{"ordinary", "DO", "TTL0"} {
		t.Run(mode, func(t *testing.T) {
			logger := newDNSListenerTestLogger()
			routing := newPhase0NamedUpstreamRouting(t, logger, "u", "192.0.2.11:53")
			option := phase0NamedUpstreamControllerOption(logger)
			tracker := newDomainRoutingTracker()
			var published *DnsCache
			option.ProjectCacheRoute = func(*DnsCache) []uint32 { return domainRoutingBitmap(1) }
			option.OptimisticCache = true
			option.OptimisticCacheTtl = 0
			option.MaxCacheSize = 16
			makeCache := option.NewCache
			option.NewCache = func(name string, ans, ns, extra []dnsmessage.RR, deadline, original time.Time) (*DnsCache, error) {
				cache, err := makeCache(name, ans, ns, extra, deadline, original)
				if cache != nil {
					cache.DomainBitmap = domainRoutingBitmap(1)
				}
				return cache, err
			}
			option.CacheAccessCallback = func(cache *DnsCache) error { published = cache; return phase5ProjectCache(tracker, 0, cache) }
			option.CacheDeleteCallback = func(_ string, cache *DnsCache) error { return phase5RemoveCache(tracker, 0, cache) }
			c, err := NewDnsController(routing, option)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			calls := 0
			original := dnsForwarderFactory
			defer func() { dnsForwarderFactory = original }()
			dnsForwarderFactory = func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
				return &stubDnsForwarder{forward: func(_ context.Context, wire []byte) (*dnsmessage.Msg, error) {
					calls++
					var q dnsmessage.Msg
					if err := q.Unpack(wire); err != nil {
						return nil, err
					}
					reply := new(dnsmessage.Msg)
					reply.SetReply(&q)
					ttl := "60"
					if mode == "TTL0" {
						ttl = "0"
					}
					rr, _ := dnsmessage.NewRR(q.Question[0].Name + " " + ttl + " IN A 192.0.2.100")
					reply.Answer = []dnsmessage.RR{rr}
					return reply, nil
				}}, nil
			}
			q := new(dnsmessage.Msg)
			q.SetQuestion(phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
			if mode == "DO" {
				q.SetEdns0(1232, true)
			}
			writer := &dnsTransportResponseWriter{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
			if err := c.HandleWithResponseWriter_(context.Background(), q, &udpRequest{routingResult: &bpfRoutingResult{}}, writer); err != nil {
				t.Fatal(err)
			}
			if got := writer.Message(); got == nil || dnsAnswerIPv4(t, got) != "192.0.2.100" {
				t.Fatal("DNS did not succeed")
			}
			if published == nil {
				t.Fatal("DNS succeeded without route projection")
			}
			phase5RequireTrackerBitmap(t, tracker, published, 1)
			if err := c.HandleWithResponseWriter_(context.Background(), q.Copy(), &udpRequest{routingResult: &bpfRoutingResult{}}, writer); err != nil {
				t.Fatal(err)
			}
			name := strings.TrimSuffix(q.Question[0].Name, ".")
			plane := &ControlPlane{
				log: logger, ctx: context.Background(),
				controlPlaneGenerationState:   controlPlaneGenerationState{dialMode: consts.DialMode_Domain},
				controlPlaneDNSRuntime:        controlPlaneDNSRuntime{dnsController: c},
				controlPlaneRealDomainRuntime: newControlPlaneRealDomainRuntime(),
			}
			target, _, dialIP := plane.ChooseDialTarget(consts.OutboundUserDefinedMin, netip.MustParseAddrPort("192.0.2.100:443"), name)
			if dialIP || target != name+":443" {
				t.Fatalf("domain-mode target=%s dialIP=%v", target, dialIP)
			}
			if mode == "ordinary" {
				if calls != 1 {
					t.Fatal("ordinary cache missed")
				}
				return
			}
			if calls != 2 {
				t.Fatal("route-only answer reused as DNS cache")
			}
			if mode == "TTL0" && writer.Message().Answer[0].Header().Ttl != 0 {
				t.Fatal("TTL0 changed")
			}
			if !published.RouteOnly || published.packedResponse.Load() != nil {
				t.Fatal("route-only entry has a reusable response")
			}
			if len(c.LookupCacheAnswers(q.Question[0].Name, q.Question[0].Qtype)) != 0 || len(c.lookupDnsCacheEntries(q.Question[0].Name, q.Question[0].Qtype)) != 0 {
				t.Fatal("internal lookup leaked route-only answers")
			}
			if !c.HasDnsKnowledge(c.cacheKey(q.Question[0].Name, q.Question[0].Qtype)) {
				t.Fatal("successful DNS did not establish domain evidence")
			}
			if c.LookupDnsRespCache(published.RouteOwnerKey, false) != nil {
				t.Fatal("direct cache lookup leaked route entry")
			}
			if wire, _ := c.LookupDnsRespCache_(q.Copy(), published.RouteOwnerKey, false); wire != nil {
				t.Fatal("wire lookup leaked route entry")
			}
			entries := c.CloneCacheForReload()
			replacement, err := NewDnsController(routing, option)
			if err != nil {
				t.Fatal(err)
			}
			defer replacement.Close()
			count, err := replacement.RestoreReloadCacheAndProject(entries, nil, published.ReceivedAt)
			if err != nil || count != 1 {
				t.Fatalf("live reload: count=%d err=%v", count, err)
			}
			if !replacement.HasDnsKnowledge(c.cacheKey(q.Question[0].Name, q.Question[0].Qtype)) {
				t.Fatal("reload lost domain evidence")
			}
			// Route-only expiration applies even when ordinary optimistic entries never expire.
			replacement.evictExpiredDnsCache(published.Deadline)
			phase5RequireTrackerAbsent(t, tracker, published)
			if replacement.HasDnsKnowledge(c.cacheKey(q.Question[0].Name, q.Question[0].Qtype)) {
				t.Fatal("expired route retained domain evidence")
			}
			count, err = replacement.RestoreReloadCacheAndProject(entries, nil, published.Deadline)
			if err != nil || count != 0 {
				t.Fatalf("expired reload resurrected route: count=%d err=%v", count, err)
			}
		})
	}
}
