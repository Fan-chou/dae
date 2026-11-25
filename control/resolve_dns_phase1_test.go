/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

func TestResolveDNSTimeoutUsesShortEndpointFailureCache(t *testing.T) {
	prev := resolveIPViaDialer
	resolveIPViaDialer = func(ctx context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, _ uint16, _ string) ([]netip.Addr, time.Duration, error) {
		return nil, 0, fmt.Errorf("%w: %w", netutils.ErrResolveTimeout, context.DeadlineExceeded)
	}
	defer func() { resolveIPViaDialer = prev }()

	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "timeout-ttl.example",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err == nil {
		t.Fatal("expected first timeout failure")
	}
	if !shouldCacheUdpEndpointCreateFailure(err) {
		t.Fatalf("shouldCacheUdpEndpointCreateFailure(%v) = false, want true for ErrResolveTimeout", err)
	}
	if ttl := udpEndpointCreateFailureTTL(err); ttl != consts.UdpEndpointFailureCacheTimeoutTTL {
		t.Fatalf("udpEndpointCreateFailureTTL = %v, want %v", ttl, consts.UdpEndpointFailureCacheTimeoutTTL)
	}
}

func TestResolveDNSDynamicFallbackDelayForHighRTTNode(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
	d.MustGetLatencies10(&componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}).AppendLatency(180 * time.Millisecond)

	if got := resolveDNSFallbackDelayForDialer(d); got != 280*time.Millisecond {
		t.Fatalf("fallback delay = %v, want 280ms", got)
	}

	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus
	var queries atomic.Int32
	prev := resolveIPViaDialer
	resolveIPViaDialer = func(ctx context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, typ uint16, _ string) ([]netip.Addr, time.Duration, error) {
		queries.Add(1)
		if typ == dnsmessage.TypeA {
			select {
			case <-time.After(260 * time.Millisecond):
				return []netip.Addr{netip.MustParseAddr("198.51.100.77")}, time.Minute, nil
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		}
		return nil, 0, nil
	}
	defer func() { resolveIPViaDialer = prev }()

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "dynamic-delay.example",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil || res.DialTarget != "198.51.100.77:443" {
		t.Fatalf("res=(%v, %v)", res, err)
	}
	if queries.Load() != 1 {
		t.Fatalf("queries = %d, want 1 (no premature AAAA stagger at 250ms)", queries.Load())
	}
}

func TestResolveDNSNegativeCacheAndNoCircuitTrip(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	var queries atomic.Int32
	prev := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		queries.Add(1)
		return nil, 0, &netutils.DnsRcodeError{Rcode: dnsmessage.RcodeNameError}
	}
	defer func() { resolveIPViaDialer = prev }()

	for i := range 8 {
		_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "nx-repeat.example",
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		if err == nil {
			t.Fatalf("call %d unexpectedly succeeded on NXDOMAIN", i)
		}
	}
	// Only the first call triggers A+AAAA (2 queries); calls 2..8 hit the negative cache.
	if queries.Load() != 2 {
		t.Fatalf("queries = %d, want 2 (1 A + 1 AAAA, rest negative-cached)", queries.Load())
	}
	if snap := d.SnapshotResolveDNSHealth(time.Now()); snap == nil || snap.State != "closed" || snap.TotalFailure != 0 {
		t.Fatalf("NXDOMAIN should not trip circuit breaker: %+v", snap)
	}
	if stats := cp.adminResolveDNSStats(); stats.NegativeHits != 7 {
		t.Fatalf("NegativeHits = %d, want 7", stats.NegativeHits)
	}
}

func TestResolveDNSCircuitBreakerFailOpenAndAdminAPI(t *testing.T) {
	d := newNamedTestEndpointDialer("breaker-node")
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:6553"))
	group := newTestFixedOutboundGroup(d)
	cp := testDialControlPlane(group)
	cp.dialMode = consts.DialMode_DomainPlus

	var queries atomic.Int32
	prev := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		queries.Add(1)
		return nil, 0, fmt.Errorf("resolver unreachable: %w", netutils.ErrResolveTimeout)
	}
	defer func() { resolveIPViaDialer = prev }()

	for i := range consts.ResolveDNSCircuitFailureThreshold {
		_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   fmt.Sprintf("down-%d.example", i),
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		if err == nil {
			t.Fatalf("pre-threshold call %d unexpectedly succeeded", i)
		}
	}

	callsBeforeFailOpen := queries.Load()
	for i := range 3 {
		res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   fmt.Sprintf("failopen-%d.example", i),
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		if err != nil {
			t.Fatalf("fail-open call %d error = %v, want nil", i, err)
		}
		if res.DialTarget != fmt.Sprintf("failopen-%d.example:443", i) || res.IsDialIp || res.ResolveDNSPinned {
			t.Fatalf("fail-open call %d DialTarget=(%q, ip=%v, pinned=%v)", i, res.DialTarget, res.IsDialIp, res.ResolveDNSPinned)
		}
	}
	if queries.Load() != callsBeforeFailOpen {
		t.Fatalf("open circuit still dispatched DNS queries (%d -> %d)", callsBeforeFailOpen, queries.Load())
	}

	metrics := cp.AdminMetricsSnapshot()
	if metrics.ResolveDNS == nil {
		t.Fatal("expected AdminMetricsSnapshot.ResolveDNS to be populated")
	}
	if metrics.ResolveDNS.FailOpen != 3 || metrics.ResolveDNS.Timeouts != uint64(consts.ResolveDNSCircuitFailureThreshold) {
		t.Fatalf("metrics.ResolveDNS = %+v", metrics.ResolveDNS)
	}
	groups := cp.AdminGroups()
	if len(groups) != 1 || len(groups[0].Members) != 1 || groups[0].Members[0].ResolveDNS == nil {
		t.Fatalf("unexpected AdminGroups resolve_dns: %+v", groups)
	}
	rdns := groups[0].Members[0].ResolveDNS
	if rdns.State != "open" || rdns.TotalFailOpen != 3 || rdns.Server != "127.0.0.2:6553" {
		t.Fatalf("member ResolveDNS = %+v", rdns)
	}
}
