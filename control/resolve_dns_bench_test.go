/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type benchMockDNSConn struct {
	reads   chan scriptedPacketRead
	closeCh chan struct{}
	closed  atomic.Bool
	answer  netip.Addr
}

func newBenchMockDNSConn(answer netip.Addr) *benchMockDNSConn {
	return &benchMockDNSConn{
		reads:   make(chan scriptedPacketRead, 256),
		closeCh: make(chan struct{}),
		answer:  answer,
	}
}

func (c *benchMockDNSConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *benchMockDNSConn) Write(_ []byte) (int, error) {
	return 0, netproxy.UnsupportedTunnelTypeError
}
func (c *benchMockDNSConn) SetDeadline(_ time.Time) error      { return nil }
func (c *benchMockDNSConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *benchMockDNSConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *benchMockDNSConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
	}
	return nil
}

func (c *benchMockDNSConn) WriteTo(b []byte, addr string) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	var req dnsmessage.Msg
	if err := req.Unpack(b); err != nil || len(req.Question) == 0 {
		return len(b), nil
	}
	resp := dnsmessage.Msg{}
	resp.SetReply(&req)
	if req.Question[0].Qtype == dnsmessage.TypeA && c.answer.Is4() {
		resp.Answer = []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: c.answer.AsSlice(),
			},
		}
	}
	raw, err := resp.Pack()
	if err != nil {
		return len(b), nil
	}
	from, _ := netip.ParseAddrPort(addr)
	select {
	case c.reads <- scriptedPacketRead{data: raw, from: from}:
	case <-c.closeCh:
	}
	return len(b), nil
}

func (c *benchMockDNSConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	select {
	case <-c.closeCh:
		return 0, netip.AddrPort{}, io.EOF
	case r := <-c.reads:
		n := copy(p, r.data)
		return n, r.from, nil
	}
}

type benchTimeoutDialer struct {
	dials atomic.Int32
}

func (d *benchTimeoutDialer) DialContext(ctx context.Context, _, _ string) (netproxy.Conn, error) {
	d.dials.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestResolveDNSLatencyAndPoolingBehavior(t *testing.T) {
	// 1. Timeout uses the short endpoint failure cache TTL.
	t.Run("TimeoutFailureCacheTTL", func(t *testing.T) {
		td := &benchTimeoutDialer{}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, _, err := netutils.ResolveNetipTTL(ctx, td, netip.MustParseAddrPort("127.0.0.2:53"), "resolve-timeout.example", dnsmessage.TypeA, "udp")
		ttl := udpEndpointCreateFailureTTL(err)
		t.Logf("RESOLVE_DNS_METRIC timeout_failure_ttl_ms=%d err=%q", ttl.Milliseconds(), err)
	})

	// 2. High-RTT node (180ms RTT) with 265ms A response adapts fallback delay and avoids firing a premature AAAA query.
	t.Run("HighRTTNodeQueryCount", func(t *testing.T) {
		d := newTestEndpointDialer()
		d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
		d.MustGetLatencies10(&componentdialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
		}).AppendLatency(180 * time.Millisecond)

		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		cp.dialMode = consts.DialMode_DomainPlus

		var queries atomic.Int32
		prev := resolveIPViaDialer
		resolveIPViaDialer = func(ctx context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, typ uint16, _ string) ([]netip.Addr, time.Duration, error) {
			queries.Add(1)
			if typ == dnsmessage.TypeA {
				select {
				case <-time.After(265 * time.Millisecond):
					return []netip.Addr{netip.MustParseAddr("198.51.100.77")}, time.Minute, nil
				case <-ctx.Done():
					return nil, 0, ctx.Err()
				}
			}
			return nil, 0, nil
		}
		defer func() { resolveIPViaDialer = prev }()

		t0 := time.Now()
		res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "us-node.example",
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		if err != nil {
			t.Fatalf("chooseProxyDialer: %v", err)
		}
		t.Logf("RESOLVE_DNS_METRIC us_180ms_queries=%d elapsed_ms=%d target=%s", queries.Load(), time.Since(t0).Milliseconds(), res.DialTarget)
	})

	// 3. Protocol cold-path: explicit resolve_dns stays synchronous across protocols,
	// while unconfigured SS/AnyTLS keep 0-RTT (SS enables passive reply pinning).
	t.Run("ProtocolColdPathAnyTLSAndSS", func(t *testing.T) {
		runProto := func(name string, withResolveDNS bool, makeDialer func() *componentdialer.Dialer) {
			d := makeDialer()
			defer func() { _ = d.Close() }()
			if withResolveDNS {
				d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
			}
			cp := testDialControlPlane(newTestFixedOutboundGroup(d))
			cp.dialMode = consts.DialMode_DomainPlus

			prev := resolveIPViaDialer
			resolveIPViaDialer = func(ctx context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, _ uint16, _ string) ([]netip.Addr, time.Duration, error) {
				select {
				case <-time.After(120 * time.Millisecond):
					return []netip.Addr{netip.MustParseAddr("198.51.100.88")}, time.Minute, nil
				case <-ctx.Done():
					return nil, 0, ctx.Err()
				}
			}
			defer func() { resolveIPViaDialer = prev }()

			t0 := time.Now()
			res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
				Outbound: consts.OutboundUserDefinedMin,
				Domain:   "cold-" + name + ".example",
				Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
				Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
				Network:  "udp",
			})
			elapsed := time.Since(t0)
			if err != nil {
				t.Fatalf("%s chooseProxyDialer: %v", name, err)
			}
			t.Logf("RESOLVE_DNS_METRIC proto=%s resolve_dns=%v cold_wait_ms=%d target=%s is_dial_ip=%v passive=%v", name, withResolveDNS, elapsed.Milliseconds(), res.DialTarget, res.IsDialIp, res.PassiveReplyPin)
		}

		runProto("anytls-explicit", true, func() *componentdialer.Dialer {
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			d, err := componentdialer.NewFromLinkContext(context.Background(), &componentdialer.GlobalOption{
				Log:           logger,
				CheckInterval: time.Minute,
			}, componentdialer.InstanceOption{DisableCheck: true}, "anytls://pass@203.0.113.1:443", "")
			if err != nil {
				t.Fatalf("NewFromLinkContext(anytls): %v", err)
			}
			return d
		})
		runProto("shadowsocks-unconfigured", false, func() *componentdialer.Dialer {
			d, _ := newCountingProxyEndpointDialer("shadowsocks", "203.0.113.2:34564", newBenchMockDNSConn(netip.MustParseAddr("198.51.100.88")))
			return d
		})
		runProto("hysteria2-explicit", true, func() *componentdialer.Dialer {
			d, _ := newCountingProxyEndpointDialer("hysteria2", "203.0.113.3:443", newBenchMockDNSConn(netip.MustParseAddr("198.51.100.88")))
			return d
		})
	})

	// 4. 50 concurrent cold misses over real netutils path (measures proxy UDP DialContext calls).
	t.Run("Concurrent50QueriesProxyDials", func(t *testing.T) {
		var connsMu sync.Mutex
		var conns []*benchMockDNSConn
		d, underlay := newFactoryProxyEndpointDialer("hysteria2", "203.0.113.4:443", func() netproxy.Conn {
			c := newBenchMockDNSConn(netip.MustParseAddr("198.51.100.99"))
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			return c
		})
		defer func() {
			_ = d.Close()
			connsMu.Lock()
			for _, c := range conns {
				_ = c.Close()
			}
			connsMu.Unlock()
		}()
		d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		cp.dialMode = consts.DialMode_DomainPlus

		const n = 50
		t0 := time.Now()
		var wg sync.WaitGroup
		var okCount atomic.Int32
		for i := range n {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
					Outbound: consts.OutboundUserDefinedMin,
					Domain:   fmt.Sprintf("conc-%d.example", idx),
					Src:      netip.MustParseAddrPort(fmt.Sprintf("192.0.2.10:%d", 40000+idx)),
					Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
					Network:  "udp",
				})
				if err == nil && res != nil {
					okCount.Add(1)
				}
			}(i)
		}
		wg.Wait()
		t.Logf("RESOLVE_DNS_METRIC concurrent_50 ok=%d proxy_udp_dials=%d elapsed_ms=%d", okCount.Load(), underlay.calls.Load(), time.Since(t0).Milliseconds())
	})

	// 5. Sustained DNS outage (20 sequential requests against failing resolver).
	t.Run("SustainedOutageResilience", func(t *testing.T) {
		d, _ := newCountingProxyEndpointDialer("hysteria2", "203.0.113.5:443", newBenchMockDNSConn(netip.Addr{}))
		d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:6553"))
		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		cp.dialMode = consts.DialMode_DomainPlus

		prev := resolveIPViaDialer
		resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
			return nil, 0, fmt.Errorf("resolve failed: %w", netutils.ErrResolveTimeout)
		}
		defer func() { resolveIPViaDialer = prev }()

		const total = 20
		var succeeded, failed int
		for i := range total {
			res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
				Outbound: consts.OutboundUserDefinedMin,
				Domain:   fmt.Sprintf("outage-%d.example", i),
				Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
				Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
				Network:  "udp",
			})
			if err == nil && res != nil {
				succeeded++
			} else {
				failed++
			}
		}
		t.Logf("RESOLVE_DNS_METRIC outage_20 succeeded=%d failed=%d", succeeded, failed)
	})
}

func BenchmarkResolveDNS50ConcurrentMisses(b *testing.B) {
	b.ReportAllocs()
	var totalDials int64
	for i := 0; i < b.N; i++ {
		var connsMu sync.Mutex
		var conns []*benchMockDNSConn
		d, underlay := newFactoryProxyEndpointDialer("hysteria2", "203.0.113.4:443", func() netproxy.Conn {
			c := newBenchMockDNSConn(netip.MustParseAddr("198.51.100.99"))
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			return c
		})
		d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		cp.dialMode = consts.DialMode_DomainPlus

		var wg sync.WaitGroup
		for j := range 50 {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_, _ = cp.chooseProxyDialer(context.Background(), &proxyDialParam{
					Outbound: consts.OutboundUserDefinedMin,
					Domain:   fmt.Sprintf("bench-%d.example", idx),
					Src:      netip.MustParseAddrPort(fmt.Sprintf("192.0.2.10:%d", 40000+idx)),
					Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
					Network:  "udp",
				})
			}(j)
		}
		wg.Wait()
		totalDials += int64(underlay.calls.Load())
		_ = d.Close()
		connsMu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		connsMu.Unlock()
	}
	b.ReportMetric(float64(totalDials)/float64(b.N), "dials/op")
}

func BenchmarkResolveDNSCacheHit(b *testing.B) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	prev := resolveIPViaDialer
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.50")}, time.Minute, nil
	}
	defer func() { resolveIPViaDialer = prev }()

	param := &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "hot-cache.example",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	}
	if _, err := cp.chooseProxyDialer(context.Background(), param); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cp.chooseProxyDialer(context.Background(), param); err != nil {
			b.Fatal(err)
		}
	}
}
