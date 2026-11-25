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
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type scriptedPeerPacketRead struct {
	data []byte
	from netip.AddrPort
	peer netip.AddrPort
	err  error
}

type peerTrackingPacketConn struct {
	reads      chan scriptedPeerPacketRead
	closeCh    chan struct{}
	closeOnce  sync.Once
	writeMu    sync.Mutex
	writeAddrs []string
	writeCh    chan string
}

func newPeerTrackingPacketConn() *peerTrackingPacketConn {
	return &peerTrackingPacketConn{
		reads:   make(chan scriptedPeerPacketRead, 16),
		closeCh: make(chan struct{}),
		writeCh: make(chan string, 16),
	}
}

func (c *peerTrackingPacketConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *peerTrackingPacketConn) Write(_ []byte) (int, error) {
	return 0, netproxy.UnsupportedTunnelTypeError
}
func (c *peerTrackingPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *peerTrackingPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *peerTrackingPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *peerTrackingPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	return nil
}

func (c *peerTrackingPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n, from, _, err := c.ReadFromWithPeer(p)
	return n, from, err
}

func (c *peerTrackingPacketConn) ReadFromWithPeer(p []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	select {
	case <-c.closeCh:
		return 0, netip.AddrPort{}, netip.AddrPort{}, io.EOF
	case r := <-c.reads:
		if r.err != nil {
			return 0, netip.AddrPort{}, netip.AddrPort{}, r.err
		}
		n := copy(p, r.data)
		return n, r.from, r.peer, nil
	}
}

func (c *peerTrackingPacketConn) WriteTo(b []byte, addr string) (int, error) {
	c.writeMu.Lock()
	c.writeAddrs = append(c.writeAddrs, addr)
	c.writeMu.Unlock()
	select {
	case c.writeCh <- addr:
	default:
	}
	return len(b), nil
}

func (c *peerTrackingPacketConn) recordedWriteAddrs() []string {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	out := make([]string, len(c.writeAddrs))
	copy(out, c.writeAddrs)
	return out
}

type peerTrackingReceiverPacketConn struct {
	*peerTrackingPacketConn
	mu      sync.Mutex
	handler netproxy.PacketReceiveHandler
}

func newPeerTrackingReceiverPacketConn() *peerTrackingReceiverPacketConn {
	return &peerTrackingReceiverPacketConn{
		peerTrackingPacketConn: newPeerTrackingPacketConn(),
	}
}

func (c *peerTrackingReceiverPacketConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	c.mu.Lock()
	c.handler = handler
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.handler = nil
		c.mu.Unlock()
	}, true
}

func (c *peerTrackingReceiverPacketConn) deliver(data []byte, from, peer netip.AddrPort) bool {
	c.mu.Lock()
	h := c.handler
	c.mu.Unlock()
	if h == nil {
		return false
	}
	pkt := netproxy.NewReceivedPacket(data, from, nil, func() {})
	pkt.Peer = peer
	return h(pkt)
}

func TestResolveDNSExplicitConfigAlwaysResolvesSynchronously(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	anyDialer, err := componentdialer.NewFromLinkContext(context.Background(), &componentdialer.GlobalOption{
		Log:           logger,
		CheckInterval: time.Minute,
	}, componentdialer.InstanceOption{DisableCheck: true}, "anytls://pass@203.0.113.1:443", "")
	if err != nil {
		t.Fatalf("NewFromLinkContext(anytls): %v", err)
	}
	defer func() { _ = anyDialer.Close() }()
	if !anyDialer.PinsUDPSessionTarget() {
		t.Fatal("anytls dialer PinsUDPSessionTarget() = false, want true")
	}
	anyDialer.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))

	ssConn := newPeerTrackingPacketConn()
	defer func() { _ = ssConn.Close() }()
	ssDialer, _ := newCountingProxyEndpointDialer("shadowsocks", "203.0.113.2:34564", ssConn)
	defer func() { _ = ssDialer.Close() }()
	ssDialer.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))

	socksConn := newPeerTrackingPacketConn()
	defer func() { _ = socksConn.Close() }()
	socksDialer, _ := newCountingProxyEndpointDialer("socks5", "203.0.113.3:1080", socksConn)
	defer func() { _ = socksDialer.Close() }()
	socksDialer.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))

	for _, tc := range []struct {
		name string
		d    *componentdialer.Dialer
	}{
		{name: "anytls", d: anyDialer},
		{name: "shadowsocks", d: ssDialer},
		{name: "socks5", d: socksDialer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := testDialControlPlane(newTestFixedOutboundGroup(tc.d))
			cp.dialMode = consts.DialMode_DomainPlus

			var queries atomic.Int32
			prev := resolveIPViaDialer
			resolveIPViaDialer = func(ctx context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, typ uint16, _ string) ([]netip.Addr, time.Duration, error) {
				queries.Add(1)
				if typ == dnsmessage.TypeA {
					return []netip.Addr{netip.MustParseAddr("198.51.100.88")}, time.Minute, nil
				}
				return nil, 0, nil
			}
			defer func() { resolveIPViaDialer = prev }()

			res1, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
				Outbound: consts.OutboundUserDefinedMin,
				Domain:   "strict-" + tc.name + ".example",
				Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
				Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
				Network:  "udp",
			})
			if err != nil {
				t.Fatalf("cold chooseProxyDialer: %v", err)
			}
			// Explicit resolve_dns must pin packet 1 to the configured resolver's IP.
			if res1.DialTarget != "198.51.100.88:443" || !res1.IsDialIp || !res1.ResolveDNSPinned || res1.PassiveReplyPin {
				t.Fatalf("cold res = (%q, dialIP=%v, pinned=%v, passive=%v)", res1.DialTarget, res1.IsDialIp, res1.ResolveDNSPinned, res1.PassiveReplyPin)
			}
			if queries.Load() == 0 {
				t.Fatal("explicit resolve_dns did not query configured DNS on cold miss")
			}

			// Warm flow reuses the cached IP with zero extra DNS queries.
			queriesBeforeHit := queries.Load()
			res2, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
				Outbound: consts.OutboundUserDefinedMin,
				Domain:   "strict-" + tc.name + ".example",
				Src:      netip.MustParseAddrPort("192.0.2.10:40001"),
				Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
				Network:  "udp",
			})
			if err != nil {
				t.Fatalf("warm chooseProxyDialer: %v", err)
			}
			if res2.DialTarget != "198.51.100.88:443" || !res2.IsDialIp || !res2.ResolveDNSPinned {
				t.Fatalf("warm res = (%q, dialIP=%v, pinned=%v)", res2.DialTarget, res2.IsDialIp, res2.ResolveDNSPinned)
			}
			if queries.Load() != queriesBeforeHit {
				t.Fatalf("warm cache hit dispatched extra DNS query (%d -> %d)", queriesBeforeHit, queries.Load())
			}
		})
	}
}

func TestResolveDNSUnconfiguredUsesPassiveReplyPinFastPath(t *testing.T) {
	t.Run("ReadLoopWithPeer", func(t *testing.T) {
		conn := newPeerTrackingPacketConn()
		defer func() { _ = conn.Close() }()
		d, _ := newCountingProxyEndpointDialer("shadowsocks", "203.0.113.2:34564", conn)
		defer func() { _ = d.Close() }()
		if d.PinsUDPSessionTarget() {
			t.Fatal("shadowsocks dialer PinsUDPSessionTarget() = true, want false")
		}
		if !isPassiveReplyPinProtocol(d) {
			t.Fatal("isPassiveReplyPinProtocol(shadowsocks) = false, want true")
		}
		// Intentionally do NOT configure resolve_dns on d.

		fakeStore, fakeV4 := newTestFakeIPStore(t, "ss-passive.example")

		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		cp.dialMode = consts.DialMode_DomainPlus
		cp.routingMatcher = testFakeIPMatcher(t, "fallback: proxy", []string{"proxy"})
		attachFakeIPStore(cp, fakeStore)

		src := netip.MustParseAddrPort("192.0.2.10:40000")
		dst := netip.AddrPortFrom(fakeV4, 443)
		res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "ss-passive.example",
			Src:      src,
			Dest:     dst,
			Network:  "udp",
		})
		if err != nil {
			t.Fatalf("chooseProxyDialer: %v", err)
		}
		if res.DialTarget != "ss-passive.example:443" || res.IsDialIp || res.ResolveDNSPinned || !res.PassiveReplyPin || res.ResolveDNSPinKey != "" {
			t.Fatalf("res = %+v", res)
		}

		pool := NewUdpEndpointPool()
		defer pool.Reset()

		replies := make(chan netip.AddrPort, 8)
		key := UdpEndpointKey{Src: src, Dst: dst}
		ue, isNew, err := pool.GetOrCreate(key, &UdpEndpointOptions{
			Handler: func(_ *UdpEndpoint, _ []byte, from netip.AddrPort) error {
				replies <- from
				return nil
			},
			GetDialOption: func(context.Context) (*DialOption, error) {
				return &DialOption{
					PassiveReplyPin:    res.PassiveReplyPin,
					ResolveDNSPinKey:   res.ResolveDNSPinKey,
					ResolveDNSPinCache: &cp.resolveDNSPins,
					Target:             res.DialTarget,
					Dialer:             res.Dialer,
					Outbound:           res.Outbound,
					Network:            res.Network,
					NetworkType:        res.SelectionNetworkTypeObj,
					SniffedDomain:      res.SniffedDomain,
					FakeIPStore:        fakeStore,
				}, nil
			},
		})
		if err != nil || !isNew {
			t.Fatalf("GetOrCreate = (%v, %v, %v)", ue, isNew, err)
		}
		defer func() { _ = ue.Close() }()

		// Packet 1 dials using domain:port (0 RTT).
		if _, err := ue.WriteTo([]byte("pkt1"), ue.dialTargetForWrite(dst)); err != nil {
			t.Fatalf("WriteTo pkt1: %v", err)
		}
		if addrs := conn.recordedWriteAddrs(); len(addrs) != 1 || addrs[0] != "ss-passive.example:443" {
			t.Fatalf("packet 1 write addrs = %v, want [ss-passive.example:443]", addrs)
		}

		// Invalid peers must not pin passivePin: loopback, FakeIP, wrong port.
		conn.reads <- scriptedPeerPacketRead{data: []byte("loop"), from: dst, peer: netip.MustParseAddrPort("127.0.0.1:443")}
		conn.reads <- scriptedPeerPacketRead{data: []byte("fake"), from: dst, peer: netip.AddrPortFrom(fakeV4, 443)}
		conn.reads <- scriptedPeerPacketRead{data: []byte("port"), from: dst, peer: netip.MustParseAddrPort("203.0.113.55:80")}
		for range 3 {
			select {
			case <-replies:
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for invalid-peer test reads")
			}
		}
		if ue.passivePin == nil || ue.passivePin.pinned.Load() != nil {
			t.Fatalf("invalid peers unexpectedly set passivePin: %+v", ue.passivePin)
		}

		// Valid decrypted peer IP pins the endpoint without polluting resolveDNSPins cache.
		validPeer := netip.MustParseAddrPort("203.0.113.55:443")
		conn.reads <- scriptedPeerPacketRead{data: []byte("ok"), from: dst, peer: validPeer}
		select {
		case <-replies:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for valid reply")
		}
		waitForCondition(t, time.Second, "endpoint did not passively pin reply peer IP", func() bool {
			return ue.activeDialTarget() == "203.0.113.55:443"
		})

		// Another valid peer later does not overwrite the locked pin.
		conn.reads <- scriptedPeerPacketRead{data: []byte("second-ip"), from: dst, peer: netip.MustParseAddrPort("203.0.113.66:443")}
		select {
		case <-replies:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for second valid reply")
		}
		if got := ue.activeDialTarget(); got != "203.0.113.55:443" {
			t.Fatalf("activeDialTarget changed to %q, want locked 203.0.113.55:443", got)
		}

		if stats := cp.adminResolveDNSStats(); stats.PassivePins != 1 || stats.CacheEntries != 0 {
			t.Fatalf("stats = %+v, want PassivePins=1 CacheEntries=0", stats)
		}

		// Packet 2 uses the passively pinned IP directly.
		if _, err := ue.WriteTo([]byte("pkt2"), ue.dialTargetForWrite(dst)); err != nil {
			t.Fatalf("WriteTo pkt2: %v", err)
		}
		addrs := conn.recordedWriteAddrs()
		if len(addrs) != 2 || addrs[1] != "203.0.113.55:443" {
			t.Fatalf("write addrs = %v, want [ss-passive.example:443 203.0.113.55:443]", addrs)
		}
	})

	t.Run("PacketReceiverAndConcurrentRace", func(t *testing.T) {
		conn := newPeerTrackingReceiverPacketConn()
		defer func() { _ = conn.Close() }()
		d, _ := newCountingProxyEndpointDialer("socks5", "203.0.113.3:1080", conn)
		defer func() { _ = d.Close() }()
		if !isPassiveReplyPinProtocol(d) {
			t.Fatal("isPassiveReplyPinProtocol(socks5) = false, want true")
		}

		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		pool := NewUdpEndpointPool()
		defer pool.Reset()

		src := netip.MustParseAddrPort("192.0.2.11:40000")
		dst := netip.MustParseAddrPort("198.51.100.30:443")
		key := UdpEndpointKey{Src: src, Dst: dst}

		var delivered atomic.Int32
		ue, _, err := pool.GetOrCreate(key, &UdpEndpointOptions{
			Handler: func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
				delivered.Add(1)
				return nil
			},
			GetDialOption: func(context.Context) (*DialOption, error) {
				return &DialOption{
					PassiveReplyPin:    true,
					ResolveDNSPinCache: &cp.resolveDNSPins,
					Target:             "socks-passive.example:443",
					Dialer:             d,
					Outbound:           cp.outbounds[consts.OutboundUserDefinedMin],
					Network:            "udp",
					SniffedDomain:      "socks-passive.example",
				}, nil
			},
		})
		if err != nil {
			t.Fatalf("GetOrCreate: %v", err)
		}
		defer func() { _ = ue.Close() }()

		peer1 := netip.MustParseAddrPort("203.0.113.77:443")
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = conn.deliver([]byte("reply"), dst, peer1)
				_ = ue.dialTargetForWrite(dst)
			}()
		}
		wg.Wait()

		waitForCondition(t, time.Second, "PacketReceiver did not pin passive reply peer cleanly", func() bool {
			return delivered.Load() == 8 && ue.activeDialTarget() == "203.0.113.77:443"
		})
		if stats := cp.adminResolveDNSStats(); stats.PassivePins != 1 {
			t.Fatalf("PassivePins = %d, want 1", stats.PassivePins)
		}
	})

	t.Run("SkipsInboundAndEnforceMode", func(t *testing.T) {
		ssConn := newPeerTrackingPacketConn()
		defer func() { _ = ssConn.Close() }()
		d, _ := newCountingProxyEndpointDialer("shadowsocks", "203.0.113.2:34564", ssConn)
		defer func() { _ = d.Close() }()

		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		cp.dialMode = consts.DialMode_DomainPlus

		// Inbound UDP (e.g. SOCKS5 inbound) does not attach passivePin.
		resInbound, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Inbound:  1,
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "inbound-no-passive.example",
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		if err != nil || resInbound.PassiveReplyPin {
			t.Fatalf("inbound UDP res = (%+v, %v), want PassiveReplyPin=false", resInbound, err)
		}

		// Enforce rebuild mode also skips passivePin.
		cp.udpReplyDrought = newUDPReplyDroughtObserver(config.UDPReplyDroughtPolicy{
			Observe:      true,
			Enforce:      true,
			RequestReply: true,
			Group:        "game",
			Peers:        []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:443")},
		})
		defer func() { _ = cp.udpReplyDrought.Close() }()

		resEnforce, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "enforce-no-passive.example",
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		if err != nil || resEnforce.PassiveReplyPin {
			t.Fatalf("enforce mode res = (%+v, %v), want PassiveReplyPin=false", resEnforce, err)
		}
	})
}

func TestResolveDNSSharedSingleflightFailureCountsOnce(t *testing.T) {
	d := newNamedTestEndpointDialer("sf-once")
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:6553"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32

	prev := resolveIPViaDialer
	resolveIPViaDialer = func(_ context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, _ uint16, _ string) ([]netip.Addr, time.Duration, error) {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return nil, 0, fmt.Errorf("upstream timeout: %w", netutils.ErrResolveTimeout)
	}
	defer func() { resolveIPViaDialer = prev }()

	const waiters = consts.ResolveDNSCircuitFailureThreshold + 2
	var wg sync.WaitGroup
	var errCount atomic.Int32
	for i := range waiters {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
				Outbound: consts.OutboundUserDefinedMin,
				Domain:   "shared-fail.example",
				Src:      netip.MustParseAddrPort(fmt.Sprintf("192.0.2.10:%d", 40000+idx)),
				Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
				Network:  "udp",
			})
			if err != nil {
				errCount.Add(1)
			}
		}(i)
	}

	<-started
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()

	if errCount.Load() != int32(waiters) {
		t.Fatalf("errCount = %d, want %d", errCount.Load(), waiters)
	}
	snap := d.SnapshotResolveDNSHealth(time.Now())
	if snap == nil || snap.State != "closed" || snap.TotalFailure != 1 || snap.ConsecutiveFailures != 1 {
		t.Fatalf("one shared singleflight failure should record 1 failure and stay closed: %+v", snap)
	}
	if stats := cp.adminResolveDNSStats(); stats.Timeouts != 1 {
		t.Fatalf("Timeouts = %d, want 1", stats.Timeouts)
	}
}

func TestResolveDNSHalfOpenNotWedgedByStaleHit(t *testing.T) {
	d := newNamedTestEndpointDialer("stale-halfopen")
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	past := time.Now().Add(-consts.ResolveDNSCircuitOpenDuration - time.Second)
	for range consts.ResolveDNSCircuitFailureThreshold {
		d.RecordResolveDNSFailure(context.DeadlineExceeded, past)
	}

	key := resolveDNSResultKey(&proxyDialResult{Dialer: d, Mark: cp.soMarkFromDae}, "stale-lock.example", false)
	cp.resolveDNSPins.mu.Lock()
	cp.resolveDNSPins.entries = map[string]proxyResolveDNSPin{
		key: {
			ip:         netip.MustParseAddr("198.51.100.44"),
			expires:    time.Now().Add(-time.Second),
			staleUntil: time.Now().Add(time.Minute),
			refreshing: true,
		},
	}
	cp.resolveDNSPins.mu.Unlock()

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "stale-lock.example",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil || res.DialTarget != "198.51.100.44:443" {
		t.Fatalf("stale hit res=(%v, %v)", res, err)
	}

	if allow, halfOpen := d.AllowResolveDNS(time.Now()); !allow || !halfOpen {
		t.Fatalf("AllowResolveDNS after already-refreshing stale hit = (%v, %v), want (true, true)", allow, halfOpen)
	}
	d.CancelResolveDNSHalfOpen()
}

func TestResolveDNSPrefetchConsumedCountsInFlightJoin(t *testing.T) {
	d := newNamedTestEndpointDialer("prefetch-join")
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	prev := resolveIPViaDialer
	resolveIPViaDialer = func(_ context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, typ uint16, _ string) ([]netip.Addr, time.Duration, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		if typ == dnsmessage.TypeA {
			return []netip.Addr{netip.MustParseAddr("198.51.100.33")}, time.Minute, nil
		}
		return nil, 0, nil
	}
	defer func() { resolveIPViaDialer = prev }()

	cp.prefetchProxyResolveDNSForResult(&proxyDialResult{
		OutboundIndex: consts.OutboundUserDefinedMin,
		Dialer:        d,
		Outbound:      cp.outbounds[consts.OutboundUserDefinedMin],
	}, "inflight-join.example", false)

	<-started
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(release)
	}()

	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "inflight-join.example",
		Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil || res.DialTarget != "198.51.100.33:443" {
		t.Fatalf("chooseProxyDialer = (%+v, %v)", res, err)
	}
	if stats := cp.adminResolveDNSStats(); stats.PrefetchStarted != 1 || stats.PrefetchConsumed != 1 {
		t.Fatalf("prefetch stats = %+v, want started=1 consumed=1", stats)
	}
}

func TestResolveDNSHalfOpenSlotHeldUntilSharedProbeCompletes(t *testing.T) {
	d := newNamedTestEndpointDialer("halfopen-lifetime")
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	cp.dialMode = consts.DialMode_DomainPlus

	past := time.Now().Add(-consts.ResolveDNSCircuitOpenDuration - time.Second)
	for range consts.ResolveDNSCircuitFailureThreshold {
		d.RecordResolveDNSFailure(context.DeadlineExceeded, past)
	}

	probeStarted := make(chan struct{}, 2)
	releaseProbe := make(chan struct{})
	var probeCalls atomic.Int32

	prev := resolveIPViaDialer
	resolveIPViaDialer = func(_ context.Context, _ netproxy.Dialer, _ netip.AddrPort, host string, _ uint16, _ string) ([]netip.Addr, time.Duration, error) {
		probeCalls.Add(1)
		if host == "probe-a.example" {
			select {
			case probeStarted <- struct{}{}:
			default:
			}
			<-releaseProbe
			return nil, 0, &netutils.DnsRcodeError{Rcode: dnsmessage.RcodeNameError}
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.55")}, time.Minute, nil
	}
	defer func() { resolveIPViaDialer = prev }()

	ctx1, cancel1 := context.WithCancel(context.Background())
	err1Ch := make(chan error, 1)
	go func() {
		_, err := cp.chooseProxyDialer(ctx1, &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "probe-a.example",
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		err1Ch <- err
	}()
	<-probeStarted
	// Cancel waiter 1 while the shared probe is still in flight.
	cancel1()
	if err := <-err1Ch; err == nil {
		t.Fatal("expected waiter 1 cancellation error")
	}

	// While probe-a is still running, a different domain must fail open and NOT start a 2nd probe.
	callsBeforeB := probeCalls.Load()
	resB, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "probe-b.example",
		Src:      netip.MustParseAddrPort("192.0.2.10:40001"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil || resB.DialTarget != "probe-b.example:443" {
		t.Fatalf("probe-b while probe-a in flight = (%+v, %v), want fail-open", resB, err)
	}
	if probeCalls.Load() != callsBeforeB {
		t.Fatalf("second half-open probe launched concurrently (%d -> %d)", callsBeforeB, probeCalls.Load())
	}

	// Finish probe-a with NXDOMAIN; half-open slot must then release so probe-c can close circuit.
	close(releaseProbe)
	waitForCondition(t, 2*time.Second, "half-open slot did not release after NXDOMAIN probe finished", func() bool {
		allow, halfOpen := d.AllowResolveDNS(time.Now())
		if allow && halfOpen {
			d.CancelResolveDNSHalfOpen()
			return true
		}
		return false
	})

	resC, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "probe-c.example",
		Src:      netip.MustParseAddrPort("192.0.2.10:40002"),
		Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
		Network:  "udp",
	})
	if err != nil || resC.DialTarget != "198.51.100.55:443" {
		t.Fatalf("probe-c recovery = (%+v, %v)", resC, err)
	}
	if snap := d.SnapshotResolveDNSHealth(time.Now()); snap == nil || snap.State != "closed" {
		t.Fatalf("expected closed circuit after probe-c recovery, got %+v", snap)
	}
}

func TestResolveDNSUDPJoiningTCPPrefetchRecordsHealth(t *testing.T) {
	t.Run("failure_updates_health", func(t *testing.T) {
		d := newNamedTestEndpointDialer("prefetch-health-fail")
		d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:6553"))
		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		cp.dialMode = consts.DialMode_DomainPlus

		started := make(chan struct{}, 2)
		release := make(chan struct{})
		prev := resolveIPViaDialer
		resolveIPViaDialer = func(_ context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, _ uint16, _ string) ([]netip.Addr, time.Duration, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return nil, 0, fmt.Errorf("prefetch timeout: %w", netutils.ErrResolveTimeout)
		}
		defer func() { resolveIPViaDialer = prev }()

		cp.prefetchProxyResolveDNSForResult(&proxyDialResult{
			OutboundIndex: consts.OutboundUserDefinedMin,
			Dialer:        d,
			Outbound:      cp.outbounds[consts.OutboundUserDefinedMin],
		}, "prefetch-fail.example", false)

		<-started
		go func() {
			time.Sleep(20 * time.Millisecond)
			close(release)
		}()

		_, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "prefetch-fail.example",
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		if err == nil {
			t.Fatal("expected failure from joined prefetch")
		}
		snap := d.SnapshotResolveDNSHealth(time.Now())
		if snap == nil || snap.TotalFailure != 1 || snap.TotalTimeout != 1 {
			t.Fatalf("joined prefetch failure missed health accounting: %+v", snap)
		}
		if stats := cp.adminResolveDNSStats(); stats.Timeouts != 1 {
			t.Fatalf("Timeouts = %d, want 1", stats.Timeouts)
		}
	})

	t.Run("success_updates_health", func(t *testing.T) {
		d := newNamedTestEndpointDialer("prefetch-health-ok")
		d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.2:53"))
		cp := testDialControlPlane(newTestFixedOutboundGroup(d))
		cp.dialMode = consts.DialMode_DomainPlus

		started := make(chan struct{}, 2)
		release := make(chan struct{})
		prev := resolveIPViaDialer
		resolveIPViaDialer = func(_ context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, typ uint16, _ string) ([]netip.Addr, time.Duration, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			if typ == dnsmessage.TypeA {
				return []netip.Addr{netip.MustParseAddr("198.51.100.77")}, time.Minute, nil
			}
			return nil, 0, nil
		}
		defer func() { resolveIPViaDialer = prev }()

		cp.prefetchProxyResolveDNSForResult(&proxyDialResult{
			OutboundIndex: consts.OutboundUserDefinedMin,
			Dialer:        d,
			Outbound:      cp.outbounds[consts.OutboundUserDefinedMin],
		}, "prefetch-ok.example", false)

		<-started
		go func() {
			time.Sleep(20 * time.Millisecond)
			close(release)
		}()

		res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
			Outbound: consts.OutboundUserDefinedMin,
			Domain:   "prefetch-ok.example",
			Src:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Dest:     netip.MustParseAddrPort("198.51.100.20:443"),
			Network:  "udp",
		})
		if err != nil || res.DialTarget != "198.51.100.77:443" {
			t.Fatalf("chooseProxyDialer = (%+v, %v)", res, err)
		}
		snap := d.SnapshotResolveDNSHealth(time.Now())
		if snap == nil || snap.TotalSuccess != 1 {
			t.Fatalf("joined prefetch success missed health accounting: %+v", snap)
		}
	})
}
