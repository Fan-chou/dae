package control

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

func TestResolveDNSFallbackBeforeTotalDeadline(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	old := resolveIPViaDialer
	defer func() { resolveIPViaDialer = old }()
	cancelled := make(chan struct{})
	resolveIPViaDialer = func(ctx context.Context, _ netproxy.Dialer, _ netip.AddrPort, _ string, typ uint16, _ string) ([]netip.Addr, time.Duration, error) {
		if typ == dnsmessage.TypeA {
			<-ctx.Done()
			close(cancelled)
			return nil, 0, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("2001:db8::10")}, time.Minute, nil
	}
	start := time.Now()
	ip, _, err := cp.lookupProxyResolveDNSUncached(&proxyDialResult{Dialer: d}, "quic.example", false)
	if err != nil || !ip.Is6() {
		t.Fatalf("fallback = %s, %v", ip, err)
	}
	if elapsed := time.Since(start); elapsed >= consts.ResolveDNSTimeout {
		t.Fatalf("fallback consumed total budget: %s", elapsed)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("losing query not cancelled")
	}
}

func TestResolveDNSPrefetchPartialRouting(t *testing.T) {
	for _, tc := range []struct {
		name, rules string
		fake, ok    bool
		out         consts.OutboundIndex
	}{
		{"domain", "domain(full: quic.example) -> proxy\nfallback: direct", false, true, consts.OutboundUserDefinedMin},
		{"hypothetical443", "dport(443) -> proxy\nfallback: direct", false, true, consts.OutboundUserDefinedMin},
		{"unknown_source_port", "sport(40000) -> direct\nfallback: proxy", false, false, 0},
		{"unknown_dscp", "dscp(8) -> direct\nfallback: proxy", false, false, 0},
		{"unknown_ip", "ip(203.0.113.0/24) -> direct\nfallback: proxy", false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testFakeIPMatcher(t, tc.rules, []string{"proxy"})
			out, _, _, ok := m.resolveDNSPrefetchRoute("quic.example", false, netip.MustParseAddr("192.0.2.10"), [6]uint8{}, tc.fake)
			if ok != tc.ok || (ok && out != tc.out) {
				t.Fatalf("out=%v known=%v", out, ok)
			}
		})
	}
}

func TestResolveDNSCandidateCacheCapacity(t *testing.T) {
	var c proxyResolveDNSPinCache
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.10")
	for i := 0; i < resolveDNSPinCacheMax; i++ {
		c.store(fmt.Sprint(i), ip, now, time.Minute)
	}
	c.store("0", ip, now, 2*time.Minute)
	if len(c.entries) != resolveDNSPinCacheMax {
		t.Fatal("update evicted cache")
	}
	c.storeCandidate("spec", ip, now, time.Minute, true)
	if _, ok := c.entries["spec"]; ok {
		t.Fatal("speculation evicted fresh demand")
	}
	c.store("new", ip, now, time.Minute)
	if len(c.entries) != resolveDNSPinCacheMax {
		t.Fatal("insertion flushed cache")
	}
	if _, ok := c.entries["0"]; !ok {
		t.Fatal("later-expiring hot entry was evicted")
	}
}

func TestResolveDNSRecoveryKeepsTargetAndBoundsIdentity(t *testing.T) {
	d := newTestEndpointDialer()
	d.Property().Address = "proxy.example:443"
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	var store resolveDNSRecoveryStore
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000"), Dst: netip.MustParseAddrPort("28.0.0.1:443")}
	initial := PacketSnifferKey{LAddr: key.Src, RAddr: key.Dst, DCIDLen: 8, DCID: [20]byte{1}}
	route := UdpRouteBinding{Outbound: consts.OutboundUserDefinedMin}
	ue := &UdpEndpoint{Dialer: d, poolKey: key, DialTarget: "203.0.113.10:443", SniffedDomain: "quic.example", flowRouteBinding: route, resolveDNSState: &udpResolveDNSState{initial: initial, id: 1}}
	ue.hasSent.Store(true)
	store.save(ue)
	r, ok := store.lookup(key, PacketSnifferKey{}, false)
	if !ok {
		t.Fatal("missing recovery")
	}
	res := &proxyDialResult{Dialer: d, OutboundIndex: route.Outbound, SniffedDomain: "quic.example", DialTarget: "203.0.113.20:443"}
	// A replacement proxy without resolve_dns must still inherit the old pin.
	if !cp.inheritResolveDNSTarget(&proxyDialParam{Network: "udp", ResolveDNSRecovery: &r}, res) || res.DialTarget != ue.DialTarget {
		t.Fatal("lost target")
	}
	if err := cp.ensureUdpDialTargetIP(context.Background(), &proxyDialParam{Network: "udp", Dest: key.Dst}, res); err != nil || res.DialTarget != ue.DialTarget {
		t.Fatal("inherited pin rewritten to domain")
	}
	changed := r
	changed.route.Mark++
	if cp.inheritResolveDNSTarget(&proxyDialParam{Network: "udp", ResolveDNSRecovery: &changed}, res) {
		t.Fatal("route change inherited")
	}
	newInitial := initial
	newInitial.DCID[0]++
	if _, ok := store.lookup(key, newInitial, true); ok {
		t.Fatal("new QUIC Initial inherited")
	}
	if _, ok := store.lookup(key, initial, false); ok {
		t.Fatal("invalidated record survived")
	}
}

func TestResolveDNSRecoveryActualEndpointRetire(t *testing.T) {
	conn := &scriptedPacketConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
	d := newTestEndpointDialer(conn)
	d.Property().Address = "proxy.example:443"
	p := NewUdpEndpointPool()
	t.Cleanup(p.Close)
	var store resolveDNSRecoveryStore
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000"), Dst: netip.MustParseAddrPort("198.51.100.10:443")}
	ue, _, err := p.GetOrCreate(key, &UdpEndpointOptions{Handler: func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil }, GetDialOption: func(context.Context) (*DialOption, error) {
		return &DialOption{Dialer: d, Target: "203.0.113.10:443", Network: "udp", ResolveDNSPinned: true, SniffedDomain: "quic.example"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	ue.resolveDNSState.store = &store
	if _, err := ue.WriteTo([]byte("packet"), ue.dialTargetForWrite(key.Dst)); err != nil {
		t.Fatal(err)
	}
	ue.retire()
	if r, ok := store.lookup(key, PacketSnifferKey{}, false); !ok || r.target.String() != "203.0.113.10:443" {
		t.Fatal("retire did not publish original target")
	}
}

func TestResolveDNSPrefetchBudgetDoesNotBlockDemand(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	for _, k := range []string{"background1", "background2"} {
		if !cp.resolveDNSPins.startBackground(k, d) {
			t.Fatal("admission")
		}
	}
	defer cp.resolveDNSPins.finishBackground("background1", d)
	defer cp.resolveDNSPins.finishBackground("background2", d)
	if cp.resolveDNSPins.startBackground("background3", d) {
		t.Fatal("budget exceeded")
	}
	old := resolveIPViaDialer
	defer func() { resolveIPViaDialer = old }()
	var calls atomic.Int32
	resolveIPViaDialer = func(context.Context, netproxy.Dialer, netip.AddrPort, string, uint16, string) ([]netip.Addr, time.Duration, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, time.Minute, nil
	}
	_, err := cp.lookupProxyResolveDNSPin(context.Background(), &proxyDialResult{Dialer: d}, "demand.example", false)
	if err != nil || calls.Load() != 1 {
		t.Fatalf("demand blocked: %v calls=%d", err, calls.Load())
	}
}

func TestResolveDNSRecoveryAdministrativeCloseDoesNotRestore(t *testing.T) {
	d := newTestEndpointDialer()
	d.Property().Address = "proxy.example:443"
	var s resolveDNSRecoveryStore
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000"), Dst: netip.MustParseAddrPort("198.51.100.10:443")}
	old := &UdpEndpoint{Dialer: d, poolKey: key, DialTarget: "203.0.113.10:443", SniffedDomain: "quic.example", resolveDNSState: &udpResolveDNSState{id: 1}}
	old.hasSent.Store(true)
	s.save(old)
	active := &UdpEndpoint{Dialer: d, poolKey: key, resolveDNSState: &udpResolveDNSState{store: &s, id: 2}}
	if err := active.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.lookup(key, PacketSnifferKey{}, false); ok {
		t.Fatal("administrative close retained old recovery record")
	}
}

func TestResolveDNSPrefetchNoResolveUsesKnownFakeIdentity(t *testing.T) {
	// Use the existing parser/normalizer so no-resolve composition stays covered.
	m := testFakeIPMatcher(t, "ip_no_resolve(203.0.113.0/24) -> direct\nfallback: proxy", []string{"proxy"})
	src := netip.MustParseAddr("192.0.2.10")
	out, _, _, ok := m.resolveDNSPrefetchRoute("quic.example", false, src, [6]uint8{}, true)
	if !ok || out != consts.OutboundUserDefinedMin {
		t.Fatalf("known FakeIP route: %v %v", out, ok)
	}
	if _, _, _, ok := m.resolveDNSPrefetchRoute("quic.example", false, src, [6]uint8{}, false); ok {
		t.Fatal("unknown real destination was treated as FakeIP")
	}
}

func TestResolveDNSPrefetchTransportAndMarkIsolation(t *testing.T) {
	d := newTestEndpointDialer()
	d.SetResolveDNS(netip.MustParseAddrPort("8.8.8.8:53"))
	g := newTestFixedOutboundGroup(d)
	a := &proxyDialResult{Dialer: d, Outbound: g}
	plain := resolveDNSResultKey(a, "quic.example", false)
	a.Mark = 1
	if resolveDNSResultKey(a, "quic.example", false) == plain {
		t.Fatal("mark not isolated")
	}
	a.Mark = 0
	g.IsolateTransport = true
	g.Name = "game"
	if resolveDNSResultKey(a, "quic.example", false) == plain {
		t.Fatal("transport class not isolated")
	}
	if _, ok := resolveDNSQueryDialer(a).(resolveDNSClassDialer); !ok {
		t.Fatal("isolated DNS did not select group transport")
	}
}
