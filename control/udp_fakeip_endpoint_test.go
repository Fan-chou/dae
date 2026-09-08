package control

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestDNSFakeIPUDPIsolatesBeforeSourceOnlyReuse(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		for _, proxy := range []bool{false, true} {
			t.Run(fmt.Sprintf("metadata=%v_proxy=%v", sensitive, proxy), func(t *testing.T) {
				restore := swapUdpEndpointPoolForTest(t)
				defer restore()
				var conns []*udpReuseSimulationConn
				protocol, address := "direct", ""
				if proxy {
					protocol, address = "hysteria2", "proxy.example:443"
				}
				// Give each endpoint its own reader and capture the actual WriteTo target.
				factory := func() netproxy.Conn {
					conn := &udpReuseSimulationConn{reads: make(chan scriptedPacketRead), closeCh: make(chan struct{})}
					conns = append(conns, conn)
					return conn
				}
				d, _ := newFactoryProxyEndpointDialer(protocol, address, factory)
				t.Cleanup(func() { _ = d.Close() })
				group := newTestFixedOutboundGroup(d)
				cp := newUdpReuseSimulationControlPlane(group)
				cp.ctx = context.Background()
				cp.udpRouteScopeSensitive = sensitive
				cp.outbounds[consts.OutboundDirect] = group
				fallback := "direct"
				out := consts.OutboundDirect
				if proxy {
					fallback = "proxy"
					out = consts.OutboundUserDefinedMin
				}
				cp.routingMatcher = testFakeIPMatcher(t, "fallback: "+fallback, []string{"proxy"})
				seedDnsCacheIP(t, cp, "first.example", netip.MustParseAddr("203.0.113.8"))
				store, first := newTestFakeIPStore(t, "first.example", "second.example")
				attachFakeIPStore(cp, store)
				second, _, _ := store.Lookup("second.example")
				port := uint16(33000)
				if sensitive {
					port += 10
				}
				if proxy {
					port++
				}
				src := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.2"), port)
				native := netip.MustParseAddrPort("198.51.100.20:27015")
				fakeA, fakeB := netip.AddrPortFrom(first, 27015), netip.AddrPortFrom(second, 27015)
				send := func(dst netip.AddrPort, rr *bpfRoutingResult) {
					t.Helper()
					data := []byte("game-data")
					if err := cp.handlePktOwned(nil, data, src, dst, rr, ClassifyUdpFlow(src, dst, data), false, nil, UdpEndpointKey{}, false); err != nil {
						t.Fatal(err)
					}
				}
				send(native, &bpfRoutingResult{Outbound: uint8(out)})
				rr := func() *bpfRoutingResult {
					return &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}
				}
				send(fakeA, rr())
				send(fakeA, rr())
				seedDnsCacheIP(t, cp, "second.example", netip.MustParseAddr("203.0.113.9"))
				send(fakeB, rr())
				send(fakeA, rr())
				if len(conns) != 3 {
					t.Fatalf("created %d endpoints, want native + two FakeIP identities", len(conns))
				}
				wantA, wantB := "203.0.113.8:27015", "203.0.113.9:27015"
				if proxy {
					wantA, wantB = "first.example:27015", "second.example:27015"
				}
				for i, want := range []string{native.String(), wantA, wantB} {
					got := conns[i].recordedWriteAddrs()
					wantCount := 1
					if i == 1 {
						wantCount = 3
					}
					if len(got) != wantCount {
						t.Fatalf("endpoint %d writes=%v", i, got)
					}
					for _, target := range got {
						if target != want {
							t.Fatalf("endpoint %d target=%s want=%s", i, target, want)
						}
					}
				}
				scope := udpEndpointRouteScope{}
				if sensitive {
					scope = newUdpEndpointRouteScope(rr())
				}
				for _, dst := range []netip.AddrPort{fakeA, fakeB} {
					ue, ok := DefaultUdpEndpointPool.Get(UdpEndpointKey{Src: src, Dst: dst, RouteScope: scope})
					if !ok {
						t.Fatalf("missing destination-scoped endpoint for %s", dst)
					}
					if got := ue.canonicalReplyFrom(netip.MustParseAddrPort("203.0.113.99:27015")); got != dst {
						t.Fatalf("reply source %s lost FakeIP %s", got, dst)
					}
				}
			})
		}
	}
}
