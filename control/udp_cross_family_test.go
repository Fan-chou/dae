package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func openCrossFamilyTestStore(t *testing.T, dir string) *UDPCrossFamilyStore {
	t.Helper()
	s := NewUDPCrossFamilyStore(dir, "peers")
	if err := s.store.Open(netip.MustParsePrefix("198.19.0.0/24"), netip.MustParsePrefix("fd00:cafe::/120")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestUDPCrossFamilyMappingPersistence(t *testing.T) {
	dir := t.TempDir()
	s := openCrossFamilyTestStore(t, dir)
	cases := []struct{ peer, client string }{
		{"192.0.2.10:27015", "[2001:db8::2]:30000"},
		{"[2001:db8::10]:27016", "192.0.2.2:30000"},
	}
	aliases := make([]netip.AddrPort, len(cases))
	for i, tc := range cases {
		peer, client := netip.MustParseAddrPort(tc.peer), netip.MustParseAddrPort(tc.client)
		alias, err := s.reply(peer, client)
		if err != nil {
			t.Fatal(err)
		}
		if alias.Addr().Is4() != client.Addr().Is4() || alias.Port() != peer.Port() {
			t.Fatalf("wrong alias family/port: %s", alias)
		}
		got, ok, err := s.decode(alias)
		if err != nil || !ok || got != peer {
			t.Fatalf("round trip: %s %v %v", got, ok, err)
		}
		aliases[i] = alias
	}
	// Capacity must never evict the older peer, even when it has been idle.
	s.store.maxLive = len(cases)
	if _, err := s.reply(netip.MustParseAddrPort("192.0.2.20:9"), netip.MustParseAddrPort(cases[0].client)); err == nil {
		t.Fatal("expected capacity failure")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openCrossFamilyTestStore(t, dir)
	for i, tc := range cases {
		got, ok, err := s.decode(aliases[i])
		if err != nil || !ok || got.String() != tc.peer {
			t.Fatalf("restart lost identity: %v %v %v", got, ok, err)
		}
		alias, err := s.reply(got, netip.MustParseAddrPort(tc.client))
		if err != nil || alias != aliases[i] {
			t.Fatalf("restart changed alias: %v %v", alias, err)
		}
	}
	if _, alias, err := s.decode(netip.MustParseAddrPort("198.19.0.254:53")); !alias || err == nil {
		t.Fatal("unassigned pool address must not escape")
	}
}

func TestUDPCrossFamilyCorruptStoreDoesNotReset(t *testing.T) {
	dir := t.TempDir()
	s := openCrossFamilyTestStore(t, dir)
	if _, err := s.reply(netip.MustParseAddrPort("192.0.2.10:9"), netip.MustParseAddrPort("[2001:db8::2]:8")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "peers", fakeIPSnapshotName)
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	next := NewUDPCrossFamilyStore(dir, "peers")
	if err := next.store.Open(netip.MustParsePrefix("198.19.0.0/24"), netip.MustParsePrefix("fd00:cafe::/120")); err == nil {
		t.Fatal("corruption must fail without rebinding aliases")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "broken" {
		t.Fatalf("corrupt data was reset: %q %v", raw, err)
	}
}

// Real sockets exercise both directions, including a first reply from B before
// A replies. The reply's alias is then sent through the control-plane fast path:
// B must receive it from the same socket/port A originally observed.
func TestUDPCrossFamilyFullConeForeignFirstReply(t *testing.T) {
	for _, v6Client := range []bool{true, false} {
		name := "client4_peer6"
		if v6Client {
			name = "client6_peer4"
		}
		t.Run(name, func(t *testing.T) {
			restore := swapUdpEndpointPoolForTest(t)
			defer restore()
			s := openCrossFamilyTestStore(t, t.TempDir())
			addrA, addrB := "127.0.0.1:0", "[::1]:0"
			client := netip.MustParseAddrPort("192.0.2.2:31000")
			if v6Client {
				addrA, addrB = addrB, addrA
				client = netip.MustParseAddrPort("[2001:db8::2]:31000")
			}
			listen := func(addr string) *net.UDPConn {
				a := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr))
				c, err := net.ListenUDP("udp", a)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Close() })
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				return c
			}
			a, b := listen(addrA), listen(addrB)
			dstA, dstB := a.LocalAddr().(*net.UDPAddr).AddrPort(), b.LocalAddr().(*net.UDPAddr).AddrPort()
			log := logrus.New()
			log.SetOutput(io.Discard)
			d := componentdialer.NewDialerContext(context.Background(), direct.FullconeDirect, &componentdialer.GlobalOption{Log: log, CheckInterval: time.Minute}, componentdialer.InstanceOption{DisableCheck: true}, &componentdialer.Property{Property: D.Property{Name: "direct", Protocol: "direct"}})
			t.Cleanup(func() { _ = d.Close() })
			cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
			cp.ctx = context.Background()
			cp.udpCrossFamily = s
			cp.routingMatcher = testFakeIPMatcher(t, "fallback: A", []string{"A"})
			cp.udpRouteScopeSensitive = true
			rr := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}
			key := UdpEndpointKey{Src: client, RouteScope: newUdpEndpointRouteScope(rr)}
			replies := make(chan netip.AddrPort, 1)
			ue, _, err := DefaultUdpEndpointPool.GetOrCreate(key, &UdpEndpointOptions{Ctx: cp.ctx, NatTimeout: time.Minute, Log: log, crossFamily: s,
				GetDialOption: func(ctx context.Context) (*DialOption, error) {
					res, err := cp.chooseProxyDialer(ctx, &proxyDialParam{Src: client, Dest: dstA, Network: "udp", Outbound: consts.OutboundUserDefinedMin})
					if err != nil {
						return nil, err
					}
					return &DialOption{Dialer: res.Dialer, Outbound: res.Outbound, Network: res.Network, NetworkType: res.SelectionNetworkTypeObj, Target: res.DialTarget}, nil
				},
				Handler: func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error {
					return forwardUdpEndpointReplyToClient(log, ue, data, from, client, func(_ *logrus.Logger, _ []byte, from, to netip.AddrPort, _ udpEndpointResponseConnSlot) error {
						replies <- from
						return nil
					}, nil)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ue.Close() })
			if _, err := ue.WriteTo([]byte("to A"), dstA.String()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			_, outside, err := a.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatal(err)
			}
			// Both loopback addresses reach the same dual-stack socket.
			bTarget := netip.AddrPortFrom(dstB.Addr(), outside.Port())
			if _, err := b.WriteToUDPAddrPort([]byte("unsolicited B"), bTarget); err != nil {
				t.Fatal(err)
			}
			var alias netip.AddrPort
			select {
			case alias = <-replies:
			case <-time.After(3 * time.Second):
				t.Fatal("foreign first reply was lost")
			}
			real, ok, err := s.decode(alias)
			if !ok || err != nil || real != dstB {
				t.Fatalf("reply lost peer identity: %v %v %v", real, ok, err)
			}
			flow := ClassifyUdpFlow(client, alias, []byte("reply B"))
			if err := cp.handlePktOwned(nil, []byte("reply B"), client, alias, &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}, flow, true, nil, UdpEndpointKey{}, false); err != nil {
				t.Fatal(err)
			}
			n, from, err := b.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatal(err)
			}
			if string(buf[:n]) != "reply B" || from.Port() != outside.Port() {
				t.Fatalf("lost full-cone mapping: payload=%q first=%s second=%s", buf[:n], outside, from)
			}
			if countPooledUdpEndpoints(DefaultUdpEndpointPool) != 1 {
				t.Fatal("alias forked the endpoint")
			}
		})
	}
}

func TestUDPCrossFamilyRoutesRealPeer(t *testing.T) {
	s := openCrossFamilyTestStore(t, t.TempDir())
	client := netip.MustParseAddrPort("[2001:db8::2]:31000")
	peer := netip.MustParseAddrPort("203.0.113.8:53")
	alias, err := s.reply(peer, client)
	if err != nil {
		t.Fatal(err)
	}
	cp := &ControlPlane{udpCrossFamily: s}
	cp.routingMatcher = testFakeIPMatcher(t, "ip_no_resolve(203.0.113.0/24) -> A\nfallback: B", []string{"A", "B"})
	rr, isAlias, err := cp.routeUDPAlias(client, alias, nil)
	if err != nil || !isAlias || rr.Outbound != uint8(consts.OutboundUserDefinedMin) {
		t.Fatalf("alias routed instead of real IP: %+v %v %v", rr, isAlias, err)
	}
}

func BenchmarkUDPCrossFamilyEstablishedMapping(b *testing.B) {
	s := NewUDPCrossFamilyStore(b.TempDir(), "peers")
	if err := s.store.Open(netip.MustParsePrefix("198.19.0.0/24"), netip.MustParsePrefix("fd00:cafe::/120")); err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	peer, client := netip.MustParseAddrPort("192.0.2.10:27015"), netip.MustParseAddrPort("[2001:db8::2]:30000")
	alias, err := s.reply(peer, client)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := s.reply(peer, client); err != nil {
			b.Fatal(err)
		}
		if _, _, err := s.decode(alias); err != nil {
			b.Fatal(err)
		}
	}
}

func TestUDPCrossFamilyIPv6ClientDirectIPv4Domain(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	log := logrus.New()
	log.SetOutput(io.Discard)
	d := componentdialer.NewDialerContext(context.Background(), direct.FullconeDirect, &componentdialer.GlobalOption{Log: log, CheckInterval: time.Minute}, componentdialer.InstanceOption{DisableCheck: true}, &componentdialer.Property{Property: D.Property{Name: "direct", Protocol: "direct"}})
	defer d.Close()
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	cp.udpCrossFamily = openCrossFamilyTestStore(t, t.TempDir())
	cp.dialMode = consts.DialMode_DomainPlus
	client := netip.MustParseAddrPort("[2001:db8::2]:31000")
	original := netip.AddrPortFrom(netip.MustParseAddr("::1"), server.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{Src: client, Dest: original, Domain: "localhost", Network: "udp", Outbound: consts.OutboundUserDefinedMin})
	if err != nil {
		t.Fatal(err)
	}
	if res.DialTarget == original.String() {
		t.Fatal("fixture did not select a domain")
	}
	conn, err := res.Dialer.DialContext(context.Background(), res.Network, res.DialTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("domain to IPv4")); err != nil {
		t.Fatalf("IPv6 client cannot write IPv4-resolved domain: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := server.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "domain to IPv4" {
		t.Fatalf("IPv4 target did not receive: %q %v", buf[:n], err)
	}
	ue := &UdpEndpoint{crossFamily: cp.udpCrossFamily, poolKey: UdpEndpointKey{Src: client, Dst: original}}
	restored, err := ue.crossFamily.reply(ue.canonicalReplyFrom(server.LocalAddr().(*net.UDPAddr).AddrPort()), client)
	if err != nil || restored != original {
		t.Fatalf("domain reply lost client destination: %s %v", restored, err)
	}
}
