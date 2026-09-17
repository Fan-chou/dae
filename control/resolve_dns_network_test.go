package control

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

type resolveDNSRealPacketConn struct {
	*net.UDPConn
	target string
}

func (c *resolveDNSRealPacketConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	return c.ReadFromUDPAddrPort(b)
}
func (c *resolveDNSRealPacketConn) WriteTo(b []byte, target string) (int, error) {
	a, e := netip.ParseAddrPort(target)
	if e != nil {
		return 0, e
	}
	return c.WriteToUDPAddrPort(b, a)
}
func (c *resolveDNSRealPacketConn) Write(b []byte) (int, error) { return c.WriteTo(b, c.target) }

type resolveDNSRealDialer struct{}

func (resolveDNSRealDialer) DialContext(_ context.Context, _, target string) (netproxy.Conn, error) {
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return nil, e
	}
	return &resolveDNSRealPacketConn{c, target}, nil
}
func resolveDNSRealNode(t *testing.T) *dialer.Dialer {
	t.Helper()
	d := newTestEndpointDialer()
	d.Dialer = resolveDNSRealDialer{}
	d.Property().Address = "test-proxy:443"
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestResolveDNSRecoveryRealPackets(t *testing.T) {
	a, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	port := a.LocalAddr().(*net.UDPAddr).Port
	b, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	d := resolveDNSRealNode(t)
	d.SetResolveDNS(netip.MustParseAddrPort("127.0.0.1:53"))
	cp := testDialControlPlane(newTestFixedOutboundGroup(d))
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000"), Dst: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.10"), uint16(port))}
	p := NewUdpEndpointPool()
	defer p.Close()
	var recovery resolveDNSRecoveryStore
	ipA, ipB := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	param := &proxyDialParam{Outbound: consts.OutboundUserDefinedMin, Domain: "quic.example", Src: key.Src, Dest: key.Dst, Network: "udp"}
	cacheKey := resolveDNSResultKey(&proxyDialResult{Dialer: d, Mark: cp.soMarkFromDae}, param.Domain, false)
	cp.resolveDNSPins.store(cacheKey, ipA, time.Now(), time.Minute)
	options := &UdpEndpointOptions{Handler: func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil }, GetDialOption: func(ctx context.Context) (*DialOption, error) {
		param.ResolveDNSRecovery = nil
		if r, ok := recovery.lookup(key, PacketSnifferKey{}, false); ok {
			param.ResolveDNSRecovery = &r
		}
		res, e := cp.chooseProxyDialer(ctx, param)
		if e != nil {
			return nil, e
		}
		o := &DialOption{Dialer: d, Outbound: res.Outbound, Target: res.DialTarget, Network: res.Network, ResolveDNSPinned: res.ResolveDNSPinned, SniffedDomain: res.SniffedDomain}
		o.Binding = newUdpFlowBinding(cp.PolicyEpoch(), res.OutboundIndex, res.Mark, res.Must, o)
		return o, nil
	}}
	send := func(want *net.UDPConn) {
		t.Helper()
		ue, _, e := p.GetOrCreate(key, options)
		if e != nil {
			t.Fatal(e)
		}
		ue.resolveDNSState.store = &recovery
		if _, e = ue.WriteTo([]byte("real datagram"), ue.dialTargetForWrite(key.Dst)); e != nil {
			t.Fatal(e)
		}
		_ = want.SetReadDeadline(time.Now().Add(time.Second))
		var buf [64]byte
		n, _, e := want.ReadFromUDPAddrPort(buf[:])
		if e != nil || string(buf[:n]) != "real datagram" {
			t.Fatalf("wrong target: %v", e)
		}
	}
	send(a)
	cp.resolveDNSPins.store(cacheKey, ipB, time.Now(), time.Minute)
	send(a) // Cache refresh must not change the live peer.
	ue, _ := p.Get(key)
	ue.retire()
	send(a) // Rebuilt transport must still reach A.
	ue, _ = p.Get(key)
	_ = p.Remove(key, ue) // Administrative close releases the old pin.
	send(b)
	t.Log("real UDP delivery: initial A, cached B/live A, retired/rebuilt A, new flow B")
}

func TestResolveDNSPrefetchResponseDelay(t *testing.T) {
	for _, delay := range []time.Duration{150 * time.Millisecond, 300 * time.Millisecond} {
		for _, lead := range []time.Duration{0, 100 * time.Millisecond, 300 * time.Millisecond} {
			t.Run(delay.String()+"/lead="+lead.String(), func(t *testing.T) {
				server, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if e != nil {
					t.Fatal(e)
				}
				defer server.Close()
				var requests atomic.Int32
				go func() {
					for {
						var buf [2048]byte
						n, from, e := server.ReadFromUDPAddrPort(buf[:])
						if e != nil {
							return
						}
						q := new(dnsmessage.Msg)
						if q.Unpack(buf[:n]) != nil {
							continue
						}
						requests.Add(1)
						go func() {
							time.Sleep(delay)
							reply := new(dnsmessage.Msg)
							reply.SetReply(q)
							if q.Question[0].Qtype == dnsmessage.TypeA {
								reply.Answer = []dnsmessage.RR{&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: q.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 10)}}
							}
							data, _ := reply.Pack()
							_, _ = server.WriteToUDPAddrPort(data, from)
						}()
					}
				}()
				d := resolveDNSRealNode(t)
				d.SetResolveDNS(server.LocalAddr().(*net.UDPAddr).AddrPort())
				cp := testDialControlPlane(newTestFixedOutboundGroup(d))
				cp.routingMatcher = testFakeIPMatcher(t, "fallback: proxy", []string{"proxy"})
				src := netip.MustParseAddrPort("192.0.2.10:40000")
				cp.prefetchProxyResolveDNS("quic.example", false, src, [6]uint8{}, 0, [16]uint8{})
				time.Sleep(lead)
				start := time.Now()
				_, e = cp.chooseProxyDialer(context.Background(), &proxyDialParam{Outbound: consts.OutboundUserDefinedMin, Domain: "quic.example", Src: src, Dest: netip.MustParseAddrPort("198.51.100.10:443"), Network: "udp"})
				waited := time.Since(start)
				if e != nil {
					t.Fatal(e)
				}
				if lead >= delay && waited > 100*time.Millisecond {
					t.Fatalf("completed prefetch waited %s", waited)
				}
				t.Logf("DNS response delay=%s prefetch lead=%s demand wait=%s DNS packets=%d", delay, lead, waited, requests.Load())
			})
		}
	}
}
