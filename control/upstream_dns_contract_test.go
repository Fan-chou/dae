package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/olicesx/quic-go"
	"github.com/sirupsen/logrus"
)

func TestDroppedDNSFallbackPreservesTransportContract(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		scheme                 dns.UpstreamScheme
		asIs, failTCP, wantTCP bool
	}{
		{"udp upgrade", dns.UpstreamScheme_UDP, false, false, true},
		{"combined", dns.UpstreamScheme_TCP_UDP, false, false, true},
		{"as-is", dns.UpstreamScheme_UDP, true, false, false},
		{"tcp failure", dns.UpstreamScheme_UDP, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := newFallbackBudgetController(t)
			original := dnsForwarderFactory
			t.Cleanup(func() { dnsForwarderFactory = original })
			tcpCalls := 0
			dnsForwarderFactory = func(_ *dns.Upstream, arg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					if arg.l4proto == consts.L4ProtoStr_UDP {
						return nil, netproxy.DatagramDropped(io.ErrShortBuffer)
					}
					tcpCalls++
					if tc.failTCP {
						return nil, net.ErrClosed
					}
					return dnsAResponseMsg("drop.test.", "198.51.100.1"), nil
				}}, nil
			}
			upstream := tcpUDPUpstream()
			upstream.Scheme = tc.scheme
			_, _, err := ctrl.forwardWithFallback(context.Background(), &udpRequest{}, upstream, udpPrimaryDialArg(), []byte{1, 2}, tc.asIs)
			if (tcpCalls == 1) != tc.wantTCP {
				t.Fatalf("TCP calls=%d", tcpCalls)
			}
			if tc.wantTCP && !tc.failTCP && err != nil {
				t.Fatal(err)
			}
			if tc.failTCP && (commonerrors.ClassifyForwardError(err) != commonerrors.ClassHardFailure || !errors.Is(err, net.ErrClosed)) {
				t.Fatalf("TCP failure masked by UDP drop: %v", err)
			}
			if got := ctrl.dnsDroppedRetries.Load(); got != uint64(tcpCalls) {
				t.Fatalf("retries=%d calls=%d", got, tcpCalls)
			}
		})
	}
}

type droppedDNSPacketConn struct {
	netproxy.Conn
	wire          []byte
	drops, closed int
}

func (c *droppedDNSPacketConn) SetDeadline(time.Time) error             { return nil }
func (c *droppedDNSPacketConn) Close() error                            { c.closed++; return nil }
func (c *droppedDNSPacketConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (c *droppedDNSPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	if c.drops > 0 {
		c.drops--
		return 0, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
	}
	return copy(p, c.wire), netip.MustParseAddrPort("192.0.2.53:53"), nil
}
func TestDNSPoolDropKeepsConnectionAndBoundsWait(t *testing.T) {
	for _, drops := range []int{1, 9} {
		msg := dnsAResponseMsg("pool.test.", "198.51.100.1")
		msg.Id = 0x1234
		wire, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		conn := &droppedDNSPacketConn{wire: wire, drops: drops}
		pool := newUdpConnPool(1, 1, func(context.Context) (netproxy.Conn, error) { return conn, nil })
		d := &DoUDP{pool: pool, dialArgument: *udpPrimaryDialArg()}
		_, err = d.ForwardDNS(context.Background(), []byte{0x12, 0x34})
		if drops == 1 {
			if err != nil || conn.closed != 0 || len(pool.idleConns) != 1 {
				t.Fatalf("drop retired conn: %v closed=%d", err, conn.closed)
			}
		} else {
			if err == nil || conn.closed != 1 {
				t.Fatalf("unbounded drops: %v closed=%d", err, conn.closed)
			}
		}
		_ = d.Close()
	}
}

type queryIDStream struct{ quic.Stream }

func (queryIDStream) Close() error { return nil }

type queryIDConnection struct{ stubEarlyConn }

func (*queryIDConnection) OpenStreamSync(context.Context) (quic.Stream, error) {
	return queryIDStream{}, nil
}
func TestDoQKeepsCallerQueryIDOnSuccessAndFailure(t *testing.T) {
	original := sendStreamDNSFunc
	t.Cleanup(func() { sendStreamDNSFunc = original })
	for _, fail := range []bool{false, true} {
		query := []byte{0x12, 0x34, 1, 0}
		before := bytes.Clone(query)
		sendStreamDNSFunc = func(_ io.ReadWriter, wire []byte) (*dnsmessage.Msg, error) {
			if wire[0] != 0 || wire[1] != 0 {
				t.Fatal("DoQ wire ID must be zero")
			}
			if fail {
				return nil, io.ErrUnexpectedEOF
			}
			return &dnsmessage.Msg{}, nil
		}
		d := &DoQ{connection: &queryIDConnection{}}
		_, _ = d.ForwardDNS(context.Background(), query)
		if !bytes.Equal(query, before) {
			t.Fatalf("query mutated: %x", query)
		}
	}
}
