package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
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
func (c *droppedDNSPacketConn) SetReadDeadline(time.Time) error         { return nil }
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

type droppedThenDeadlineDNSConn struct {
	droppedDNSPacketConn
	reads         int
	deadline      time.Time
	nextError     error
	onReplacement func()
}

func (c *droppedThenDeadlineDNSConn) SetDeadline(d time.Time) error     { c.deadline = d; return nil }
func (c *droppedThenDeadlineDNSConn) SetReadDeadline(d time.Time) error { c.deadline = d; return nil }
func (c *droppedThenDeadlineDNSConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	c.reads++
	if c.reads == 1 {
		return 0, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
	}
	if c.onReplacement != nil {
		c.onReplacement()
	}
	if c.nextError != nil {
		return 0, netip.AddrPort{}, c.nextError
	}
	time.Sleep(max(0, time.Until(c.deadline)))
	return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
}

func TestSingleDroppedDNSReplyUsesTCPWithoutHealthPenalty(t *testing.T) {
	for _, tc := range []struct {
		name          string
		scheme        dns.UpstreamScheme
		asIs, failTCP bool
	}{
		{"udp", dns.UpstreamScheme_UDP, false, false},
		{"combined", dns.UpstreamScheme_TCP_UDP, false, false},
		{"as-is", dns.UpstreamScheme_UDP, true, false},
		{"TCP hard failure", dns.UpstreamScheme_UDP, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := newFallbackBudgetController(t)
			t.Cleanup(func() { ctrl.closeAllDnsForwarders() })
			original := dnsForwarderFactory
			t.Cleanup(func() { dnsForwarderFactory = original })
			conn := &droppedThenDeadlineDNSConn{}
			upstream := tcpUDPUpstream()
			upstream.Scheme = tc.scheme
			primary := udpPrimaryDialArg()
			tcpCalls := 0
			dnsForwarderFactory = func(_ *dns.Upstream, arg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
				if arg.l4proto == consts.L4ProtoStr_UDP {
					p := newUdpConnPool(1, 1, func(context.Context) (netproxy.Conn, error) { return conn, nil })
					return &DoUDP{pool: p, dialArgument: arg}, nil
				}
				return &stubDnsForwarder{forward: func(ctx context.Context, _ []byte) (*dnsmessage.Msg, error) {
					tcpCalls++
					if ctx.Err() != nil {
						t.Fatal("TCP budget exhausted")
					}
					if tc.failTCP {
						return nil, net.ErrClosed
					}
					return dnsAResponseMsg("drop.test.", "198.51.100.1"), nil
				}}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, _, err := ctrl.forwardWithFallback(ctx, &udpRequest{}, upstream, primary, []byte{0x12, 0x34}, tc.asIs)
			if tc.asIs {
				if tcpCalls != 0 || commonerrors.ClassifyForwardError(err) != commonerrors.ClassDatagramDropped {
					t.Fatalf("as-is: TCP=%d err=%v", tcpCalls, err)
				}
			} else if tcpCalls != 1 || (!tc.failTCP && err != nil) {
				t.Fatalf("TCP=%d err=%v", tcpCalls, err)
			}
			if tc.failTCP && (!errors.Is(err, net.ErrClosed) || commonerrors.ClassifyForwardError(err) != commonerrors.ClassHardFailure) {
				t.Fatalf("TCP fault hidden: %v", err)
			}
			cached, ok := ctrl.dnsForwarderCache.Load(newDnsForwarderKey(upstream, primary))
			if !ok || cached.(*cachedDnsForwarder).consecutiveErrors.Load() != 0 || conn.closed != 0 {
				t.Fatal("dropped reply retired or penalized UDP")
			}
			if ctrl.dnsDroppedDatagrams.Load() != 1 {
				t.Fatal("drop event lost")
			}
		})
	}
}

func TestDroppedDNSReplyDoesNotHideResetOrCancellation(t *testing.T) {
	for _, nextError := range []error{net.ErrClosed, &quic.IdleTimeoutError{}, &quic.HandshakeTimeoutError{}} {
		for _, canceled := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			conn := &droppedThenDeadlineDNSConn{nextError: nextError}
			if canceled {
				conn.onReplacement = cancel
			}
			p := newUdpConnPool(1, 1, func(context.Context) (netproxy.Conn, error) { return conn, nil })
			d := &DoUDP{pool: p, dialArgument: *udpPrimaryDialArg()}
			_, err := d.ForwardDNS(ctx, []byte{0x12, 0x34})
			cancel()
			if canceled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation hidden: %v", err)
				}
			} else if !errors.Is(err, net.ErrClosed) || commonerrors.ClassifyForwardError(err) != commonerrors.ClassHardFailure {
				t.Fatalf("reset hidden: %v", err)
			}
			if conn.closed != 1 {
				t.Fatal("closed session returned to UDP pool")
			}
			_ = d.Close()
		}
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
