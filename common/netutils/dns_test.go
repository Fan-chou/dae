/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package netutils

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

type stdNetDialer struct{}

func (stdNetDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func TestResolveNetipLargeTCPResponse(t *testing.T) {
	serverAddr := startTCPDNSServer(t, func(req *dnsmessage.Msg, conn net.Conn) error {
		resp := new(dnsmessage.Msg)
		resp.SetReply(req)
		for i := 0; i < 100; i++ {
			resp.Answer = append(resp.Answer, &dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(fmt.Sprintf("1.1.1.%d", i+1)).To4(),
			})
		}
		return writeTCPDNSResponse(conn, resp, false)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := ResolveNetip(ctx, stdNetDialer{}, serverAddr, "example.com", dnsmessage.TypeA, "tcp")
	if err != nil {
		t.Fatalf("ResolveNetip failed: %v", err)
	}
	if len(addrs) != 100 {
		t.Fatalf("unexpected address count: got %d want 100", len(addrs))
	}
}

func TestResolveNetipFragmentedTCPResponse(t *testing.T) {
	serverAddr := startTCPDNSServer(t, func(req *dnsmessage.Msg, conn net.Conn) error {
		resp := new(dnsmessage.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: []byte{203, 0, 113, 7},
		})
		return writeTCPDNSResponse(conn, resp, true)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := ResolveNetip(ctx, stdNetDialer{}, serverAddr, "example.com", dnsmessage.TypeA, "tcp")
	if err != nil {
		t.Fatalf("ResolveNetip failed: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("unexpected address count: got %d want 1", len(addrs))
	}
	if got := addrs[0].String(); got != "203.0.113.7" {
		t.Fatalf("unexpected address: got %s want 203.0.113.7", got)
	}
}

func TestResolveNetipTTLUsesMinAnswerTTL(t *testing.T) {
	serverAddr := startTCPDNSServer(t, func(req *dnsmessage.Msg, conn net.Conn) error {
		resp := new(dnsmessage.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer,
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: req.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 120},
				A:   []byte{203, 0, 113, 7},
			},
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: req.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 45},
				A:   []byte{203, 0, 113, 8},
			},
		)
		return writeTCPDNSResponse(conn, resp, false)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, ttl, err := ResolveNetipTTL(ctx, stdNetDialer{}, serverAddr, "example.com", dnsmessage.TypeA, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 {
		t.Fatalf("addrs = %d, want 2", len(addrs))
	}
	if ttl != 45*time.Second {
		t.Fatalf("ttl = %v, want 45s", ttl)
	}
}

func startTCPDNSServer(t *testing.T, handler func(req *dnsmessage.Msg, conn net.Conn) error) netip.AddrPort {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return
		}

		reqBuf := make([]byte, length)
		if _, err := io.ReadFull(conn, reqBuf); err != nil {
			return
		}

		var req dnsmessage.Msg
		if err := req.Unpack(reqBuf); err != nil {
			return
		}
		_ = handler(&req, conn)
	}()

	return netip.MustParseAddrPort(l.Addr().String())
}

// fakeDNSUDPConn is an in-process stand-in for a UDP upstream. Read copies at
// most len(p) bytes of the prepared reply, which is what a datagram read does
// when the caller's buffer is smaller than the datagram, so the production
// resolver's read buffer becomes the only variable under test.
type fakeDNSUDPConn struct {
	query    []byte
	response []byte
	readLen  int
}

func (c *fakeDNSUDPConn) Write(p []byte) (int, error) {
	c.query = append([]byte(nil), p...)
	return len(p), nil
}

func (c *fakeDNSUDPConn) Read(p []byte) (int, error) {
	if c.response == nil {
		var req dnsmessage.Msg
		if err := req.Unpack(c.query); err != nil {
			return 0, err
		}
		resp := new(dnsmessage.Msg)
		resp.SetReply(&req)
		// Compression off: Pack rejects a message that would need more
		// compression pointers than the format allows.
		resp.Compress = false
		for i := range 200 {
			resp.Answer = append(resp.Answer, &dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/250, i%250+1)).To4(),
			})
		}
		out, err := resp.Pack()
		if err != nil {
			return 0, err
		}
		c.response = out
	}
	c.readLen = len(p)
	return copy(p, c.response), nil
}

func (c *fakeDNSUDPConn) Close() error                     { return nil }
func (c *fakeDNSUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeDNSUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeDNSUDPConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*fakeDNSUDPConn)(nil)

func (c *fakeDNSUDPConn) dialer() fakeDNSUDPDialer { return fakeDNSUDPDialer{conn: c} }

type fakeDNSUDPDialer struct{ conn *fakeDNSUDPConn }

func (d fakeDNSUDPDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return d.conn, nil
}

// TestResolveNetipLargeUDPResponse pins the internal resolver's UDP read buffer
// to the full legal DNS message range. This resolver builds its queries without
// an EDNS0 OPT record, so a compliant upstream answers within 512 bytes or sets
// TC; an oversized reply must still not be read short and then be misreported as
// a decode failure. The reply here is several times larger than a
// link-MTU-sized buffer could hold.
func TestResolveNetipLargeUDPResponse(t *testing.T) {
	conn := &fakeDNSUDPConn{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A loopback UDP fixture cannot carry this reply in every environment
	// (some sandboxes do not deliver large loopback datagrams at all), so the
	// upstream is modelled in-process.
	addrs, err := ResolveNetip(ctx, conn.dialer(), netip.MustParseAddrPort("192.0.2.53:53"),
		"example.com", dnsmessage.TypeA, "udp")
	if err != nil {
		t.Fatalf("ResolveNetip over UDP failed: %v", err)
	}
	if len(addrs) != 200 {
		t.Fatalf("unexpected address count: got %d want 200", len(addrs))
	}
	if conn.readLen < len(conn.response) {
		t.Fatalf("resolver read buffer = %d bytes, reply = %d: the buffer must cover the "+
			"full legal DNS message", conn.readLen, len(conn.response))
	}
}

func writeTCPDNSResponse(conn net.Conn, resp *dnsmessage.Msg, fragmented bool) error {
	respBuf, err := resp.Pack()
	if err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, uint16(len(respBuf))); err != nil {
		return err
	}

	if !fragmented {
		if _, err := conn.Write(respBuf); err != nil {
			return err
		}
		return nil
	}

	split := len(respBuf) / 2
	if split == 0 {
		split = 1
	}
	if _, err := conn.Write(respBuf[:split]); err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := conn.Write(respBuf[split:]); err != nil {
		return err
	}
	return nil
}

type blockingDialer struct{}

func (blockingDialer) DialContext(ctx context.Context, _, _ string) (netproxy.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type hangingReadConn struct {
	fakeDNSUDPConn
	closeCh chan struct{}
}

func (c *hangingReadConn) Read(p []byte) (int, error) {
	<-c.closeCh
	return 0, io.EOF
}

func (c *hangingReadConn) Close() error {
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
	}
	return nil
}

type funcNetDialer struct {
	fn func(context.Context, string, string) (netproxy.Conn, error)
}

func (d funcNetDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return d.fn(ctx, network, addr)
}

type scriptedResponseUDPConn struct {
	fakeDNSUDPConn
	buildResp func(req *dnsmessage.Msg) *dnsmessage.Msg
}

func (c *scriptedResponseUDPConn) Read(p []byte) (int, error) {
	var req dnsmessage.Msg
	if err := req.Unpack(c.query); err != nil {
		return 0, err
	}
	resp := c.buildResp(&req)
	out, err := resp.Pack()
	if err != nil {
		return 0, err
	}
	return copy(p, out), nil
}

func TestResolveNetipTimeoutWrapsErrResolveTimeout(t *testing.T) {
	t.Run("dial_deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, _, err := ResolveNetipTTL(ctx, blockingDialer{}, netip.MustParseAddrPort("192.0.2.53:53"), "example.com", dnsmessage.TypeA, "udp")
		if !errors.Is(err, ErrResolveTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want ErrResolveTimeout and context.DeadlineExceeded", err)
		}
	})
	t.Run("read_deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		conn := &hangingReadConn{closeCh: make(chan struct{})}
		_, _, err := ResolveNetipTTL(ctx, funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			return conn, nil
		}}, netip.MustParseAddrPort("192.0.2.53:53"), "example.com", dnsmessage.TypeA, "udp")
		if !errors.Is(err, ErrResolveTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want ErrResolveTimeout and context.DeadlineExceeded", err)
		}
	})
}

func TestResolveNetipRcodeTruncatedAndEDNS0(t *testing.T) {
	t.Run("edns0_and_nxdomain", func(t *testing.T) {
		var sawOPT bool
		var udpSize uint16
		conn := &scriptedResponseUDPConn{
			buildResp: func(req *dnsmessage.Msg) *dnsmessage.Msg {
				if opt := req.IsEdns0(); opt != nil {
					sawOPT = true
					udpSize = opt.UDPSize()
				}
				resp := new(dnsmessage.Msg)
				resp.SetReply(req)
				resp.Rcode = dnsmessage.RcodeNameError
				return resp
			},
		}
		_, _, err := ResolveNetipTTL(context.Background(), funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			return conn, nil
		}}, netip.MustParseAddrPort("192.0.2.53:53"), "nx.example", dnsmessage.TypeA, "udp")
		if !sawOPT || udpSize != edns0UDPPayloadLen {
			t.Fatalf("edns0 opt = (%v, %d), want (true, %d)", sawOPT, udpSize, edns0UDPPayloadLen)
		}
		if !IsDnsNegativeError(err) {
			t.Fatalf("err = %v, want IsDnsNegativeError=true", err)
		}
	})
	t.Run("servfail_not_negative", func(t *testing.T) {
		conn := &scriptedResponseUDPConn{
			buildResp: func(req *dnsmessage.Msg) *dnsmessage.Msg {
				resp := new(dnsmessage.Msg)
				resp.SetReply(req)
				resp.Rcode = dnsmessage.RcodeServerFailure
				return resp
			},
		}
		_, _, err := ResolveNetipTTL(context.Background(), funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			return conn, nil
		}}, netip.MustParseAddrPort("192.0.2.53:53"), "sf.example", dnsmessage.TypeA, "udp")
		var rcodeErr *DnsRcodeError
		if !errors.As(err, &rcodeErr) || rcodeErr.Rcode != dnsmessage.RcodeServerFailure {
			t.Fatalf("err = %v, want SERVFAIL DnsRcodeError", err)
		}
		if IsDnsNegativeError(err) {
			t.Fatalf("SERVFAIL must not be treated as authoritative negative")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		conn := &scriptedResponseUDPConn{
			buildResp: func(req *dnsmessage.Msg) *dnsmessage.Msg {
				resp := new(dnsmessage.Msg)
				resp.SetReply(req)
				resp.Truncated = true
				return resp
			},
		}
		_, _, err := ResolveNetipTTL(context.Background(), funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			return conn, nil
		}}, netip.MustParseAddrPort("192.0.2.53:53"), "tc.example", dnsmessage.TypeA, "udp")
		if !errors.Is(err, ErrDnsTruncated) {
			t.Fatalf("err = %v, want ErrDnsTruncated", err)
		}
	})
}
