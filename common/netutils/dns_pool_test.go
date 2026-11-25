/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"go.uber.org/goleak"
)

type poolMockUDPConn struct {
	reads      chan []byte
	closeCh    chan struct{}
	closeOnce  sync.Once
	failWrites atomic.Bool
	writeHook  func(req *dnsmessage.Msg, conn *poolMockUDPConn)
	writeCount atomic.Int32
}

func newPoolMockUDPConn(writeHook func(req *dnsmessage.Msg, conn *poolMockUDPConn)) *poolMockUDPConn {
	return &poolMockUDPConn{
		reads:     make(chan []byte, 128),
		closeCh:   make(chan struct{}),
		writeHook: writeHook,
	}
}

func (c *poolMockUDPConn) Read(p []byte) (int, error) {
	select {
	case <-c.closeCh:
		return 0, io.EOF
	case data := <-c.reads:
		n := copy(p, data)
		return n, nil
	}
}

func (c *poolMockUDPConn) Write(p []byte) (int, error) {
	c.writeCount.Add(1)
	if c.failWrites.Load() {
		return 0, net.ErrClosed
	}
	var req dnsmessage.Msg
	if err := req.Unpack(p); err == nil && c.writeHook != nil {
		c.writeHook(&req, c)
	}
	return len(p), nil
}

func (c *poolMockUDPConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	return nil
}

func (c *poolMockUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *poolMockUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *poolMockUDPConn) SetWriteDeadline(time.Time) error { return nil }

func (c *poolMockUDPConn) pushReply(msg *dnsmessage.Msg) {
	raw, err := msg.Pack()
	if err != nil {
		return
	}
	select {
	case c.reads <- raw:
	case <-c.closeCh:
	}
}

func makeAReply(req *dnsmessage.Msg, ip netip.Addr, ttl uint32) *dnsmessage.Msg {
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    ttl,
			},
			A: ip.AsSlice(),
		},
	}
	return resp
}

func TestPooledUDPResolver50ConcurrentSingleDialAndTxIDMux(t *testing.T) {
	defer goleak.VerifyNone(t)

	var dials atomic.Int32
	var conn *poolMockUDPConn
	var seenMu sync.Mutex
	seenEDNS := true

	resolver := NewPooledUDPResolverWithIdle(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		if dials.Add(1) == 1 {
			conn = newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
				if opt := req.IsEdns0(); opt == nil || opt.UDPSize() != edns0UDPPayloadLen {
					seenMu.Lock()
					seenEDNS = false
					seenMu.Unlock()
				}
				lastOctet := byte(10)
				if len(req.Question) > 0 {
					var idx int
					_, _ = fmt.Sscanf(req.Question[0].Name, "host-%d.example.", &idx)
					lastOctet = byte(1 + (idx % 200))
				}
				ip := netip.AddrFrom4([4]byte{198, 51, 100, lastOctet})
				ttl := uint32(30 + int(lastOctet))
				mc.pushReply(makeAReply(req, ip, ttl))
			})
			return conn, nil
		}
		c := newPoolMockUDPConn(nil)
		return c, nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp", 5*time.Second)
	defer func() { _ = resolver.Close() }()

	const n = 50
	var wg sync.WaitGroup
	var reusedTrue atomic.Int32
	var reusedFalse atomic.Int32
	errs := make(chan error, n)

	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			addrs, ttl, reused, err := resolver.ResolveTTL(ctx, fmt.Sprintf("host-%d.example", idx), dnsmessage.TypeA)
			if err != nil {
				errs <- fmt.Errorf("idx %d: %w", idx, err)
				return
			}
			wantIP := netip.AddrFrom4([4]byte{198, 51, 100, byte(1 + (idx % 200))})
			wantTTL := time.Duration(30+1+(idx%200)) * time.Second
			if len(addrs) != 1 || addrs[0] != wantIP || ttl != wantTTL {
				errs <- fmt.Errorf("idx %d got (%v, %v), want (%v, %v)", idx, addrs, ttl, wantIP, wantTTL)
				return
			}
			if reused {
				reusedTrue.Add(1)
			} else {
				reusedFalse.Add(1)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1", got)
	}
	if reusedFalse.Load() != 1 || reusedTrue.Load() != n-1 {
		t.Fatalf("reused false/true = %d/%d, want 1/%d", reusedFalse.Load(), reusedTrue.Load(), n-1)
	}
	seenMu.Lock()
	okEDNS := seenEDNS
	seenMu.Unlock()
	if !okEDNS {
		t.Fatal("missing or mismatched EDNS0 1232 option on pooled query")
	}
}

func TestPooledUDPResolverErrorsResendAndShortPacket(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Run("nxdomain_truncated_and_ignores_garbage", func(t *testing.T) {
		conn := newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
			// Inject a 1-byte runt packet and unknown txID packet first; must not break conn.
			mc.reads <- []byte{0x42}
			fakeOther := new(dnsmessage.Msg)
			fakeOther.SetReply(req)
			fakeOther.Id = req.Id ^ 0x1234
			mc.pushReply(fakeOther)

			resp := new(dnsmessage.Msg)
			resp.SetReply(req)
			switch req.Question[0].Name {
			case "nx.example.":
				resp.Rcode = dnsmessage.RcodeNameError
			case "tc.example.":
				resp.Truncated = true
			default:
				resp = makeAReply(req, netip.MustParseAddr("203.0.113.10"), 45)
			}
			mc.pushReply(resp)
		})
		var dials atomic.Int32
		r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			dials.Add(1)
			return conn, nil
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
		defer func() { _ = r.Close() }()

		_, _, _, err := r.ResolveTTL(context.Background(), "nx.example", dnsmessage.TypeA)
		if !IsDnsNegativeError(err) {
			t.Fatalf("nxdomain err = %v, want IsDnsNegativeError", err)
		}
		_, _, _, err = r.ResolveTTL(context.Background(), "tc.example", dnsmessage.TypeA)
		if !errors.Is(err, ErrDnsTruncated) {
			t.Fatalf("truncated err = %v, want ErrDnsTruncated", err)
		}
		addrs, ttl, reused, err := r.ResolveTTL(context.Background(), "ok.example", dnsmessage.TypeA)
		if err != nil || !reused || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.10") || ttl != 45*time.Second {
			t.Fatalf("post-garbage ok query = (%v, %v, %v, %v)", addrs, ttl, reused, err)
		}
		if dials.Load() != 1 {
			t.Fatalf("dials = %d, want 1", dials.Load())
		}
	})

	t.Run("timeout_and_resend", func(t *testing.T) {
		conn := newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
			// Reply only on the second write (resend after ResolveDNSUDPResendInterval).
			if mc.writeCount.Load() >= 2 && req.Question[0].Name == "resend.example." {
				mc.pushReply(makeAReply(req, netip.MustParseAddr("203.0.113.20"), 60))
			}
		})
		r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			return conn, nil
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
		defer func() { _ = r.Close() }()

		// Verify timeout wraps ErrResolveTimeout.
		ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancelTimeout()
		_, _, _, err := r.ResolveTTL(ctxTimeout, "silent.example", dnsmessage.TypeA)
		if !errors.Is(err, ErrResolveTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout err = %v, want ErrResolveTimeout + DeadlineExceeded", err)
		}

		// Reset writeCount before resend check and expect resend reply after ~400ms.
		conn.writeCount.Store(0)
		ctxResend, cancelResend := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelResend()
		addrs, _, _, err := r.ResolveTTL(ctxResend, "resend.example", dnsmessage.TypeA)
		if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.20") {
			t.Fatalf("resend query = (%v, %v)", addrs, err)
		}
	})
}

func TestPooledUDPResolverIdleResetStaleRetryAndClose(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Run("idle_teardown_and_lazy_redial", func(t *testing.T) {
		var dials atomic.Int32
		var connsMu sync.Mutex
		var conns []*poolMockUDPConn
		r := NewPooledUDPResolverWithIdle(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			dials.Add(1)
			c := newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
				mc.pushReply(makeAReply(req, netip.MustParseAddr("203.0.113.30"), 60))
			})
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			return c, nil
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp", 40*time.Millisecond)
		defer func() { _ = r.Close() }()

		if _, _, reused, err := r.ResolveTTL(context.Background(), "one.example", dnsmessage.TypeA); err != nil || reused {
			t.Fatalf("first resolve reused=%v err=%v", reused, err)
		}

		// Wait past idle timeout and confirm socket closed cleanly.
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			connsMu.Lock()
			c0 := conns[0]
			connsMu.Unlock()
			select {
			case <-c0.closeCh:
				goto closedOK
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("idle timer did not close idle socket")
	closedOK:

		if _, _, reused, err := r.ResolveTTL(context.Background(), "two.example", dnsmessage.TypeA); err != nil || reused {
			t.Fatalf("post-idle redial reused=%v err=%v", reused, err)
		}
		if dials.Load() != 2 {
			t.Fatalf("dials = %d, want 2 after idle teardown", dials.Load())
		}
	})

	t.Run("reset_and_stale_write_retry", func(t *testing.T) {
		var dials atomic.Int32
		var c1 *poolMockUDPConn
		r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			idx := dials.Add(1)
			c := newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
				mc.pushReply(makeAReply(req, netip.MustParseAddr("203.0.113.40"), 60))
			})
			if idx == 1 {
				c1 = c
			}
			return c, nil
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
		defer func() { _ = r.Close() }()

		if _, _, _, err := r.ResolveTTL(context.Background(), "a.example", dnsmessage.TypeA); err != nil {
			t.Fatal(err)
		}
		// Simulate broken cached socket: failWrites on c1 causes one automatic redial retry.
		c1.failWrites.Store(true)
		if _, _, reused, err := r.ResolveTTL(context.Background(), "b.example", dnsmessage.TypeA); err != nil || reused {
			t.Fatalf("stale-conn retry returned reused=%v err=%v", reused, err)
		}
		if !r.Reset() {
			t.Fatal("Reset() = false, want true when active conn existed")
		}
		if r.Reset() {
			t.Fatal("second Reset() = true, want false when already empty")
		}
		if _, _, reused, err := r.ResolveTTL(context.Background(), "c.example", dnsmessage.TypeA); err != nil || reused {
			t.Fatalf("post-reset redial returned reused=%v err=%v", reused, err)
		}
		if dials.Load() != 3 {
			t.Fatalf("dials = %d, want 3", dials.Load())
		}
	})

	t.Run("close_cancels_blocking_dial_and_pending", func(t *testing.T) {
		dialStarted := make(chan struct{})
		r := NewPooledUDPResolver(funcNetDialer{fn: func(ctx context.Context, _, _ string) (netproxy.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")

		errCh := make(chan error, 1)
		go func() {
			_, _, _, err := r.ResolveTTL(context.Background(), "hang.example", dnsmessage.TypeA)
			errCh <- err
		}()
		<-dialStarted
		if err := r.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := <-errCh; err == nil {
			t.Fatal("expected error when Close cancels in-flight dial")
		}
	})
}

func TestPooledUDPResolverRejectsMismatchedQuestionAndQueryPackets(t *testing.T) {
	defer goleak.VerifyNone(t)

	conn := newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
		// 1. Corrupt bytes sharing the exact txID.
		corrupt := []byte{0, 0, 0xff, 0xff}
		binary.BigEndian.PutUint16(corrupt[:2], req.Id)
		mc.reads <- corrupt

		// 2. Non-response (QR=0) sharing the exact txID.
		queryEcho := req.Copy()
		queryEcho.Response = false
		mc.pushReply(queryEcho)

		// 3. Valid response sharing the exact txID, but for a DIFFERENT domain.
		wrong := new(dnsmessage.Msg)
		wrong.SetQuestion("wrong.example.", dnsmessage.TypeA)
		wrong.Id = req.Id
		wrong.Response = true
		wrong.Answer = []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "wrong.example.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(198, 51, 100, 250).To4(),
			},
		}
		mc.pushReply(wrong)

		// 4. Finally the genuine response matching txID + Question.
		mc.pushReply(makeAReply(req, netip.MustParseAddr("198.51.100.77"), 60))
	})

	r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		return conn, nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() { _ = r.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, ttl, _, err := r.ResolveTTL(ctx, "right.example", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("ResolveTTL failed after spoofed/mismatched packets: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.77") || ttl != 60*time.Second {
		t.Fatalf("got (%v, %v), want (198.51.100.77, 60s)", addrs, ttl)
	}
}

func TestPooledUDPResolverDropsSilentlyDeadReusedSocketOnTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)

	var dials atomic.Int32
	var silent atomic.Bool
	r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		idx := dials.Add(1)
		return newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
			if idx == 1 && silent.Load() {
				// Simulate silent proxy/NAT UDP session expiry: Write succeeds, no reply ever returns.
				return
			}
			mc.pushReply(makeAReply(req, netip.MustParseAddr("203.0.113.88"), 60))
		}), nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() { _ = r.Close() }()

	if _, _, reused, err := r.ResolveTTL(context.Background(), "warm.example", dnsmessage.TypeA); err != nil || reused {
		t.Fatalf("initial query = (reused=%v, err=%v)", reused, err)
	}

	silent.Store(true)
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, _, reused, err := r.ResolveTTL(ctxTimeout, "dead.example", dnsmessage.TypeA); !errors.Is(err, ErrResolveTimeout) || !reused {
		t.Fatalf("silent reused query = (reused=%v, err=%v), want (true, ErrResolveTimeout)", reused, err)
	}

	// Next query must redial a fresh socket instead of staying stuck on the dead one.
	addrs, _, reused, err := r.ResolveTTL(context.Background(), "recovered.example", dnsmessage.TypeA)
	if err != nil || reused || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.88") {
		t.Fatalf("post-timeout query = (%v, reused=%v, err=%v), want fresh dial success", addrs, reused, err)
	}
	if dials.Load() != 2 {
		t.Fatalf("dials = %d, want 2", dials.Load())
	}
}

func TestPooledUDPResolverResetDuringInFlightDial(t *testing.T) {
	defer goleak.VerifyNone(t)

	dial1Started := make(chan struct{})
	dial1Release := make(chan struct{})
	var dials atomic.Int32
	var staleConnClosed atomic.Bool

	r := NewPooledUDPResolver(funcNetDialer{fn: func(ctx context.Context, _, _ string) (netproxy.Conn, error) {
		idx := dials.Add(1)
		if idx == 1 {
			close(dial1Started)
			<-dial1Release
			c := newPoolMockUDPConn(nil)
			go func() {
				<-c.closeCh
				staleConnClosed.Store(true)
			}()
			return c, nil
		}
		return newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
			mc.pushReply(makeAReply(req, netip.MustParseAddr("203.0.113.99"), 60))
		}), nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() { _ = r.Close() }()

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		addrs, _, _, err := r.ResolveTTL(ctx, "wan-reset.example", dnsmessage.TypeA)
		if err != nil {
			done <- err
			return
		}
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.99") {
			done <- fmt.Errorf("unexpected addrs: %v", addrs)
			return
		}
		done <- nil
	}()

	<-dial1Started
	if !r.Reset() {
		t.Fatal("Reset() during in-flight dial = false, want true")
	}
	close(dial1Release)

	if err := <-done; err != nil {
		t.Fatalf("ResolveTTL after in-flight Reset failed: %v", err)
	}
	if dials.Load() != 2 {
		t.Fatalf("dials = %d, want 2 (discarded pre-reset socket and redialed)", dials.Load())
	}
}

type blockingWriteMockConn struct {
	closeCh      chan struct{}
	closeOnce    sync.Once
	writeEntered chan struct{}
	enterOnce    sync.Once
}

func newBlockingWriteMockConn() *blockingWriteMockConn {
	return &blockingWriteMockConn{
		closeCh:      make(chan struct{}),
		writeEntered: make(chan struct{}),
	}
}

func (c *blockingWriteMockConn) Read(_ []byte) (int, error) {
	<-c.closeCh
	return 0, io.EOF
}

func (c *blockingWriteMockConn) Write(_ []byte) (int, error) {
	c.enterOnce.Do(func() { close(c.writeEntered) })
	<-c.closeCh
	return 0, net.ErrClosed
}

func (c *blockingWriteMockConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	return nil
}

func (c *blockingWriteMockConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingWriteMockConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingWriteMockConn) SetWriteDeadline(time.Time) error { return nil }

func TestPooledUDPResolverBlockingWriteRespectsContextAndDoesNotStallOthers(t *testing.T) {
	defer goleak.VerifyNone(t)

	var dials atomic.Int32
	r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		if dials.Add(1) == 1 {
			return newBlockingWriteMockConn(), nil
		}
		return newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
			mc.pushReply(makeAReply(req, netip.MustParseAddr("198.51.100.123"), 60))
		}), nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() { _ = r.Close() }()

	// Query 1 hits a blocking Write conn with a 50ms deadline; must return promptly near 50ms.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel1()
	t0 := time.Now()
	_, _, _, err := r.ResolveTTL(ctx1, "blocked-write.example", dnsmessage.TypeA)
	elapsed := time.Since(t0)
	if !errors.Is(err, ErrResolveTimeout) {
		t.Fatalf("blocked write err = %v, want ErrResolveTimeout", err)
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("blocked write stalled caller for %v (want < 200ms for 50ms ctx)", elapsed)
	}

	// Next query must redial a fresh healthy socket instead of piling onto the stalled writer.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	addrs, _, reused, err := r.ResolveTTL(ctx2, "healthy-after-stall.example", dnsmessage.TypeA)
	if err != nil || reused || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.123") {
		t.Fatalf("post-stall query = (%v, reused=%v, err=%v)", addrs, reused, err)
	}
	if dials.Load() != 2 {
		t.Fatalf("dials = %d, want 2", dials.Load())
	}
}

func TestPooledUDPResolverTimeoutDrainDoesNotAbortActiveWaiter(t *testing.T) {
	defer goleak.VerifyNone(t)

	var dials atomic.Int32
	slowReplyReady := make(chan *dnsmessage.Msg, 1)
	var firstConn *poolMockUDPConn

	r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		idx := dials.Add(1)
		if idx == 1 {
			firstConn = newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
				if len(req.Question) > 0 && req.Question[0].Name == "q3-slow-ok.example." {
					slowReplyReady <- req.Copy()
				}
				// q1 and q2 never get replies.
			})
			return firstConn, nil
		}
		return newPoolMockUDPConn(func(req *dnsmessage.Msg, mc *poolMockUDPConn) {
			mc.pushReply(makeAReply(req, netip.MustParseAddr("198.51.100.200"), 60))
		}), nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() { _ = r.Close() }()

	// Start Q3 (2s budget) first so it establishes conn 1.
	q3Done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		addrs, _, _, err := r.ResolveTTL(ctx, "q3-slow-ok.example", dnsmessage.TypeA)
		if err != nil {
			q3Done <- err
			return
		}
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.103") {
			q3Done <- fmt.Errorf("q3 addrs = %v, want 198.51.100.103", addrs)
			return
		}
		q3Done <- nil
	}()
	q3Req := <-slowReplyReady

	// Now Q1 and Q2 share conn 1 and both time out (reaching consecTO == 2).
	for _, host := range []string{"q1-timeout.example", "q2-timeout.example"} {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
		_, _, _, err := r.ResolveTTL(ctx, host, dnsmessage.TypeA)
		cancel()
		if !errors.Is(err, ErrResolveTimeout) {
			t.Fatalf("%s err = %v, want ErrResolveTimeout", host, err)
		}
	}

	// Conn 1 must have retired for new queries (Q4 dials conn 2), WITHOUT aborting Q3!
	addrs4, _, reused4, err := r.ResolveTTL(context.Background(), "q4-fresh.example", dnsmessage.TypeA)
	if err != nil || reused4 || len(addrs4) != 1 || addrs4[0] != netip.MustParseAddr("198.51.100.200") {
		t.Fatalf("q4 = (%v, reused=%v, err=%v), want fresh conn 2", addrs4, reused4, err)
	}
	if dials.Load() != 2 {
		t.Fatalf("dials = %d, want 2", dials.Load())
	}

	// Deliver Q3's reply on the draining conn 1; Q3 must succeed cleanly.
	firstConn.pushReply(makeAReply(q3Req, netip.MustParseAddr("198.51.100.103"), 60))
	if err := <-q3Done; err != nil {
		t.Fatalf("q3 was aborted or failed despite remaining budget: %v", err)
	}
}

func TestPooledUDPResolverUnregisterAndTimeoutCheckWaiterIdentity(t *testing.T) {
	defer goleak.VerifyNone(t)

	conn := newPoolMockUDPConn(nil)
	r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		return conn, nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() { _ = r.Close() }()

	pc, _, err := r.acquireConn(context.Background())
	if err != nil {
		t.Fatalf("acquireConn: %v", err)
	}
	oldCh := make(chan dnsResolveResult, 1)
	newCh := make(chan dnsResolveResult, 1)

	r.mu.Lock()
	pc.pending[0x1234] = pooledPendingQuery{ch: newCh, fqdn: "new.example.", qtype: dnsmessage.TypeA}
	r.mu.Unlock()

	// Stale cancel/timeout carrying oldCh must NOT remove newCh or increment consecTO.
	r.unregisterPending(pc, 0x1234, oldCh)
	r.handleTimeout(pc, 0x1234, oldCh, true, time.Now().Add(-time.Second))

	r.mu.Lock()
	cur, ok := pc.pending[0x1234]
	consec := pc.consecTO
	retired := pc.retired
	r.mu.Unlock()
	if !ok || cur.ch != newCh {
		t.Fatalf("stale cleanup deleted active waiter: ok=%v", ok)
	}
	if consec != 0 || retired {
		t.Fatalf("stale timeout mutated socket state: consecTO=%d retired=%v", consec, retired)
	}
}

type writeTimeoutSecondMockConn struct {
	*poolMockUDPConn
	mu                sync.Mutex
	writeDeadline     time.Time
	write2Started     chan struct{}
	write2TimedOut    chan struct{}
	write2StartOnce   sync.Once
	write2TimeoutOnce sync.Once
	q1ReqCh           chan *dnsmessage.Msg
}

func newWriteTimeoutSecondMockConn() *writeTimeoutSecondMockConn {
	return &writeTimeoutSecondMockConn{
		poolMockUDPConn: newPoolMockUDPConn(nil),
		write2Started:   make(chan struct{}),
		write2TimedOut:  make(chan struct{}),
		q1ReqCh:         make(chan *dnsmessage.Msg, 1),
	}
}

func (c *writeTimeoutSecondMockConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *writeTimeoutSecondMockConn) Write(p []byte) (int, error) {
	n := c.writeCount.Add(1)
	var req dnsmessage.Msg
	_ = req.Unpack(p)
	if n == 1 {
		c.q1ReqCh <- req.Copy()
		return len(p), nil
	}
	// Simulate second write stalling until its write deadline expires.
	c.write2StartOnce.Do(func() { close(c.write2Started) })
	c.mu.Lock()
	dl := c.writeDeadline
	c.mu.Unlock()
	wait := 80 * time.Millisecond
	if !dl.IsZero() {
		if d := time.Until(dl); d < wait && d > 0 {
			wait = d
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	case <-timer.C:
		c.write2TimeoutOnce.Do(func() { close(c.write2TimedOut) })
		return 0, os.ErrDeadlineExceeded
	}
}

func TestPooledUDPResolverCancelledWriteTimeoutDoesNotAbortSiblingQuery(t *testing.T) {
	defer goleak.VerifyNone(t)

	conn := newWriteTimeoutSecondMockConn()
	r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		return conn, nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() { _ = r.Close() }()

	// Q1 sends successfully and waits with a generous 2s budget.
	q1Done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		addrs, _, _, err := r.ResolveTTL(ctx, "q1-sibling.example", dnsmessage.TypeA)
		if err != nil {
			q1Done <- err
			return
		}
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.111") {
			q1Done <- fmt.Errorf("q1 addrs = %v, want 198.51.100.111", addrs)
			return
		}
		q1Done <- nil
	}()
	q1Req := <-conn.q1ReqCh

	// Q2 shares conn, enters blocking Write #2, cancels after 30ms, and its write subsequently times out.
	ctx2, cancel2 := context.WithCancel(context.Background())
	q2Done := make(chan error, 1)
	go func() {
		_, _, _, err := r.ResolveTTL(ctx2, "q2-cancel.example", dnsmessage.TypeA)
		q2Done <- err
	}()
	<-conn.write2Started
	time.Sleep(30 * time.Millisecond)
	cancel2()
	if err := <-q2Done; !errors.Is(err, context.Canceled) {
		t.Fatalf("q2 err = %v, want context.Canceled", err)
	}

	// Wait until Q2's underlying write actually returns os.ErrDeadlineExceeded.
	<-conn.write2TimedOut
	time.Sleep(20 * time.Millisecond)

	// Deliver Q1's reply AFTER Q2's write timeout; Q1 must still succeed cleanly.
	conn.pushReply(makeAReply(q1Req, netip.MustParseAddr("198.51.100.111"), 60))
	if err := <-q1Done; err != nil {
		t.Fatalf("q1 was aborted by cancelled sibling's write timeout: %v", err)
	}
}

// blockingCloseLikeAnyTLSConn models a transport whose Close() waits on the
// same write mutex as a blocked Write() (like AnyTLS stream.Close sending FIN).
type blockingCloseLikeAnyTLSConn struct {
	writeMu     sync.Mutex
	releaseW    chan struct{}
	releaseOnce sync.Once
	closeCh     chan struct{}
	closeOnce   sync.Once
}

func newBlockingCloseLikeAnyTLSConn() *blockingCloseLikeAnyTLSConn {
	return &blockingCloseLikeAnyTLSConn{
		releaseW: make(chan struct{}),
		closeCh:  make(chan struct{}),
	}
}

func (c *blockingCloseLikeAnyTLSConn) releaseWrite() {
	c.releaseOnce.Do(func() { close(c.releaseW) })
}

func (c *blockingCloseLikeAnyTLSConn) Read(_ []byte) (int, error) {
	<-c.closeCh
	return 0, io.EOF
}

func (c *blockingCloseLikeAnyTLSConn) Write(_ []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	<-c.releaseW
	return 0, net.ErrClosed
}

func (c *blockingCloseLikeAnyTLSConn) Close() error {
	c.writeMu.Lock()
	c.closeOnce.Do(func() { close(c.closeCh) })
	c.writeMu.Unlock()
	return nil
}

func (c *blockingCloseLikeAnyTLSConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingCloseLikeAnyTLSConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingCloseLikeAnyTLSConn) SetWriteDeadline(time.Time) error { return nil }

func TestPooledUDPResolverSlowCloseDoesNotBlockQueryReturn(t *testing.T) {
	defer goleak.VerifyNone(t)

	slowConn := newBlockingCloseLikeAnyTLSConn()
	r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		return slowConn, nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() {
		slowConn.releaseWrite()
		_ = r.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	_, _, _, err := r.ResolveTTL(ctx, "slow-close.example", dnsmessage.TypeA)
	elapsed := time.Since(t0)
	if !errors.Is(err, ErrResolveTimeout) {
		t.Fatalf("err = %v, want ErrResolveTimeout", err)
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("query return stalled in Close() for %v (want < 200ms for 50ms ctx)", elapsed)
	}
}

func TestPooledUDPResolverSkippedCancelledQueuedWriteDoesNotDropSibling(t *testing.T) {
	defer goleak.VerifyNone(t)

	write1Started := make(chan struct{})
	write1Release := make(chan struct{})
	q1ReqCh := make(chan *dnsmessage.Msg, 1)
	var write1Once sync.Once
	var dials atomic.Int32

	conn := newPoolMockUDPConn(nil)
	gatedConn := &gatedFirstWriteConn{
		poolMockUDPConn: conn,
		onWrite: func(n int32, req *dnsmessage.Msg) {
			if n == 1 {
				q1ReqCh <- req.Copy()
				write1Once.Do(func() { close(write1Started) })
				<-write1Release
			}
		},
	}

	r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
		dials.Add(1)
		return gatedConn, nil
	}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
	defer func() { _ = r.Close() }()

	// Q1 holds writeLoop briefly on Write #1 so Q2 queues behind it in writeCh.
	q1Done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		addrs, _, _, err := r.ResolveTTL(ctx, "q1-healthy.example", dnsmessage.TypeA)
		if err != nil {
			q1Done <- err
			return
		}
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.144") {
			q1Done <- fmt.Errorf("q1 addrs = %v, want 198.51.100.144", addrs)
			return
		}
		q1Done <- nil
	}()
	q1Req := <-q1ReqCh
	<-write1Started

	// Q2 enters writeCh while Q1 is writing, then cancels before Q2 is dequeued.
	ctx2, cancel2 := context.WithCancel(context.Background())
	q2Done := make(chan error, 1)
	go func() {
		_, _, _, err := r.ResolveTTL(ctx2, "q2-queued-cancel.example", dnsmessage.TypeA)
		q2Done <- err
	}()
	time.Sleep(15 * time.Millisecond)
	cancel2()
	close(write1Release)

	if err := <-q2Done; !errors.Is(err, context.Canceled) {
		t.Fatalf("q2 err = %v, want context.Canceled", err)
	}

	// Q1 must still receive its reply on the exact same connection without dropConn.
	conn.pushReply(makeAReply(q1Req, netip.MustParseAddr("198.51.100.144"), 60))
	if err := <-q1Done; err != nil {
		t.Fatalf("q1 aborted by skipped cancelled queued write: %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1", dials.Load())
	}
}

type gatedFirstWriteConn struct {
	*poolMockUDPConn
	onWrite func(n int32, req *dnsmessage.Msg)
}

func (c *gatedFirstWriteConn) Write(p []byte) (int, error) {
	n := c.writeCount.Add(1)
	var req dnsmessage.Msg
	_ = req.Unpack(p)
	if c.onWrite != nil {
		c.onWrite(n, &req)
	}
	return len(p), nil
}

type slowCloseAfterWriteConn struct {
	sent         chan struct{}
	sentOnce     sync.Once
	releaseClose chan struct{}
	releaseOnce  sync.Once
	closeCh      chan struct{}
	closeOnce    sync.Once
}

func newSlowCloseAfterWriteConn() *slowCloseAfterWriteConn {
	return &slowCloseAfterWriteConn{
		sent:         make(chan struct{}),
		releaseClose: make(chan struct{}),
		closeCh:      make(chan struct{}),
	}
}

func (c *slowCloseAfterWriteConn) unblockClose() {
	c.releaseOnce.Do(func() { close(c.releaseClose) })
}

func (c *slowCloseAfterWriteConn) Read(_ []byte) (int, error) {
	<-c.closeCh
	return 0, io.EOF
}

func (c *slowCloseAfterWriteConn) Write(p []byte) (int, error) {
	c.sentOnce.Do(func() { close(c.sent) })
	return len(p), nil
}

func (c *slowCloseAfterWriteConn) Close() error {
	<-c.releaseClose
	c.closeOnce.Do(func() { close(c.closeCh) })
	return nil
}

func (c *slowCloseAfterWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *slowCloseAfterWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *slowCloseAfterWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestPooledUDPResolverResetAndCloseNotifyWaitersImmediatelyOnSlowClose(t *testing.T) {
	t.Run("reset", func(t *testing.T) {
		defer goleak.VerifyNone(t)

		sc := newSlowCloseAfterWriteConn()
		r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			return sc, nil
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
		defer func() {
			sc.unblockClose()
			_ = r.Close()
		}()

		errCh := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _, _, err := r.ResolveTTL(ctx, "reset-slow-close.example", dnsmessage.TypeA)
			errCh <- err
		}()
		<-sc.sent

		t0 := time.Now()
		if !r.Reset() {
			t.Fatal("Reset() = false, want true")
		}
		if elapsed := time.Since(t0); elapsed >= 100*time.Millisecond {
			t.Fatalf("Reset() blocked on slow Close() for %v", elapsed)
		}
		select {
		case err := <-errCh:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("waiter err = %v, want net.ErrClosed", err)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("waiter did not receive net.ErrClosed promptly after Reset()")
		}
	})

	t.Run("close", func(t *testing.T) {
		defer goleak.VerifyNone(t)

		sc := newSlowCloseAfterWriteConn()
		r := NewPooledUDPResolver(funcNetDialer{fn: func(context.Context, string, string) (netproxy.Conn, error) {
			return sc, nil
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
		defer sc.unblockClose()

		errCh := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _, _, err := r.ResolveTTL(ctx, "close-slow-close.example", dnsmessage.TypeA)
			errCh <- err
		}()
		<-sc.sent

		closeDone := make(chan error, 1)
		go func() { closeDone <- r.Close() }()

		select {
		case err := <-errCh:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("waiter err = %v, want net.ErrClosed", err)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("waiter did not receive net.ErrClosed promptly after Close()")
		}

		sc.unblockClose()
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Close(): %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close() did not finish after underlying conn unblocked")
		}
	})
}

func TestPooledUDPResolverLateDialCloseIsAsyncAndTrackedByClose(t *testing.T) {
	t.Run("reset_does_not_block_caller_on_slow_late_close", func(t *testing.T) {
		defer goleak.VerifyNone(t)

		dialStarted := make(chan struct{})
		releaseDial := make(chan struct{})
		lateConn := newSlowCloseAfterWriteConn()

		r := NewPooledUDPResolver(funcNetDialer{fn: func(_ context.Context, _, _ string) (netproxy.Conn, error) {
			close(dialStarted)
			<-releaseDial
			return lateConn, nil
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
		defer func() {
			lateConn.unblockClose()
			_ = r.Close()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		errCh := make(chan error, 1)
		t0 := time.Now()
		go func() {
			_, _, _, err := r.ResolveTTL(ctx, "late-reset.example", dnsmessage.TypeA)
			errCh <- err
		}()

		<-dialStarted
		if !r.Reset() {
			t.Fatal("Reset() = false, want true during in-flight dial")
		}
		// Let ctx expire (~50ms), then release the late dial returning a slow-closing conn.
		time.Sleep(60 * time.Millisecond)
		close(releaseDial)

		err := <-errCh
		elapsed := time.Since(t0)
		if !errors.Is(err, ErrResolveTimeout) {
			t.Fatalf("err = %v, want ErrResolveTimeout", err)
		}
		if elapsed >= 200*time.Millisecond {
			t.Fatalf("caller blocked on slow late conn Close() for %v", elapsed)
		}
	})

	t.Run("close_waits_for_late_dial_conn_close", func(t *testing.T) {
		defer goleak.VerifyNone(t)

		dialStarted := make(chan struct{})
		releaseDial := make(chan struct{})
		lateConn := newSlowCloseAfterWriteConn()

		r := NewPooledUDPResolver(funcNetDialer{fn: func(_ context.Context, _, _ string) (netproxy.Conn, error) {
			close(dialStarted)
			<-releaseDial
			return lateConn, nil
		}}, netip.MustParseAddrPort("127.0.0.2:53"), "udp")
		defer lateConn.unblockClose()

		queryDone := make(chan error, 1)
		go func() {
			_, _, _, err := r.ResolveTTL(context.Background(), "late-close.example", dnsmessage.TypeA)
			queryDone <- err
		}()
		<-dialStarted

		closeDone := make(chan error, 1)
		go func() { closeDone <- r.Close() }()
		time.Sleep(20 * time.Millisecond)
		close(releaseDial)

		// Query returns net.ErrClosed immediately while Close() must wait until lateConn.Close() finishes.
		select {
		case err := <-queryDone:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("query err = %v, want net.ErrClosed", err)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("query did not return promptly after Close()")
		}

		select {
		case err := <-closeDone:
			t.Fatalf("Close() returned early (%v) before late dialed conn finished closing", err)
		case <-time.After(60 * time.Millisecond):
		}

		lateConn.unblockClose()
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Close(): %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close() did not complete after lateConn unblocked")
		}
	})
}
