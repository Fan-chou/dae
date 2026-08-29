package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// blockingMockConn blocks on Read until closed; Write always succeeds.
type blockingMockConn struct {
	closed atomic.Bool
}

func (m *blockingMockConn) Read(b []byte) (int, error) {
	for !m.closed.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	return 0, net.ErrClosed
}
func (m *blockingMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *blockingMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *blockingMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *blockingMockConn) Close() error                               { m.closed.Store(true); return nil }
func (m *blockingMockConn) SetDeadline(t time.Time) error              { return nil }
func (m *blockingMockConn) SetReadDeadline(t time.Time) error          { return nil }
func (m *blockingMockConn) SetWriteDeadline(t time.Time) error         { return nil }

// A fully idle relay (both directions blocked on Read, no traffic) must be
// reclaimed by the idle watchdog.
func TestRelayIdleWatchdogReclaimsIdleRelay(t *testing.T) {
	l := &blockingMockConn{}
	r := &blockingMockConn{}
	rc := newRelayCore(l, r, defaultRelayCopyEngine{}, nil, nil)
	// Inject a short idle bound and fast check cadence for the test.
	rc.idleTimeout = 200 * time.Millisecond
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	select {
	case <-done:
		// run returned -> both directional copies were unblocked and the
		// relay reclaimed.
	case <-time.After(3 * time.Second):
		t.Fatal("idle relay was not reclaimed by the watchdog")
	}
}

// Active relays (traffic refreshing lastActiveNano) must NOT be reclaimed.
func TestRelayIdleWatchdogKeepsActiveRelay(t *testing.T) {
	l := &blockingMockConn{}
	r := &activeMockConn{}
	rc := newRelayCore(l, r, defaultRelayCopyEngine{}, nil, nil)
	rc.idleTimeout = 300 * time.Millisecond
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Let the watchdog tick several times; an active relay must survive.
	time.Sleep(1 * time.Second)
	select {
	case err := <-done:
		t.Fatalf("active relay was reclaimed: %v", err)
	default:
	}
	cancel()
}

// Default idleTimeout is 0: a fully idle relay must not be reclaimed.
func TestRelayIdleWatchdogDisabledLeavesIdleRelay(t *testing.T) {
	l := &blockingMockConn{}
	r := &blockingMockConn{}
	rc := newRelayCore(l, r, defaultRelayCopyEngine{}, nil, nil)
	if rc.idleTimeout != 0 {
		t.Fatalf("idleTimeout = %s, want 0 (disabled)", rc.idleTimeout)
	}
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	time.Sleep(400 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("idle relay was reclaimed with idleTimeout=0: %v", err)
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not return after ctx cancel")
	}
}

// activeMockConn produces a steady stream of reads so the relay is never idle.
type activeMockConn struct {
	closed atomic.Bool
	reads  atomic.Int64
}

func (m *activeMockConn) Read(b []byte) (int, error) {
	for !m.closed.Load() {
		if m.reads.Add(1) > 0 && m.reads.Load()%5 == 0 {
			b[0] = 'x'
			return 1, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return 0, net.ErrClosed
}
func (m *activeMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *activeMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *activeMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *activeMockConn) Close() error                               { m.closed.Store(true); return nil }
func (m *activeMockConn) SetDeadline(t time.Time) error              { return nil }
func (m *activeMockConn) SetReadDeadline(t time.Time) error          { return nil }
func (m *activeMockConn) SetWriteDeadline(t time.Time) error         { return nil }

// The idle watchdog must not interfere with graceful half-close semantics:
// a relay reclaimed by the watchdog returns promptly (its reads were
// unblocked by forceClose), whatever the surfaced error.
func TestRelayIdleWatchdogCoexistsWithHalfClose(t *testing.T) {
	l := &blockingMockConn{}
	rc := newRelayCore(l, l, defaultRelayCopyEngine{}, nil, nil)
	rc.idleTimeout = 100 * time.Millisecond
	rc.idleCheckPeriod = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Both directions blocked; watchdog should reclaim after ~100ms.
	select {
	case <-done:
		// Reclaimed promptly; the surfaced error (closed conn) is expected.
	case <-time.After(3 * time.Second):
		t.Fatal("relay not reclaimed")
	}
}

// delayedReleaseMockConn simulates a QUIC stream Read that does not unblock
// immediately on Close/SetReadDeadline, but eventually returns after a delay.
// This mirrors the real-world quic-go behavior where CancelRead may take a
// tick or two to propagate to the blocked goroutine.
type delayedReleaseMockConn struct {
	closed       atomic.Bool
	closeCh      chan struct{}
	releaseDelay time.Duration
}

func newDelayedReleaseMockConn(delay time.Duration) *delayedReleaseMockConn {
	return &delayedReleaseMockConn{closeCh: make(chan struct{}), releaseDelay: delay}
}

func (m *delayedReleaseMockConn) Read(b []byte) (int, error) {
	<-m.closeCh
	time.Sleep(m.releaseDelay)
	return 0, net.ErrClosed
}
func (m *delayedReleaseMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *delayedReleaseMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *delayedReleaseMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *delayedReleaseMockConn) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		close(m.closeCh)
	}
	return nil
}
func (m *delayedReleaseMockConn) SetDeadline(t time.Time) error      { return nil }
func (m *delayedReleaseMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *delayedReleaseMockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestRelayWatchdogSurvivesCtxCancel verifies that the watchdog keeps the
// relay alive after ctx cancellation (e.g. reload) and eventually reclaims
// it when the QUIC-like delayed Read finally returns.
func TestRelayWatchdogSurvivesCtxCancel(t *testing.T) {
	// Conn whose Read releases 200ms after Close (simulating quic-go delay).
	l := newDelayedReleaseMockConn(200 * time.Millisecond)
	r := newDelayedReleaseMockConn(200 * time.Millisecond)
	rc := newRelayCore(l, r, defaultRelayCopyEngine{}, nil, nil)
	rc.idleTimeout = 5 * time.Second // long idle; we test ctx-cancel, not idle
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Cancel ctx (simulating reload) after a brief warm-up.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success: the watchdog nudged forceClose, the delayed Reads
		// eventually returned, and run() finished cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("relay leaked: run() did not return after ctx cancel + delayed Read release")
	}
}

func TestRelayProductionHalfCloseTimeoutIsZero(t *testing.T) {
	rc := newRelayCore(&blockingMockConn{}, &blockingMockConn{}, defaultRelayCopyEngine{}, nil, nil)
	if rc.halfCloseTimeout != 0 {
		t.Fatalf("halfCloseTimeout = %s, want 0 (disabled in production)", rc.halfCloseTimeout)
	}
	if relayHalfCloseTimeout != 0 {
		t.Fatalf("relayHalfCloseTimeout = %s, want 0 (sockmap must not 10s force-close)", relayHalfCloseTimeout)
	}
}

func TestHalfCloseForceCloseDisabled(t *testing.T) {
	now := time.Now()
	first := now.Add(-20 * time.Second)
	if halfCloseForceClose(first, 0, now) {
		t.Fatal("timeout 0 must never force-close")
	}
	if !halfCloseForceClose(first, 10*time.Second, now) {
		t.Fatal("timeout 10s after 20s must force-close")
	}
	if halfCloseForceClose(time.Time{}, 10*time.Second, now) {
		t.Fatal("zero firstClose must not force-close")
	}
}

type eofOnceThenBlockConn struct {
	blockingMockConn
	eofOnce atomic.Bool
}

func (m *eofOnceThenBlockConn) Read(b []byte) (int, error) {
	if m.eofOnce.CompareAndSwap(false, true) {
		return 0, io.EOF
	}
	return m.blockingMockConn.Read(b)
}

type deadlineWatchConn struct {
	blockingMockConn
	deadlines atomic.Int32
}

func (m *deadlineWatchConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		m.deadlines.Add(1)
	}
	return nil
}

func TestRelayHalfCloseDisabledDoesNotSetReadDeadline(t *testing.T) {
	left := &eofOnceThenBlockConn{}
	right := &deadlineWatchConn{}
	rc := newRelayCore(left, right, defaultRelayCopyEngine{}, nil, nil)
	if rc.halfCloseTimeout != 0 {
		t.Fatalf("halfCloseTimeout = %s, want 0", rc.halfCloseTimeout)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	time.Sleep(200 * time.Millisecond)
	if got := right.deadlines.Load(); got != 0 {
		t.Fatalf("SetReadDeadline called %d times after CloseWrite, want 0", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not return after ctx cancel")
	}
}

type netproxyTCPConn struct {
	*net.TCPConn
}

func (c *netproxyTCPConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n, err := c.TCPConn.Read(p)
	return n, netip.AddrPort{}, err
}

func (c *netproxyTCPConn) WriteTo(p []byte, addr string) (int, error) {
	return c.TCPConn.Write(p)
}

func TestRelayHalfCloseDisabledDeliversDelayedPeerWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 20s half-close delivery test in short mode")
	}

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverLn.Close()

	leftCh := make(chan *net.TCPConn, 1)
	go func() {
		c, accErr := clientLn.Accept()
		if accErr != nil {
			leftCh <- nil
			return
		}
		leftCh <- c.(*net.TCPConn)
	}()
	serverCh := make(chan *net.TCPConn, 1)
	go func() {
		c, accErr := serverLn.Accept()
		if accErr != nil {
			serverCh <- nil
			return
		}
		serverCh <- c.(*net.TCPConn)
	}()

	appClient, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer appClient.Close()
	relayRightRaw, err := net.Dial("tcp", serverLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer relayRightRaw.Close()

	relayLeft := <-leftCh
	if relayLeft == nil {
		t.Fatal("accept left")
	}
	defer relayLeft.Close()
	appServer := <-serverCh
	if appServer == nil {
		t.Fatal("accept server")
	}
	defer appServer.Close()

	rc := newRelayCore(
		&netproxyTCPConn{TCPConn: relayLeft},
		&netproxyTCPConn{TCPConn: relayRightRaw.(*net.TCPConn)},
		defaultRelayCopyEngine{},
		nil,
		nil,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	if _, err := appClient.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := appClient.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, 4)
	if err := appServer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(appServer, got); err != nil {
		t.Fatalf("server did not receive request: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("server got %q, want ping", got)
	}

	time.Sleep(20 * time.Second)
	if _, err := appServer.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := appServer.Close(); err != nil {
		t.Fatal(err)
	}

	if err := appClient.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(appClient, resp); err != nil {
		t.Fatalf("client did not receive delayed response after CloseWrite: %v", err)
	}
	if string(resp) != "pong" {
		t.Fatalf("client got %q, want pong", resp)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not return")
	}
}
