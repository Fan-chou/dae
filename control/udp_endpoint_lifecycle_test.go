package control

import (
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
)

// mockPacketConn is a minimal netproxy.PacketConn whose WriteTo result is
// scriptable per test.
type mockPacketConn struct {
	writeToFn func(p []byte, addr string) (int, error)
}

func (m *mockPacketConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (m *mockPacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *mockPacketConn) WriteTo(p []byte, addr string) (int, error) {
	if m.writeToFn != nil {
		return m.writeToFn(p, addr)
	}
	return len(p), nil
}
func (m *mockPacketConn) Close() error                       { return nil }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func newTestEndpoint(conn netproxy.PacketConn) *UdpEndpoint {
	return &UdpEndpoint{conn: conn}
}

// The ss/vmess regression: protocol dialers that return the encapsulated
// datagram size (len(payload)+overhead) must NOT be treated as a short write.
func TestUdpEndpointWriteToAcceptsOverheadReturn(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			// shadowsocks AEAD returns len(payload)+39 (salt+metadata+tag)
			return len(p) + 39, nil
		},
	}
	ue := newTestEndpoint(mock)
	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("WriteTo with overhead return should succeed, got err: %v", err)
	}
	if n != len("hello world")+39 {
		t.Fatalf("expected encapsulated length %d, got %d", len("hello world")+39, n)
	}
	if ue.dead.Load() {
		t.Fatal("endpoint must not be retired when WriteTo returns n > len(b)")
	}
	if !ue.hasSent.Load() {
		t.Fatal("hasSent should be set after a successful write")
	}
}

// A genuine short write (n < len(b)) must still retire the endpoint.
func TestUdpEndpointWriteToRetiresOnRealShortWrite(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return len(p) - 1, nil
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err == nil || !stderrors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired on a real short write")
	}
}

// fdae bounds consecutive tolerated write errors and resets on success.
func TestUdpEndpointWriteToToleratesTransientErrors(t *testing.T) {
	sentinel := stderrors.New("boom")
	var calls int
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			calls++
			if calls <= writeSoftErrorThreshold {
				return 0, sentinel
			}
			return len(p), nil
		},
	}
	ue := newTestEndpoint(mock)
	for i := 1; i <= writeSoftErrorThreshold; i++ {
		_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
		if !stderrors.Is(err, sentinel) {
			t.Fatalf("attempt %d: expected sentinel error, got: %v", i, err)
		}
		if !isUdpEndpointWriteTolerated(err) {
			t.Fatalf("attempt %d: expected tolerated error, got: %v", i, err)
		}
		if ue.dead.Load() {
			t.Fatalf("attempt %d: endpoint must survive tolerated errors", i)
		}
	}
	// After the transient window a write succeeds and resets the counter.
	if _, err := ue.WriteTo([]byte("ok"), "1.2.3.4:53"); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if got := ue.writeSoftErrorCount.Load(); got != 0 {
		t.Fatalf("expected write soft error counter reset, got %d", got)
	}
}

// Queue pressure drops the packet without discarding the session.
func TestUdpEndpointWriteToKeepsSessionOnDatagramQueueTimeout(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, quic.ErrDatagramQueueFullTimeout
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, quic.ErrDatagramQueueFullTimeout) {
		t.Fatalf("expected datagram queue timeout error, got: %v", err)
	}
	if ue.dead.Load() || !isUdpEndpointWriteTolerated(err) {
		t.Fatal("datagram queue timeout must preserve the session")
	}
}

// Hitting the armed write deadline means the transport stopped draining: the
// first deadline-exceeded error retires the endpoint (fail fast). Only
// non-QUIC transports arm the deadline, so this is their stall probe.
func TestUdpEndpointWriteToRetiresOnWriteDeadlineExceeded(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, os.ErrDeadlineExceeded
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error, got: %v", err)
	}
	if isUdpEndpointWriteTolerated(err) {
		t.Fatal("deadline-exceeded must not be wrapped as tolerated")
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must retire on the first write-deadline hit")
	}
}

// A closed conn is retired on the first write error, not tolerated.
func TestUdpEndpointWriteToRetiresOnClosedConn(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, net.ErrClosed
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got: %v", err)
	}
	if isUdpEndpointWriteTolerated(err) {
		t.Fatal("net.ErrClosed must not be wrapped as tolerated")
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must retire on a closed conn")
	}
}

// A game-shaped endpoint keeps its identity across loading/menu pauses.
func TestUdpEndpointKeepsGameSessionAcrossSilence(t *testing.T) {
	for _, pause := range []time.Duration{6 * time.Second, time.Minute} {
		t.Run(pause.String(), func(t *testing.T) {
			calls := 0
			conn := &mockPacketConn{writeToFn: func(p []byte, addr string) (int, error) { calls++; return len(p), nil }}
			d, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", conn)
			ue := newTestEndpoint(conn)
			ue.Dialer = d
			ue.DialTarget = "203.0.113.1:27015"
			ue.poolKey.Dst = netip.MustParseAddrPort(ue.DialTarget)
			ue.NatTimeout = QuicNatTimeout
			ue.hasReply.Store(true)
			ue.lastSendNano.Store(time.Now().Add(-pause).UnixNano())
			ue.lastReplyNano.Store(time.Now().Add(-pause).UnixNano())
			n, err := ue.WriteTo([]byte("next tick"), ue.DialTarget)
			if err != nil || n != len("next tick") || calls != 1 || ue.IsDead() {
				t.Fatalf("paused session not reused: n=%d err=%v writes=%d dead=%v", n, err, calls, ue.IsDead())
			}
			if ue.lastSendNano.Load() < time.Now().Add(-time.Second).UnixNano() {
				t.Fatal("successful send not recorded")
			}
		})
	}
}

// deadlineRecordingPacketConn records whether SetWriteDeadline was called and
// optionally implements TransportLifecycle (a QUIC-backed transport).
type deadlineRecordingPacketConn struct {
	writeToFn              func(p []byte, addr string) (int, error)
	setWriteDeadlineCalled bool
	transportDone          <-chan struct{}
}

func (c *deadlineRecordingPacketConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (c *deadlineRecordingPacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *deadlineRecordingPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (c *deadlineRecordingPacketConn) WriteTo(p []byte, addr string) (int, error) {
	if c.writeToFn != nil {
		return c.writeToFn(p, addr)
	}
	return len(p), nil
}
func (c *deadlineRecordingPacketConn) Close() error                      { return nil }
func (c *deadlineRecordingPacketConn) SetDeadline(t time.Time) error     { return nil }
func (c *deadlineRecordingPacketConn) SetReadDeadline(t time.Time) error { return nil }
func (c *deadlineRecordingPacketConn) SetWriteDeadline(t time.Time) error {
	c.setWriteDeadlineCalled = true
	return nil
}
func (c *deadlineRecordingPacketConn) TransportDone() <-chan struct{} { return c.transportDone }

// A QUIC-backed transport (TransportLifecycle implemented, non-nil channel)
// must NOT arm a write deadline: datagram send-queue backpressure is a normal
// congestion signal, not a dead peer, and connection death is handled by the
// transport lifecycle watcher.
func TestArmWriteDeadlineSkipsTransportLifecycleConn(t *testing.T) {
	conn := &deadlineRecordingPacketConn{transportDone: make(chan struct{})}
	ue := newTestEndpoint(conn)

	ue.armWriteDeadline(time.Now())

	if conn.setWriteDeadlineCalled {
		t.Fatal("armWriteDeadline must not call SetWriteDeadline on a TransportLifecycle conn")
	}
	if ue.writeDeadlineArmedAtNano.Load() != 0 {
		t.Fatal("writeDeadlineArmedAtNano must not be armed for a TransportLifecycle conn")
	}
}

// Transports without a transport-lifecycle channel keep the legacy
// write-deadline behaviour for dead-peer detection.
func TestArmWriteDeadlineStillArmsPlainConn(t *testing.T) {
	conn := &deadlineRecordingPacketConn{}
	ue := newTestEndpoint(conn)

	ue.armWriteDeadline(time.Now())

	if !conn.setWriteDeadlineCalled {
		t.Fatal("armWriteDeadline must keep arming plain (non-lifecycle) conns")
	}
	if ue.writeDeadlineArmedAtNano.Load() == 0 {
		t.Fatal("writeDeadlineArmedAtNano should be armed for a plain conn")
	}
}

func TestCanonicalReplyFromUsesSymmetricPoolKey(t *testing.T) {
	orig := netip.MustParseAddrPort("198.18.0.10:443")
	resolved := netip.MustParseAddrPort("203.0.113.20:443")
	ue := &UdpEndpoint{poolKey: UdpEndpointKey{Dst: orig}}
	if got := ue.canonicalReplyFrom(resolved); got != orig {
		t.Fatalf("canonicalReplyFrom() = %v, want original dest %v", got, orig)
	}

	fullCone := &UdpEndpoint{}
	if got := fullCone.canonicalReplyFrom(resolved); got != resolved {
		t.Fatalf("FullCone canonicalReplyFrom() = %v, want server peer %v", got, resolved)
	}
}

func TestUdpEndpointWriteToRetiresOnPersistentError(t *testing.T) {
	sentinel := stderrors.New("boom")
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, sentinel
		},
	}
	ue := newTestEndpoint(mock)
	for i := 0; i < writeSoftErrorThreshold; i++ {
		if _, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53"); !isUdpEndpointWriteTolerated(err) {
			t.Fatalf("attempt %d: expected tolerated error, got: %v", i+1, err)
		}
	}
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !stderrors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired after the tolerated threshold is exceeded")
	}
}

type independentDeadlinePacketConn struct{ deadlineRecordingPacketConn }

func (*independentDeadlinePacketConn) SupportsIndependentPacketWriteDeadline() bool { return true }

func TestIndependentDatagramDeadlineKeepsSession(t *testing.T) {
	done := make(chan struct{})
	conn := &independentDeadlinePacketConn{deadlineRecordingPacketConn{transportDone: done, writeToFn: func([]byte, string) (int, error) { return 0, os.ErrDeadlineExceeded }}}
	d, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", conn)
	ue := newTestEndpoint(conn)
	ue.Dialer = d
	for range 5 {
		_, err := ue.WriteTo([]byte("tick"), "192.0.2.1:27015")
		if !isUdpEndpointWriteTolerated(err) || ue.IsDead() {
			t.Fatalf("deadline retired datagram session: %v", err)
		}
	}
	if !conn.setWriteDeadlineCalled {
		t.Fatal("independent deadline not armed")
	}
	close(done)
	if _, err := ue.WriteTo([]byte("tick"), "192.0.2.1:27015"); err == nil || !ue.IsDead() {
		t.Fatal("dead transport must retire")
	}
}
