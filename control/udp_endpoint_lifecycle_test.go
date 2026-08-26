package control

import (
	stderrors "errors"
	"io"
	"net/netip"
	"testing"
	"time"

	daeerrors "github.com/daeuniverse/dae/common/errors"
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

// Transient write errors are tolerated up to writeSoftErrorThreshold: the
// endpoint survives and callers can identify the dropped datagram via
// isUdpEndpointWriteTolerated. A successful write resets the counter.
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

// A datagram send-queue timeout signals a stalled transport, not a transient
// error: it must retire immediately. Counting it toward the tolerated
// threshold is unsafe — a later enqueue (which is not a peer ACK) would reset
// the counter and let a half-dead transport dodge retirement forever.
func TestUdpEndpointWriteToRetiresOnDatagramQueueTimeout(t *testing.T) {
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
	if !ue.dead.Load() {
		t.Fatal("endpoint must retire on a datagram send-queue timeout")
	}
}

// A write error beyond the tolerated threshold must retire the endpoint and
// surface the underlying error (not the tolerated wrapper).
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

// A session that was established (hasReply) but whose client has been silent
// for udpEndpointSendStaleTimeout must be rebuilt on the next write: the pause
// means a new round is starting and the remote (e.g. a game server) may have
// reaped the old session. Retiring now lets the next GetOrCreate dial a fresh
// hy2 session with a new forwarding source port.
//
// Rebuild is gated to the game profile (proxy-backed, not H3/DNS ports, no
// sniffed domain). A nil Dialer is userspace-direct and must not rebuild.
func TestUdpEndpointWriteToRebuildsStaleSession(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newGameProxyEndpoint(t, mock, "203.0.113.1:27015")
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())
	ue.lastReplyNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())

	_, err := ue.WriteTo([]byte("hello world"), "203.0.113.1:27015")
	if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected ErrClosedConnection on stale session, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired when the client session is stale")
	}
}

// An established session whose client sent recently must NOT be rebuilt: this
// keeps normal gameplay (sub-second heartbeats) on the same hy2 session. After
// a successful write the lastSendNano is refreshed.
func TestUdpEndpointWriteToKeepsFreshSession(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().UnixNano())
	ue.lastReplyNano.Store(time.Now().UnixNano())

	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("expected success on fresh session, got: %v", err)
	}
	if n != len("hello world") {
		t.Fatalf("expected %d bytes written, got %d", len("hello world"), n)
	}
	if ue.dead.Load() {
		t.Fatal("fresh session must not be retired")
	}
	if ue.lastSendNano.Load() < time.Now().Add(-time.Second).UnixNano() {
		t.Fatal("lastSendNano must be refreshed after a successful write")
	}
}

// A client that paused briefly but whose server is still replying must NOT be
// rebuilt: the session is mid-round and only the client side is silent. This
// is what keeps a live game from being kicked when the player hits a loading
// or idle stretch.
func TestUdpEndpointWriteToKeepsSessionWhileServerReplyFresh(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())
	ue.lastReplyNano.Store(time.Now().UnixNano())

	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("expected success while upstream still replies, got: %v", err)
	}
	if n != len("hello world") {
		t.Fatalf("expected %d bytes written, got %d", len("hello world"), n)
	}
	if ue.dead.Load() {
		t.Fatal("endpoint must not be retired while the upstream is still replying")
	}
}

// A probing endpoint (never replied) is not subject to stale-session rebuild:
// the reply guard is only meaningful once the session has been established.
func TestUdpEndpointWriteToProbingNotRebuilt(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newTestEndpoint(mock)
	// hasReply stays false; lastSendNano is irrelevant.

	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("expected success while probing, got: %v", err)
	}
	if n != len("hello world") {
		t.Fatalf("expected %d bytes written, got %d", len("hello world"), n)
	}
	if ue.dead.Load() {
		t.Fatal("probing endpoint must not be retired")
	}
}

func newGameProxyEndpoint(t *testing.T, conn netproxy.PacketConn, dialTarget string) *UdpEndpoint {
	t.Helper()
	d, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", conn)
	ue := newTestEndpoint(conn)
	ue.Dialer = d
	ue.DialTarget = dialTarget
	if ap, err := netip.ParseAddrPort(dialTarget); err == nil {
		ue.poolKey.Dst = ap
	}
	return ue
}

func markBothDirectionsStale(ue *UdpEndpoint) {
	ue.hasReply.Store(true)
	ue.lastSendNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())
	ue.lastReplyNano.Store(time.Now().Add(-2 * udpEndpointSendStaleTimeout).UnixNano())
}

func TestStaleRebuildTimeout(t *testing.T) {
	hy2, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", &mockPacketConn{})
	ss, _ := newCountingProxyEndpointDialer("shadowsocks", "127.0.0.1:8388", &mockPacketConn{})
	direct, _ := newCountingProxyEndpointDialer("direct", "", &mockPacketConn{})

	tests := []struct {
		name  string
		setup func(*UdpEndpoint)
		want  time.Duration
	}{
		{
			name: "hy2 full-cone game",
			setup: func(ue *UdpEndpoint) {
				ue.Dialer = hy2
				ue.DialTarget = "203.0.113.1:27015"
			},
			want: udpEndpointSendStaleTimeout,
		},
		{
			name: "hy2 quic game on non-443",
			setup: func(ue *UdpEndpoint) {
				ue.Dialer = hy2
				ue.poolKey.Dst = netip.MustParseAddrPort("203.0.113.1:27015")
			},
			want: udpEndpointSendStaleTimeout,
		},
		{
			name: "hy2 h3 on 443",
			setup: func(ue *UdpEndpoint) {
				ue.Dialer = hy2
				ue.poolKey.Dst = netip.MustParseAddrPort("203.0.113.1:443")
			},
			want: 0,
		},
		{
			name: "hy2 sniffed domain on game port",
			setup: func(ue *UdpEndpoint) {
				ue.Dialer = hy2
				ue.DialTarget = "203.0.113.1:8443"
				ue.SniffedDomain = "video.example.com"
			},
			want: 0,
		},
		{
			name: "hy2 doq 853",
			setup: func(ue *UdpEndpoint) {
				ue.Dialer = hy2
				ue.poolKey.Dst = netip.MustParseAddrPort("1.1.1.1:853")
			},
			want: 0,
		},
		{
			name: "userspace direct",
			setup: func(ue *UdpEndpoint) {
				ue.Dialer = direct
				ue.DialTarget = "203.0.113.1:27015"
			},
			want: 0,
		},
		{
			name: "shadowsocks",
			setup: func(ue *UdpEndpoint) {
				ue.Dialer = ss
				ue.DialTarget = "203.0.113.1:27015"
			},
			want: 0,
		},
		{
			name:  "nil dialer",
			setup: func(ue *UdpEndpoint) {},
			want:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ue := newTestEndpoint(&mockPacketConn{})
			tt.setup(ue)
			if got := ue.staleRebuildTimeout(); got != tt.want {
				t.Fatalf("staleRebuildTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUdpEndpointWriteToKeepsStaleDirectAndH3(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*UdpEndpoint)
	}{
		{
			name: "userspace direct",
			setup: func(ue *UdpEndpoint) {
				d, _ := newCountingProxyEndpointDialer("direct", "", ue.conn)
				ue.Dialer = d
				ue.DialTarget = "203.0.113.1:27015"
			},
		},
		{
			name: "hy2 h3 443",
			setup: func(ue *UdpEndpoint) {
				d, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", ue.conn)
				ue.Dialer = d
				ue.poolKey.Dst = netip.MustParseAddrPort("203.0.113.1:443")
				ue.DialTarget = "203.0.113.1:443"
			},
		},
		{
			name: "hy2 sniffed video",
			setup: func(ue *UdpEndpoint) {
				d, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", ue.conn)
				ue.Dialer = d
				ue.DialTarget = "203.0.113.1:8443"
				ue.SniffedDomain = "video.example.com"
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPacketConn{}
			ue := newTestEndpoint(mock)
			tt.setup(ue)
			markBothDirectionsStale(ue)
			n, err := ue.WriteTo([]byte("hello world"), ue.DialTarget)
			if err != nil {
				t.Fatalf("expected success, got: %v", err)
			}
			if n != len("hello world") {
				t.Fatalf("expected %d bytes written, got %d", len("hello world"), n)
			}
			if ue.dead.Load() {
				t.Fatal("non-game profile must not rebuild after bidirectional silence")
			}
		})
	}
}

func TestUdpEndpointWriteToRebuildsStaleQuicGame(t *testing.T) {
	mock := &mockPacketConn{}
	ue := newGameProxyEndpoint(t, mock, "203.0.113.1:27015")
	markBothDirectionsStale(ue)

	_, err := ue.WriteTo([]byte("hello world"), "203.0.113.1:27015")
	if !stderrors.Is(err, daeerrors.ErrClosedConnection) {
		t.Fatalf("expected rebuild for non-443 QUIC game, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("non-443 QUIC game must still rebuild after bidirectional silence")
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
