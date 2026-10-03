//go:build linux

package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	outcommon "github.com/daeuniverse/outbound/common"
	outdialer "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	quic "github.com/olicesx/quic-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Opt-in, one-connection WAN fixture. Read credentials in place on the gateway;
// never export links. The client, private bind address and ready path must be
// supplied explicitly. No routes, production listeners or config are modified.
func TestTCPProxyWANLive(t *testing.T) {
	if os.Getenv("DAE_TEST_TCP_PROXY_WAN") != "1" {
		t.Skip("set DAE_TEST_TCP_PROXY_WAN=1 for the bounded WAN fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture requires root for the production socket mark")
	}
	// Dependency diagnostics can include node links. This dedicated test
	// process reports only the explicitly selected metadata below.
	logrus.StandardLogger().SetOutput(io.Discard)
	sections, _, err := config.NewMerger("/etc/dae/config.dae").Merge()
	if err != nil {
		t.Fatalf("read local configuration: %T", err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("decode local configuration: %T", err)
	}
	gopt := componentdialer.NewGlobalOption(&conf.Global, logrus.New())
	base := &wanTrackedDialer{Dialer: direct.NewDirectDialersWithOption(direct.Option{
		FallbackDNS: conf.Global.FallbackResolver,
		TCPMaxSeg:   wanFixtureMSS(t, "DAE_TEST_TCP_WAN_DIAL_MSS"),
	}).Symmetric}
	label := os.Getenv("DAE_TEST_TCP_WAN_NODE")
	var proxy netproxy.Dialer
	var property *outdialer.Property
	for _, node := range conf.Node {
		name, body := outcommon.GetTagFromLinkLikePlaintext(string(node))
		if name == "" {
			if index := strings.LastIndexByte(body, '#'); index >= 0 {
				name, _ = url.PathUnescape(body[index+1:])
			}
		}
		if name != label {
			continue
		}
		// Constructor errors may embed a URI. Output only their type. Names
		// and protocol metadata are safe to report; links stay in this process.
		d, p, e := outdialer.NewNetproxyDialerFromLink(base, &gopt.ExtraOption, string(node))
		if e != nil {
			t.Fatalf("construct local node: %T", e)
		}
		if p.Name == label {
			proxy, property = d, p
			break
		}
		if closer, ok := d.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	if proxy == nil {
		t.Fatal("requested node label was not found")
	}
	if closer, ok := proxy.(io.Closer); ok {
		defer closer.Close()
	}
	if os.Getenv("DAE_TEST_TCP_WAN_INVENTORY") == "1" {
		wanFixtureJSON(t, "WAN_INVENTORY", map[string]any{"node": property.Name, "protocol": property.Protocol})
		return
	}
	bind, e1 := netip.ParseAddr(os.Getenv("DAE_TEST_TCP_WAN_BIND"))
	client, e2 := netip.ParseAddr(os.Getenv("DAE_TEST_TCP_WAN_CLIENT"))
	if e1 != nil || e2 != nil || !bind.Is4() || !client.Is4() || !bind.IsPrivate() || !client.IsPrivate() {
		t.Fatal("explicit private bind and allowed client addresses are required")
	}
	readyPath := os.Getenv("DAE_TEST_TCP_WAN_READY")
	if readyPath == "" {
		t.Fatal("explicit ready path is required")
	}
	listenMSS := wanFixtureMSS(t, "DAE_TEST_TCP_WAN_LISTEN_MSS")
	prefixParts := 1
	if raw := os.Getenv("DAE_TEST_TCP_WAN_PREFIX_PARTS"); raw != "" {
		prefixParts, err = strconv.Atoi(raw)
		if err != nil || (prefixParts != 1 && prefixParts != 2) {
			t.Fatal("prefix parts must be 1 (natural) or 2 (controlled segmentation)")
		}
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		return tcpIngressListenControl(raw, listenMSS)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	listener, err := lc.Listen(ctx, "tcp4", net.JoinHostPort(bind.String(), "0"))
	if err != nil {
		t.Fatalf("create private listener: %T", err)
	}
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(35 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ready, err := json.Marshal(map[string]any{"address": listener.Addr().String(), "node": property.Name, "protocol": property.Protocol,
		"listen_mss": listenMSS, "dial_mss": wanFixtureMSS(t, "DAE_TEST_TCP_WAN_DIAL_MSS"), "coalesce": relayWrappedGatherEnabled,
		"prefix_parts": prefixParts})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(readyPath+".next", ready, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(readyPath+".next", readyPath); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(readyPath)
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept test client: %T", err)
	}
	defer accepted.Close()
	tcp := accepted.(*net.TCPConn)
	if tcp.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap() != client.Unmap() {
		t.Fatal("unexpected client refused")
	}
	deadline, _ := ctx.Deadline()
	if local := time.Now().Add(40 * time.Second); local.Before(deadline) {
		deadline = local
	}
	if err := tcp.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	headerReader := bufio.NewReader(tcp)
	request, err := http.ReadRequest(headerReader)
	if err != nil {
		t.Fatalf("CONNECT header: %T", err)
	}
	if request.Method != http.MethodConnect || (request.Host != "speed.cloudflare.com:443" && request.Host != "cdnjs.cloudflare.com:443") {
		t.Fatal("only CONNECT to the two fixed public test origins is allowed")
	}
	if headerReader.Buffered() != 0 {
		t.Fatal("fixture client must wait for CONNECT before sending TLS")
	}
	upstream, err := proxy.DialContext(ctx, common.MagicNetwork("tcp", gopt.SoMarkFromDae, conf.Global.Mptcp), request.Host)
	if err != nil {
		t.Fatalf("proxy dial failed: %T", err)
	}
	defer upstream.Close()
	if _, ok := unwrapRelayTCPConn(upstream); ok {
		t.Fatal("fixture requires an opaque protocol connection to preserve the production copy path")
	}
	if err := upstream.SetDeadline(deadline); err != nil {
		t.Fatalf("proxy deadline: %T", err)
	}
	if _, err := io.WriteString(tcp, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	ingress := &wanIngressCounter{TCPConn: tcp, initial: wanTCPInfo(tcp)}
	source := &wanBufioSource{bufioConn: &bufioConn{Conn: ingress, reader: bufio.NewReaderSize(ingress, 4096)}, prefixParts: prefixParts}
	if _, err := source.reader.Peek(1); err != nil {
		t.Fatalf("TLS prefix: %T", err)
	}
	observed := &wanProxyCounter{Conn: upstream, source: source}
	var up, down atomic.Int64
	core := newRelayCore(source, observed, defaultRelayCopyEngine{}, func(n int64) { down.Add(n) }, func(n int64) { up.Add(n) })
	start := time.Now()
	relayErr := core.run(ctx)
	if up.Load() != observed.written.Load() || down.Load() != ingress.written.Load() {
		t.Fatalf("actual-write accounting: up=%d/%d down=%d/%d", up.Load(), observed.written.Load(), down.Load(), ingress.written.Load())
	}
	if up.Load() == 0 || down.Load() == 0 {
		t.Fatal("WAN fixture did not relay both directions")
	}
	// This result proves logical-stream accounting, not delivery. A sample
	// is valid only when the client independently verifies TLS, HTTP status
	// and the complete expected body. Preserve relay errors for that join.
	wanFixtureJSON(t, "WAN_RESULT", map[string]any{
		"node": property.Name, "protocol": property.Protocol, "listen_mss": listenMSS,
		"dial_mss": wanFixtureMSS(t, "DAE_TEST_TCP_WAN_DIAL_MSS"), "coalesce": relayWrappedGatherEnabled,
		"prefix_parts": prefixParts, "prefix_segments": source.prefixSegments,
		"relay_seconds": time.Since(start).Seconds(), "relay_error_type": fmt.Sprintf("%T", relayErr),
		"relay_error_details": wanRelayErrorDetails(relayErr),
		"up_bytes":            up.Load(), "down_bytes": down.Load(), "source_read_bytes": ingress.read.Load(),
		"proxy_read_bytes": observed.read.Load(), "prefix_bytes": source.prefixBytes, "gather_body_bytes": source.gatherBodyBytes,
		"first_write_bytes": observed.firstWriteBytes, "proxy_write_calls": observed.writeCalls,
		"ingress_tcp": ingress.snapshots(), "wire_tcp": base.snapshots(),
	})
}

// Classify teardown without printing remote addresses, URIs or error messages.
func wanRelayErrorDetails(err error) map[string]any {
	result := map[string]any{
		"closed": errors.Is(err, net.ErrClosed), "canceled": errors.Is(err, context.Canceled),
		"deadline": errors.Is(err, context.DeadlineExceeded),
	}
	var stream *quic.StreamError
	if errors.As(err, &stream) {
		result["quic_stream_code"] = uint64(stream.ErrorCode)
		result["quic_stream_remote"] = stream.Remote
	}
	var network net.Error
	if errors.As(err, &network) {
		result["timeout"] = network.Timeout()
	}
	return result
}

func wanFixtureMSS(t *testing.T, key string) int {
	t.Helper()
	raw := os.Getenv(key)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || (n != 0 && n != 1380) {
		t.Fatalf("%s must be 0 or 1380", key)
	}
	return n
}

func wanFixtureJSON(t *testing.T, prefix string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s %s\n", prefix, data)
}

type wanTCPStats struct {
	Available   bool   `json:"available"`
	SendMSS     uint32 `json:"send_mss"`
	ReceiveMSS  uint32 `json:"receive_mss"`
	RTT         uint32 `json:"rtt_us"`
	Retransmits uint32 `json:"total_retransmits"`
}

func wanTCPInfo(tcp *net.TCPConn) wanTCPStats {
	raw, err := tcp.SyscallConn()
	if err != nil {
		return wanTCPStats{}
	}
	var info *unix.TCPInfo
	var sockErr error
	if err := raw.Control(func(fd uintptr) { info, sockErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil || sockErr != nil {
		return wanTCPStats{}
	}
	return wanTCPStats{true, info.Snd_mss, info.Rcv_mss, info.Rtt, info.Total_retrans}
}

type wanTrackedDialer struct {
	netproxy.Dialer
	mu      sync.Mutex
	sockets []*wanTrackedTCP
}

func (d *wanTrackedDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if tcp, ok := unwrapRelayTCPConn(c); ok {
		tracked := &wanTrackedTCP{Conn: c, tcp: tcp, initial: wanTCPInfo(tcp)}
		d.mu.Lock()
		d.sockets = append(d.sockets, tracked)
		d.mu.Unlock()
		return tracked, nil
	}
	// Preserve all UDP ancillary/receiver capabilities for QUIC.
	return c, nil
}

func (d *wanTrackedDialer) snapshots() []map[string]wanTCPStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]map[string]wanTCPStats, 0, len(d.sockets))
	for _, c := range d.sockets {
		c.mu.Lock()
		final := c.final
		c.mu.Unlock()
		if !final.Available {
			final = wanTCPInfo(c.tcp)
		}
		result = append(result, map[string]wanTCPStats{"initial": c.initial, "final": final})
	}
	return result
}

type wanTrackedTCP struct {
	netproxy.Conn
	tcp     *net.TCPConn
	initial wanTCPStats
	mu      sync.Mutex
	final   wanTCPStats
}

func (c *wanTrackedTCP) UnderlyingConn() net.Conn              { return c.tcp }
func (c *wanTrackedTCP) CloseWrite() error                     { return c.tcp.CloseWrite() }
func (c *wanTrackedTCP) CloseRead() error                      { return c.tcp.CloseRead() }
func (c *wanTrackedTCP) SyscallConn() (syscall.RawConn, error) { return c.tcp.SyscallConn() }
func (c *wanTrackedTCP) Close() error {
	c.mu.Lock()
	if !c.final.Available {
		c.final = wanTCPInfo(c.tcp)
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

type wanIngressCounter struct {
	*net.TCPConn
	read, written atomic.Int64
	initial       wanTCPStats
	mu            sync.Mutex
	final         wanTCPStats
}

func (c *wanIngressCounter) UnderlyingConn() net.Conn { return c.TCPConn }
func (c *wanIngressCounter) Close() error {
	c.mu.Lock()
	if !c.final.Available {
		c.final = wanTCPInfo(c.TCPConn)
	}
	c.mu.Unlock()
	return c.TCPConn.Close()
}
func (c *wanIngressCounter) snapshots() map[string]wanTCPStats {
	c.mu.Lock()
	final := c.final
	c.mu.Unlock()
	if !final.Available {
		final = wanTCPInfo(c.TCPConn)
	}
	return map[string]wanTCPStats{"initial": c.initial, "final": final}
}
func (c *wanIngressCounter) Read(p []byte) (int, error) {
	n, err := c.TCPConn.Read(p)
	c.read.Add(int64(n))
	return n, err
}
func (c *wanIngressCounter) Write(p []byte) (int, error) {
	n, err := c.TCPConn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

type wanBufioSource struct {
	*bufioConn
	prefixBytes, gatherBodyBytes int
	prefixParts, prefixSegments  int
	writeStarted                 bool
}

func (c *wanBufioSource) TakeRelaySegments() [][]byte {
	p := c.bufioConn.TakeRelaySegments()
	// Controlled workload: split already available bytes without delaying,
	// modifying or adding data. Natural traffic keeps the original segments.
	if c.prefixParts == 2 && len(p) == 1 && len(p[0]) > 1 {
		middle := len(p[0]) / 2
		p = [][]byte{p[0][:middle], p[0][middle:]}
	}
	c.prefixSegments += len(p)
	for _, b := range p {
		c.prefixBytes += len(b)
	}
	return p
}
func (c *wanBufioSource) Read(p []byte) (int, error) {
	n, err := c.bufioConn.Read(p)
	if !c.writeStarted {
		c.gatherBodyBytes += n
	}
	return n, err
}

type wanProxyCounter struct {
	netproxy.Conn
	source                      *wanBufioSource
	read, written               atomic.Int64
	writeCalls, firstWriteBytes int
}

func (c *wanProxyCounter) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}
func (c *wanProxyCounter) Write(p []byte) (int, error) {
	c.source.writeStarted = true
	if c.writeCalls == 0 {
		c.firstWriteBytes = len(p)
	}
	c.writeCalls++
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}
func (c *wanProxyCounter) CloseWrite() error {
	closeWriteRelayConn(c.Conn)
	return nil
}
