//go:build linux

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
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
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// The opt-in fixture relays only synthetic DNS requests from one explicit LAN
// client to two fixed public resolvers. Node links remain on the gateway. It
// creates no control plane, changes no routes and never handles game payloads.
func TestUDPProxyWANLive(t *testing.T) {
	if os.Getenv("DAE_TEST_UDP_PROXY_WAN") != "1" {
		t.Skip("set DAE_TEST_UDP_PROXY_WAN=1 for bounded UDP diagnostics")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture requires root for the production socket mark")
	}
	bind, e1 := netip.ParseAddr(os.Getenv("DAE_TEST_UDP_WAN_BIND"))
	client, e2 := netip.ParseAddr(os.Getenv("DAE_TEST_UDP_WAN_CLIENT"))
	target := os.Getenv("DAE_TEST_UDP_WAN_TARGET")
	count, e3 := strconv.Atoi(os.Getenv("DAE_TEST_UDP_WAN_REQUESTS"))
	mode := os.Getenv("DAE_TEST_UDP_WAN_READ_MODE")
	ready := os.Getenv("DAE_TEST_UDP_WAN_READY")
	if e1 != nil || e2 != nil || !bind.Is4() || !client.Is4() || !bind.IsPrivate() || !client.IsPrivate() || ready == "" || e3 != nil || count < 1 || count > 48 {
		t.Fatal("explicit private bind/client, ready path and 1..48 requests required")
	}
	if target != "1.1.1.1:53" && target != "8.8.8.8:53" {
		t.Fatal("only the two fixed public DNS targets are allowed")
	}
	if mode != "read_from" && mode != "packet_receiver" {
		t.Fatal("explicit read_from or packet_receiver required")
	}
	logrus.StandardLogger().SetOutput(io.Discard)
	sections, _, err := config.NewMerger("/etc/dae/config.dae").Merge()
	if err != nil {
		t.Fatalf("read local configuration: %T", err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("decode local configuration: %T", err)
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	gopt := componentdialer.NewGlobalOption(&conf.Global, logger)
	base := &udpWANTrackedDialer{Dialer: direct.NewDirectDialersWithOption(direct.Option{FallbackDNS: conf.Global.FallbackResolver}).Symmetric}
	label := os.Getenv("DAE_TEST_UDP_WAN_NODE")
	var proxy netproxy.Dialer = base
	protocol := "direct"
	if label != "direct" {
		proxy = nil
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
			d, p, err := outdialer.NewNetproxyDialerFromLink(base, &gopt.ExtraOption, string(node))
			if err != nil {
				t.Fatalf("construct local node: %T", err)
			}
			if p.Name != label {
				if c, ok := d.(io.Closer); ok {
					_ = c.Close()
				}
				continue
			}
			proxy, protocol = d, p.Protocol
			break
		}
	}
	if proxy == nil {
		t.Fatal("requested node was not found")
	}
	if closer, ok := proxy.(io.Closer); ok {
		defer closer.Close()
	}
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(bind, 0)))
	if err != nil {
		t.Fatalf("private listener: %T", err)
	}
	defer listener.Close()
	metadata := map[string]any{"address": listener.LocalAddr().String(), "client": client.String(), "node": label, "protocol": protocol, "target": target, "read_mode": mode, "requests": count}
	data, _ := json.Marshal(metadata)
	if err := os.WriteFile(ready+".next", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ready+".next", ready); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(ready)
	wanFixtureJSON(t, "UDP_WAN_READY", metadata)
	ctx, cancel := context.WithTimeout(context.Background(), 220*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	buf := make([]byte, 2048)
	for index := 0; index < count; index++ {
		_ = listener.SetReadDeadline(minTime(deadline, time.Now().Add(15*time.Second)))
		n, peer, err := listener.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("test client input: %T", err)
		}
		query := new(dns.Msg)
		if peer.Addr().Unmap() != client || n > 1800 || query.Unpack(buf[:n]) != nil || !udpWANAllowedQuery(query) {
			t.Fatal("unexpected client or non-fixture request")
		}
		result, response := udpWANProbe(ctx, proxy, base, common.MagicNetwork("udp", gopt.SoMarkFromDae, false), target, mode, buf[:n], query)
		result["index"], result["node"], result["protocol"] = index, label, protocol
		wanFixtureJSON(t, "UDP_WAN_PROBE", result)
		if response == nil {
			response = []byte("UDP_WAN_ERROR")
		}
		if _, err := listener.WriteToUDPAddrPort(response, peer); err != nil {
			t.Fatalf("test client reply: %T", err)
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func udpWANAllowedQuery(m *dns.Msg) bool {
	if m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 || len(m.Answer) != 0 || len(m.Ns) != 0 || len(m.Extra) != 1 {
		return false
	}
	q := m.Question[0]
	if q.Qclass != dns.ClassINET || !((q.Name == "one.one.one.one." && q.Qtype == dns.TypeA) || (q.Name == "cloudflare.com." && q.Qtype == dns.TypeTXT)) {
		return false
	}
	opt := m.IsEdns0()
	if opt == nil || (opt.UDPSize() != 1232 && opt.UDPSize() != 4096) || len(opt.Option) != 1 {
		return false
	}
	// A private-use option changes query size without invoking the encrypted-
	// DNS-only EDNS Padding semantics. Public resolvers remain an uncontrolled
	// endpoint: a timeout by itself does not prove a path MTU failure.
	option, ok := opt.Option[0].(*dns.EDNS0_LOCAL)
	if !ok || option.Code != 65001 {
		return false
	}
	for _, b := range option.Data {
		if b != 0 {
			return false
		}
	}
	return true
}

func udpWANProbe(parent context.Context, proxy netproxy.Dialer, base *udpWANTrackedDialer, network, target, mode string, wire []byte, query *dns.Msg) (map[string]any, []byte) {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	start := time.Now()
	result := map[string]any{"id": query.Id, "request_bytes": len(wire), "qtype": query.Question[0].Qtype, "edns_size": query.IsEdns0().UDPSize(), "target": target, "read_mode": mode, "response_valid": false}
	stage, reason := "dial", "operation_failed"
	finish := func(err error) {
		result["milliseconds"] = time.Since(start).Milliseconds()
		result["error_type"] = fmt.Sprintf("%T", err)
		if err != nil {
			result["error_stage"], result["error_reason"] = stage, reason
		}
		result["timeout"] = errors.Is(err, context.DeadlineExceeded)
		var ne net.Error
		if errors.As(err, &ne) {
			result["timeout"] = ne.Timeout()
		}
		result["message_too_long"] = errors.Is(err, syscall.EMSGSIZE)
		var errno syscall.Errno
		if errors.As(err, &errno) {
			result["errno"] = int(errno)
		}
		result["carrier"] = base.snapshots()
	}
	conn, err := proxy.DialContext(ctx, network, target)
	if err != nil {
		finish(err)
		return result, nil
	}
	defer conn.Close()
	pc, ok := conn.(netproxy.PacketConn)
	if !ok {
		stage, reason = "capability", "packet_conn_unavailable"
		finish(errors.New("packet connection unavailable"))
		return result, nil
	}
	deadline, _ := ctx.Deadline()
	stage = "deadline"
	if err := pc.SetDeadline(deadline); err != nil {
		finish(err)
		return result, nil
	}
	type reply struct {
		data []byte
		peer netip.AddrPort
		err  error
	}
	var replies chan reply
	if mode == "packet_receiver" {
		receiver, ok := pc.(netproxy.PacketReceiver)
		if !ok {
			stage, reason = "capability", "receiver_unavailable"
			finish(errors.New("packet receiver unavailable"))
			return result, nil
		}
		replies = make(chan reply, 1)
		stop, registered := receiver.RegisterPacketReceiver(func(p *netproxy.ReceivedPacket) bool {
			r := reply{data: append([]byte(nil), p.Data...), peer: p.From, err: p.Err}
			p.Release()
			select {
			case replies <- r:
			default:
			}
			return true
		})
		if !registered {
			stage, reason = "capability", "receiver_registration_failed"
			finish(errors.New("packet receiver registration failed"))
			return result, nil
		}
		defer stop()
	}
	stage, reason = "write", "operation_failed"
	n, err := pc.WriteTo(wire, target)
	result["write_n"] = n
	if err != nil || n < len(wire) {
		if err == nil {
			err = io.ErrShortWrite
			reason = "short_write"
		}
		finish(err)
		return result, nil
	}
	var r reply
	stage, reason = "read", "operation_failed"
	if replies != nil {
		select {
		case r = <-replies:
		case <-ctx.Done():
			r.err = ctx.Err()
		}
	} else {
		buf := make([]byte, 8192)
		n, from, err := pc.ReadFrom(buf)
		r = reply{data: buf[:n], peer: from, err: err}
	}
	result["reply_bytes"], result["reply_peer"] = len(r.data), r.peer.String()
	if r.err == nil {
		stage = "validation"
		response := new(dns.Msg)
		err := response.Unpack(r.data)
		if err == nil {
			result["rcode"], result["truncated"], result["answers"] = response.Rcode, response.Truncated, len(response.Answer)
		}
		peer := r.peer
		if peer.IsValid() {
			peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		}
		if err != nil {
			reason = "dns_unpack_failed"
			r.err = errors.New("invalid DNS wire response")
		} else if peer != netip.MustParseAddrPort(target) {
			reason = "peer_mismatch"
			r.err = errors.New("unexpected response peer")
		} else if !response.Response || response.Id != query.Id || response.Opcode != dns.OpcodeQuery {
			reason = "transaction_mismatch"
			r.err = errors.New("unexpected DNS response or peer")
		} else if len(response.Question) != 1 || response.Question[0] != query.Question[0] {
			reason = "question_mismatch"
			r.err = errors.New("unexpected DNS question")
		} else {
			result["response_valid"] = true
		}
	}
	finish(r.err)
	if r.err != nil {
		return result, nil
	}
	return result, r.data
}

type udpWANTrackedDialer struct {
	netproxy.Dialer
	mu      sync.Mutex
	sockets []netproxy.Conn
}

func (d *udpWANTrackedDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, address)
	if err == nil {
		d.mu.Lock()
		d.sockets = append(d.sockets, c)
		d.mu.Unlock()
	}
	// Preserve every receiver/ancillary capability of the original carrier.
	return c, err
}

func (d *udpWANTrackedDialer) snapshots() []map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	var result []map[string]any
	for _, c := range d.sockets {
		rawConn, ok := c.(interface {
			SyscallConn() (syscall.RawConn, error)
		})
		if !ok {
			continue
		}
		raw, err := rawConn.SyscallConn()
		if err != nil {
			continue
		}
		s := make(map[string]any)
		if a, ok := c.(interface{ LocalAddr() net.Addr }); ok {
			s["local"] = a.LocalAddr().String()
		}
		if err := raw.Control(func(fd uintptr) {
			for name, opt := range map[string]int{"path_mtu": unix.IP_MTU, "mtu_discover": unix.IP_MTU_DISCOVER} {
				if n, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, opt); err == nil {
					s[name] = n
				}
			}
		}); err != nil {
			continue
		}
		if len(s) > 0 {
			result = append(result, s)
		}
	}
	return result
}
