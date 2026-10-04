// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	ss "github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
	"github.com/sirupsen/logrus"
)

// The relay keeps a real UDP mapping per client socket and application peer.
// The fault drops only B's original mapping; A and all new mappings keep working.
type rebuildRelay struct {
	udp         *net.UDPConn
	tcp         net.Listener
	key         *ss.Key
	mu          sync.Mutex
	connections []net.Conn
	mappings    map[string]*net.UDPConn
	seen        map[string]int
	first       netip.AddrPort
	badPeer     netip.AddrPort
	drop        atomic.Bool
	wg          sync.WaitGroup
	err         chan error
}

func listenRebuildUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func rebuildEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	c := listenRebuildUDP(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 2048)
		for {
			n, p, e := c.ReadFromUDPAddrPort(b)
			if e != nil {
				return
			}
			_, _ = c.WriteToUDPAddrPort(b[:n], p)
		}
	}()
	t.Cleanup(func() { _ = c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func newRebuildRelay(t *testing.T, kind string, badPeer netip.AddrPort) (*rebuildRelay, netproxy.Dialer) {
	t.Helper()
	r := &rebuildRelay{udp: listenRebuildUDP(t), badPeer: badPeer, mappings: make(map[string]*net.UDPConn), seen: make(map[string]int), err: make(chan error, 16)}
	addr := r.udp.LocalAddr().String()
	var d netproxy.Dialer
	var err error
	if kind == "shadowsocks" {
		conf := ciphers.AeadCiphersConf["aes-128-gcm"]
		r.key = &ss.Key{CipherConf: conf, MasterKey: common.EVPBytesToKey("fixture-password", conf.KeyLen)}
		d, err = protocol.NewDialer("shadowsocks", direct.FullconeDirect, protocol.Header{IsClient: true, ProxyAddress: addr, Cipher: "aes-128-gcm", Password: "fixture-password"})
	} else {
		r.tcp, err = net.Listen("tcp4", "127.0.0.1:0")
		if err == nil {
			d, err = socks5.NewSocks5("socks5://"+r.tcp.Addr().String(), direct.FullconeDirect)
		}
		if err == nil {
			r.wg.Add(1)
			go r.accept()
		}
	}
	if err != nil {
		_ = r.udp.Close()
		t.Fatal(err)
	}
	r.wg.Add(1)
	go r.serve()
	t.Cleanup(func() {
		_ = r.udp.Close()
		if r.tcp != nil {
			_ = r.tcp.Close()
		}
		r.mu.Lock()
		for _, c := range r.connections {
			_ = c.Close()
		}
		for _, c := range r.mappings {
			_ = c.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
		select {
		case e := <-r.err:
			t.Errorf("relay: %v", e)
		default:
		}
	})
	return r, d
}

func (r *rebuildRelay) accept() {
	defer r.wg.Done()
	for {
		c, e := r.tcp.Accept()
		if e != nil {
			return
		}
		r.mu.Lock()
		r.connections = append(r.connections, c)
		r.mu.Unlock()
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			var h [2]byte
			if _, e := io.ReadFull(c, h[:]); e != nil {
				return
			}
			methods := make([]byte, int(h[1]))
			if _, e := io.ReadFull(c, methods); e != nil {
				return
			}
			if _, e := c.Write([]byte{5, 0}); e != nil {
				return
			}
			var q [10]byte
			if _, e := io.ReadFull(c, q[:]); e != nil {
				return
			}
			if q[0] != 5 || q[1] != 3 || q[3] != 1 {
				r.err <- fmt.Errorf("unexpected UDP associate: %x", q)
				return
			}
			p := r.udp.LocalAddr().(*net.UDPAddr).AddrPort()
			b := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
			binary.BigEndian.PutUint16(b[8:], p.Port())
			if _, e := c.Write(b); e != nil {
				return
			}
			_ = c.SetDeadline(time.Time{})
			_, _ = io.Copy(io.Discard, c)
		}()
	}
}

func (r *rebuildRelay) decode(b []byte) (netip.AddrPort, []byte, error) {
	if r.key != nil {
		plain, e := ss.DecryptUDPFromPool(r.key, b, ss.ShadowsocksReusedInfo)
		if e != nil {
			return netip.AddrPort{}, nil, e
		}
		defer plain.Put()
		b = plain
	} else {
		if len(b) < 3 || b[2] != 0 {
			return netip.AddrPort{}, nil, errors.New("fragmented SOCKS fixture")
		}
		b = b[3:]
	}
	n, e := ss.BytesSizeForMetadata(b)
	if e != nil {
		return netip.AddrPort{}, nil, e
	}
	m, e := ss.NewMetadata(b)
	if e != nil {
		return netip.AddrPort{}, nil, e
	}
	return netip.AddrPortFrom(m.IP, m.Port), append([]byte(nil), b[n:]...), nil
}
func (r *rebuildRelay) reply(client, peer netip.AddrPort, b []byte) error {
	m := ss.Metadata{Metadata: protocol.Metadata{Type: protocol.MetadataTypeIPv4, IP: peer.Addr(), Port: peer.Port()}}
	h, e := m.Bytes()
	if e != nil {
		return e
	}
	plain := append(h, b...)
	if r.key != nil {
		salt := make([]byte, r.key.CipherConf.SaltLen)
		if _, e = rand.Read(salt); e != nil {
			return e
		}
		wire, e := ss.EncryptUDPFromPool(r.key, plain, salt, ss.ShadowsocksReusedInfo)
		if e != nil {
			return e
		}
		defer wire.Put()
		_, e = r.udp.WriteToUDPAddrPort(wire, client)
		return e
	}
	_, e = r.udp.WriteToUDPAddrPort(append([]byte{0, 0, 0}, plain...), client)
	return e
}
func (r *rebuildRelay) serve() {
	defer r.wg.Done()
	b := make([]byte, 4096)
	for {
		n, client, e := r.udp.ReadFromUDPAddrPort(b)
		if e != nil {
			return
		}
		peer, payload, e := r.decode(b[:n])
		if e != nil {
			r.err <- e
			return
		}
		r.mu.Lock()
		if !r.first.IsValid() {
			r.first = client
		}
		r.seen[string(payload)]++
		key := client.String() + "/" + peer.String()
		c := r.mappings[key]
		if c == nil {
			c, e = net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(peer))
			if e == nil {
				r.mappings[key] = c
			}
		}
		shouldDrop := r.drop.Load() && client == r.first && peer == r.badPeer
		r.mu.Unlock()
		if e != nil {
			r.err <- e
			return
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, e = c.Write(payload); e != nil {
			r.err <- e
			return
		}
		n, e = c.Read(b)
		if e != nil {
			r.err <- e
			return
		}
		if !shouldDrop {
			if e = r.reply(client, peer, b[:n]); e != nil {
				return
			}
		}
	}
}
func (r *rebuildRelay) mapping(client, peer netip.AddrPort) netip.AddrPort {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.mappings[client.String()+"/"+peer.String()]; c != nil {
		return c.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	return netip.AddrPort{}
}

type rebuildDialer struct {
	next    netproxy.Dialer
	dials   atomic.Int32
	fail    atomic.Bool
	entered chan struct{}
	unblock chan struct{}
	gate    *rebuildWriteGate
}

type rebuildWriteGate struct {
	peer    string
	enabled atomic.Bool
	entered chan struct{}
	release chan struct{}
}
type rebuildGatedConn struct {
	netproxy.PacketConn
	gate *rebuildWriteGate
}

func (c *rebuildGatedConn) PacketRecoveryCapabilities() netproxy.PacketRecoveryCapabilities {
	return netproxy.RecoveryCapabilities(c.PacketConn)
}
func (c *rebuildGatedConn) ReadFromWithPeer(b []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	return netproxy.ReadFromWithPeer(c.PacketConn, b)
}
func (c *rebuildGatedConn) WriteTo(b []byte, addr string) (int, error) {
	if c.gate.enabled.Load() && addr == c.gate.peer {
		select {
		case c.gate.entered <- struct{}{}:
		default:
		}
		<-c.gate.release
	}
	return c.PacketConn.WriteTo(b, addr)
}

func (d *rebuildDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	n := d.dials.Add(1)
	if n > 1 {
		if d.entered != nil {
			select {
			case d.entered <- struct{}{}:
			default:
			}
		}
		if d.unblock != nil {
			select {
			case <-d.unblock:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if d.fail.Load() {
			return nil, errors.New("fixture prepare failure")
		}
	}
	c, err := d.next.DialContext(ctx, network, addr)
	if err == nil && n == 1 && d.gate != nil {
		return &rebuildGatedConn{PacketConn: c.(netproxy.PacketConn), gate: d.gate}, nil
	}
	return c, err
}

type rebuildReply struct {
	payload  string
	peer     netip.AddrPort
	endpoint *UdpEndpoint
}
type rebuildFixture struct {
	m       *SessionManager
	o       *udpReplyDroughtObserver
	c       *ControlPlane
	pool    *UdpEndpointPool
	old     *UdpEndpoint
	relay   *rebuildRelay
	dial    *rebuildDialer
	a, b    netip.AddrPort
	replies chan rebuildReply
	options *UdpEndpointOptions
}

func newRebuildFixture(t *testing.T, kind, mode string) *rebuildFixture {
	return newRebuildFixtureWithGate(t, kind, mode, false)
}
func newRebuildFixtureWithGate(t *testing.T, kind, mode string, gated bool) *rebuildFixture {
	t.Helper()
	f := &rebuildFixture{a: rebuildEcho(t), b: rebuildEcho(t), replies: make(chan rebuildReply, 256)}
	r, base := newRebuildRelay(t, kind, f.b)
	f.relay = r
	f.dial = &rebuildDialer{next: base}
	if gated {
		f.dial.gate = &rebuildWriteGate{peer: f.b.String(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	}
	log := logrus.New()
	log.SetOutput(io.Discard)
	d := componentdialer.NewDialer(f.dial, &componentdialer.GlobalOption{Log: log}, componentdialer.InstanceOption{DisableCheck: true}, &componentdialer.Property{})
	d.Property().Name = "proxy"
	d.Property().Protocol = kind
	d.Property().Address = r.udp.LocalAddr().String()
	g := newTestFixedOutboundGroup(d)
	g.Name = "game"
	t.Cleanup(func() { g.Close(); _ = d.Close() })
	f.m = NewSessionManager(context.Background())
	t.Cleanup(func() { _ = f.m.Close() })
	p := config.UDPReplyDroughtPolicy{Observe: mode != "off", Enforce: mode == "enforce", RequestReply: true, Group: "game", Client: netip.MustParseAddr("192.0.2.201"), Peers: []netip.AddrPort{f.a, f.b}}
	f.o = newUDPReplyDroughtObserver(p)
	if f.o != nil {
		t.Cleanup(func() { _ = f.o.Close() })
	}
	f.c = recoveryTestPlane(f.m, f.o, 1)
	resetActiveControlPlanePublicationForTest(t)
	f.c.publishActiveControlPlane()
	f.pool = NewUdpEndpointPool()
	t.Cleanup(f.pool.Close)
	nt := componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: componentdialer.UdpHealthDomainData}
	binding := UdpFlowBinding{Route: UdpRouteBinding{PolicyEpoch: routing.PolicyEpoch(1)}, Egress: UdpEgressBinding{Dialer: d, Outbound: g, Network: "udp", Target: f.a.String(), NetworkType: nt}}
	f.options = &UdpEndpointOptions{Ctx: context.Background(), Log: log, NatTimeout: time.Minute, ConnStateOwner: f.m, sessionManager: f.m, replyDrought: f.o, Handler: func(e *UdpEndpoint, b []byte, p netip.AddrPort) error {
		f.replies <- rebuildReply{string(b), p, e}
		return nil
	}, GetDialOption: func(context.Context) (*DialOption, error) {
		return &DialOption{Dialer: d, Outbound: g, Network: "udp", Target: f.a.String(), NetworkType: &nt, Binding: binding}, nil
	}}
	var err error
	f.old, _, err = f.pool.GetOrCreate(UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.201:32000")}, f.options)
	if err != nil {
		t.Fatal(err)
	}
	f.old.udpConnStateOwner = f.m
	return f
}
func waitRebuild(t *testing.T, fn func() bool) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for !fn() {
		if time.Now().After(until) {
			t.Fatal("UDP rebuild condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func (f *rebuildFixture) send(t *testing.T, e *UdpEndpoint, peer netip.AddrPort, payload string, wantReply bool) rebuildReply {
	t.Helper()
	if _, err := e.WriteTo([]byte(payload), peer.String()); err != nil {
		t.Fatal(err)
	}
	if !wantReply {
		return rebuildReply{}
	}
	select {
	case r := <-f.replies:
		if r.payload != payload || r.peer != peer {
			t.Fatalf("reply %+v, want %s/%s", r, payload, peer)
		}
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("missing fixture reply")
		return rebuildReply{}
	}
}
func (f *rebuildFixture) qualify(t *testing.T) {
	now := f.qualifyEvidence(t)
	if f.o != nil {
		f.o.scan(now)
	}
}
func (f *rebuildFixture) qualifyEvidence(t *testing.T) time.Time {
	t.Helper()
	for i := 0; i < 3; i++ {
		f.send(t, f.old, f.b, fmt.Sprintf("B/history/%d", i), true)
	}
	f.send(t, f.old, f.a, "A/before", true)
	f.old.TrackUdpConnStateTuplePair(f.old.poolKey.Src, f.a)
	f.old.TrackUdpConnStateTuplePair(f.old.poolKey.Src, f.b)
	f.relay.drop.Store(true)
	for i := 0; i < 61; i++ {
		f.send(t, f.old, f.b, fmt.Sprintf("B/drought/%d", i), false)
	}
	waitRebuild(t, func() bool { f.relay.mu.Lock(); defer f.relay.mu.Unlock(); return len(f.relay.seen) >= 65 })
	if f.o == nil {
		return time.Now()
	}
	// Only retime the 61 already completed, real datagrams. Network mappings,
	// ownership, encryption, counts and replies are never synthesized.
	flow := f.old.replyDrought
	now := time.Now()
	epoch := f.o.stamp(now) / int64(udpDroughtBucketDuration)
	flow.mu.Lock()
	p := flow.peers[f.b]
	if p.writes != 64 || p.replies != 3 {
		t.Fatalf("real evidence: %+v", p)
	}
	p.first = (epoch - 7) * int64(udpDroughtBucketDuration)
	p.lastReply = p.first
	p.lastWrite = f.o.stamp(now)
	p.invalidatedAt = 0
	for i := int64(0); i < 7; i++ {
		e := epoch - i
		writes := 10
		if i == 0 {
			writes = 1
		}
		p.buckets[e%7] = udpDroughtBucket{epoch: e, writes: writes}
	}
	flow.mu.Unlock()
	return now
}

func TestUDPRebuildRealProxyIsolation(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			f := newRebuildFixture(t, kind, "enforce")
			f.qualify(t)
			slot := f.old.rebuildPeer(f.b)
			waitRebuild(t, func() bool { return slot.owner.Load().endpoint != f.old })
			next := slot.owner.Load().endpoint
			// Every lookup and a stale prefetch must honor the published owner.
			previousPool := DefaultUdpEndpointPool
			DefaultUdpEndpointPool = f.pool
			t.Cleanup(func() { DefaultUdpEndpointPool = previousPool })
			decision := UdpFlowDecision{Key: NewUdpFlowKey(f.old.poolKey.Src, f.b)}
			_, looked, ok := lookupUdpEndpointForFlowWithPrefetch(decision, udpEndpointRouteScope{}, false, f.b, false, f.old, f.old.poolKey, true)
			if !ok || looked != next {
				t.Fatal("stale prefetch bypassed peer owner")
			}
			if looked, ok := f.m.retainedUDPEndpoint(f.old.poolKey.Src, f.b, nil, 2); !ok || looked != next {
				t.Fatal("retained lookup bypassed peer owner")
			}
			if looked := lookupCachedRoutingBinding(decision, f.b); looked.owner != next {
				t.Fatal("routing cache bypassed peer owner")
			}
			// Stale tuple acquisition must not reattach the detached B to S.
			f.old.TrackUdpConnStateTuplePair(f.old.poolKey.Src, f.b)
			f.m.udpStateMu.Lock()
			for _, peer := range []netip.AddrPort{f.a, f.b} {
				for _, pair := range [][2]netip.AddrPort{{f.old.poolKey.Src, peer}, {peer, f.old.poolKey.Src}} {
					if n := f.m.pinnedUDP[bpfTuplesKeyFromAddrPorts(pair[0], pair[1], 17)]; n != 1 {
						t.Errorf("tuple %v refs=%d", pair, n)
					}
				}
			}
			f.m.udpStateMu.Unlock()
			if next.prepared.Load() || f.dial.dials.Load() != 2 || f.old.dead.Load() {
				t.Fatal("publication affected shared ancestor")
			}
			f.relay.mu.Lock()
			originalClient := f.relay.first
			f.relay.mu.Unlock()
			oldA, oldB := f.relay.mapping(originalClient, f.a), f.relay.mapping(originalClient, f.b)
			// A late, valid packet is forwarded but never credited to the successor.
			if err := f.relay.reply(originalClient, f.b, []byte("B/late")); err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-f.replies:
				if r.payload != "B/late" || r.endpoint != f.old {
					t.Fatal("late ownership lost")
				}
			case <-time.After(time.Second):
				t.Fatal("late reply not drained")
			}
			if got := f.m.udpRebuild.Load().snapshot(time.Now()).Records[0].FreshReplies; got != 0 {
				t.Fatalf("late reply credited: %d", got)
			}
			for i := 0; i < 3; i++ {
				f.send(t, f.old, f.a, fmt.Sprintf("A/after/%d", i), true)
				r := f.send(t, f.old, f.b, fmt.Sprintf("B/new/%d", i), true)
				if r.endpoint != next {
					t.Fatal("cached ancestor sent B")
				}
				snap := f.m.udpRebuild.Load().snapshot(time.Now())
				if snap.Records[0].FreshReplies != uint64(i+1) {
					t.Fatalf("fresh evidence: %+v", snap)
				}
			}
			snap := f.m.udpRebuild.Load().snapshot(time.Now())
			if snap.Counts["committed"] != 1 || snap.Counts["recovered"] != 1 || snap.AttemptsInWindow != 1 {
				t.Fatalf("budget/result: %+v", snap)
			}
			f.relay.mu.Lock()
			var newB netip.AddrPort
			for k, c := range f.relay.mappings {
				if c.LocalAddr().(*net.UDPAddr).AddrPort() != oldB && k != originalClient.String()+"/"+f.a.String() {
					newB = c.LocalAddr().(*net.UDPAddr).AddrPort()
				}
			}
			for p, n := range f.relay.seen {
				if n != 1 {
					t.Errorf("replayed %s %d times", p, n)
				}
			}
			f.relay.mu.Unlock()
			if !newB.IsValid() || newB == oldB || f.relay.mapping(originalClient, f.a) != oldA {
				t.Fatal("remote mapping was not isolated")
			}
			if got, ok := f.pool.rebuildLookup(next.poolKey); !ok || got != next {
				t.Fatal("dedicated lookup lost")
			}
			_ = f.o.Close()
			f.send(t, f.old, f.b, "B/after-off", true)
			_ = next.Close()
			if _, err := f.old.WriteTo([]byte("B/no-ancestor-fallback"), f.b.String()); !isUdpEndpointWriteTolerated(err) {
				t.Fatalf("closed successor fell back: %v", err)
			}
			// Normal expiry/error replacement keeps the lineage and reply gate.
			opts := *f.options
			opts.replyDrought = nil
			originalDial := opts.GetDialOption
			opts.GetDialOption = func(ctx context.Context) (*DialOption, error) {
				option, err := originalDial(ctx)
				if err == nil {
					option.Target = f.b.String()
					option.Binding.Egress.Target = option.Target
					option.Binding.Route.PolicyEpoch = 2
				}
				return option, err
			}
			ordinary, _, err := f.pool.GetOrCreate(next.poolKey, &opts)
			if err != nil {
				t.Fatal(err)
			}
			if ordinary.rebuildLineage != next.rebuildLineage || ordinary.rebuildRevision != next.rebuildRevision+1 {
				t.Fatal("normal successor lost lineage")
			}
			for i := 0; i < 3; i++ {
				f.send(t, f.old, f.b, fmt.Sprintf("B/ordinary/%d", i), true)
			}
			if snap := f.m.udpRebuild.Load().snapshot(time.Now()); snap.Counts["attempt_started"] != 1 || snap.Counts["recovered"] != 2 {
				t.Fatalf("ordinary reply gate: %+v", snap)
			}
			journal := f.c.AdminUDPRecovery(0, "")
			if journal.EventCounts["recovered"] != 2 {
				t.Fatal("ordinary off successor lost recovery event")
			}
			for _, event := range journal.Records {
				if event.Kind == "recovered" && event.RuntimeID == ordinary.sessionRuntime.id {
					if event.PolicyEpoch != 2 || event.Generation != 0 || event.Revision != ordinary.rebuildRevision {
						t.Fatalf("off successor event identity: %+v", event)
					}
				}
			}

		})
	}
}

func TestUDPRebuildFenceDoesNotBlockHealthyPeer(t *testing.T) {
	f := newRebuildFixtureWithGate(t, "shadowsocks", "enforce", true)
	now := f.qualifyEvidence(t)
	gate := f.dial.gate
	var once sync.Once
	release := func() { once.Do(func() { close(gate.release) }) }
	defer release()
	gate.enabled.Store(true)
	done := make(chan error, 1)
	go func() { _, err := f.old.WriteTo([]byte("B/held-write"), f.b.String()); done <- err }()
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("write gate not entered")
	}
	f.o.scan(now)
	// The B claim remains in actual I/O while A can write and receive.
	f.send(t, f.old, f.a, "A/during-B-fence", true)
	waitRebuild(t, func() bool { return f.m.udpRebuild.Load().snapshot(time.Now()).Counts["fence_cancelled"] == 1 })
	if f.old.rebuildPeer(f.b).owner.Load().endpoint != f.old {
		t.Fatal("published over active I/O")
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old write did not finish")
	}
	waitRebuild(t, func() bool { return f.m.udpCount.Load() == 1 })
	waitRebuild(t, func() bool { f.relay.mu.Lock(); defer f.relay.mu.Unlock(); return f.relay.seen["B/held-write"] > 0 })
	f.relay.mu.Lock()
	n := f.relay.seen["B/held-write"]
	f.relay.mu.Unlock()
	if n != 1 {
		t.Fatalf("active business write replayed: %d", n)
	}
}

func TestUDPRebuildWaitingClaimIsBounded(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	m.rebuildLedger()
	old, slot, _ := testRebuildSlot(m, 1)
	if !slot.fence(context.Background(), old) {
		t.Fatal("fence failed")
	}
	defer slot.unfence()
	start := time.Now()
	_, err := slot.claim(context.Background(), true)
	if !isUdpEndpointWriteTolerated(err) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("unbounded claim: %v/%s", err, time.Since(start))
	}
	slot.mu.Lock()
	timedOut := slot.fenceTimedOut
	slot.mu.Unlock()
	if !timedOut || m.udpRebuild.Load().snapshot(time.Now()).Counts["handoff_wait_timeout"] != 1 {
		t.Fatal("claim timeout did not abort publication")
	}
}

func TestUDPRebuildExecutionExcludesUnsupportedTransport(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	o := testDroughtObserver(t, true)
	c := recoveryTestPlane(m, o, 1)
	ue := recoveryTestEndpoint(t, m, o, 1, netip.MustParseAddrPort("192.0.2.10:1200"), droughtTestPeer)
	x := &udpRebuildExecutor{plane: c, observer: o}
	// A protocol label with no capability on the actual PacketConn is insufficient.
	if reason := x.exclusion(ue, droughtTestPeer); reason != "transport_capability_missing" {
		t.Fatalf("unknown underlay admitted: %s", reason)
	}
	ue.writeBatch = &udpWriteBatchAggregator{}
	if reason := x.exclusion(ue, droughtTestPeer); reason != "batch_fence_unsupported" {
		t.Fatalf("queued batch admitted: %s", reason)
	}
	ue.writeBatch = nil
}

func TestUDPRebuildOffObserveDoNotDial(t *testing.T) {
	for _, mode := range []string{"off", "observe"} {
		t.Run(mode, func(t *testing.T) {
			f := newRebuildFixture(t, "shadowsocks", mode)
			f.qualify(t)
			if f.dial.dials.Load() != 1 || f.m.udpRebuild.Load() != nil || f.old.rebuildPeers.Load() != nil || (f.o != nil && f.o.execution.Load() != nil) {
				t.Fatal("off/observe allocated execution or changed mapping")
			}
		})
	}
}

func TestUDPRebuildPrepareFailurePreservesOwner(t *testing.T) {
	f := newRebuildFixture(t, "socks5", "enforce")
	f.dial.fail.Store(true)
	f.qualify(t)
	waitRebuild(t, func() bool { return f.m.udpRebuild.Load().snapshot(time.Now()).Counts["prepare_failed"] == 1 })
	if f.old.rebuildPeer(f.b).owner.Load().endpoint != f.old || f.old.dead.Load() || f.m.udpCount.Load() != 1 {
		t.Fatal("failed preparation changed owner/resources")
	}
	f.send(t, f.old, f.a, "A/after-failure", true)
	s := f.m.udpRebuild.Load().snapshot(time.Now())
	if s.Counts["committed"] != 0 || s.AttemptsInWindow != 1 {
		t.Fatalf("failure budget: %+v", s)
	}
}

func TestUDPRebuildReplyAndReloadCancelPreparation(t *testing.T) {
	for _, kind := range []string{"reply", "reload"} {
		t.Run(kind, func(t *testing.T) {
			f := newRebuildFixture(t, "shadowsocks", "enforce")
			f.dial.entered = make(chan struct{}, 1)
			f.dial.unblock = make(chan struct{})
			f.qualify(t)
			select {
			case <-f.dial.entered:
			case <-time.After(time.Second):
				t.Fatal("prepare did not start")
			}
			if kind == "reply" {
				f.relay.drop.Store(false)
				f.send(t, f.old, f.b, "B/recovered-original", true)
				close(f.dial.unblock)
				waitRebuild(t, func() bool { return f.m.udpRebuild.Load().snapshot(time.Now()).Counts["evidence_changed"] == 1 })
			} else {
				next := recoveryTestPlane(f.m, nil, 2)
				next.publishActiveControlPlane()
				if !f.o.execution.Load().closing.Load() {
					t.Fatal("reload did not drain executor")
				}
				f.c.publishActiveControlPlane()
				if f.o.execution.Load().closing.Load() {
					t.Fatal("rollback did not reactivate executor")
				}
			}
			if f.old.rebuildPeer(f.b).owner.Load().endpoint != f.old || f.old.dead.Load() {
				t.Fatal("cancelled prepare published")
			}
			waitRebuild(t, func() bool { return f.m.udpCount.Load() == 1 })
			if s := f.m.udpRebuild.Load().snapshot(time.Now()); s.Counts["committed"] != 0 || s.AttemptsInWindow != 1 {
				t.Fatalf("cancel budget: %+v", s)
			}
		})
	}
}
