// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

type pinnedRebuildFixture struct {
	*rebuildFixture
	pin      *UdpEndpoint
	original netip.AddrPort
	initial  PacketSnifferKey
	options  *UdpEndpointOptions
	dnsPlane *ControlPlane
	dnsIP    atomic.Value
	queries  atomic.Int32
	fake     *FakeIPStore
}

func newPinnedRebuildFixture(t *testing.T, kind string) *pinnedRebuildFixture {
	return newPinnedRebuildFixtureFamily(t, kind, false)
}

func newPinnedRebuildFixtureFamily(t *testing.T, kind string, v6 bool) *pinnedRebuildFixture {
	return newPinnedRebuildFixtureFamilies(t, kind, v6, v6, nil)
}

func newPinnedRebuildFixtureFamilies(t *testing.T, kind string, clientV6, peerV6 bool, store *UDPCrossFamilyStore) *pinnedRebuildFixture {
	return newPinnedRebuildFixtureWith(t, kind, clientV6, peerV6, store, nil)
}

// A non-nil fake store makes the client destination a DNS FakeIP mapped to
// pinned.example, as handlePktOwned records it in the dial option.
func newPinnedRebuildFixtureWith(t *testing.T, kind string, clientV6, peerV6 bool, store *UDPCrossFamilyStore, fake *FakeIPStore) *pinnedRebuildFixture {
	t.Helper()
	f := &pinnedRebuildFixture{rebuildFixture: newRebuildFixtureFamilies(t, kind, "enforce", false, store, clientV6, peerV6), fake: fake}
	f.original = netip.AddrPortFrom(netip.MustParseAddr("198.51.100.10"), f.b.Port())
	if clientV6 {
		f.original = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::10"), f.b.Port())
	}
	fakeName := ""
	if fake != nil {
		v4, v6, _, err := fake.Assign("pinned.example")
		if err != nil {
			t.Fatal(err)
		}
		if clientV6 {
			v4 = v6
		}
		f.original, fakeName = netip.AddrPortFrom(v4, f.b.Port()), "pinned.example"
	}
	key := UdpEndpointKey{Src: f.old.poolKey.Src, Dst: f.original}
	// The explicit Initial metadata also lets identity tests construct matching
	// and conflicting ingress decisions. Application datagrams are real echoes.
	f.initial = PacketSnifferKey{LAddr: key.Src, RAddr: key.Dst, DCIDLen: 1, DCID: [20]byte{1}}
	f.dnsIP.Store(f.b.Addr())
	dns := listenRebuildUDP(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [2048]byte
		for {
			n, src, err := dns.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			q := new(dnsmessage.Msg)
			if q.Unpack(b[:n]) != nil || len(q.Question) != 1 {
				continue
			}
			f.queries.Add(1)
			r := new(dnsmessage.Msg)
			r.SetReply(q)
			ip := f.dnsIP.Load().(netip.Addr)
			if q.Question[0].Qtype == dnsmessage.TypeA && ip.Is4() {
				r.Answer = []dnsmessage.RR{&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: q.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60}, A: net.IP(ip.AsSlice())}}
			} else if q.Question[0].Qtype == dnsmessage.TypeAAAA && ip.Is6() {
				r.Answer = []dnsmessage.RR{&dnsmessage.AAAA{Hdr: dnsmessage.RR_Header{Name: q.Question[0].Name, Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 60}, AAAA: net.IP(ip.AsSlice())}}
			}
			wire, _ := r.Pack()
			_, _ = dns.WriteToUDPAddrPort(wire, src)
		}
	}()
	t.Cleanup(func() { _ = dns.Close(); <-done })
	f.old.Dialer.SetResolveDNS(dns.LocalAddr().(*net.UDPAddr).AddrPort())
	f.dnsPlane = testDialControlPlane(f.old.Outbound)
	f.dnsPlane.policyIdentity = f.c.policyIdentity
	cacheKey := resolveDNSResultKey(&proxyDialResult{Dialer: f.old.Dialer, Mark: f.dnsPlane.soMarkFromDae}, "pinned.example", clientV6)
	f.dnsPlane.resolveDNSPins.store(cacheKey, f.b.Addr(), time.Now(), time.Minute)
	opts := *f.rebuildFixture.options
	// A retained endpoint may already own a read-only mapping view. Install
	// the requested view before publication rather than mutating a live flow.
	opts.crossFamily = store
	opts.GetDialOption = func(ctx context.Context) (*DialOption, error) {
		param := &proxyDialParam{Outbound: consts.OutboundUserDefinedMin, Domain: "pinned.example", Src: key.Src, Dest: key.Dst, Network: "udp"}
		if r, ok := f.m.resolveDNSRecovery.lookup(key, f.initial, false); ok {
			param.ResolveDNSRecovery = &r
		}
		res, err := f.dnsPlane.chooseProxyDialer(ctx, param)
		if err != nil {
			return nil, err
		}
		binding := f.old.sessionRuntime.binding
		binding.Route = UdpRouteBinding{PolicyEpoch: f.dnsPlane.PolicyEpoch(), Outbound: res.OutboundIndex, Mark: res.Mark, Must: res.Must}
		binding.Egress.Target, binding.Egress.SniffedDomain, binding.Egress.IsDialIp = res.DialTarget, res.SniffedDomain, true
		return &DialOption{Dialer: res.Dialer, Outbound: res.Outbound, Network: binding.Egress.Network, NetworkType: &binding.Egress.NetworkType, Target: res.DialTarget, IsDialIp: true, Binding: binding, ResolveDNSPinned: res.ResolveDNSPinned, ResolveDNSOriginalNative: fake == nil, FakeIPName: fakeName, FakeIPStore: fake, ResolveDNSInitial: f.initial, SniffedDomain: res.SniffedDomain}, nil
	}
	f.options = &opts
	var err error
	f.pin, _, err = f.pool.GetOrCreate(key, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if f.pin.pinnedTarget == nil || f.pin.DialTarget != f.b.String() {
		t.Fatal("missing fixed native DNS target")
	}
	return f
}

func (f *pinnedRebuildFixture) sendPin(t *testing.T, e *UdpEndpoint, payload string, wantReply bool) rebuildReply {
	t.Helper()
	if _, err := e.WriteTo([]byte(payload), e.dialTargetForWrite(f.original)); err != nil {
		t.Fatal(err)
	}
	if !wantReply {
		return rebuildReply{}
	}
	select {
	case r := <-f.replies:
		if r.payload != payload || r.peer != f.original {
			t.Fatalf("reply %+v, want %s from original %s", r, payload, f.original)
		}
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("missing pinned reply")
		return rebuildReply{}
	}
}

func (f *pinnedRebuildFixture) qualifyPin(t *testing.T) time.Time {
	t.Helper()
	for i := 0; i < 3; i++ {
		f.sendPin(t, f.pin, fmt.Sprintf("pin/history/%d", i), true)
	}
	f.pin.TrackUdpConnStateTuplePair(f.pin.poolKey.Src, f.original)
	f.relay.drop.Store(true)
	for i := 0; i < 61; i++ {
		f.sendPin(t, f.pin, fmt.Sprintf("pin/drought/%d", i), false)
	}
	waitRebuild(t, func() bool { f.relay.mu.Lock(); defer f.relay.mu.Unlock(); return f.relay.seen["pin/drought/60"] == 1 })
	// Retime only already completed real packets, as in the native fixture.
	now := time.Now()
	flow := f.pin.replyDrought
	epoch := f.o.stamp(now) / int64(udpDroughtBucketDuration)
	flow.mu.Lock()
	p := flow.peers[f.b]
	if p == nil || p.writes != 64 || p.replies != 3 {
		flow.mu.Unlock()
		t.Fatalf("actual-peer evidence: %+v", p)
	}
	p.first, p.lastReply = (epoch-7)*int64(udpDroughtBucketDuration), (epoch-7)*int64(udpDroughtBucketDuration)
	p.lastWrite, p.invalidatedAt = f.o.stamp(now), 0
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

func TestUDPRebuildResolveDNSRealProxy(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "shadowsocks2022", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			runUDPRebuildResolveDNSRealProxy(t, newPinnedRebuildFixture(t, kind))
		})
	}
}

func runUDPRebuildResolveDNSRealProxy(t *testing.T, f *pinnedRebuildFixture) {
	t.Helper()
	f.send(t, f.old, f.a, "A/before-pin-recovery", true)
	f.relay.mu.Lock()
	healthyMappings := make(map[string]netip.AddrPort)
	for key, conn := range f.relay.mappings {
		if strings.HasSuffix(key, "/"+f.a.String()) {
			healthyMappings[key] = conn.LocalAddr().(*net.UDPAddr).AddrPort()
		}
	}
	f.relay.mu.Unlock()
	// Fetch a changed answer through the real relay. The live pin remains P1.
	f.dnsIP.Store(netip.MustParseAddr("127.0.0.2"))
	f.dnsPlane.resolveDNSPins.mu.Lock()
	clear(f.dnsPlane.resolveDNSPins.entries)
	f.dnsPlane.resolveDNSPins.mu.Unlock()
	option, err := f.options.GetDialOption(context.Background())
	if err != nil || option.Target != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), f.b.Port()).String() || f.queries.Load() == 0 {
		t.Fatalf("changed DNS answer: %v, %+v", err, option)
	}
	queries := f.queries.Load()
	f.relay.mu.Lock()
	f.relay.first = netip.AddrPort{}
	f.relay.mu.Unlock()
	f.o.scan(f.qualifyPin(t))
	slot := f.pin.rebuildPeer(f.b)
	waitRebuild(t, func() bool { return slot.owner.Load().endpoint != f.pin })
	next := slot.owner.Load().endpoint
	if next.poolKey != f.pin.poolKey || slot.original != f.original || next.DialTarget != f.b.String() || next.resolveDNSState.id == f.pin.resolveDNSState.id || next.resolveDNSState.initial != f.initial {
		t.Fatal("original/actual/DNS state handover failed")
	}
	if f.pin.resolveDNSState.phase.Load() != udpDNSPinSuperseded || next.resolveDNSState.phase.Load() != udpDNSPinCurrent {
		t.Fatal("DNS publication phase")
	}
	if got, ok := f.pool.rebuildLookup(f.pin.poolKey); !ok || got != next {
		t.Fatal("original-key override lost")
	}
	previousPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = f.pool
	t.Cleanup(func() { DefaultUdpEndpointPool = previousPool })
	decision := UdpFlowDecision{Key: NewUdpFlowKey(f.pin.poolKey.Src, f.original)}
	_, looked, ok := lookupUdpEndpointForFlowWithPrefetch(decision, udpEndpointRouteScope{}, true, f.original, false, f.pin, f.pin.poolKey, true)
	if !ok || looked != next {
		t.Fatal("stale pinned prefetch bypassed successor")
	}
	if looked, ok := f.m.retainedUDPEndpoint(f.pin.poolKey.Src, f.original, nil, 2); !ok || looked != next {
		t.Fatal("retained original-key lookup lost pin")
	}
	// Old replies and a new socket's unsolicited reply before a fresh write
	// cannot satisfy the post-commit confirmation requirement.
	f.pin.recordRebuildReply(f.b)
	next.recordRebuildReply(f.b)
	for i := 0; i < 3; i++ {
		f.send(t, f.old, f.a, fmt.Sprintf("A/healthy/%d", i), true)
		if r := f.sendPin(t, f.pin, fmt.Sprintf("pin/new/%d", i), true); r.endpoint != next {
			t.Fatal("stale sender did not follow actual-peer claim")
		}
		// A client-visible O is never substituted for actual peer P in evidence.
		next.recordRebuildReply(f.original)
		if i < 2 && f.m.udpRebuild.Load().snapshot(time.Now()).Counts["recovered"] != 0 {
			t.Fatal("recovery confirmed before three fresh actual-peer replies")
		}
	}
	snap := f.m.udpRebuild.Load().snapshot(time.Now())
	if snap.Counts["committed"] != 1 || snap.Counts["recovered"] != 1 || snap.AttemptsInWindow != 1 || f.queries.Load() != queries {
		t.Fatalf("budget/replies/DNS queries: %+v, %d -> %d", snap, queries, f.queries.Load())
	}
	journal := f.m.recoveryJournal()
	journal.mu.Lock()
	for _, e := range journal.records {
		if e.Kind == "committed" || e.Kind == "recovered" {
			if e.OriginalTarget != f.original.String() || e.ActualPeer != f.b.String() || e.OriginalFamily != udpPinnedAddrFamily(f.original.Addr()) || e.ActualPeerFamily != udpPinnedAddrFamily(f.b.Addr()) || e.DNSPinOwnerID != next.resolveDNSState.id || e.FlowIdentityRevision != 1 || !e.PinInherited {
				t.Errorf("incomplete pin evidence: %+v", e)
			}
		}
	}
	journal.mu.Unlock()
	f.relay.mu.Lock()
	for key, addr := range healthyMappings {
		if conn := f.relay.mappings[key]; conn == nil || conn.LocalAddr().(*net.UDPAddr).AddrPort() != addr {
			t.Error("healthy peer's mapping changed")
		}
	}
	for key := range f.relay.mappings {
		if strings.HasSuffix(key, "/"+option.Target) {
			t.Error("application payload reached P2")
		}
	}
	for payload, n := range f.relay.seen {
		if len(payload) >= 4 && payload[:4] == "pin/" && n != 1 {
			t.Errorf("replayed %s: %d", payload, n)
		}
	}
	f.relay.mu.Unlock()
	if next.crossFamily != f.pin.crossFamily {
		t.Fatal("successor changed the reply mapping view")
	}
	f.m.udpStateMu.Lock()
	for _, pair := range [][2]netip.AddrPort{{f.pin.poolKey.Src, f.original}, {f.original, f.pin.poolKey.Src}} {
		if refs := f.m.pinnedUDP[bpfTuplesKeyFromAddrPorts(pair[0], pair[1], 17)]; refs != 1 {
			t.Errorf("client-visible tuple %v refs=%d", pair, refs)
		}
	}
	f.m.udpStateMu.Unlock()
	// Turning observation off preserves the established owner and pin.
	_ = f.o.Close()
	f.sendPin(t, f.pin, "pin/after-off", true)
	next.retire()
	waitRebuild(t, func() bool { return next.dead.Load() })
	opts := *f.options
	opts.replyDrought = nil
	// Ordinary retirement retains the cache under the original route epoch.
	ordinary, _, err := f.pool.GetOrCreate(next.poolKey, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.DialTarget != f.b.String() || ordinary.pinnedTarget == nil || ordinary.rebuildPeer(f.b) != slot || ordinary.rebuildRevision != next.rebuildRevision+1 {
		t.Fatal("ordinary successor lost DNS pin/lineage")
	}
	f.sendPin(t, f.pin, "pin/ordinary", true)
}

func TestUDPRebuildResolveDNSPreparedCancel(t *testing.T) {
	f := newPinnedRebuildFixture(t, "shadowsocks")
	f.sendPin(t, f.pin, "pin/cache", true)
	f.m.resolveDNSRecovery.save(f.pin)
	next, err := f.o.execution.Load().prepare(context.Background(), f.pin, f.b)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	r, ok := f.m.resolveDNSRecovery.lookup(f.pin.poolKey, f.initial, false)
	if !ok || r.owner != f.pin.resolveDNSState.id || f.pin.resolveDNSState.phase.Load() != udpDNSPinCurrent {
		t.Fatal("cancelled preparation deleted old pin")
	}
	f.sendPin(t, f.pin, "pin/still-live", true)
}

func TestUDPRebuildResolveDNSLateSave(t *testing.T) {
	f := newPinnedRebuildFixture(t, "shadowsocks")
	f.sendPin(t, f.pin, "pin/before", true)
	next, err := f.o.execution.Load().prepare(context.Background(), f.pin, f.b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	s := &f.m.resolveDNSRecovery
	s.mu.Lock()
	done := make(chan struct{})
	go func() { s.save(f.pin); close(done) }()
	// Once can be occupied by the old save waiting for store.mu. Transfer must
	// not wait for Once, and the save must recheck phase after acquiring mu.
	f.pin.pinnedTarget.flow.mu.Lock()
	transferPinnedDNSLocked(f.pin, next)
	f.pin.pinnedTarget.flow.mu.Unlock()
	s.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("save/transfer deadlock")
	}
	next.prepared.Store(false)
	next.hasSent.Store(true)
	s.save(next)
	s.discard(f.pin)
	f.pin.rememberFlowIdentityOnRetire()
	r, ok := s.lookup(next.poolKey, f.initial, false)
	if !ok || r.owner != next.resolveDNSState.id {
		t.Fatal("old callback changed successor recovery record")
	}
}

func TestUDPRebuildResolveDNSInitialBoundary(t *testing.T) {
	for _, kind := range []string{"same", "unknown", "changed"} {
		t.Run(kind, func(t *testing.T) {
			f := newPinnedRebuildFixture(t, "shadowsocks")
			f.sendPin(t, f.pin, "pin/history", true)
			f.m.resolveDNSRecovery.save(f.pin)
			flowKey := NewUdpFlowKey(f.pin.poolKey.Src, f.original)
			f.pin.rememberFlowIdentityOnRetire()
			initial := f.initial
			if kind == "unknown" {
				initial.DCIDLen = 0
			}
			if kind == "changed" {
				initial.DCID[0]++
			}
			decision := UdpFlowDecision{Key: NewUdpFlowKey(f.pin.poolKey.Src, f.original), SnifferKey: initial, IsQuicInitial: true}
			changed := f.pool.checkPinnedRebuildInitial(f.pin.poolKey, decision)
			if changed != (kind == "changed") || f.pin.dead.Load() != (kind == "changed") {
				t.Fatal("Initial boundary destroyed/retained wrong owner")
			}
			if kind == "unknown" && !f.pin.pinnedTarget.flow.uncertain.Load() {
				t.Fatal("unknown Initial remained executable")
			}
			if kind == "changed" {
				if _, ok := f.m.resolveDNSRecovery.lookup(f.pin.poolKey, f.initial, false); ok {
					t.Fatal("conflicting Initial kept old pin")
				}
				f.m.resolveDNSRecovery.save(f.pin)
				if _, ok := f.m.resolveDNSRecovery.lookup(f.pin.poolKey, f.initial, false); ok {
					t.Fatal("late save resurrected old identity")
				}
				defaultQuicRejectMemory.rememberDomain(flowKey, time.Now().UnixNano(), "new.example")
				f.pin.rememberFlowIdentityOnRetire()
				if got := defaultQuicRejectMemory.rememberedDomain(flowKey, time.Now().UnixNano()); got != "new.example" {
					t.Fatalf("old retirement overwrote new domain: %q", got)
				}
			} else {
				f.sendPin(t, f.pin, "pin/continues", true)
			}
		})
	}
}

func TestUDPRebuildResolveDNSCancelDuringPrepare(t *testing.T) {
	for _, reason := range []string{"reply", "reload", "unknown_initial", "new_initial", "store_busy"} {
		t.Run(reason, func(t *testing.T) {
			runUDPRebuildResolveDNSCancelDuringPrepare(t, newPinnedRebuildFixture(t, "shadowsocks"), reason)
		})
	}
}

func runUDPRebuildResolveDNSCancelDuringPrepare(t *testing.T, f *pinnedRebuildFixture, reason string) {
	t.Helper()
	now := f.qualifyPin(t)
	f.m.resolveDNSRecovery.save(f.pin)
	f.dial.entered, f.dial.unblock = make(chan struct{}, 1), make(chan struct{})
	f.o.scan(now)
	select {
	case <-f.dial.entered:
	case <-time.After(time.Second):
		t.Fatal("prepare did not start")
	}
	// The unrelated healthy peer keeps sending while B's dial is blocked.
	f.send(t, f.old, f.a, "A/during-prepare", true)
	storeLocked := false
	defer func() {
		if storeLocked {
			f.m.resolveDNSRecovery.mu.Unlock()
		}
	}()
	switch reason {
	case "reply":
		f.relay.drop.Store(false)
		f.sendPin(t, f.pin, "pin/original-recovers", true)
	case "reload":
		recoveryTestPlane(f.m, nil, 2).publishActiveControlPlane()
	case "unknown_initial", "new_initial":
		initial := f.initial
		if reason == "unknown_initial" {
			initial.DCIDLen = 0
		} else {
			initial.DCID[0]++
		}
		f.pool.checkPinnedRebuildInitial(f.pin.poolKey, UdpFlowDecision{Key: NewUdpFlowKey(f.pin.poolKey.Src, f.original), SnifferKey: initial, IsQuicInitial: true})
	case "store_busy":
		f.m.resolveDNSRecovery.mu.Lock()
		storeLocked = true
	}
	close(f.dial.unblock)
	waitRebuild(t, func() bool { return f.o.execution.Load().idleForTest() })
	if storeLocked {
		f.m.resolveDNSRecovery.mu.Unlock()
		storeLocked = false
	}
	snap := f.m.udpRebuild.Load().snapshot(time.Now())
	if snap.Counts["committed"] != 0 || snap.AttemptsInWindow != 1 {
		t.Fatalf("cancel published/refunded attempt: %+v", snap)
	}
	if reason != "new_initial" {
		if f.pin.dead.Load() || f.pin.resolveDNSState.phase.Load() != udpDNSPinCurrent {
			t.Fatal("cancel changed old owner")
		}
		if r, ok := f.m.resolveDNSRecovery.lookup(f.pin.poolKey, f.initial, false); !ok || r.owner != f.pin.resolveDNSState.id {
			t.Fatal("cancel discarded original cache")
		}
		f.relay.drop.Store(false)
		f.sendPin(t, f.pin, "pin/after-cancel", true)
	}
}

func (x *udpRebuildExecutor) idleForTest() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.pending) == 0
}

func TestUDPRebuildResolveDNSOccupiedOnce(t *testing.T) {
	f := newPinnedRebuildFixture(t, "shadowsocks")
	f.sendPin(t, f.pin, "pin/before-once", true)
	next, err := f.o.execution.Load().prepare(context.Background(), f.pin, f.b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	s := &f.m.resolveDNSRecovery
	s.mu.Lock()
	entered, done := make(chan struct{}), make(chan struct{})
	go func() {
		f.pin.resolveDNSState.once.Do(func() { close(entered); s.mu.Lock(); s.mu.Unlock() })
		close(done)
	}()
	<-entered
	transferred := make(chan struct{})
	go func() {
		f.pin.pinnedTarget.flow.mu.Lock()
		transferPinnedDNSLocked(f.pin, next)
		f.pin.pinnedTarget.flow.mu.Unlock()
		close(transferred)
	}()
	select {
	case <-transferred:
		s.mu.Unlock()
	case <-time.After(time.Second):
		s.mu.Unlock()
		<-transferred
		t.Fatal("transfer waited for Once under store lock")
	}
	<-done
}

func TestUDPRebuildResolveDNSEligibility(t *testing.T) {
	f := newPinnedRebuildFixture(t, "shadowsocks")
	x := f.o.execution.Load()
	if got := x.exclusion(f.pin, f.b); got != "" {
		t.Fatalf("native pin excluded: %s", got)
	}
	f.pin.pinnedTarget.native = false
	if got := x.exclusion(f.pin, f.b); got != "resolve_dns_fakeip_unleased" {
		t.Fatalf("fake pin included: %s", got)
	}
	f.pin.pinnedTarget.native = true
	if got := x.exclusion(f.pin, f.a); got != "resolve_dns_peer_mismatch" {
		t.Fatalf("wrong peer included: %s", got)
	}
}

func TestUDPRebuildResolveDNSInitialBeforeRoutingCache(t *testing.T) {
	f := newPinnedRebuildFixture(t, "shadowsocks")
	f.sendPin(t, f.pin, "pin/cache-boundary", true)
	previous := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = f.pool
	t.Cleanup(func() { DefaultUdpEndpointPool = previous })
	decision := UdpFlowDecision{Key: NewUdpFlowKey(f.pin.poolKey.Src, f.original), SnifferKey: f.initial, IsQuicInitial: true}
	bound := &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin), Mark: 42, Must: 1}
	f.pin.UpdateCachedRoutingResult(f.original, 17, bound)
	if hit := lookupCachedRoutingBinding(decision, f.original); !hit.bindingHit || hit.identityChanged {
		t.Fatal("same Initial lost routing cache")
	}
	decision.SnifferKey.DCID[0]++
	hit := lookupCachedRoutingBinding(decision, f.original)
	if !hit.identityChanged || hit.bindingHit || hit.prefetchOK || hit.owner != nil || hit.bound != nil {
		t.Fatal("new Initial reused routing cache/override")
	}
	current := currentPolicyUDPRoutingResult(bound)
	if current.Outbound != uint8(consts.OutboundControlPlaneRouting) || current.Mark != 0 || current.Must != 0 || current.RoutingEpochSlot != bpfRoutingEpochSlotUnknown {
		t.Fatal("new identity retained old policy binding")
	}
}

func TestUDPRebuildResolveDNSRetiredIdentityExit(t *testing.T) {
	for _, reason := range []string{"initial", "domain", "route"} {
		t.Run(reason, func(t *testing.T) {
			f := newPinnedRebuildFixture(t, "shadowsocks")
			f.o.scan(f.qualifyPin(t))
			slot := f.pin.rebuildPeer(f.b)
			waitRebuild(t, func() bool { return slot.owner.Load().endpoint != f.pin })
			old := slot.owner.Load().endpoint
			f.sendPin(t, old, "pin/before-retirement", true)
			old.retire()
			flowKey := NewUdpFlowKey(old.poolKey.Src, f.original)
			if reason == "initial" {
				initial := f.initial
				initial.DCID[0]++
				if !f.pool.checkPinnedRebuildInitial(old.poolKey, UdpFlowDecision{Key: flowKey, SnifferKey: initial, IsQuicInitial: true}) {
					t.Fatal("retired owner hid Initial conflict")
				}
			} else {
				opts := *f.options
				originalDial := opts.GetDialOption
				opts.GetDialOption = func(ctx context.Context) (*DialOption, error) {
					option, err := originalDial(ctx)
					if err == nil {
						if reason == "domain" {
							option.SniffedDomain = "new.example"
							option.Binding.Egress.SniffedDomain = option.SniffedDomain
						} else {
							option.Binding.Route.Mark++
						}
					}
					return option, err
				}
				fresh, _, err := f.pool.GetOrCreate(old.poolKey, &opts)
				if err != nil {
					t.Fatal(err)
				}
				if fresh.rebuildPeer(f.b) == slot || fresh.pinnedTarget.flow == old.pinnedTarget.flow {
					t.Fatal("new business flow retained old recovery identity")
				}
			}
			if !old.pinnedTarget.flow.revoked.Load() {
				t.Fatal("retired pin token remained valid")
			}
			defaultQuicRejectMemory.rememberDomain(flowKey, time.Now().UnixNano(), "new.example")
			old.rememberFlowIdentityOnRetire()
			f.m.resolveDNSRecovery.save(old)
			if got := defaultQuicRejectMemory.rememberedDomain(flowKey, time.Now().UnixNano()); got != "new.example" {
				t.Fatalf("late callback resurrected %q", got)
			}
			if r, ok := f.m.resolveDNSRecovery.lookup(old.poolKey, f.initial, false); ok && r.owner == old.resolveDNSState.id {
				t.Fatal("old save resurrected retired pin")
			}
			if f.m.udpRebuild.Load().snapshot(time.Now()).AttemptsInWindow != 1 {
				t.Fatal("identity change refunded execution budget")
			}
		})
	}
}

func TestUDPRebuildResolveDNSAdministrativeCloseAfterSave(t *testing.T) {
	for _, action := range []string{"abort", "close", "idle"} {
		t.Run(action, func(t *testing.T) {
			f := newPinnedRebuildFixture(t, "shadowsocks")
			f.sendPin(t, f.pin, "pin/save-before-close", true)
			// Retire has saved its record but has not yet marked the endpoint dead.
			f.m.resolveDNSRecovery.save(f.pin)
			switch action {
			case "abort":
				_ = f.pin.sessionRuntime.abort()
			case "close":
				_ = f.pin.Close()
			case "idle":
				_ = f.pin.closeIdleExpired()
			}
			f.pin.retire() // A delayed retirement cannot restore that pin.
			if _, ok := f.m.resolveDNSRecovery.lookup(f.pin.poolKey, f.initial, false); ok || f.pin.resolveDNSState.phase.Load() != udpDNSPinClosed {
				t.Fatal("administrative close kept saved DNS recovery")
			}
		})
	}
}

func TestUDPRebuildResolveDNSClosedMemory(t *testing.T) {
	for _, idle := range []bool{false, true} {
		t.Run(fmt.Sprintf("idle=%t", idle), func(t *testing.T) {
			f := newPinnedRebuildFixture(t, "shadowsocks")
			old := f.pin
			key := NewUdpFlowKey(old.poolKey.Src, old.poolKey.Dst)
			shard := defaultQuicRejectMemory.shard(key)
			shard.mu.Lock()
			delete(shard.flows, key)
			shard.mu.Unlock()
			// This owner has no recovery override, so same-key publication cannot
			// rely on failed override inheritance to revoke old memory writes.
			if _, ok := f.pool.rebuildOverride(old.poolKey); ok {
				t.Fatal("fixture unexpectedly has an override")
			}
			if idle {
				_ = old.closeIdleExpired()
			} else {
				_ = old.Close()
			}
			got := defaultQuicRejectMemory.rememberedDomain(key, time.Now().UnixNano())
			if idle && got != "" || !idle && got != "pinned.example" {
				t.Fatalf("final close memory=%q idle=%t", got, idle)
			}
			// A new business flow on the same client tuple now owns its memory.
			defaultQuicRejectMemory.rememberDomain(key, time.Now().UnixNano(), "new.example")
			old.rememberFlowIdentityOnRetire()
			old.retire()
			if got := defaultQuicRejectMemory.rememberedDomain(key, time.Now().UnixNano()); got != "new.example" {
				t.Fatalf("closed owner overwrote new memory: %q", got)
			}
			if old.resolveDNSState.phase.Load() != udpDNSPinClosed {
				t.Fatal("late retirement reopened the DNS pin")
			}
		})
	}
}

func TestUDPRebuildResolveDNSCloseMemoryBoundary(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprintf("removed=%t", removed), func(t *testing.T) {
			f := newPinnedRebuildFixture(t, "shadowsocks")
			old := f.pin
			key := NewUdpFlowKey(old.poolKey.Src, old.poolKey.Dst)
			flow := old.pinnedTarget.flow
			flow.mu.Lock()
			closing, done := make(chan struct{}), make(chan struct{})
			go func() { close(closing); _ = old.Close(); close(done) }()
			<-closing
			// Wait until Close owns lifecycle.mu and is blocked on flow.mu.
			waitRebuild(t, func() bool {
				if old.rebuildLifecycleMu.TryLock() {
					old.rebuildLifecycleMu.Unlock()
					return false
				}
				return true
			})
			if old.IsDead() {
				flow.mu.Unlock()
				t.Fatal("Close permitted replacement before memory/token closure")
			}
			if removed {
				// Reset/expiry can remove an endpoint even while it is still live.
				old.selfRemoveFromPool()
				defaultQuicRejectMemory.rememberDomain(key, time.Now().UnixNano(), "new.example")
			}
			flow.mu.Unlock()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("close memory boundary deadlock")
			}
			if !removed {
				defaultQuicRejectMemory.rememberDomain(key, time.Now().UnixNano(), "new.example")
			}
			old.retire()
			if got := defaultQuicRejectMemory.rememberedDomain(key, time.Now().UnixNano()); got != "new.example" {
				t.Fatalf("old closure overwrote fresh memory: %q", got)
			}
		})
	}
}

func TestUDPRebuildResolveDNSAddressEligibility(t *testing.T) {
	for _, tc := range []struct{ name, client, original, peer, exclusion string }{
		{"v4", "192.0.2.201:32000", "198.51.100.10:27015", "203.0.113.20:27015", ""},
		{"v6", "[2001:db8::201]:32000", "[2001:db8::10]:27015", "[2001:db8::20]:27015", ""},
		{"mapped v4", "[::ffff:192.0.2.201]:32000", "[::ffff:198.51.100.10]:27015", "203.0.113.20:27015", ""},
		{"v4 to v6", "192.0.2.201:32000", "198.51.100.10:27015", "[2001:db8::20]:27015", ""},
		{"v6 to v4", "[2001:db8::201]:32000", "[2001:db8::10]:27015", "203.0.113.20:27015", ""},
		{"mapped v4 to v6", "[::ffff:192.0.2.201]:32000", "[::ffff:198.51.100.10]:27015", "[2001:db8::20]:27015", ""},
		{"v6 to mapped v4", "[2001:db8::201]:32000", "[2001:db8::10]:27015", "[::ffff:203.0.113.20]:27015", ""},
		{"original family", "[2001:db8::201]:32000", "198.51.100.10:27015", "[2001:db8::20]:27015", "resolve_dns_peer_mismatch"},
		{"original v6 for v4 client", "192.0.2.201:32000", "[2001:db8::10]:27015", "203.0.113.20:27015", "resolve_dns_peer_mismatch"},
		{"port", "192.0.2.201:32000", "198.51.100.10:27016", "203.0.113.20:27015", "resolve_dns_peer_mismatch"},
		{"no client", "", "[2001:db8::10]:27015", "[2001:db8::20]:27015", "resolve_dns_peer_mismatch"},
		{"dns", "192.0.2.201:32000", "198.51.100.10:53", "203.0.113.20:53", "resolve_dns_peer_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, _ := netip.ParseAddrPort(tc.client)
			parsed := netip.MustParseAddrPort(tc.peer)
			peer := netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port())
			ue := &UdpEndpoint{poolKey: UdpEndpointKey{Src: src, Dst: netip.MustParseAddrPort(tc.original)}, DialTarget: tc.peer, SniffedDomain: "PINNED.EXAMPLE.", resolveDNSState: &udpResolveDNSState{}}
			ue.pinnedTarget = newUDPPinnedTarget(ue, &DialOption{Target: tc.peer, SniffedDomain: ue.SniffedDomain, ResolveDNSOriginalNative: true})
			if got := ue.pinnedDNSExclusion(peer); got != tc.exclusion {
				t.Fatalf("eligibility=%q want %q", got, tc.exclusion)
			}
			if tc.exclusion == "" {
				ue.crossFamily = &UDPCrossFamilyStore{}
				if got := ue.pinnedDNSExclusion(peer); got != "peer_alias_unsupported" {
					t.Fatalf("unready alias store admitted: %q", got)
				}
			}
		})
	}
}

func TestUDPRebuildResolveDNSWriteRetryCleanupKeepsPin(t *testing.T) {
	f := newPinnedRebuildFixture(t, "shadowsocks")
	f.sendPin(t, f.pin, "pin/before-write-error", true)
	// This is the cleanup used by both actual handlePkt write-error branches.
	f.pin.retire()
	_ = f.pool.removeForRetry(f.pin.poolKey, f.pin)
	f.dial.fail.Store(true)
	if _, _, err := f.pool.GetOrCreate(f.pin.poolKey, f.options); err == nil {
		t.Fatal("fixture replacement dial unexpectedly succeeded")
	}
	if r, ok := f.m.resolveDNSRecovery.lookup(f.pin.poolKey, f.initial, false); !ok || r.target != f.b {
		t.Fatal("ordinary cleanup/dial failure discarded retry pin")
	}
	f.dial.fail.Store(false)
	var next *UdpEndpoint
	waitRebuild(t, func() bool {
		var err error
		next, _, err = f.pool.GetOrCreate(f.pin.poolKey, f.options)
		return err == nil
	})
	if next.DialTarget != f.b.String() {
		t.Fatal("next packet lost fixed target")
	}
	f.sendPin(t, next, "pin/after-dial-retry", true)
	_ = f.pool.Remove(next.poolKey, next)
	if _, ok := f.m.resolveDNSRecovery.lookup(next.poolKey, f.initial, false); ok {
		t.Fatal("administrative Remove retained pin")
	}
}

func TestUDPRebuildResolveDNSIPv6RealProxy(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "shadowsocks2022", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			// Client and application target are IPv6; the proxy relay is IPv4.
			f := newPinnedRebuildFixtureFamily(t, kind, true)
			f.o.scan(f.qualifyPin(t))
			slot := f.pin.rebuildPeer(f.b)
			waitRebuild(t, func() bool { return slot.owner.Load().endpoint != f.pin })
			next := slot.owner.Load().endpoint
			for i := 0; i < 3; i++ {
				if r := f.sendPin(t, f.pin, fmt.Sprintf("pin/v6/%d", i), true); r.endpoint != next {
					t.Fatal("IPv6 claim/reply ownership")
				}
			}
			if next.poolKey != f.pin.poolKey || next.DialTarget != f.b.String() || f.m.udpRebuild.Load().snapshot(time.Now()).Counts["recovered"] != 1 {
				t.Fatal("IPv6 fixed-target handover")
			}
		})
	}
}

func TestUDPRebuildResolveDNSPreparedCloseAtPublication(t *testing.T) {
	f := newPinnedRebuildFixture(t, "shadowsocks")
	f.sendPin(t, f.pin, "pin/close-publication", true)
	next, err := f.o.execution.Load().prepare(context.Background(), f.pin, f.b)
	if err != nil {
		t.Fatal(err)
	}
	next.rebuildLifecycleMu.Lock()
	closing, done := make(chan struct{}), make(chan struct{})
	go func() { close(closing); _ = next.Close(); close(done) }()
	<-closing
	// Simulate the DNS publication while Close waits for the lifecycle boundary.
	flow := f.pin.pinnedTarget.flow
	flow.mu.Lock()
	f.m.resolveDNSRecovery.mu.Lock()
	transferPinnedDNSLocked(f.pin, next)
	f.m.resolveDNSRecovery.mu.Unlock()
	flow.mu.Unlock()
	next.prepared.Store(false)
	next.hasSent.Store(true)
	f.m.resolveDNSRecovery.save(next)
	next.rebuildLifecycleMu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publication/close deadlock")
	}
	if next.resolveDNSState.phase.Load() != udpDNSPinClosed {
		t.Fatal("prepared Close left published pin active")
	}
	if _, ok := f.m.resolveDNSRecovery.lookup(next.poolKey, f.initial, false); ok {
		t.Fatal("prepared Close failed to discard newly published recovery")
	}
}
