/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestShouldRejectIdentifiedQuic(t *testing.T) {
	t.Parallel()
	if shouldRejectIdentifiedQuic(false, true, dialer.UdpForwardReliableOrdered) {
		t.Fatal("block_quic=false must not reject")
	}
	if shouldRejectIdentifiedQuic(true, false, dialer.UdpForwardReliableOrdered) {
		t.Fatal("unidentified flow must not reject")
	}
	if shouldRejectIdentifiedQuic(true, true, dialer.UdpForwardDatagram) {
		t.Fatal("datagram chain must not reject")
	}
	if !shouldRejectIdentifiedQuic(true, true, dialer.UdpForwardReliableOrdered) {
		t.Fatal("reliable_ordered must reject")
	}
	if !shouldRejectIdentifiedQuic(true, true, dialer.UdpForwardNone) {
		t.Fatal("udp_unsupported must reject")
	}
}

func TestIsQuicBlockCandidate(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	openvpn := []byte{0x00, 0x0e, 0x38, 0x01, 0x02, 0x03, 0x04, 0x05}
	shortInitial := makeLikelyQuicInitialPayload(0x11)
	paddedInitial := makePaddedQuicClientInitial(0x11)
	emptyDecision := UdpFlowDecision{Key: NewUdpFlowKey(
		netip.MustParseAddrPort("192.0.2.10:54321"),
		netip.MustParseAddrPort("203.0.113.1:443"),
	)}
	if isIdentifiedQuicPacket(emptyDecision, openvpn) {
		t.Fatal("non-QUIC UDP/443 must not be identified as QUIC")
	}
	alt := UdpFlowDecision{Key: NewUdpFlowKey(
		netip.MustParseAddrPort("192.0.2.10:54321"),
		netip.MustParseAddrPort("203.0.113.1:8443"),
	)}
	if isIdentifiedQuicPacket(alt, openvpn) {
		t.Fatal("non-QUIC UDP/8443 must not be identified as QUIC")
	}
	game := UdpFlowDecision{Key: NewUdpFlowKey(
		netip.MustParseAddrPort("192.0.2.10:54321"),
		netip.MustParseAddrPort("203.0.113.1:7777"),
	)}
	if isIdentifiedQuicPacket(game, openvpn) {
		t.Fatal("non-QUIC port without Initial must not be a candidate")
	}
	if isIdentifiedQuicPacket(game, shortInitial) {
		t.Fatal("cheap long-header lookalike on a game port must not identify QUIC")
	}
	if isIdentifiedQuicPacket(UdpFlowDecision{IsQuicInitial: true, HasSnifferSession: true}, openvpn) {
		t.Fatal("cheap 443 sniff flags must not identify QUIC for block_quic")
	}
	if !isIdentifiedQuicPacket(UdpFlowDecision{IsStrictClientInitial: true}, openvpn) {
		t.Fatal("strict client Initial flag must identify")
	}
	if !isIdentifiedQuicPacket(game, paddedInitial) {
		t.Fatal("strict client Initial must identify on a non-443 port")
	}
}

func TestIdentifiedQuicIgnoresFakeIPSniffedDomain(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	openvpn := []byte{0x00, 0x0e, 0x38, 0x01}
	anytls, _ := newCountingProxyEndpointDialer("anytls", "127.0.0.1:443", &mockPacketConn{})
	cp := &ControlPlane{blockQuic: true}

	ue := &UdpEndpoint{Dialer: anytls, conn: &mockPacketConn{}, SniffedDomain: "app.example"}
	if cp.rejectEndpointQuic(ue, openvpn, src, dst, false) {
		t.Fatal("FakeIP SniffedDomain on UDP/443 must not count as QUIC")
	}
	if ue.IsDead() {
		t.Fatal("non-QUIC FakeIP endpoint must stay alive")
	}

	ue.markIdentifiedQuic()
	if !cp.rejectEndpointQuic(ue, openvpn, src, dst, false) {
		t.Fatal("persisted endpoint QUIC mark must identify later 1-RTT")
	}
}

func TestBlockQuicFalseSkipsRejectMemory(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	key := NewUdpFlowKey(
		netip.MustParseAddrPort("192.0.2.10:40001"),
		netip.MustParseAddrPort("203.0.113.50:443"),
	)
	decision := UdpFlowDecision{Key: key}
	openvpn := []byte{0x00, 0x0e, 0x38, 0x01}
	defaultQuicRejectMemory.noteRejected(key, time.Now().UnixNano())

	off := &ControlPlane{blockQuic: false}
	if off.isQuicBlockCandidate(decision, openvpn) {
		t.Fatal("block_quic=false must not consult reject memory")
	}
	on := &ControlPlane{blockQuic: true}
	if !on.isQuicBlockCandidate(decision, openvpn) {
		t.Fatal("block_quic=true should remember a recently rejected 4-tuple")
	}
}

func TestQuicRejectMemoryRateLimitsICMP(t *testing.T) {
	mem := newQuicRejectMemory()
	key := NewUdpFlowKey(
		netip.MustParseAddrPort("192.0.2.10:40000"),
		netip.MustParseAddrPort("203.0.113.50:443"),
	)
	now := int64(1_000_000)
	if !mem.noteRejected(key, now) {
		t.Fatal("first rejected datagram must send ICMP immediately")
	}
	if !mem.recentlyIdentified(key, now+1) {
		t.Fatal("rejected 4-tuple must stay identified")
	}
	if mem.noteRejected(key, now+1) {
		t.Fatal("follow-up datagrams in the same interval must not send another ICMP")
	}
	if !mem.noteRejected(key, now+int64(quicICMPMinInterval)) {
		t.Fatal("ICMP may be sent again after the min interval")
	}
	last := now + int64(quicICMPMinInterval)
	if mem.recentlyIdentified(key, last+int64(quicRejectRememberTTL)+1) {
		t.Fatal("reject memory must expire")
	}
}

func TestQuicRejectMemoryCapsGrowth(t *testing.T) {
	mem := newQuicRejectMemory()
	now := int64(1_000_000)
	src := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("203.0.113.50")
	const extra = 512
	for i := 0; i < quicRejectMemoryShards*quicRejectMemoryPerShard+extra; i++ {
		key := NewUdpFlowKey(
			netip.AddrPortFrom(src, uint16(1024+i%50000)),
			netip.AddrPortFrom(dst, uint16(443+i%1000)),
		)
		_ = mem.noteRejected(key, now)
	}
	got := mem.lenForTest()
	max := quicRejectMemoryShards * quicRejectMemoryPerShard
	if got > max {
		t.Fatalf("reject memory grew to %d, want <= %d", got, max)
	}
	if got < quicRejectMemoryPerShard {
		t.Fatalf("reject memory shrank too far: %d", got)
	}
}

func TestRejectEndpointQuicOnRetainedAnyTLS(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	openvpn := []byte{0x00, 0x0e, 0x38, 0x01, 0x02, 0x03}

	anytls, _ := newCountingProxyEndpointDialer("anytls", "127.0.0.1:443", &mockPacketConn{})
	hy2, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", &mockPacketConn{})
	cp := &ControlPlane{blockQuic: true}

	openvpnUE := &UdpEndpoint{Dialer: anytls, conn: &mockPacketConn{}}
	if cp.rejectEndpointQuic(openvpnUE, openvpn, src, dst, false) {
		t.Fatal("OpenVPN-like UDP/443 on AnyTLS must not be rejected")
	}
	if openvpnUE.IsDead() {
		t.Fatal("non-QUIC retained endpoint must stay alive")
	}

	h3UE := &UdpEndpoint{Dialer: anytls, conn: &mockPacketConn{}}
	h3UE.markIdentifiedQuic()
	if !cp.rejectEndpointQuic(h3UE, openvpn, src, dst, false) {
		t.Fatal("retained AnyTLS H3 must REJECT-NO-DROP after reload")
	}
	if !h3UE.IsDead() {
		t.Fatal("rejected retained endpoint must be retired")
	}

	hy2UE := &UdpEndpoint{Dialer: hy2, conn: &mockPacketConn{}, SniffedDomain: "h3.example"}
	if cp.rejectEndpointQuic(hy2UE, makeLikelyQuicInitialPayload(0x22), src, dst, true) {
		t.Fatal("datagram Hy2 must still forward identified QUIC")
	}
	if hy2UE.IsDead() {
		t.Fatal("Hy2 endpoint must not be retired")
	}
	if !hy2UE.identifiedQuic() {
		t.Fatal("Hy2 endpoint should persist the QUIC mark")
	}
}

func TestQuicIdentifiedSurvivesEndpointRebuild(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	hy2, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", &mockPacketConn{})
	anytls, _ := newCountingProxyEndpointDialer("anytls", "127.0.0.1:443", &mockPacketConn{})
	ue := &UdpEndpoint{Dialer: hy2, conn: &mockPacketConn{}}
	ue.markIdentifiedQuic()

	identified := quicIdentifiedFromEndpoint(false, ue)
	if !identified {
		t.Fatal("1-RTT rebuild must inherit the endpoint QUIC mark")
	}
	cp := &ControlPlane{blockQuic: true}
	cp.rememberIdentifiedQuic(src, dst)
	if !cp.shouldRejectProxiedQuic(anytls, identified) {
		t.Fatal("failover onto AnyTLS must still reject identified QUIC")
	}
	if !cp.isQuicBlockCandidate(UdpFlowDecision{Key: NewUdpFlowKey(src, dst)}, []byte{0x01, 0x02}) {
		t.Fatal("remembered QUIC 4-tuple must identify the next packet after endpoint retire")
	}
}

func TestClassifyUdpFlow_StrictOffPortInitialUsesSymmetricKey(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:7777")
	cheap := ClassifyUdpFlow(src, dst, makeLikelyQuicInitialPayload(0x33))
	if cheap.IsQuicInitial || cheap.AllowsSniffing || cheap.IsStrictClientInitial {
		t.Fatal("short Initial lookalike on a game port must stay out of the QUIC flow model")
	}
	strict := ClassifyUdpFlow(src, dst, makePaddedQuicClientInitial(0x33))
	if !strict.IsStrictClientInitial || !strict.IsQuicInitial || !strict.AllowsSniffing {
		t.Fatal("strict client Initial on a non-443 port must enter the QUIC flow model")
	}
	if key := strict.EndpointKeyForDial(""); key != strict.SymmetricNatEndpointKey() {
		t.Fatalf("strict off-port QUIC key = %+v, want symmetric", key)
	}
	if got := strict.NatTimeoutForDial(""); got != QuicNatTimeout {
		t.Fatalf("NAT timeout = %s, want %s", got, QuicNatTimeout)
	}
}

func TestQuicRejectIsNotCachedAsEndpointFailure(t *testing.T) {
	t.Parallel()
	if shouldCacheUdpEndpointCreateFailure(ErrQuicAdministrativelyProhibited) {
		t.Fatal("QUIC REJECT-NO-DROP must not occupy the UDP endpoint negative cache")
	}
}

func TestBuildIPv4ICMPAdminProhibited(t *testing.T) {
	t.Parallel()
	client := netip.MustParseAddrPort("192.0.2.10:54321")
	dest := netip.MustParseAddrPort("203.0.113.50:443")
	payload := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}
	msg := buildIPv4ICMPAdminProhibited(client, dest, payload)
	if msg[0] != icmp4DestUnreach || msg[1] != icmp4CommAdministrativelyProhib {
		t.Fatalf("icmp type/code = %d/%d, want 3/13", msg[0], msg[1])
	}
	got := binary.BigEndian.Uint16(msg[2:4])
	binary.BigEndian.PutUint16(msg[2:4], 0)
	if internetChecksum16(msg) != got {
		t.Fatalf("icmp checksum %d does not match recomputed %d", got, internetChecksum16(msg))
	}
	quoted := msg[8:]
	if quoted[9] != ipprotoUDP {
		t.Fatalf("quoted proto = %d, want UDP", quoted[9])
	}
	if binary.BigEndian.Uint16(quoted[20:22]) != client.Port() || binary.BigEndian.Uint16(quoted[22:24]) != dest.Port() {
		t.Fatalf("quoted udp ports = %d->%d", binary.BigEndian.Uint16(quoted[20:22]), binary.BigEndian.Uint16(quoted[22:24]))
	}
}

func TestBuildIPv6ICMPAdminProhibited(t *testing.T) {
	t.Parallel()
	client := netip.MustParseAddrPort("[2001:db8::1]:54321")
	dest := netip.MustParseAddrPort("[2001:db8::2]:443")
	msg := buildIPv6ICMPAdminProhibited(client, dest, []byte{0xc0, 0x00})
	if msg[0] != icmp6DestUnreach || msg[1] != icmp6CommAdministrativelyProhib {
		t.Fatalf("icmp6 type/code = %d/%d, want 1/1", msg[0], msg[1])
	}
	got := binary.BigEndian.Uint16(msg[2:4])
	binary.BigEndian.PutUint16(msg[2:4], 0)
	want := icmp6Checksum(dest.Addr(), client.Addr(), msg)
	if got != want {
		t.Fatalf("icmp6 checksum %d, want %d", got, want)
	}
}

func putPooledUdpEndpointForTest(t *testing.T, key UdpEndpointKey, ue *UdpEndpoint) {
	t.Helper()
	shard := DefaultUdpEndpointPool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()
}

func TestLookupUdpEndpointPrefersDestSymmetricOverFullCone(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	t.Cleanup(func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	})

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:7777")
	decision := ClassifyUdpFlow(src, dst, []byte{0x01, 0x02, 0x03})
	if decision.AllowsSniffing || decision.IsQuicInitial {
		t.Fatal("off-port 1-RTT must use full-cone as the primary lookup key")
	}
	scope := udpEndpointRouteScope{}
	fullCone := &UdpEndpoint{DialTarget: dst.String()}
	symmetric := &UdpEndpoint{DialTarget: "quic.example", SniffedDomain: "quic.example"}
	symmetric.markIdentifiedQuic()
	putPooledUdpEndpointForTest(t, decision.FullConeNatEndpointKeyWithScope(scope), fullCone)
	putPooledUdpEndpointForTest(t, decision.SymmetricNatEndpointKeyWithScope(scope), symmetric)

	key, ue, ok := lookupUdpEndpointForFlow(decision, scope, false, dst, false)
	if !ok || ue != symmetric {
		t.Fatal("1-RTT must reuse the dest-scoped QUIC endpoint even when a full-cone mapping already exists")
	}
	if key != decision.SymmetricNatEndpointKeyWithScope(scope) {
		t.Fatalf("lookup key = %+v, want dest-scoped symmetric", key)
	}
}

func TestLookupUdpEndpointIdentifiedMissStillProbesFullCone(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	t.Cleanup(func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	})

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:7777")
	decision := ClassifyUdpFlow(src, dst, []byte{0x01, 0x02, 0x03})
	scope := udpEndpointRouteScope{}
	fullCone := &UdpEndpoint{DialTarget: dst.String()}
	fullCone.markIdentifiedQuic()
	putPooledUdpEndpointForTest(t, decision.FullConeNatEndpointKeyWithScope(scope), fullCone)

	key, ue, ok := lookupUdpEndpointForFlow(decision, scope, false, dst, true)
	if !ok || ue != fullCone {
		t.Fatal("identified 1-RTT must still reuse a dest-matching src-only endpoint when no symmetric mapping exists")
	}
	if key != decision.FullConeNatEndpointKeyWithScope(scope) {
		t.Fatalf("lookup key = %+v, want full-cone", key)
	}
}

func TestPreserveIdentifiedQuicStoresSniffedDomain(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	ue := &UdpEndpoint{SniffedDomain: "app.example"}
	ue.markIdentifiedQuic()
	cp := &ControlPlane{blockQuic: true}
	if !cp.preserveIdentifiedQuic(ue, false, src, dst) {
		t.Fatal("marked endpoint must preserve QUIC identity")
	}
	if got := cp.rememberedUdpFlowDomain(src, dst); got != "app.example" {
		t.Fatalf("remembered domain = %q, want app.example", got)
	}
}

func TestRememberedDomainDoesNotIdentifyNonQuic(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	cp := &ControlPlane{blockQuic: true}
	cp.rememberUdpFlowDomain(src, dst, "files.example")
	if cp.isQuicBlockCandidate(UdpFlowDecision{Key: NewUdpFlowKey(src, dst)}, []byte{0x01, 0x02}) {
		t.Fatal("domain-only tombstone must not identify the flow as QUIC")
	}
	if got := cp.rememberedUdpFlowDomain(src, dst); got != "files.example" {
		t.Fatalf("remembered domain = %q", got)
	}
}

func TestRetireRemembersSniffedDomainForSameTuple(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	ue := &UdpEndpoint{
		SniffedDomain: "h3.example",
		lAddr:         src,
		poolKey:       UdpEndpointKey{Src: src, Dst: dst},
	}
	ue.markIdentifiedQuic()
	ue.retire()
	if got := defaultQuicRejectMemory.rememberedDomain(NewUdpFlowKey(src, dst), time.Now().UnixNano()); got != "h3.example" {
		t.Fatalf("retired domain = %q, want h3.example", got)
	}
	if !defaultQuicRejectMemory.recentlyIdentified(NewUdpFlowKey(src, dst), time.Now().UnixNano()) {
		t.Fatal("retire must also keep QUIC identity")
	}
}

func TestCloseRemembersSniffedDomainWithoutRetire(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	ue := &UdpEndpoint{
		SniffedDomain: "h3.example",
		lAddr:         src,
		poolKey:       UdpEndpointKey{Src: src, Dst: dst},
	}
	ue.markIdentifiedQuic()
	if err := ue.Close(); err != nil {
		t.Fatal(err)
	}
	if got := defaultQuicRejectMemory.rememberedDomain(NewUdpFlowKey(src, dst), time.Now().UnixNano()); got != "h3.example" {
		t.Fatalf("closed domain = %q, want h3.example", got)
	}
	if !defaultQuicRejectMemory.recentlyIdentified(NewUdpFlowKey(src, dst), time.Now().UnixNano()) {
		t.Fatal("Close must keep QUIC identity even without retire()")
	}
}

func TestIdleExpiredCloseDoesNotRememberFlowIdentity(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	ue := &UdpEndpoint{
		SniffedDomain: "h3.example",
		lAddr:         src,
		poolKey:       UdpEndpointKey{Src: src, Dst: dst},
	}
	ue.markIdentifiedQuic()
	ue.expiresAtNano.Store(1)
	if err := ue.closeIdleExpired(); err != nil {
		t.Fatal(err)
	}
	if got := defaultQuicRejectMemory.rememberedDomain(NewUdpFlowKey(src, dst), time.Now().UnixNano()); got != "" {
		t.Fatalf("idle-expired close refreshed domain = %q", got)
	}
	if defaultQuicRejectMemory.recentlyIdentified(NewUdpFlowKey(src, dst), time.Now().UnixNano()) {
		t.Fatal("idle-expired close must not refresh QUIC identity")
	}
}

func TestIdleExpiredCloseLeavesExistingMemoryUntouched(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54322")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	key := NewUdpFlowKey(src, dst)
	now := time.Now().UnixNano()
	defaultQuicRejectMemory.rememberDomain(key, now, "keep.example")
	defaultQuicRejectMemory.rememberIdentified(key, now)

	ue := &UdpEndpoint{
		SniffedDomain: "h3.example",
		lAddr:         src,
		poolKey:       UdpEndpointKey{Src: src, Dst: dst},
	}
	ue.markIdentifiedQuic()
	if err := ue.closeIdleExpired(); err != nil {
		t.Fatal(err)
	}
	if got := defaultQuicRejectMemory.rememberedDomain(key, time.Now().UnixNano()); got != "keep.example" {
		t.Fatalf("idle-expired close must not rewrite domain, got %q", got)
	}
	if !defaultQuicRejectMemory.recentlyIdentified(key, time.Now().UnixNano()) {
		t.Fatal("idle-expired close must not drop existing QUIC identity")
	}
}

func TestPreserveIdentifiedQuicRefreshesRejectMemory(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:7777")
	ue := &UdpEndpoint{}
	ue.markIdentifiedQuic()
	cp := &ControlPlane{blockQuic: true}
	if !cp.preserveIdentifiedQuic(ue, false, src, dst) {
		t.Fatal("marked endpoint must preserve QUIC identity")
	}
	if !cp.isQuicBlockCandidate(UdpFlowDecision{Key: NewUdpFlowKey(src, dst)}, []byte{0x01, 0x02}) {
		t.Fatal("abandoning a marked endpoint must refresh 4-tuple reject memory")
	}
}

func TestRejectEndpointQuicRefreshesMemoryForAlreadyMarkedEndpoint(t *testing.T) {
	resetQuicRejectMemoryForTest()
	t.Cleanup(resetQuicRejectMemoryForTest)

	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	hy2, _ := newCountingProxyEndpointDialer("hysteria2", "127.0.0.1:443", &mockPacketConn{})
	ue := &UdpEndpoint{Dialer: hy2, conn: &mockPacketConn{}}
	ue.markIdentifiedQuic()
	cp := &ControlPlane{blockQuic: true}
	if cp.rejectEndpointQuic(ue, []byte{0x01, 0x02}, src, dst, false) {
		t.Fatal("datagram Hy2 must not reject")
	}
	if !cp.isQuicBlockCandidate(UdpFlowDecision{Key: NewUdpFlowKey(src, dst)}, []byte{0x01, 0x02}) {
		t.Fatal("already-marked endpoint must refresh 4-tuple memory on every identified packet")
	}
}

func TestWithIdentifiedQuicDialUsesSymmetricKey(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.1:7777")
	decision := ClassifyUdpFlow(src, dst, []byte{0x01, 0x02})
	if decision.EndpointKeyForDial("").Dst.Port() != 0 {
		t.Fatal("ordinary off-port UDP must dial with a src-only key")
	}
	keyed := decision.withIdentifiedQuic(true)
	if keyed.EndpointKeyForDial("") != keyed.SymmetricNatEndpointKey() {
		t.Fatal("identified 1-RTT must dial dest-scoped so rebuild keeps the QUIC association")
	}
	if keyed.NatTimeoutForDial("") != QuicNatTimeout {
		t.Fatal("identified 1-RTT must keep the QUIC NAT timeout")
	}
}
