/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/sirupsen/logrus"
)

// ErrQuicAdministrativelyProhibited is returned instead of dialing when
// block_quic is on and the selected chain cannot carry identified QUIC as
// unreliable datagrams. Callers send ICMP admin-prohibited (REJECT-NO-DROP)
// and must not forward the datagram.
var ErrQuicAdministrativelyProhibited = fmt.Errorf("quic rejected: administratively prohibited")

const (
	icmp4DestUnreach                = 3
	icmp4CommAdministrativelyProhib = 13
	icmp6DestUnreach                = 1
	icmp6CommAdministrativelyProhib = 1
	icmpQuoteBytes                  = 128

	ipprotoUDP    = 17
	ipprotoICMPV6 = 58

	quicRejectRememberTTL    = 5 * time.Minute
	quicICMPMinInterval      = 200 * time.Millisecond
	quicRejectMemoryShards   = 16
	quicRejectMemoryPerShard = 256
)

type quicRejectFlowState struct {
	identifiedUntilNano int64
	domainUntilNano     int64
	nextICMPNano        int64
	domain              string
}

type quicRejectShard struct {
	mu    sync.Mutex
	flows map[UdpFlowKey]quicRejectFlowState
}

type quicRejectMemory struct {
	shards [quicRejectMemoryShards]quicRejectShard
}

var defaultQuicRejectMemory = newQuicRejectMemory()

func newQuicRejectMemory() *quicRejectMemory {
	m := &quicRejectMemory{}
	for i := range m.shards {
		m.shards[i].flows = make(map[UdpFlowKey]quicRejectFlowState)
	}
	return m
}

func resetQuicRejectMemoryForTest() {
	m := defaultQuicRejectMemory
	if m == nil {
		defaultQuicRejectMemory = newQuicRejectMemory()
		return
	}
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		s.flows = make(map[UdpFlowKey]quicRejectFlowState)
		s.mu.Unlock()
	}
}

func quicRejectShardIndex(key UdpFlowKey) int {
	var h uint64
	if src := key.Src.Addr(); src.IsValid() {
		if src.Is4() {
			a := src.As4()
			h ^= uint64(binary.LittleEndian.Uint32(a[:]))
		} else {
			a := src.As16()
			h ^= binary.LittleEndian.Uint64(a[0:8]) ^ binary.LittleEndian.Uint64(a[8:16])
		}
	}
	if dst := key.Dst.Addr(); dst.IsValid() {
		if dst.Is4() {
			a := dst.As4()
			h ^= uint64(binary.LittleEndian.Uint32(a[:])) << 1
		} else {
			a := dst.As16()
			h ^= binary.LittleEndian.Uint64(a[8:16])
		}
	}
	h ^= uint64(key.Src.Port()) | uint64(key.Dst.Port())<<16
	return int(h & uint64(quicRejectMemoryShards-1))
}

func (m *quicRejectMemory) shard(key UdpFlowKey) *quicRejectShard {
	if m == nil {
		return nil
	}
	return &m.shards[quicRejectShardIndex(key)]
}

func (m *quicRejectMemory) recentlyIdentified(key UdpFlowKey, nowNano int64) bool {
	s := m.shard(key)
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.flows[key]
	return ok && st.identifiedUntilNano > nowNano
}

func (m *quicRejectMemory) rememberedDomain(key UdpFlowKey, nowNano int64) string {
	s := m.shard(key)
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.flows[key]
	if !ok || st.domainUntilNano <= nowNano {
		return ""
	}
	return st.domain
}

func (m *quicRejectMemory) noteRejected(key UdpFlowKey, nowNano int64) (sendICMP bool) {
	s := m.shard(key)
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.flows[key]; ok {
		sendICMP = st.nextICMPNano == 0 || nowNano >= st.nextICMPNano
		st.identifiedUntilNano = nowNano + int64(quicRejectRememberTTL)
		if sendICMP {
			st.nextICMPNano = nowNano + int64(quicICMPMinInterval)
		}
		s.flows[key] = st
		return sendICMP
	}
	if len(s.flows) >= quicRejectMemoryPerShard {
		s.purgeExpiredLocked(nowNano)
	}
	if len(s.flows) >= quicRejectMemoryPerShard {
		s.evictOldestLocked(quicRejectMemoryPerShard / 2)
	}
	st := quicRejectFlowState{
		identifiedUntilNano: nowNano + int64(quicRejectRememberTTL),
		nextICMPNano:        nowNano + int64(quicICMPMinInterval),
	}
	s.flows[key] = st
	return true
}

func (m *quicRejectMemory) rememberIdentified(key UdpFlowKey, nowNano int64) {
	s := m.shard(key)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until := nowNano + int64(quicRejectRememberTTL)
	if st, ok := s.flows[key]; ok {
		if st.identifiedUntilNano < until {
			st.identifiedUntilNano = until
			s.flows[key] = st
		}
		return
	}
	if len(s.flows) >= quicRejectMemoryPerShard {
		s.purgeExpiredLocked(nowNano)
	}
	if len(s.flows) >= quicRejectMemoryPerShard {
		s.evictOldestLocked(quicRejectMemoryPerShard / 2)
	}
	s.flows[key] = quicRejectFlowState{identifiedUntilNano: until}
}

func (m *quicRejectMemory) rememberDomain(key UdpFlowKey, nowNano int64, domain string) {
	domain = strings.TrimSuffix(domain, ".")
	if m == nil || domain == "" || isIPLikeDomain(domain) {
		return
	}
	s := m.shard(key)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until := nowNano + int64(quicRejectRememberTTL)
	if st, ok := s.flows[key]; ok {
		st.domain = domain
		if st.domainUntilNano < until {
			st.domainUntilNano = until
		}
		s.flows[key] = st
		return
	}
	if len(s.flows) >= quicRejectMemoryPerShard {
		s.purgeExpiredLocked(nowNano)
	}
	if len(s.flows) >= quicRejectMemoryPerShard {
		s.evictOldestLocked(quicRejectMemoryPerShard / 2)
	}
	s.flows[key] = quicRejectFlowState{domain: domain, domainUntilNano: until}
}

func flowStateLiveUntil(st quicRejectFlowState) int64 {
	if st.domainUntilNano > st.identifiedUntilNano {
		return st.domainUntilNano
	}
	return st.identifiedUntilNano
}

func (s *quicRejectShard) purgeExpiredLocked(nowNano int64) {
	for key, st := range s.flows {
		if flowStateLiveUntil(st) <= nowNano {
			delete(s.flows, key)
		}
	}
}

func (s *quicRejectShard) evictOldestLocked(keep int) {
	if keep < 0 {
		keep = 0
	}
	for len(s.flows) > keep {
		var oldest UdpFlowKey
		oldestUntil := int64(0)
		first := true
		for key, st := range s.flows {
			until := flowStateLiveUntil(st)
			if first || until < oldestUntil {
				oldest = key
				oldestUntil = until
				first = false
			}
		}
		if first {
			return
		}
		delete(s.flows, oldest)
	}
}

func (m *quicRejectMemory) lenForTest() int {
	if m == nil {
		return 0
	}
	n := 0
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		n += len(s.flows)
		s.mu.Unlock()
	}
	return n
}

// isIdentifiedQuicPacket reports QUIC for block_quic. Cheap 443/8443 sniff
// classification (IsLikelyQuicInitialPacket / a just-created sniffer) is not
// enough: those fire on ~1/8 of random long-header lookalikes. Blocking
// requires a strict client Initial, a persisted endpoint mark, or reject memory.
func isIdentifiedQuicPacket(decision UdpFlowDecision, data []byte) bool {
	if decision.IsStrictClientInitial {
		return true
	}
	return sniffing.IsStrictQuicClientInitialPacket(data)
}

func quicIdentifiedFromEndpoint(identified bool, ue *UdpEndpoint) bool {
	if ue != nil && ue.identifiedQuic() {
		return true
	}
	return identified
}

func (c *ControlPlane) preserveIdentifiedQuic(ue *UdpEndpoint, identified bool, client, dest netip.AddrPort) bool {
	identified = quicIdentifiedFromEndpoint(identified, ue)
	if identified {
		c.rememberIdentifiedQuic(client, dest)
	}
	if ue != nil {
		c.rememberUdpFlowDomain(client, dest, ue.SniffedDomain)
	}
	return identified
}

func (c *ControlPlane) isQuicBlockCandidate(decision UdpFlowDecision, data []byte) bool {
	if isIdentifiedQuicPacket(decision, data) {
		return true
	}
	if c == nil || !c.blockQuic {
		return false
	}
	return defaultQuicRejectMemory.recentlyIdentified(decision.Key, time.Now().UnixNano())
}

func (c *ControlPlane) rememberIdentifiedQuic(client, dest netip.AddrPort) {
	if c == nil || !client.IsValid() || !dest.IsValid() {
		return
	}
	defaultQuicRejectMemory.rememberIdentified(NewUdpFlowKey(client, dest), time.Now().UnixNano())
}

func (c *ControlPlane) rememberUdpFlowDomain(client, dest netip.AddrPort, domain string) {
	if c == nil || !client.IsValid() || !dest.IsValid() {
		return
	}
	defaultQuicRejectMemory.rememberDomain(NewUdpFlowKey(client, dest), time.Now().UnixNano(), domain)
}

func (c *ControlPlane) rememberedUdpFlowDomain(client, dest netip.AddrPort) string {
	if c == nil || !client.IsValid() || !dest.IsValid() {
		return ""
	}
	return defaultQuicRejectMemory.rememberedDomain(NewUdpFlowKey(client, dest), time.Now().UnixNano())
}

func shouldRejectIdentifiedQuic(blockQuic bool, identified bool, mode dialer.UdpForwardMode) bool {
	return blockQuic && identified && !mode.AllowsUnreliableDatagram()
}

func (c *ControlPlane) shouldRejectProxiedQuic(d *dialer.Dialer, identified bool) bool {
	if c == nil || !c.blockQuic || !identified {
		return false
	}
	return !d.UdpForwardMode().AllowsUnreliableDatagram()
}

func (c *ControlPlane) rejectEndpointQuic(ue *UdpEndpoint, data []byte, client, dest netip.AddrPort, identified bool) bool {
	if c == nil || ue == nil {
		return false
	}
	identified = quicIdentifiedFromEndpoint(identified, ue)
	if identified {
		ue.markIdentifiedQuic()
		c.rememberIdentifiedQuic(client, dest)
	}
	if !c.shouldRejectProxiedQuic(ue.Dialer, identified) {
		return false
	}
	c.rejectQuicWithICMP(data, client, dest)
	ue.retire()
	return true
}

func (c *ControlPlane) rejectQuicWithICMP(data []byte, client, dest netip.AddrPort) {
	if c == nil {
		return
	}
	sendICMP := defaultQuicRejectMemory.noteRejected(NewUdpFlowKey(client, dest), time.Now().UnixNano())
	if !sendICMP {
		return
	}
	if err := sendICMPAdminProhibited(data, client, dest, c.soMarkFromDae); err != nil {
		if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithError(err).WithField("src", client).WithField("dst", dest).
				Debug("REJECT-NO-DROP: failed to send ICMP administratively prohibited for QUIC")
		}
		return
	}
	if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithField("src", client).WithField("dst", dest).
			Debug("REJECT-NO-DROP: QUIC administratively prohibited")
	}
}

func buildIPv4ICMPAdminProhibited(client, dest netip.AddrPort, udpPayload []byte) []byte {
	quoted := quoteOriginalUDPv4(client, dest, udpPayload)
	msg := make([]byte, 8+len(quoted))
	msg[0] = icmp4DestUnreach
	msg[1] = icmp4CommAdministrativelyProhib
	copy(msg[8:], quoted)
	binary.BigEndian.PutUint16(msg[2:4], internetChecksum16(msg))
	return msg
}

func buildIPv6ICMPAdminProhibited(client, dest netip.AddrPort, udpPayload []byte) []byte {
	quoted := quoteOriginalUDPv6(client, dest, udpPayload)
	msg := make([]byte, 8+len(quoted))
	msg[0] = icmp6DestUnreach
	msg[1] = icmp6CommAdministrativelyProhib
	copy(msg[8:], quoted)
	binary.BigEndian.PutUint16(msg[2:4], icmp6Checksum(dest.Addr(), client.Addr(), msg))
	return msg
}

func quoteOriginalUDPv4(client, dest netip.AddrPort, udpPayload []byte) []byte {
	src := client.Addr().Unmap().As4()
	dst := dest.Addr().Unmap().As4()
	payload := udpPayload
	if len(payload) > icmpQuoteBytes-28 {
		payload = payload[:icmpQuoteBytes-28]
	}
	udpLen := 8 + len(udpPayload)
	if udpLen > 0xffff {
		udpLen = 0xffff
	}
	total := 20 + 8 + len(payload)
	buf := make([]byte, total)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(20+udpLen))
	buf[8] = 64
	buf[9] = ipprotoUDP
	copy(buf[12:16], src[:])
	copy(buf[16:20], dst[:])
	binary.BigEndian.PutUint16(buf[10:12], internetChecksum16(buf[:20]))
	binary.BigEndian.PutUint16(buf[20:22], client.Port())
	binary.BigEndian.PutUint16(buf[22:24], dest.Port())
	binary.BigEndian.PutUint16(buf[24:26], uint16(udpLen))
	copy(buf[28:], payload)
	return buf
}

func quoteOriginalUDPv6(client, dest netip.AddrPort, udpPayload []byte) []byte {
	src := client.Addr().As16()
	dst := dest.Addr().As16()
	payload := udpPayload
	if len(payload) > icmpQuoteBytes-48 {
		payload = payload[:icmpQuoteBytes-48]
	}
	udpLen := 8 + len(udpPayload)
	if udpLen > 0xffff {
		udpLen = 0xffff
	}
	buf := make([]byte, 40+8+len(payload))
	buf[0] = 0x60
	binary.BigEndian.PutUint16(buf[4:6], uint16(udpLen))
	buf[6] = ipprotoUDP
	buf[7] = 64
	copy(buf[8:24], src[:])
	copy(buf[24:40], dst[:])
	binary.BigEndian.PutUint16(buf[40:42], client.Port())
	binary.BigEndian.PutUint16(buf[42:44], dest.Port())
	binary.BigEndian.PutUint16(buf[44:46], uint16(udpLen))
	copy(buf[48:], payload)
	return buf
}

func icmp6Checksum(src, dst netip.Addr, icmp []byte) uint16 {
	pseudo := make([]byte, 40+len(icmp))
	s := src.As16()
	d := dst.As16()
	copy(pseudo[0:16], s[:])
	copy(pseudo[16:32], d[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = ipprotoICMPV6
	copy(pseudo[40:], icmp)
	return internetChecksum16(pseudo)
}

func internetChecksum16(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
