/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
)

type FakeIPPolicy struct {
	enabled bool
	ttl     uint32
	store   *FakeIPStore
	matcher *RoutingMatcher
	filter  *fakeIPFilterMatcher

	epoch uint64
}

func NewFakeIPPolicy(cfg config.FakeIP, store *FakeIPStore, matcher *RoutingMatcher, filter *fakeIPFilterMatcher, epoch uint64) *FakeIPPolicy {
	return &FakeIPPolicy{
		enabled: cfg.Enable && store != nil,
		ttl:     uint32(cfg.ResolvedTTL()),
		store:   store,
		matcher: matcher,
		filter:  filter,
		epoch:   epoch,
	}
}

func (p *FakeIPPolicy) Enabled() bool {
	return p != nil && p.enabled && p.store != nil && p.store.Ready()
}

func (p *FakeIPPolicy) ShouldFake(qname string, qtype uint16, src netip.Addr, mac [6]byte, dests []netip.Addr) bool {
	if !p.Enabled() {
		return false
	}
	if p.filter != nil && p.filter.Hit(qname) {
		return false
	}
	if p.matcher == nil {
		return false
	}
	var ipVersion *consts.IpVersionType
	switch qtype {
	case dnsmessage.TypeA:
		v := consts.IpVersion_4
		ipVersion = &v
	case dnsmessage.TypeAAAA:
		v := consts.IpVersion_6
		ipVersion = &v
	}
	switch p.matcher.FakeIPEligibilityFor(strings.TrimSuffix(qname, "."), ipVersion, src, mac, dests) {
	case FakeIPEligibilityProxy:
		return true
	default:
		return false
	}
}

func (p *FakeIPPolicy) PackedOrReal(qname string, qtype uint16, realPacked []byte, src netip.Addr, mac [6]byte) ([]byte, error) {
	if !p.Enabled() {
		return realPacked, nil
	}
	msg := new(dnsmessage.Msg)
	if err := msg.Unpack(realPacked); err != nil {
		return realPacked, nil
	}
	if !p.ShouldFake(qname, qtype, src, mac, fakeIPMsgAddrs(msg)) || !p.shouldRewrite(msg, qtype) {
		return realPacked, nil
	}
	return p.packedAnswer(qname, qtype)
}

func (p *FakeIPPolicy) RewriteMsg(msg *dnsmessage.Msg, src netip.Addr, mac [6]byte) error {
	if msg == nil || len(msg.Question) == 0 {
		return nil
	}
	q := msg.Question[0]
	if !p.ShouldFake(q.Name, q.Qtype, src, mac, fakeIPMsgAddrs(msg)) {
		return nil
	}
	if !p.shouldRewrite(msg, q.Qtype) {
		return nil
	}
	packed, err := p.packedAnswer(q.Name, q.Qtype)
	if err != nil {
		return err
	}
	out := new(dnsmessage.Msg)
	if err := out.Unpack(packed); err != nil {
		return err
	}
	out.Id = msg.Id
	*msg = *out
	return nil
}

// shouldRewrite requires positive answer evidence. Empty answers, including
// response-policy rejection and A NODATA, must never acquire a FakeIP merely
// because no IPv6 pool is configured. Negative answers retain their authority.
func (p *FakeIPPolicy) shouldRewrite(msg *dnsmessage.Msg, qtype uint16) bool {
	if msg == nil || len(msg.Question) != 1 || msg.Question[0].Qclass != dnsmessage.ClassINET || msg.Rcode != dnsmessage.RcodeSuccess || len(msg.Answer) == 0 {
		return false
	}
	switch qtype {
	case dnsmessage.TypeA:
		return fakeIPMsgHasIP(msg, false) || (!p.inet6Enabled() && fakeIPMsgHasIP(msg, true))
	case dnsmessage.TypeAAAA:
		if !p.inet6Enabled() {
			return true
		}
		return fakeIPMsgHasIP(msg, true)
	default:
		return true
	}
}

func (p *FakeIPPolicy) packedAnswer(qname string, qtype uint16) ([]byte, error) {
	qname = canonicalizeFakeIPQname(qname)
	// Derive the response from the current mapping every time. A separate
	// packed cache can outlive a retired IPv4 range and return its old IP.

	msg := new(dnsmessage.Msg)
	msg.SetReply(&dnsmessage.Msg{Question: []dnsmessage.Question{{
		Name:   qname,
		Qtype:  qtype,
		Qclass: dnsmessage.ClassINET,
	}}})
	msg.Authoritative = false
	msg.RecursionAvailable = true
	msg.AuthenticatedData = false
	msg.Compress = true

	switch qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		v4, v6, err := p.assign(qname)
		if err != nil {
			return nil, err
		}
		if qtype == dnsmessage.TypeA {
			msg.Answer = []dnsmessage.RR{&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: qname, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: p.ttl},
				A:   net.IP(v4.AsSlice()),
			}}
		} else if v6.IsValid() {
			msg.Answer = []dnsmessage.RR{&dnsmessage.AAAA{
				Hdr:  dnsmessage.RR_Header{Name: qname, Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: p.ttl},
				AAAA: net.IP(v6.AsSlice()),
			}}
		} else {
			msg.Answer = nil
		}
	default:
		// Eligible HTTPS/SVCB and other types: NODATA so clients fall back to A/AAAA.
		msg.Answer = nil
	}

	return msg.Pack()
}

func (p *FakeIPPolicy) assign(qname string) (netip.Addr, netip.Addr, error) {
	v4, v6, ok := p.store.Lookup(qname)
	if ok && (!p.inet6Enabled() || v6.IsValid()) {
		return v4, v6, nil
	}
	v4, v6, _, err := p.store.Assign(qname)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	return v4, v6, nil
}

func (p *FakeIPPolicy) inet6Enabled() bool {
	return p.inet6CacheID() != "off"
}

func (p *FakeIPPolicy) inet6CacheID() string {
	if p == nil || p.store == nil {
		return "off"
	}
	active, _ := p.store.Prefixes()
	for _, prefix := range active {
		if prefix.IsValid() && prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
			return prefix.String()
		}
	}
	return "off"
}

func (p *FakeIPPolicy) Store() *FakeIPStore {
	if p == nil {
		return nil
	}
	return p.store
}

func fakeIPMsgHasIP(msg *dnsmessage.Msg, ipv6 bool) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Answer {
		ip, ok := dnsAnswerIP(rr)
		if !ok {
			continue
		}
		if ipv6 && ip.Is6() && !ip.Is4In6() {
			return true
		}
		if !ipv6 && (ip.Is4() || ip.Is4In6()) {
			return true
		}
	}
	return false
}

func fakeIPMsgAddrs(msg *dnsmessage.Msg) []netip.Addr {
	if msg == nil {
		return nil
	}
	var out []netip.Addr
	for _, rr := range msg.Answer {
		ip, ok := dnsAnswerIP(rr)
		if !ok || !ip.IsValid() {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func fakeIPDialRejected(store *FakeIPStore, addr netip.Addr) error {
	if store == nil || !store.Contains(addr) {
		return nil
	}
	return fmt.Errorf("refusing to dial FakeIP %s", addr)
}
