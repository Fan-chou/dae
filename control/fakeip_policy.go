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
	"sync"

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

	mu     sync.Mutex
	packed map[fakeIPPackedKey][]byte
	epoch  uint64
}

type fakeIPPackedKey struct {
	qname string
	qtype uint16
}

func NewFakeIPPolicy(cfg config.FakeIP, store *FakeIPStore, matcher *RoutingMatcher, filter *fakeIPFilterMatcher, epoch uint64) *FakeIPPolicy {
	return &FakeIPPolicy{
		enabled: cfg.Enable && store != nil,
		ttl:     uint32(cfg.ResolvedTTL()),
		store:   store,
		matcher: matcher,
		filter:  filter,
		packed:  make(map[fakeIPPackedKey][]byte),
		epoch:   epoch,
	}
}

func (p *FakeIPPolicy) Enabled() bool {
	return p != nil && p.enabled && p.store != nil && p.store.Ready()
}

func (p *FakeIPPolicy) ShouldFake(qname string, qtype uint16, src netip.Addr, mac [6]byte) bool {
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
	switch p.matcher.FakeIPEligibilityFor(strings.TrimSuffix(qname, "."), ipVersion, src, mac) {
	case FakeIPEligibilityProxy:
		return true
	default:
		return false
	}
}

func (p *FakeIPPolicy) PackedOrReal(qname string, qtype uint16, realPacked []byte, src netip.Addr, mac [6]byte) ([]byte, error) {
	if !p.ShouldFake(qname, qtype, src, mac) {
		return realPacked, nil
	}
	return p.packedAnswer(qname, qtype)
}

func (p *FakeIPPolicy) RewriteMsg(msg *dnsmessage.Msg, src netip.Addr, mac [6]byte) error {
	if msg == nil || len(msg.Question) == 0 {
		return nil
	}
	if msg.Rcode != dnsmessage.RcodeSuccess {
		return nil
	}
	q := msg.Question[0]
	if !p.ShouldFake(q.Name, q.Qtype, src, mac) {
		return nil
	}
	// Do not synthesize a Fake A/AAAA when the real answer has no address
	// of that family. Happy Eyeballs would otherwise try Fake AAAA first
	// and hang on names that only have A records.
	if q.Qtype == dnsmessage.TypeA && !fakeIPMsgHasIP(msg, false) {
		return nil
	}
	if q.Qtype == dnsmessage.TypeAAAA && !fakeIPMsgHasIP(msg, true) {
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

func (p *FakeIPPolicy) packedAnswer(qname string, qtype uint16) ([]byte, error) {
	qname = canonicalizeFakeIPQname(qname)
	key := fakeIPPackedKey{qname: qname, qtype: qtype}
	p.mu.Lock()
	if packed, ok := p.packed[key]; ok {
		p.mu.Unlock()
		p.store.Touch(qname)
		return packed, nil
	}
	p.mu.Unlock()

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
		} else {
			msg.Answer = []dnsmessage.RR{&dnsmessage.AAAA{
				Hdr:  dnsmessage.RR_Header{Name: qname, Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: p.ttl},
				AAAA: net.IP(v6.AsSlice()),
			}}
		}
	default:
		// Eligible HTTPS/SVCB and other types: NODATA so clients fall back to A/AAAA.
		msg.Answer = nil
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.packed[key] = packed
	p.mu.Unlock()
	return packed, nil
}

func (p *FakeIPPolicy) assign(qname string) (netip.Addr, netip.Addr, error) {
	v4, v6, ok := p.store.Lookup(qname)
	if ok {
		return v4, v6, nil
	}
	v4, v6, _, err := p.store.Assign(qname)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	return v4, v6, nil
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

func fakeIPDialRejected(store *FakeIPStore, addr netip.Addr) error {
	if store == nil || !store.Contains(addr) {
		return nil
	}
	return fmt.Errorf("refusing to dial FakeIP %s", addr)
}
