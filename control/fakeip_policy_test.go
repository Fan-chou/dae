/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
)

func TestRewriteMsgNoInet6AAAAIsNODATA(t *testing.T) {
	store := NewFakeIPStore(t.TempDir(), 8)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	if err := store.Open(v4, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := testFakeIPMatcher(t, `
domain(suffix: chatgpt.com) -> AI
fallback: direct
`, []string{"AI"})
	p := NewFakeIPPolicy(config.FakeIP{Enable: true, Ttl: 60}, store, m, nil, 1)

	aaaa := new(dnsmessage.Msg)
	aaaa.SetQuestion("chatgpt.com.", dnsmessage.TypeAAAA)
	aaaa.Response = true
	aaaa.Rcode = dnsmessage.RcodeSuccess
	aaaa.Answer = []dnsmessage.RR{&dnsmessage.AAAA{
		Hdr:  dnsmessage.RR_Header{Name: "chatgpt.com.", Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("2001:db8::1"),
	}}
	if err := p.RewriteMsg(aaaa, netip.Addr{}, [6]byte{}); err != nil {
		t.Fatal(err)
	}
	if len(aaaa.Answer) != 0 {
		t.Fatalf("AAAA answers = %v, want NODATA", aaaa.Answer)
	}

	a := new(dnsmessage.Msg)
	a.SetQuestion("chatgpt.com.", dnsmessage.TypeA)
	a.Response = true
	a.Rcode = dnsmessage.RcodeSuccess
	a.Answer = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "chatgpt.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.1.1.1").To4(),
	}}
	if err := p.RewriteMsg(a, netip.Addr{}, [6]byte{}); err != nil {
		t.Fatal(err)
	}
	mustFakeA(t, a, v4)

	aaaaOnlyA := new(dnsmessage.Msg)
	aaaaOnlyA.SetQuestion("ipv6only.chatgpt.com.", dnsmessage.TypeA)
	aaaaOnlyA.Response = true
	aaaaOnlyA.Rcode = dnsmessage.RcodeSuccess
	if err := p.RewriteMsg(aaaaOnlyA, netip.Addr{}, [6]byte{}); err != nil {
		t.Fatal(err)
	}
	mustFakeA(t, aaaaOnlyA, v4)
}

func TestRewriteMsgInet6StillFakesAAAA(t *testing.T) {
	store := NewFakeIPStore(t.TempDir(), 8)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	v6 := netip.MustParsePrefix("fd00:daee::/112")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := testFakeIPMatcher(t, `
domain(suffix: chatgpt.com) -> AI
fallback: direct
`, []string{"AI"})
	p := NewFakeIPPolicy(config.FakeIP{Enable: true, Ttl: 60}, store, m, nil, 1)

	aaaa := new(dnsmessage.Msg)
	aaaa.SetQuestion("chatgpt.com.", dnsmessage.TypeAAAA)
	aaaa.Response = true
	aaaa.Rcode = dnsmessage.RcodeSuccess
	aaaa.Answer = []dnsmessage.RR{&dnsmessage.AAAA{
		Hdr:  dnsmessage.RR_Header{Name: "chatgpt.com.", Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("2001:db8::1"),
	}}
	if err := p.RewriteMsg(aaaa, netip.Addr{}, [6]byte{}); err != nil {
		t.Fatal(err)
	}
	if len(aaaa.Answer) != 1 {
		t.Fatalf("AAAA answers = %v, want one FakeIP", aaaa.Answer)
	}
	ip, ok := dnsAnswerIP(aaaa.Answer[0])
	if !ok || !v6.Contains(ip) {
		t.Fatalf("AAAA answer = %v, want FakeIP in %s", aaaa.Answer[0], v6)
	}
}

func mustFakeA(t *testing.T, msg *dnsmessage.Msg, v4 netip.Prefix) {
	t.Helper()
	if msg == nil || len(msg.Answer) != 1 {
		t.Fatalf("A answers = %v, want one FakeIP", msg)
	}
	ip, ok := dnsAnswerIP(msg.Answer[0])
	if !ok || !v4.Contains(ip) {
		t.Fatalf("A answer = %v, want FakeIP in %s", msg.Answer[0], v4)
	}
}

func TestPackedAnswerDoesNotAliasCachedBytes(t *testing.T) {
	store := NewFakeIPStore(t.TempDir(), 8)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	if err := store.Open(v4, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := testFakeIPMatcher(t, `
domain(suffix: chatgpt.com) -> AI
fallback: direct
`, []string{"AI"})
	p := NewFakeIPPolicy(config.FakeIP{Enable: true, Ttl: 60}, store, m, nil, 1)

	first, err := p.packedAnswer("chatgpt.com.", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 2 {
		t.Fatalf("packed too short: %d", len(first))
	}
	first[0], first[1] = 0x12, 0x34

	second, err := p.packedAnswer("chatgpt.com.", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if second[0] == 0x12 && second[1] == 0x34 {
		t.Fatal("cached packed bytes were mutated by the caller")
	}
	if &first[0] == &second[0] {
		t.Fatal("packedAnswer returned the same backing array twice")
	}
}

func TestPackedOrRealDoesNotFakeInvalidRealAnswers(t *testing.T) {
	store := NewFakeIPStore(t.TempDir(), 8)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	if err := store.Open(v4, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := testFakeIPMatcher(t, `
domain(suffix: chatgpt.com) -> AI
fallback: direct
`, []string{"AI"})
	p := NewFakeIPPolicy(config.FakeIP{Enable: true, Ttl: 60}, store, m, nil, 1)
	src := netip.Addr{}
	var mac [6]byte

	nx := new(dnsmessage.Msg)
	nx.SetQuestion("chatgpt.com.", dnsmessage.TypeA)
	nx.SetRcode(nx, dnsmessage.RcodeNameError)
	nxPacked, err := nx.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.PackedOrReal("chatgpt.com.", dnsmessage.TypeA, nxPacked, src, mac)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(nxPacked) {
		t.Fatal("NXDOMAIN must not be rewritten to FakeIP")
	}

	mustPackedFakeA := func(t *testing.T, packed []byte) {
		t.Helper()
		out := new(dnsmessage.Msg)
		if err := out.Unpack(packed); err != nil {
			t.Fatal(err)
		}
		mustFakeA(t, out, v4)
	}

	nodata := new(dnsmessage.Msg)
	nodata.SetQuestion("chatgpt.com.", dnsmessage.TypeA)
	nodata.SetReply(nodata)
	nodataPacked, err := nodata.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err = p.PackedOrReal("chatgpt.com.", dnsmessage.TypeA, nodataPacked, src, mac)
	if err != nil {
		t.Fatal(err)
	}
	mustPackedFakeA(t, got)

	aaaaOnly := new(dnsmessage.Msg)
	aaaaOnly.SetQuestion("chatgpt.com.", dnsmessage.TypeA)
	aaaaOnly.SetReply(aaaaOnly)
	aaaaOnly.Answer = []dnsmessage.RR{&dnsmessage.AAAA{
		Hdr:  dnsmessage.RR_Header{Name: "chatgpt.com.", Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("2001:db8::1"),
	}}
	aaaaOnlyPacked, err := aaaaOnly.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err = p.PackedOrReal("chatgpt.com.", dnsmessage.TypeA, aaaaOnlyPacked, src, mac)
	if err != nil {
		t.Fatal(err)
	}
	mustPackedFakeA(t, got)

	okA := new(dnsmessage.Msg)
	okA.SetQuestion("chatgpt.com.", dnsmessage.TypeA)
	okA.SetReply(okA)
	okA.Answer = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "chatgpt.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.1.1.1").To4(),
	}}
	okPacked, err := okA.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err = p.PackedOrReal("chatgpt.com.", dnsmessage.TypeA, okPacked, src, mac)
	if err != nil {
		t.Fatal(err)
	}
	mustPackedFakeA(t, got)
}

func TestPackedOrRealInet6OnDoesNotFakeNODATAA(t *testing.T) {
	store := NewFakeIPStore(t.TempDir(), 8)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	v6 := netip.MustParsePrefix("fd00:daee::/112")
	if err := store.Open(v4, v6); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := testFakeIPMatcher(t, `
domain(suffix: chatgpt.com) -> AI
fallback: direct
`, []string{"AI"})
	p := NewFakeIPPolicy(config.FakeIP{Enable: true, Ttl: 60}, store, m, nil, 1)

	nodata := new(dnsmessage.Msg)
	nodata.SetQuestion("chatgpt.com.", dnsmessage.TypeA)
	nodata.SetReply(nodata)
	nodataPacked, err := nodata.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.PackedOrReal("chatgpt.com.", dnsmessage.TypeA, nodataPacked, netip.Addr{}, [6]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(nodataPacked) {
		t.Fatal("with inet6 on, NODATA A must not be rewritten to Fake A")
	}
}

func TestAssignAfterInet6PoolSwitchGetsAAAA(t *testing.T) {
	store := NewFakeIPStore(t.TempDir(), 8)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	v6a := netip.MustParsePrefix("fd00:daee::/112")
	v6b := netip.MustParsePrefix("fd00:daef::/112")
	if err := store.Open(v4, v6a); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := testFakeIPMatcher(t, `
domain(suffix: chatgpt.com) -> AI
fallback: direct
`, []string{"AI"})
	p := NewFakeIPPolicy(config.FakeIP{Enable: true, Ttl: 60}, store, m, nil, 1)

	old4, old6, err := p.assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if !v6a.Contains(old6) {
		t.Fatalf("initial AAAA = %v, want %s", old6, v6a)
	}
	if _, err := p.packedAnswer("chatgpt.com.", dnsmessage.TypeAAAA); err != nil {
		t.Fatal(err)
	}

	store.ApplyRanges(v4, v6b)
	got4, got6, err := p.assign("chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	if got4 != old4 {
		t.Fatalf("IPv4 changed %v -> %v", old4, got4)
	}
	if !got6.IsValid() || !v6b.Contains(got6) {
		t.Fatalf("after pool switch AAAA = %v, want new address in %s", got6, v6b)
	}
	if got6 == old6 {
		t.Fatal("after pool switch AAAA stayed on the parked prefix")
	}

	packed, err := p.packedAnswer("chatgpt.com.", dnsmessage.TypeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	msg := new(dnsmessage.Msg)
	if err := msg.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("packed AAAA = %v, want one FakeIP", msg.Answer)
	}
	ip, ok := dnsAnswerIP(msg.Answer[0])
	if !ok || ip != got6 {
		t.Fatalf("packed AAAA = %v, want %v", msg.Answer, got6)
	}
}

func TestRewriteMsgSkipsFakeWhenDestCIDRIsDirect(t *testing.T) {
	store := NewFakeIPStore(t.TempDir(), 8)
	v4 := netip.MustParsePrefix("198.18.0.0/24")
	if err := store.Open(v4, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m := testFakeIPMatcher(t, `
domain(suffix: example.com) && ip(203.0.113.0/24) -> CN_CN
domain(suffix: example.com) -> AI
fallback: direct
`, []string{"CN_CN", "AI"})
	m.fakeIPLeafIsProxy = func(idx consts.OutboundIndex) bool {
		return idx != consts.OutboundUserDefinedMin
	}
	p := NewFakeIPPolicy(config.FakeIP{Enable: true, Ttl: 60}, store, m, nil, 1)

	real := net.ParseIP("203.0.113.1").To4()
	a := new(dnsmessage.Msg)
	a.SetQuestion("www.example.com.", dnsmessage.TypeA)
	a.Response = true
	a.Rcode = dnsmessage.RcodeSuccess
	a.Answer = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "www.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
		A:   real,
	}}
	if err := p.RewriteMsg(a, netip.Addr{}, [6]byte{}); err != nil {
		t.Fatal(err)
	}
	if len(a.Answer) != 1 {
		t.Fatalf("answers = %v, want real A kept", a.Answer)
	}
	ip, ok := dnsAnswerIP(a.Answer[0])
	if !ok || ip.String() != "203.0.113.1" {
		t.Fatalf("got %v, want real 203.0.113.1 (CN dest must not FakeIP)", a.Answer)
	}

	proxy := new(dnsmessage.Msg)
	proxy.SetQuestion("www.example.com.", dnsmessage.TypeA)
	proxy.Response = true
	proxy.Rcode = dnsmessage.RcodeSuccess
	proxy.Answer = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "www.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
		A:   net.ParseIP("198.51.100.1").To4(),
	}}
	if err := p.RewriteMsg(proxy, netip.Addr{}, [6]byte{}); err != nil {
		t.Fatal(err)
	}
	mustFakeA(t, proxy, v4)
}
