/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package socks5

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

// duplex feeds canned client bytes and records what the server wrote.
type duplex struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func newDuplex(client ...byte) *duplex { return &duplex{in: bytes.NewReader(client)} }

func (d *duplex) Read(p []byte) (int, error)  { return d.in.Read(p) }
func (d *duplex) Write(p []byte) (int, error) { return d.out.Write(p) }

func TestHandshakeNoAuth(t *testing.T) {
	d := newDuplex(5, 2, MethodUserPass, MethodNoAuth)
	if err := Handshake(d, nil); err != nil {
		t.Fatal(err)
	}
	if got := d.out.Bytes(); !bytes.Equal(got, []byte{5, MethodNoAuth}) {
		t.Fatalf("reply = %v", got)
	}
}

func TestHandshakeNoAcceptableMethod(t *testing.T) {
	// Client only offers no-auth but the inbound requires credentials.
	d := newDuplex(5, 1, MethodNoAuth)
	err := Handshake(d, &Credentials{Username: "u", Password: "p"})
	if !errors.Is(err, ErrNoAcceptable) {
		t.Fatalf("err = %v", err)
	}
	if got := d.out.Bytes(); !bytes.Equal(got, []byte{5, MethodNoMatch}) {
		t.Fatalf("reply = %v", got)
	}
}

func TestHandshakeBadVersion(t *testing.T) {
	if err := Handshake(newDuplex(4, 1, 0), nil); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("err = %v", err)
	}
}

func authBytes(user, pass string) []byte {
	b := []byte{5, 1, MethodUserPass, 1, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

func TestHandshakeUserPass(t *testing.T) {
	creds := &Credentials{Username: "alice", Password: "s3cret"}

	d := newDuplex(authBytes("alice", "s3cret")...)
	if err := Handshake(d, creds); err != nil {
		t.Fatal(err)
	}
	if got := d.out.Bytes(); !bytes.Equal(got, []byte{5, MethodUserPass, 1, 0}) {
		t.Fatalf("reply = %v", got)
	}

	for _, tc := range [][2]string{{"alice", "wrong"}, {"bob", "s3cret"}, {"", ""}} {
		d := newDuplex(authBytes(tc[0], tc[1])...)
		if err := Handshake(d, creds); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("%v: err = %v", tc, err)
		}
		if got := d.out.Bytes(); !bytes.Equal(got, []byte{5, MethodUserPass, 1, 1}) {
			t.Fatalf("%v: reply = %v", tc, got)
		}
	}
}

func TestReadRequest(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		cmd  byte
		want Addr
	}{
		{"ipv4", []byte{5, CmdConnect, 0, AtypIPv4, 1, 2, 3, 4, 0x01, 0xBB}, CmdConnect,
			Addr{IP: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		{"ipv6", append([]byte{5, CmdUDPAssociate, 0, AtypIPv6}, append(netip.MustParseAddr("2001:db8::1").AsSlice(), 0x00, 0x35)...), CmdUDPAssociate,
			Addr{IP: netip.MustParseAddr("2001:db8::1"), Port: 53}},
		{"domain", append([]byte{5, CmdConnect, 0, AtypDomain, 11}, append([]byte("example.com"), 0x00, 0x50)...), CmdConnect,
			Addr{Domain: "example.com", Port: 80}},
	}
	for _, tc := range cases {
		cmd, addr, err := ReadRequest(bytes.NewReader(tc.in))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if cmd != tc.cmd || addr != tc.want {
			t.Fatalf("%s: got %v %+v, want %v %+v", tc.name, cmd, addr, tc.cmd, tc.want)
		}
	}
}

func TestReadRequestRejects(t *testing.T) {
	var re *ReplyError
	_, _, err := ReadRequest(bytes.NewReader([]byte{5, CmdConnect, 0, 0x09, 1, 2, 3, 4, 0, 80}))
	if !errors.As(err, &re) || re.Code != ReplyAddrTypeNotSupport {
		t.Fatalf("unknown atyp: err = %v", err)
	}
	_, _, err = ReadRequest(bytes.NewReader([]byte{5, CmdConnect, 0, AtypDomain, 0, 0, 80}))
	if !errors.As(err, &re) || re.Code != ReplyGeneralFailure {
		t.Fatalf("empty domain: err = %v", err)
	}
	_, _, err = ReadRequest(bytes.NewReader([]byte{5, CmdConnect, 1, AtypIPv4, 1, 2, 3, 4, 0, 80}))
	if !errors.As(err, &re) || re.Code != ReplyGeneralFailure {
		t.Fatalf("nonzero RSV: err = %v", err)
	}
	if _, _, err = ReadRequest(bytes.NewReader([]byte{4, CmdConnect, 0})); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("bad version: err = %v", err)
	}
	if _, _, err = ReadRequest(bytes.NewReader([]byte{5, CmdConnect, 0, AtypIPv4, 1, 2})); err == nil {
		t.Fatal("truncated request accepted")
	}
}

func TestWriteReply(t *testing.T) {
	var buf bytes.Buffer
	bind := Addr{IP: netip.MustParseAddr("10.0.0.1"), Port: 1080}
	if err := WriteReply(&buf, ReplySucceeded, bind); err != nil {
		t.Fatal(err)
	}
	if want := []byte{5, 0, 0, AtypIPv4, 10, 0, 0, 1, 0x04, 0x38}; !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("reply = %v, want %v", buf.Bytes(), want)
	}
	buf.Reset()
	if err := WriteReply(&buf, ReplyHostUnreachable, Addr{}); err != nil {
		t.Fatal(err)
	}
	if want := []byte{5, ReplyHostUnreachable, 0, AtypIPv4, 0, 0, 0, 0, 0, 0}; !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("failure reply = %v, want %v", buf.Bytes(), want)
	}
}

func TestUDPPacketRoundTrip(t *testing.T) {
	payload := []byte("hello")
	for _, a := range []Addr{
		{IP: netip.MustParseAddr("8.8.8.8"), Port: 53},
		{IP: netip.MustParseAddr("2001:db8::2"), Port: 443},
		{Domain: "example.org", Port: 8443},
	} {
		pkt := append(AppendUDPHeader(nil, a), payload...)
		got, data, err := ParseUDPPacket(pkt)
		if err != nil {
			t.Fatalf("%v: %v", a, err)
		}
		if got != a || !bytes.Equal(data, payload) {
			t.Fatalf("%v: got %+v %q", a, got, data)
		}
	}
}

func TestUDPPacketIPv4MappedIPv6IsUnmapped(t *testing.T) {
	a := Addr{IP: netip.MustParseAddr("::ffff:1.2.3.4"), Port: 9}
	got, _, err := ParseUDPPacket(append(AppendUDPHeader(nil, a), 'x'))
	if err != nil {
		t.Fatal(err)
	}
	if got.IP != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("ip = %v", got.IP)
	}
}

func TestUDPPacketRejects(t *testing.T) {
	good := append(AppendUDPHeader(nil, Addr{IP: netip.MustParseAddr("1.1.1.1"), Port: 53}), 'x')

	frag := append([]byte(nil), good...)
	frag[2] = 1
	if _, _, err := ParseUDPPacket(frag); !errors.Is(err, ErrFragmentedPacket) {
		t.Fatalf("fragment: err = %v", err)
	}
	rsv := append([]byte(nil), good...)
	rsv[0] = 1
	if _, _, err := ParseUDPPacket(rsv); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("rsv: err = %v", err)
	}
	for n := 0; n < len(good)-1; n++ {
		// Every strict prefix that cuts into the header must fail without panic;
		// the full header with an empty payload is legal.
		if _, _, err := ParseUDPPacket(good[:n]); err == nil && n < len(good)-1 {
			t.Fatalf("prefix of %d bytes accepted", n)
		}
	}
	if _, _, err := ParseUDPPacket([]byte{0, 0, 0, AtypDomain, 0, 0, 80}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("empty domain: err = %v", err)
	}
	if _, _, err := ParseUDPPacket([]byte{0, 0, 0, 0x09, 1, 2, 3, 4, 0, 80}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unknown atyp: err = %v", err)
	}
}
