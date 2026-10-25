/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Package socks5 implements the server side wire format of SOCKS5
// (RFC 1928) with username/password authentication (RFC 1929). It only
// parses and formats; sockets, routing and relaying belong to the caller.
package socks5

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

const (
	Version         = 0x05
	authVersion     = 0x01
	MethodNoAuth    = 0x00
	MethodUserPass  = 0x02
	MethodNoMatch   = 0xFF
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

// Reply codes of RFC 1928 section 6.
const (
	ReplySucceeded          = 0x00
	ReplyGeneralFailure     = 0x01
	ReplyNotAllowed         = 0x02
	ReplyNetworkUnreachable = 0x03
	ReplyHostUnreachable    = 0x04
	ReplyConnectionRefused  = 0x05
	ReplyTTLExpired         = 0x06
	ReplyCommandNotSupport  = 0x07
	ReplyAddrTypeNotSupport = 0x08
)

var (
	ErrBadVersion       = errors.New("socks5: unsupported protocol version")
	ErrNoAcceptable     = errors.New("socks5: no acceptable authentication method")
	ErrAuthFailed       = errors.New("socks5: authentication failed")
	ErrBadRequest       = errors.New("socks5: malformed request")
	ErrShortPacket      = errors.New("socks5: short UDP packet")
	ErrFragmentedPacket = errors.New("socks5: fragmented UDP packet")
)

// ReplyError carries the reply code a server should answer a bad request with.
type ReplyError struct {
	Code byte
	Err  error
}

func (e *ReplyError) Error() string { return e.Err.Error() }
func (e *ReplyError) Unwrap() error { return e.Err }

// Addr is a SOCKS5 address: an IP or a domain name, plus a port.
type Addr struct {
	IP     netip.Addr // valid for IPv4/IPv6 addresses
	Domain string     // set instead of IP for domain names
	Port   uint16
}

// IsDomain reports whether the address is a domain name.
func (a Addr) IsDomain() bool { return a.Domain != "" }

// Host returns the domain or the textual IP.
func (a Addr) Host() string {
	if a.IsDomain() {
		return a.Domain
	}
	return a.IP.String()
}

// String returns host:port.
func (a Addr) String() string {
	return net.JoinHostPort(a.Host(), strconv.Itoa(int(a.Port)))
}

// AddrFromAddrPort converts a socket address.
func AddrFromAddrPort(ap netip.AddrPort) Addr {
	return Addr{IP: ap.Addr().Unmap(), Port: ap.Port()}
}

// Credentials are the RFC 1929 username and password a client must present.
type Credentials struct {
	Username string
	Password string
}

// Handshake runs method negotiation and, when creds is non-nil, the RFC 1929
// sub-negotiation. With nil creds only the "no authentication" method is
// accepted.
func Handshake(rw io.ReadWriter, creds *Credentials) error {
	var head [2]byte
	if _, err := io.ReadFull(rw, head[:]); err != nil {
		return err
	}
	if head[0] != Version {
		return ErrBadVersion
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return err
	}
	want := byte(MethodNoAuth)
	if creds != nil {
		want = MethodUserPass
	}
	found := false
	for _, m := range methods {
		if m == want {
			found = true
			break
		}
	}
	if !found {
		_, _ = rw.Write([]byte{Version, MethodNoMatch})
		return ErrNoAcceptable
	}
	if _, err := rw.Write([]byte{Version, want}); err != nil {
		return err
	}
	if creds == nil {
		return nil
	}
	return authenticate(rw, creds)
}

func authenticate(rw io.ReadWriter, creds *Credentials) error {
	var head [2]byte
	if _, err := io.ReadFull(rw, head[:1]); err != nil {
		return err
	}
	if head[0] != authVersion {
		_, _ = rw.Write([]byte{authVersion, 0x01})
		return ErrBadVersion
	}
	user, err := readLenPrefixed(rw)
	if err != nil {
		return err
	}
	pass, err := readLenPrefixed(rw)
	if err != nil {
		return err
	}
	// Compare both fields in constant time and without short-circuiting, so
	// the reply timing does not reveal which one was wrong.
	okUser := subtle.ConstantTimeCompare(user, []byte(creds.Username))
	okPass := subtle.ConstantTimeCompare(pass, []byte(creds.Password))
	if okUser&okPass != 1 {
		_, _ = rw.Write([]byte{authVersion, 0x01})
		return ErrAuthFailed
	}
	_, err = rw.Write([]byte{authVersion, 0x00})
	return err
}

func readLenPrefixed(r io.Reader) ([]byte, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, n[0])
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ReadRequest reads a request after Handshake. A *ReplyError result tells the
// caller which failure reply to send before closing.
func ReadRequest(r io.Reader) (cmd byte, addr Addr, err error) {
	var head [3]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return 0, Addr{}, err
	}
	if head[0] != Version {
		return 0, Addr{}, ErrBadVersion
	}
	if head[2] != 0x00 {
		return 0, Addr{}, &ReplyError{Code: ReplyGeneralFailure, Err: ErrBadRequest}
	}
	addr, err = readAddr(r)
	if err != nil {
		return 0, Addr{}, err
	}
	return head[1], addr, nil
}

func readAddr(r io.Reader) (Addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Addr{}, err
	}
	var a Addr
	switch atyp[0] {
	case AtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Addr{}, err
		}
		a.IP = netip.AddrFrom4(b)
	case AtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Addr{}, err
		}
		a.IP = netip.AddrFrom16(b).Unmap()
	case AtypDomain:
		name, err := readLenPrefixed(r)
		if err != nil {
			return Addr{}, err
		}
		if len(name) == 0 {
			return Addr{}, &ReplyError{Code: ReplyGeneralFailure, Err: fmt.Errorf("%w: empty domain", ErrBadRequest)}
		}
		a.Domain = string(name)
	default:
		return Addr{}, &ReplyError{Code: ReplyAddrTypeNotSupport, Err: fmt.Errorf("%w: address type %#x", ErrBadRequest, atyp[0])}
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Addr{}, err
	}
	a.Port = uint16(port[0])<<8 | uint16(port[1])
	return a, nil
}

// AppendAddr appends ATYP, address and port to dst.
func AppendAddr(dst []byte, a Addr) []byte {
	switch {
	case a.IsDomain():
		name := a.Domain
		if len(name) > 255 {
			name = name[:255]
		}
		dst = append(dst, AtypDomain, byte(len(name)))
		dst = append(dst, name...)
	case a.IP.Is4() || a.IP.Is4In6():
		b := a.IP.Unmap().As4()
		dst = append(dst, AtypIPv4)
		dst = append(dst, b[:]...)
	default:
		b := a.IP.As16()
		dst = append(dst, AtypIPv6)
		dst = append(dst, b[:]...)
	}
	return append(dst, byte(a.Port>>8), byte(a.Port))
}

// WriteReply writes a reply with the given code and bound address. An invalid
// bind address is sent as 0.0.0.0:0.
func WriteReply(w io.Writer, code byte, bind Addr) error {
	if !bind.IsDomain() && !bind.IP.IsValid() {
		bind.IP = netip.IPv4Unspecified()
		bind.Port = 0
	}
	buf := make([]byte, 0, 4+1+255+2)
	buf = append(buf, Version, code, 0x00)
	buf = AppendAddr(buf, bind)
	_, err := w.Write(buf)
	return err
}

// ParseUDPPacket splits a client datagram into destination and payload. The
// payload aliases b. Fragmented datagrams are rejected, which RFC 1928 allows.
func ParseUDPPacket(b []byte) (Addr, []byte, error) {
	// RSV(2) FRAG(1) ATYP(1) + at least one address byte + PORT(2)
	if len(b) < 4 {
		return Addr{}, nil, ErrShortPacket
	}
	if b[0] != 0 || b[1] != 0 {
		return Addr{}, nil, ErrBadRequest
	}
	if b[2] != 0 {
		return Addr{}, nil, ErrFragmentedPacket
	}
	var a Addr
	rest := b[4:]
	switch b[3] {
	case AtypIPv4:
		if len(rest) < 4+2 {
			return Addr{}, nil, ErrShortPacket
		}
		a.IP = netip.AddrFrom4([4]byte(rest[:4]))
		rest = rest[4:]
	case AtypIPv6:
		if len(rest) < 16+2 {
			return Addr{}, nil, ErrShortPacket
		}
		a.IP = netip.AddrFrom16([16]byte(rest[:16])).Unmap()
		rest = rest[16:]
	case AtypDomain:
		if len(rest) < 1 {
			return Addr{}, nil, ErrShortPacket
		}
		n := int(rest[0])
		if n == 0 {
			return Addr{}, nil, ErrBadRequest
		}
		if len(rest) < 1+n+2 {
			return Addr{}, nil, ErrShortPacket
		}
		a.Domain = string(rest[1 : 1+n])
		rest = rest[1+n:]
	default:
		return Addr{}, nil, ErrBadRequest
	}
	a.Port = uint16(rest[0])<<8 | uint16(rest[1])
	return a, rest[2:], nil
}

// AppendUDPHeader appends the UDP request/reply header for a to dst.
func AppendUDPHeader(dst []byte, a Addr) []byte {
	dst = append(dst, 0x00, 0x00, 0x00)
	return AppendAddr(dst, a)
}
