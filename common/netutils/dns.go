/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
)

var (
	systemDnsMu              sync.Mutex
	systemDns                netip.AddrPort
	systemDnsNextUpdateAfter time.Time

	ErrBadDnsAns      = fmt.Errorf("bad dns answer")
	ErrResolveTimeout = fmt.Errorf("timeout")
	ErrDnsTruncated   = fmt.Errorf("dns response truncated")

	FallbackDns netip.AddrPort
)

// DnsRcodeError reports a non-zero DNS response code.
type DnsRcodeError struct {
	Rcode int
}

func (e *DnsRcodeError) Error() string {
	if s, ok := dnsmessage.RcodeToString[e.Rcode]; ok {
		return fmt.Sprintf("dns rcode %s (%d)", s, e.Rcode)
	}
	return fmt.Sprintf("dns rcode %d", e.Rcode)
}

// IsDnsRcodeError reports whether err is a DNS non-zero response code error.
func IsDnsRcodeError(err error) bool {
	var rcodeErr *DnsRcodeError
	return errors.As(err, &rcodeErr)
}

// IsDnsNegativeError reports whether err represents an authoritative negative
// DNS answer (NXDOMAIN) rather than a resolver or transport failure.
func IsDnsNegativeError(err error) bool {
	var rcodeErr *DnsRcodeError
	return errors.As(err, &rcodeErr) && rcodeErr.Rcode == dnsmessage.RcodeNameError
}

const (
	maxDNSMessageSize  = 65535
	edns0UDPPayloadLen = 1232
)

type dnsResolveResult struct {
	ans []dnsmessage.RR
	err error
}

// SystemDNSResolver caches the host resolver independently for one runtime generation.
type SystemDNSResolver struct {
	mu              sync.Mutex
	dns             netip.AddrPort
	nextUpdateAfter time.Time
	fallback        netip.AddrPort
	readConfig      func(string) *dnsConfig
}

// NewSystemDNSResolver creates a generation-scoped system DNS resolver.
func NewSystemDNSResolver(fallback netip.AddrPort) *SystemDNSResolver {
	return &SystemDNSResolver{fallback: fallback, readConfig: dnsReadConfig}
}

// TryUpdateElapse updates the cached system DNS if the minimum interval elapsed.
func (r *SystemDNSResolver) TryUpdateElapse(k time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tryUpdateElapse(k)
}

func (r *SystemDNSResolver) tryUpdateElapse(k time.Duration) error {
	if time.Now().Before(r.nextUpdateAfter) {
		return fmt.Errorf("update too quickly")
	}
	if err := r.update(); err != nil {
		return err
	}
	r.nextUpdateAfter = time.Now().Add(k)
	return nil
}

func (r *SystemDNSResolver) update() error {
	readConfig := r.readConfig
	if readConfig == nil {
		readConfig = dnsReadConfig
	}
	dnsConf := readConfig("/etc/resolv.conf")
	r.dns = netip.AddrPort{}
	for _, s := range dnsConf.servers {
		ipPort := netip.MustParseAddrPort(s)
		if !ipPort.Addr().IsLoopback() {
			r.dns = ipPort
			break
		}
	}
	if !r.dns.IsValid() {
		r.dns = r.fallback
	}
	return nil
}

// SystemDNS returns the current generation's cached system DNS server.
func (r *SystemDNSResolver) SystemDNS() (netip.AddrPort, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dns.IsValid() {
		if err := r.update(); err != nil {
			return netip.AddrPort{}, err
		}
	}
	// Refresh periodically so environment changes are eventually observed.
	_ = r.tryUpdateElapse(5 * time.Second)
	return r.dns, nil
}

var defaultSystemDNSResolver = NewSystemDNSResolver(netip.AddrPort{})

// TryUpdateSystemDnsElapse updates the process-default resolver for compatibility.
func TryUpdateSystemDnsElapse(k time.Duration) error {
	return defaultSystemDNSResolver.TryUpdateElapse(k)
}

// SystemDns returns the process-default resolver for compatibility.
func SystemDns() (netip.AddrPort, error) {
	return defaultSystemDNSResolver.SystemDNS()
}

func ResolveNetip(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) (addrs []netip.Addr, err error) {
	addrs, _, err = ResolveNetipTTL(ctx, d, dns, host, typ, network)
	return addrs, err
}

// ResolveNetipTTL is ResolveNetip plus the minimum TTL among matching answers.
func ResolveNetipTTL(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) (addrs []netip.Addr, ttl time.Duration, err error) {
	resources, err := resolve(ctx, d, dns, host, typ, network)
	if err != nil {
		return nil, 0, err
	}
	return extractNetipTTL(resources, typ)
}

func extractNetipTTL(resources []dnsmessage.RR, typ uint16) (addrs []netip.Addr, ttl time.Duration, err error) {
	var minTTL uint32
	foundTTL := false
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		var (
			ip  netip.Addr
			okk bool
		)
		switch typ {
		case dnsmessage.TypeA:
			a, ok := ans.(*dnsmessage.A)
			if !ok {
				return nil, 0, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.A)
		case dnsmessage.TypeAAAA:
			a, ok := ans.(*dnsmessage.AAAA)
			if !ok {
				return nil, 0, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.AAAA)
		}
		if !okk {
			continue
		}
		addrs = append(addrs, ip)
		hdrTTL := ans.Header().Ttl
		if !foundTTL || hdrTTL < minTTL {
			minTTL = hdrTTL
			foundTTL = true
		}
	}
	if foundTTL {
		ttl = time.Duration(minTTL) * time.Second
	}
	return addrs, ttl, nil
}

func parseLiteralIPAnswer(host string, typ uint16) ([]dnsmessage.RR, bool) {
	if typ != dnsmessage.TypeA && typ != dnsmessage.TypeAAAA {
		return nil, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, false
	}
	fqdn := dnsmessage.CanonicalName(host)
	if (addr.Is4() || addr.Is4In6()) && typ == dnsmessage.TypeA {
		return []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   fqdn,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
					Rrtype: typ,
				},
				A: addr.AsSlice(),
			},
		}, true
	}
	if addr.Is6() && typ == dnsmessage.TypeAAAA {
		return []dnsmessage.RR{
			&dnsmessage.AAAA{
				Hdr: dnsmessage.RR_Header{
					Name:   fqdn,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
					Rrtype: typ,
				},
				AAAA: addr.AsSlice(),
			},
		}, true
	}
	// MUST No record.
	return nil, true
}

func packDNSQuery(fqdn string, typ uint16, id uint16, edns0 bool) ([]byte, error) {
	var builder dnsmessage.Msg
	// SetQuestion assigns a random Id and resets header flags, so set Id after it.
	builder.SetQuestion(fqdn, typ)
	builder.Id = id
	builder.RecursionDesired = true
	if edns0 {
		builder.SetEdns0(edns0UDPPayloadLen, false)
	}
	return builder.Pack()
}

func resolve(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) ([]dnsmessage.RR, error) {
	if d == nil {
		return nil, fmt.Errorf("nil dialer")
	}
	if ans, ok := parseLiteralIPAnswer(host, typ); ok {
		return ans, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fqdn := dnsmessage.CanonicalName(host)
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	// Build DNS req.
	queryID := uint16(fastrand.Intn(math.MaxUint16 + 1))
	b, err := packDNSQuery(fqdn, typ, queryID, magicNetwork.Network == "udp")
	if err != nil {
		return nil, err
	}
	if magicNetwork.Network == "tcp" {
		// Put DNS request length
		buf := pool.Get(2 + len(b))
		defer pool.Put(buf)
		binary.BigEndian.PutUint16(buf, uint16(len(b)))
		copy(buf[2:], b)
		b = buf
	}

	// Dial and write.
	c, err := d.DialContext(ctx, network, dns.String())
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %w", ErrResolveTimeout, ctx.Err())
		}
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if magicNetwork.Network == "udp" {
		_, err = WriteUDPConn(c, dns.String(), b)
	} else {
		_, err = c.Write(b)
	}
	if err != nil {
		return nil, err
	}
	ch := make(chan dnsResolveResult, 2)
	if magicNetwork.Network == "udp" {
		go func() {
			ticker := time.NewTicker(consts.ResolveDNSUDPResendInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_, err := WriteUDPConn(c, dns.String(), b)
					if err != nil {
						ch <- dnsResolveResult{err: err}
						return
					}
				}
			}
		}()
	}
	go func() {
		if magicNetwork.Network == "tcp" {
			var header [2]byte
			// Read DNS response length
			if _, err := io.ReadFull(c, header[:]); err != nil {
				ch <- dnsResolveResult{err: err}
				return
			}
			msgLen := int(binary.BigEndian.Uint16(header[:]))
			if msgLen <= 0 || msgLen > maxDNSMessageSize {
				ch <- dnsResolveResult{err: fmt.Errorf("invalid dns resp size: %d", msgLen)}
				return
			}
			buf := pool.GetFullCap(msgLen)
			defer buf.Put()
			if _, err := io.ReadFull(c, buf[:msgLen]); err != nil {
				ch <- dnsResolveResult{err: err}
				return
			}
			ch <- decodeResolvedAnswer(buf[:msgLen], queryID, fqdn, typ)
			return
		}

		// Cover the full legal DNS message, not a link-MTU-sized guess, so
		// even non-compliant oversized UDP responses are not truncated at the
		// read buffer before decoding. Callers that forward a client's
		// advertised EDNS0 size must cover that size instead
		// (control.dnsUdpMaxResponseSize).
		buf := pool.GetFullCap(maxDNSMessageSize)
		defer buf.Put()
		n, err := ReadUDPConn(c, buf)
		if err != nil {
			ch <- dnsResolveResult{err: err}
			return
		}
		ch <- decodeResolvedAnswer(buf[:n], queryID, fqdn, typ)
	}()
	select {
	case <-ctx.Done():
		// Wrap ErrResolveTimeout on deadline expiry so callers can separate
		// DNS timeouts from cancellation and handshake deadlines.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %w", ErrResolveTimeout, ctx.Err())
		}
		return nil, fmt.Errorf("timeout: %w", ctx.Err())
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		return res.ans, nil
	}
}

func decodeResolvedAnswer(payload []byte, expectedID uint16, expectedFQDN string, expectedType uint16) dnsResolveResult {
	var msg dnsmessage.Msg
	if err := msg.Unpack(payload); err != nil {
		return dnsResolveResult{err: err}
	}
	res, matched := decodeUnpackedAnswer(&msg, expectedID, expectedFQDN, expectedType)
	if !matched {
		if msg.Id != expectedID {
			return dnsResolveResult{err: fmt.Errorf("id mismatch: expect %v, got %v", expectedID, msg.Id)}
		}
		return dnsResolveResult{err: ErrBadDnsAns}
	}
	return res
}

func decodeUnpackedAnswer(msg *dnsmessage.Msg, expectedID uint16, expectedFQDN string, expectedType uint16) (dnsResolveResult, bool) {
	if msg == nil || !msg.Response || msg.Id != expectedID {
		return dnsResolveResult{}, false
	}
	if expectedFQDN != "" {
		if len(msg.Question) > 0 {
			q := msg.Question[0]
			if !strings.EqualFold(dnsmessage.CanonicalName(q.Name), expectedFQDN) || (expectedType != 0 && q.Qtype != expectedType) {
				return dnsResolveResult{}, false
			}
		} else if msg.Rcode == dnsmessage.RcodeSuccess {
			return dnsResolveResult{}, false
		}
	}
	if msg.Truncated {
		return dnsResolveResult{err: ErrDnsTruncated}, true
	}
	if msg.Rcode != dnsmessage.RcodeSuccess {
		return dnsResolveResult{err: &DnsRcodeError{Rcode: msg.Rcode}}, true
	}

	// Copy RRs before returning so callers don't retain pooled memory indirectly.
	var ans []dnsmessage.RR
	if len(msg.Answer) > 0 {
		ans = make([]dnsmessage.RR, len(msg.Answer))
		for i, rr := range msg.Answer {
			ans[i] = dnsmessage.Copy(rr)
		}
	}
	return dnsResolveResult{ans: ans}, true
}
