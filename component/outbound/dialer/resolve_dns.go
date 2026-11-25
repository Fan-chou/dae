/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
)

const (
	LinkQuery_ResolveDNS  = "resolve_dns"
	defaultResolveDNSPort = 53
)

func parseResolveDNS(val string) (netip.AddrPort, error) {
	s := strings.TrimSpace(val)
	s = strings.Trim(s, `'"`)
	s = strings.TrimPrefix(s, "udp://")
	s = strings.TrimPrefix(s, "UDP://")
	if strings.HasPrefix(strings.ToLower(s), "tcp://") {
		return netip.AddrPort{}, fmt.Errorf("resolve_dns does not support TCP; use IP[:port] or udp://IP[:port]")
	}
	if s == "" {
		return netip.AddrPort{}, fmt.Errorf("resolve_dns must be an IP address")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if err := validateResolveDNSAddr(ap.Addr()); err != nil {
			return netip.AddrPort{}, err
		}
		return ap, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve_dns must be an IP address: %s", val)
	}
	if err := validateResolveDNSAddr(addr); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, defaultResolveDNSPort), nil
}

func validateResolveDNSAddr(addr netip.Addr) error {
	if !addr.IsValid() || addr.IsUnspecified() {
		return fmt.Errorf("invalid resolve_dns address: %s", addr)
	}
	return nil
}

// extractLinkResolveDNS pulls resolve_dns off a node link query so outbound
// protocol parsers never see it. Invalid values fail node load.
//
// Named nodes are stored as "Name:scheme://..." (dae KeyableString). url.Parse
// treats the name as the scheme and never sees the query, so the tag is split
// off first the same way NewNetproxyDialerFromLink does.
func extractLinkResolveDNS(link string) (stripped string, dns netip.AddrPort, err error) {
	tag, body := common.GetTagFromLinkLikePlaintext(link)
	u, err := url.Parse(body)
	if err != nil || u == nil {
		return link, netip.AddrPort{}, nil
	}
	raw := u.Query().Get(LinkQuery_ResolveDNS)
	if raw == "" {
		return link, netip.AddrPort{}, nil
	}
	dns, err = parseResolveDNS(raw)
	if err != nil {
		return "", netip.AddrPort{}, fmt.Errorf("node %s: %w", LinkQuery_ResolveDNS, err)
	}
	u.RawQuery = stripQueryParam(u.RawQuery, LinkQuery_ResolveDNS)
	stripped = u.String()
	if tag != "" {
		stripped = tag + ":" + stripped
	}
	return stripped, dns, nil
}

// stripQueryParam removes key from a raw query string without re-encoding
// remaining parameters. Query().Encode() would turn + into space and %3A
// colons, which breaks protocol fields such as pinSHA256 and obfs-password.
func stripQueryParam(rawQuery, key string) string {
	if rawQuery == "" || key == "" {
		return rawQuery
	}
	parts := strings.Split(rawQuery, "&")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name, _, _ := strings.Cut(p, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		if decoded == key {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "&")
}

// ResolveDNSHealthSnapshot summarizes a node's resolve_dns resolver health and
// circuit-breaker state for Admin API observability without leaking credentials.
type ResolveDNSHealthSnapshot struct {
	Server              string `json:"server"`
	State               string `json:"state"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	TotalSuccess        uint64 `json:"total_success"`
	TotalFailure        uint64 `json:"total_failure"`
	TotalTimeout        uint64 `json:"total_timeout"`
	TotalFailOpen       uint64 `json:"total_fail_open"`
	LastLatencyMs       *int32 `json:"last_latency_ms,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	LastErrorAt         string `json:"last_error_at,omitempty"`
	LastSuccessAt       string `json:"last_success_at,omitempty"`
	CircuitOpenUntil    string `json:"circuit_open_until,omitempty"`
}

type resolveDNSHealthState struct {
	mu                  sync.Mutex
	consecutiveFailures int
	totalSuccess        uint64
	totalFailure        uint64
	totalTimeout        uint64
	totalFailOpen       uint64
	circuitOpenUntil    time.Time
	halfOpenInFlight    bool
	lastLatencyMs       int32
	hasLatency          bool
	lastError           string
	lastErrorAt         time.Time
	lastSuccessAt       time.Time
	lastWarnAt          time.Time
}

func truncateResolveDNSError(s string, maxRunes int) string {
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	count := 0
	for i := range s {
		if count == maxRunes {
			return s[:i] + "..."
		}
		count++
	}
	return s
}

func isTimeoutResolveDNSError(err error) bool {
	return err != nil && (errors.Is(err, netutils.ErrResolveTimeout) || errors.Is(err, context.DeadlineExceeded))
}

// ResolveDNSReferenceRTT returns a representative positive RTT for this dialer
// from its probed TCP/DNS collections, or 0 if no RTT has been observed yet.
func (d *Dialer) ResolveDNSReferenceRTT() time.Duration {
	if d == nil {
		return 0
	}
	probes := [...]*NetworkType{
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, IsDns: true, UdpHealthDomain: UdpHealthDomainDns},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, IsDns: true, UdpHealthDomain: UdpHealthDomainDns},
	}
	var best time.Duration
	d.collectionFineMu.RLock()
	defer d.collectionFineMu.RUnlock()
	for _, nt := range probes {
		col := d.mustGetCollection(nt)
		if col == nil {
			continue
		}
		rtt := col.MovingAverage
		if rtt <= 0 && col.Latencies10 != nil {
			if avg, ok := col.Latencies10.AvgLatency(); ok && avg > 0 {
				rtt = avg
			} else if last, ok := col.Latencies10.LastLatency(); ok && last > 0 {
				rtt = last
			}
		}
		if rtt > 0 && (best == 0 || rtt < best) {
			best = rtt
		}
	}
	return best
}

// AllowResolveDNS reports whether a resolve_dns lookup may execute now. When
// the circuit is open and the cooldown has elapsed, one caller is admitted as a
// half-open probe while concurrent callers fail open immediately.
func (d *Dialer) AllowResolveDNS(now time.Time) (allow bool, halfOpen bool) {
	if d == nil || !d.ResolveDNS().IsValid() {
		return false, false
	}
	h := &d.resolveDNSHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.circuitOpenUntil.IsZero() {
		return true, false
	}
	if now.Before(h.circuitOpenUntil) {
		return false, false
	}
	if h.halfOpenInFlight {
		return false, false
	}
	h.halfOpenInFlight = true
	return true, true
}

// RecordResolveDNSSuccess records a successful resolve_dns lookup and closes the circuit.
func (d *Dialer) RecordResolveDNSSuccess(latency time.Duration) {
	if d == nil || !d.ResolveDNS().IsValid() {
		return
	}
	if latency < 0 {
		latency = 0
	}
	now := time.Now()
	h := &d.resolveDNSHealth
	h.mu.Lock()
	h.totalSuccess++
	h.consecutiveFailures = 0
	h.circuitOpenUntil = time.Time{}
	h.halfOpenInFlight = false
	h.lastSuccessAt = now
	h.lastLatencyMs = int32(latency.Milliseconds())
	h.hasLatency = true
	h.mu.Unlock()
}

// RecordResolveDNSFailure records a non-negative resolve_dns failure and opens
// the circuit breaker after ResolveDNSCircuitFailureThreshold consecutive failures
// or on a failed half-open probe. It returns true when the circuit transitions
// from closed into open state.
func (d *Dialer) RecordResolveDNSFailure(err error, now time.Time) (opened bool) {
	if d == nil || !d.ResolveDNS().IsValid() || err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	h := &d.resolveDNSHealth
	h.mu.Lock()
	h.totalFailure++
	if isTimeoutResolveDNSError(err) {
		h.totalTimeout++
	}
	h.consecutiveFailures++
	h.lastError = truncateResolveDNSError(err.Error(), 160)
	h.lastErrorAt = now

	wasClosed := h.circuitOpenUntil.IsZero() && !h.halfOpenInFlight
	shouldOpen := h.halfOpenInFlight || h.consecutiveFailures >= consts.ResolveDNSCircuitFailureThreshold
	if shouldOpen {
		h.halfOpenInFlight = false
		h.circuitOpenUntil = now.Add(consts.ResolveDNSCircuitOpenDuration)
	}
	h.mu.Unlock()

	if shouldOpen {
		// Drop any silently expired pooled UDP sockets so recovery probes redial cleanly.
		d.ResetResolveDNSPools()
		return wasClosed
	}
	return false
}

// RecordResolveDNSFailOpen increments the fail-open counter when the circuit
// breaker bypasses resolve_dns and falls back to proxy-side resolution.
func (d *Dialer) RecordResolveDNSFailOpen() {
	if d == nil || !d.ResolveDNS().IsValid() {
		return
	}
	h := &d.resolveDNSHealth
	h.mu.Lock()
	h.totalFailOpen++
	h.mu.Unlock()
}

// ShouldLogResolveDNSWarn rate-limits repeated fail-open warnings for this dialer.
func (d *Dialer) ShouldLogResolveDNSWarn(now time.Time, interval time.Duration) bool {
	if d == nil {
		return false
	}
	h := &d.resolveDNSHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.lastWarnAt.IsZero() && now.Sub(h.lastWarnAt) < interval {
		return false
	}
	h.lastWarnAt = now
	return true
}

// ResetResolveDNSCircuit resets the circuit breaker state (e.g. on WAN change).
func (d *Dialer) ResetResolveDNSCircuit() {
	if d == nil {
		return
	}
	h := &d.resolveDNSHealth
	h.mu.Lock()
	h.consecutiveFailures = 0
	h.circuitOpenUntil = time.Time{}
	h.halfOpenInFlight = false
	h.mu.Unlock()
}

// CancelResolveDNSHalfOpen releases a reserved half-open probe slot if the
// probe could not run or was cancelled without testing the resolver.
func (d *Dialer) CancelResolveDNSHalfOpen() {
	if d == nil {
		return
	}
	h := &d.resolveDNSHealth
	h.mu.Lock()
	h.halfOpenInFlight = false
	h.mu.Unlock()
}

// SnapshotResolveDNSHealth returns nil when resolve_dns is not configured on d.
func (d *Dialer) SnapshotResolveDNSHealth(now time.Time) *ResolveDNSHealthSnapshot {
	if d == nil {
		return nil
	}
	srv := d.ResolveDNS()
	if !srv.IsValid() {
		return nil
	}
	h := &d.resolveDNSHealth
	h.mu.Lock()
	defer h.mu.Unlock()

	state := "closed"
	if !h.circuitOpenUntil.IsZero() {
		if h.halfOpenInFlight || !now.Before(h.circuitOpenUntil) {
			state = "half_open"
		} else {
			state = "open"
		}
	}
	snap := &ResolveDNSHealthSnapshot{
		Server:              srv.String(),
		State:               state,
		ConsecutiveFailures: h.consecutiveFailures,
		TotalSuccess:        h.totalSuccess,
		TotalFailure:        h.totalFailure,
		TotalTimeout:        h.totalTimeout,
		TotalFailOpen:       h.totalFailOpen,
		LastError:           h.lastError,
	}
	if h.hasLatency {
		ms := h.lastLatencyMs
		snap.LastLatencyMs = &ms
	}
	if !h.lastErrorAt.IsZero() {
		snap.LastErrorAt = h.lastErrorAt.UTC().Format(time.RFC3339)
	}
	if !h.lastSuccessAt.IsZero() {
		snap.LastSuccessAt = h.lastSuccessAt.UTC().Format(time.RFC3339)
	}
	if !h.circuitOpenUntil.IsZero() && state == "open" {
		snap.CircuitOpenUntil = h.circuitOpenUntil.UTC().Format(time.RFC3339)
	}
	return snap
}

type resolveDNSPoolKey struct {
	dns     netip.AddrPort
	network string
}

// IsResolveDNSCircuitOpen reports whether resolve_dns circuit breaker is currently
// open or awaiting a half-open probe, without mutating probe state.
func (d *Dialer) IsResolveDNSCircuitOpen(_ time.Time) bool {
	if d == nil || !d.ResolveDNS().IsValid() {
		return false
	}
	h := &d.resolveDNSHealth
	h.mu.Lock()
	open := !h.circuitOpenUntil.IsZero()
	h.mu.Unlock()
	return open
}

func (d *Dialer) getOrCreateResolveDNSPool(dns netip.AddrPort, network string) (*netutils.PooledUDPResolver, error) {
	if d == nil || d.Dialer == nil {
		return nil, fmt.Errorf("nil dialer")
	}
	key := resolveDNSPoolKey{dns: dns, network: network}
	d.resolveDNSPoolsMu.Lock()
	defer d.resolveDNSPoolsMu.Unlock()
	if d.resolveDNSPoolsClosed {
		return nil, net.ErrClosed
	}
	if d.resolveDNSPools == nil {
		d.resolveDNSPools = make(map[resolveDNSPoolKey]*netutils.PooledUDPResolver)
	}
	if p := d.resolveDNSPools[key]; p != nil {
		return p, nil
	}
	p := netutils.NewPooledUDPResolver(d.Dialer, dns, network)
	d.resolveDNSPools[key] = p
	return p, nil
}

// ResolveDNSLookup resolves host using a pooled txID-multiplexed UDP socket per
// (dns, network) when network is UDP, falling back to netutils.ResolveNetipTTL
// for non-UDP networks.
func (d *Dialer) ResolveDNSLookup(ctx context.Context, dns netip.AddrPort, host string, typ uint16, network string) ([]netip.Addr, time.Duration, bool, error) {
	if d == nil || d.Dialer == nil {
		return nil, 0, false, fmt.Errorf("nil dialer")
	}
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, 0, false, err
	}
	if magicNetwork.Network == "udp" {
		pool, err := d.getOrCreateResolveDNSPool(dns, network)
		if err != nil {
			return nil, 0, false, err
		}
		return pool.ResolveTTL(ctx, host, typ)
	}
	addrs, ttl, err := netutils.ResolveNetipTTL(ctx, d.Dialer, dns, host, typ, network)
	return addrs, ttl, false, err
}

// ResolveDNSLookupForClass runs ResolveDNSLookup on the isolated transport
// class dialer when class is non-empty so isolated groups keep private sockets.
func (d *Dialer) ResolveDNSLookupForClass(ctx context.Context, dns netip.AddrPort, host string, typ uint16, network string, class string) ([]netip.Addr, time.Duration, bool, error) {
	if d == nil {
		return nil, 0, false, fmt.Errorf("nil dialer")
	}
	target := d
	if class != "" {
		t, err := d.transportForClass(class)
		if err != nil {
			return nil, 0, false, err
		}
		target = t
	}
	return target.ResolveDNSLookup(ctx, dns, host, typ, network)
}

// ResetResolveDNSPools drops all pooled resolve_dns UDP sockets while keeping the
// pools open for lazy redial on subsequent queries.
func (d *Dialer) ResetResolveDNSPools() bool {
	if d == nil {
		return false
	}
	d.resolveDNSPoolsMu.Lock()
	pools := make([]*netutils.PooledUDPResolver, 0, len(d.resolveDNSPools))
	for _, p := range d.resolveDNSPools {
		if p != nil {
			pools = append(pools, p)
		}
	}
	d.resolveDNSPoolsMu.Unlock()

	reset := false
	for _, p := range pools {
		if p.Reset() {
			reset = true
		}
	}
	return reset
}

// CloseResolveDNSPools permanently shuts down all pooled resolve_dns UDP resolvers.
func (d *Dialer) CloseResolveDNSPools() {
	if d == nil {
		return
	}
	d.resolveDNSPoolsMu.Lock()
	d.resolveDNSPoolsClosed = true
	pools := d.resolveDNSPools
	d.resolveDNSPools = nil
	d.resolveDNSPoolsMu.Unlock()

	for _, p := range pools {
		if p != nil {
			_ = p.Close()
		}
	}
}
