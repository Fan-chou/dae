/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// BPF update configuration
const (
	// MinBpfUpdateInterval is the minimum time between BPF map updates for the same cache.
	// This prevents excessive BPF map updates while maintaining freshness.
	MinBpfUpdateInterval = 1 * time.Second

	// MaxBpfUpdateInterval is the maximum time before forcing a BPF map update.
	// Even if data hasn't changed, we refresh periodically to handle edge cases.
	MaxBpfUpdateInterval = 60 * time.Second
)

type dnsPackedResponse struct {
	wire              []byte
	ttlOffsets        []int
	ttl               uint32
	createdAtUnixNano int64
}

type DnsCache struct {
	// RouteOnly entries own address routing, never reusable DNS answers.
	RouteOnly            bool
	Rcode                int
	RouteOwnerKey        string
	RouteProjectionEpoch uint64
	DomainBitmap         []uint32
	Answer               []dnsmessage.RR
	NS                   []dnsmessage.RR
	Extra                []dnsmessage.RR
	Deadline             time.Time
	ReceivedAt           time.Time
	OriginalDeadline     time.Time // This field is not impacted by `fixed_domain_ttl`.

	// lastRouteSyncNano tracks when route binding was last synced to BPF.
	lastRouteSyncNano atomic.Int64

	// lastBpfDataHash stores a hash of the data used for BPF update.
	// This enables differential updates - only update when data changes.
	lastBpfDataHash atomic.Uint64

	// packedResponse is a pre-packed DNS response message with compression enabled.
	// This avoids repeated Pack() calls on cache hits, significantly reducing latency.
	// The packed response includes: Answer, Rcode=Success, Response=true, RecursionAvailable=true.
	// Note: DNS Message ID is NOT included and must be patched by the caller.
	//
	// OPTIMIZATION: Uses Copy-on-Write with one atomic.Pointer for lock-free
	// reads. The wire bytes and the metadata used to interpret them are one
	// immutable publication unit, so readers cannot mix refresh generations.
	packedResponse atomic.Pointer[dnsPackedResponse]
	// deadlineNano caches the Deadline as UnixNano for fast comparison.
	// This avoids time.Time method calls on every cache hit.
	deadlineNano atomic.Int64

	// OPTIMISTIC CACHE (RFC 8767): Stale-while-revalidate support
	// refreshing tracks whether background refresh is in progress.
	// This prevents multiple concurrent refresh attempts for the same cache key.
	refreshing atomic.Bool

	// lastAccessNano tracks when this cache was last accessed (for LRU eviction).
	lastAccessNano atomic.Int64
}

func ttlFromDeadline(deadline time.Time, now time.Time) uint32 {
	deadlineNano := deadline.UnixNano()
	nowNano := now.UnixNano()
	if deadlineNano <= nowNano {
		return 0
	}

	ttlSeconds := (deadlineNano - nowNano) / 1e9
	return uint32(ttlSeconds)
}

func (c *DnsCache) GetFqdn() string {
	if len(c.Answer) > 0 {
		return c.Answer[0].Header().Name
	}
	return ""
}

// ComputeBpfDataHash computes a hash of the data used for BPF updates.
// This includes IP addresses from Answer and the DomainBitmap.
// Returns 0 if there are no valid IPs (no update needed).
func (c *DnsCache) ComputeBpfDataHash() uint64 {
	if len(c.Answer) == 0 {
		return 0
	}

	var hash uint64 = 14695981039346656037 // FNV-1a offset basis

	// Hash IP addresses from Answer
	for _, ans := range c.Answer {
		var ipBytes []byte
		switch body := ans.(type) {
		case *dnsmessage.A:
			ipBytes = body.A
		case *dnsmessage.AAAA:
			ipBytes = body.AAAA
		}
		if len(ipBytes) > 0 {
			for _, b := range ipBytes {
				hash ^= uint64(b)
				hash *= 1099511628211 // FNV-1a prime
			}
		}
	}

	// Hash DomainBitmap
	for _, v := range c.DomainBitmap {
		hash ^= uint64(v)
		hash *= 1099511628211
	}

	return hash
}

// NeedsBpfUpdate checks if BPF map update is needed using differential detection.
// Returns true if:
//  1. Minimum interval has passed since last update AND
//     (data has changed OR maximum interval has passed)
//  2. Never been updated before
//
// IMPORTANT: This method uses CAS to prevent race conditions. Only one goroutine
// will successfully trigger an update request.
func (c *DnsCache) NeedsBpfUpdate(now time.Time) bool {
	nowNano := now.UnixNano()
	lastSync := c.lastRouteSyncNano.Load()

	// Never updated - needs update (use CAS to claim first update)
	if lastSync == 0 {
		return c.lastRouteSyncNano.CompareAndSwap(0, nowNano)
	}

	timeSinceLastSync := time.Duration(nowNano - lastSync)

	// Haven't reached minimum interval - skip
	if timeSinceLastSync < MinBpfUpdateInterval {
		return false
	}

	// Maximum interval reached - force update (use CAS to claim)
	if timeSinceLastSync >= MaxBpfUpdateInterval {
		return c.lastRouteSyncNano.CompareAndSwap(lastSync, nowNano)
	}

	// Check if data has changed
	currentHash := c.ComputeBpfDataHash()
	if currentHash == 0 {
		// No valid IPs - no update needed
		return false
	}

	lastHash := c.lastBpfDataHash.Load()
	if currentHash == lastHash {
		// Data unchanged - no update needed
		return false
	}

	// Data changed - use CAS to claim this update
	// Only one goroutine will succeed
	return c.lastRouteSyncNano.CompareAndSwap(lastSync, nowNano)
}

// MarkBpfUpdated marks the BPF map as updated with the current data hash.
// This should be called after a successful BPF update.
func (c *DnsCache) MarkBpfUpdated(now time.Time) {
	c.lastRouteSyncNano.Store(now.UnixNano())
	c.lastBpfDataHash.Store(c.ComputeBpfDataHash())
}

func (c *DnsCache) FillInto(req *dnsmessage.Msg) {
	req.Answer = nil
	if c.Answer != nil {
		req.Answer = make([]dnsmessage.RR, len(c.Answer))
		for i, rr := range c.Answer {
			req.Answer[i] = dnsmessage.Copy(rr)
		}
	}
	req.Ns = nil
	if c.NS != nil {
		req.Ns = make([]dnsmessage.RR, len(c.NS))
		for i, rr := range c.NS {
			req.Ns[i] = dnsmessage.Copy(rr)
		}
	}
	req.Extra = nil
	if c.Extra != nil {
		req.Extra = make([]dnsmessage.RR, len(c.Extra))
		for i, rr := range c.Extra {
			req.Extra[i] = dnsmessage.Copy(rr)
		}
	}

	req.Rcode = c.Rcode
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
}

// FillIntoWithPacked fills the DNS response using pre-packed data if available.
// This is the fast path for cache hits - it avoids deep copy and packing overhead.
// Returns the packed response bytes (caller should patch the DNS ID if needed).
func (c *DnsCache) FillIntoWithPacked(req *dnsmessage.Msg) []byte {
	// Fast path: use pre-packed response (lock-free read)
	packedPtr := c.packedResponse.Load()
	if packedPtr != nil && packedPtr.wire != nil {
		// Still need to unpack to fill the request message for logging/tracing
		// But we return the pre-packed bytes for sending
		return packedPtr.withTTL(time.Now(), ttlFromDeadline(c.Deadline, time.Now()))
	}
	// Slow path: fill and pack (should not happen if cache is properly initialized)
	c.FillInto(req)
	req.Compress = true
	b, err := req.Pack()
	if err != nil {
		return nil
	}
	return b
}

func (c *DnsCache) Clone() *DnsCache {
	newCache := &DnsCache{
		RouteOnly:            c.RouteOnly,
		Rcode:                c.Rcode,
		RouteOwnerKey:        c.RouteOwnerKey,
		RouteProjectionEpoch: c.RouteProjectionEpoch,
		Deadline:             c.Deadline,
		OriginalDeadline:     c.OriginalDeadline,
		ReceivedAt:           c.ReceivedAt,
	}

	if c.DomainBitmap != nil {
		newCache.DomainBitmap = slices.Clone(c.DomainBitmap)
	}

	if c.Answer != nil {
		newCache.Answer = make([]dnsmessage.RR, len(c.Answer))
		for i, rr := range c.Answer {
			newCache.Answer[i] = dnsmessage.Copy(rr)
		}
	}
	if c.NS != nil {
		newCache.NS = make([]dnsmessage.RR, len(c.NS))
		for i, rr := range c.NS {
			newCache.NS[i] = dnsmessage.Copy(rr)
		}
	}
	if c.Extra != nil {
		newCache.Extra = make([]dnsmessage.RR, len(c.Extra))
		for i, rr := range c.Extra {
			newCache.Extra[i] = dnsmessage.Copy(rr)
		}
	}

	if packedPtr := c.packedResponse.Load(); packedPtr != nil && packedPtr.wire != nil {
		packedCopy := *packedPtr
		packedCopy.wire = slices.Clone(packedPtr.wire)
		newCache.packedResponse.Store(&packedCopy)
	}

	newCache.deadlineNano.Store(c.deadlineNano.Load())
	newCache.lastRouteSyncNano.Store(0)
	newCache.lastBpfDataHash.Store(0)

	return newCache

}

// cloneWithDeadlines publishes a new wrapper with updated deadlines.
// Answer/NS/Extra, DomainBitmap, and packed bytes are shared; they must not
// be mutated after the original entry was published.
func (c *DnsCache) cloneWithDeadlines(deadline, originalDeadline time.Time) *DnsCache {
	if c == nil {
		return nil
	}
	next := &DnsCache{
		RouteOnly:            c.RouteOnly,
		Rcode:                c.Rcode,
		RouteOwnerKey:        c.RouteOwnerKey,
		RouteProjectionEpoch: c.RouteProjectionEpoch,
		DomainBitmap:         c.DomainBitmap,
		Answer:               c.Answer,
		NS:                   c.NS,
		Extra:                c.Extra,
		Deadline:             deadline,
		OriginalDeadline:     originalDeadline,
		ReceivedAt:           c.ReceivedAt,
	}
	if packedPtr := c.packedResponse.Load(); packedPtr != nil {
		next.packedResponse.Store(packedPtr)
	}
	next.deadlineNano.Store(deadline.UnixNano())
	next.lastAccessNano.Store(c.lastAccessNano.Load())
	next.lastRouteSyncNano.Store(c.lastRouteSyncNano.Load())
	next.lastBpfDataHash.Store(c.lastBpfDataHash.Load())
	next.refreshing.Store(c.refreshing.Load())
	return next
}

// CloneForReload creates a new generation-local cache wrapper for reload.
//
// WARNING: Answer, NS, and Extra slices share memory with the original cache.
// DO NOT mutate any RR after it has been inserted into the cache.
// Violating this contract will cause data corruption across generations.
//
// Immutable payload such as RR slices and the current packed response are reused
// to avoid the reload-time deep-copy spike. Per-generation routing metadata is
// reset so the new control plane can repopulate BPF state with its own routing
// matcher and lifecycle bookkeeping.
func (c *DnsCache) CloneForReload() *DnsCache {
	newCache := &DnsCache{
		RouteOnly:            c.RouteOnly,
		Rcode:                c.Rcode,
		RouteOwnerKey:        c.RouteOwnerKey,
		RouteProjectionEpoch: c.RouteProjectionEpoch,
		Answer:               c.Answer,
		NS:                   c.NS,
		Extra:                c.Extra,
		Deadline:             c.Deadline,
		OriginalDeadline:     c.OriginalDeadline,
		ReceivedAt:           c.ReceivedAt,
	}

	if packed := c.packedResponse.Load(); packed != nil && packed.wire != nil {
		// Packed responses are immutable after publication. Sharing the current
		// snapshot avoids a reload-only copy, and each generation still owns its
		// atomic pointer for future TTL refreshes.
		newCache.packedResponse.Store(packed)
	}

	deadlineNano := c.deadlineNano.Load()
	if deadlineNano == 0 && !c.Deadline.IsZero() {
		deadlineNano = c.Deadline.UnixNano()
	}
	newCache.deadlineNano.Store(deadlineNano)
	newCache.lastAccessNano.Store(c.lastAccessNano.Load())
	newCache.lastRouteSyncNano.Store(0)
	newCache.lastBpfDataHash.Store(0)
	newCache.refreshing.Store(false)

	return newCache
}

// PrepackResponse generates a pre-packed DNS response message.
// This should be called once when creating the cache entry.
// The qname should be the full qualified domain name (with trailing dot).
// TTL field offsets are indexed once; cache hits age a private wire copy.
func (c *DnsCache) PrepackResponse(qname string, qtype uint16) error {
	now := time.Now()

	// Cache deadline as UnixNano for fast comparison
	c.deadlineNano.Store(c.Deadline.UnixNano())

	return c.prepackResponseWithTTL(qname, qtype, ttlFromDeadline(c.Deadline, now), now)
}

func ttlScratchSlice(n int, stack *[8]uint32) []uint32 {
	if n <= len(stack) {
		return stack[:n]
	}
	return make([]uint32, n)
}

func setRecordTTL(rr dnsmessage.RR, ttl uint32) {
	hdr := rr.Header()
	// OPT encodes EDNS version and flags in this field, not a lifetime.
	if hdr.Rrtype != dnsmessage.TypeOPT {
		hdr.Ttl = ttl
	}
}

func restoreSectionTTL(rrs []dnsmessage.RR, scratch []uint32) {
	for i, rr := range rrs {
		rr.Header().Ttl = scratch[i]
	}
}

// prepackResponseBeforeStore is a lighter pre-pack path used only before the
// cache entry becomes visible to concurrent readers. It temporarily rewrites
// the TTLs in-place, packs the response, and restores the original TTLs before
// returning. This preserves the stored RR values while avoiding deep copies on
// the cold cache-insert path.
func (c *DnsCache) prepackResponseBeforeStore(qname string, qtype uint16, ttl uint32, now time.Time) error {
	var question [1]dnsmessage.Question
	question[0] = dnsmessage.Question{Name: qname, Qtype: qtype, Qclass: dnsmessage.ClassINET}

	msg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Rcode:              c.Rcode,
			Response:           true,
			RecursionAvailable: true,
			RecursionDesired:   true,
			Truncated:          false,
		},
		Question: question[:],
		Answer:   c.Answer,
		Ns:       c.NS,
		Extra:    c.Extra,
		Compress: true,
	}

	var (
		answerStack [8]uint32
		nsStack     [8]uint32
		extraStack  [8]uint32
	)
	answerTTLs := ttlScratchSlice(len(c.Answer), &answerStack)
	nsTTLs := ttlScratchSlice(len(c.NS), &nsStack)
	extraTTLs := ttlScratchSlice(len(c.Extra), &extraStack)

	c.setSectionRemainingTTL(c.Answer, ttl, now, answerTTLs)
	c.setSectionRemainingTTL(c.NS, ttl, now, nsTTLs)
	c.setSectionRemainingTTL(c.Extra, ttl, now, extraTTLs)
	defer func() {
		restoreSectionTTL(c.Extra, extraTTLs)
		restoreSectionTTL(c.NS, nsTTLs)
		restoreSectionTTL(c.Answer, answerTTLs)
	}()

	packed, err := msg.Pack()
	if err != nil {
		return err
	}

	offsets, err := dnsWireTTLOffsets(packed)
	if err != nil {
		return err
	}
	c.packedResponse.Store(&dnsPackedResponse{
		ttlOffsets:        offsets,
		wire:              packed,
		ttl:               ttl,
		createdAtUnixNano: now.UnixNano(),
	})
	// deadlineNano gates the packed fast path and stale-while-revalidate
	// lookups; leaving it zero makes both treat a freshly stored entry as
	// already expired. Entries are prepacked before they become visible to
	// concurrent readers, so a plain store is sufficient here.
	c.deadlineNano.Store(c.Deadline.UnixNano())
	return nil
}

// prepackResponseWithTTL creates pre-packed response with specified TTL
// OPTIMIZED: Uses Copy-on-Write with atomic pointer swap for thread-safe updates.
// Creates a new []byte slice and atomically swaps the pointer - no blocking readers.
func (c *DnsCache) prepackResponseWithTTL(qname string, qtype uint16, ttl uint32, now time.Time) error {
	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Rcode:              c.Rcode,
			Response:           true,
			RecursionAvailable: true,
			RecursionDesired:   true,
			Truncated:          false,
		},
		Question: []dnsmessage.Question{
			{Name: qname, Qtype: qtype, Qclass: dnsmessage.ClassINET},
		},
		Compress: true,
	}

	if c.Answer != nil {
		msg.Answer = make([]dnsmessage.RR, len(c.Answer))
		for i, rr := range c.Answer {
			copiedRR := dnsmessage.Copy(rr)
			setRecordTTL(copiedRR, c.recordTTL(rr, ttl, now))
			msg.Answer[i] = copiedRR
		}
	}
	if c.NS != nil {
		msg.Ns = make([]dnsmessage.RR, len(c.NS))
		for i, rr := range c.NS {
			copiedRR := dnsmessage.Copy(rr)
			setRecordTTL(copiedRR, c.recordTTL(rr, ttl, now))
			msg.Ns[i] = copiedRR
		}
	}
	if c.Extra != nil {
		msg.Extra = make([]dnsmessage.RR, len(c.Extra))
		for i, rr := range c.Extra {
			copiedRR := dnsmessage.Copy(rr)
			setRecordTTL(copiedRR, c.recordTTL(rr, ttl, now))
			msg.Extra[i] = copiedRR
		}
	}

	packed, err := msg.Pack()
	if err != nil {
		return err
	}

	offsets, err := dnsWireTTLOffsets(packed)
	if err != nil {
		return err
	}
	c.packedResponse.Store(&dnsPackedResponse{
		ttlOffsets:        offsets,
		wire:              packed,
		ttl:               ttl,
		createdAtUnixNano: now.UnixNano(),
	})
	return nil
}

// GetPackedResponseWithApproximateTTL retains its API name but now ages every
// wire TTL on a private copy. Readers never observe a previous refresh's TTL.
func (c *DnsCache) GetPackedResponseWithApproximateTTL(qname string, qtype uint16, now time.Time) []byte {
	if c.RouteOnly || c.deadlineNano.Load() <= now.UnixNano() {
		return nil
	}
	packed := c.packedResponse.Load()
	if packed == nil {
		return nil
	}
	return packed.withTTL(now, ttlFromDeadline(c.Deadline, now))
}

func (p *dnsPackedResponse) withTTL(now time.Time, limit uint32) []byte {
	out := slices.Clone(p.wire)
	// Round elapsed time up so truncation to whole seconds never extends a RR.
	elapsed := max(int64(0), now.UnixNano()-p.createdAtUnixNano)
	age := uint64((elapsed + int64(time.Second) - 1) / int64(time.Second))
	for _, offset := range p.ttlOffsets {
		original := binary.BigEndian.Uint32(out[offset:])
		remaining := uint32(0)
		if uint64(original) > age {
			remaining = uint32(uint64(original) - age)
		}
		binary.BigEndian.PutUint32(out[offset:], min(remaining, limit))
	}
	return out
}

// dnsWireTTLOffsets runs once on locally packed data, never on each cache hit.
func dnsWireTTLOffsets(wire []byte) ([]int, error) {
	if len(wire) < 12 {
		return nil, fmt.Errorf("short packed DNS header")
	}
	pos := 12
	for range int(binary.BigEndian.Uint16(wire[4:6])) {
		_, next, err := dnsmessage.UnpackDomainName(wire, pos)
		if err != nil || next+4 > len(wire) {
			return nil, fmt.Errorf("invalid packed DNS question")
		}
		pos = next + 4
	}
	count := int(binary.BigEndian.Uint16(wire[6:8])) + int(binary.BigEndian.Uint16(wire[8:10])) + int(binary.BigEndian.Uint16(wire[10:12]))
	offsets := make([]int, 0, count)
	for range count {
		_, next, err := dnsmessage.UnpackDomainName(wire, pos)
		if err != nil || next+10 > len(wire) {
			return nil, fmt.Errorf("invalid packed DNS record")
		}
		if binary.BigEndian.Uint16(wire[next:]) != dnsmessage.TypeOPT {
			offsets = append(offsets, next+4)
		}
		pos = next + 10 + int(binary.BigEndian.Uint16(wire[next+8:]))
		if pos > len(wire) {
			return nil, fmt.Errorf("invalid packed DNS record length")
		}
	}
	return offsets, nil
}

func (c *DnsCache) recordTTL(rr dnsmessage.RR, limit uint32, now time.Time) uint32 {
	// Explicit fixed_domain_ttl retains its existing override contract.
	if c.ReceivedAt.IsZero() || !c.Deadline.Equal(c.OriginalDeadline) {
		return limit
	}
	return min(limit, ttlFromDeadline(c.ReceivedAt.Add(time.Duration(rr.Header().Ttl)*time.Second), now))
}

func (c *DnsCache) setSectionRemainingTTL(rrs []dnsmessage.RR, ttl uint32, now time.Time, saved []uint32) {
	for i, rr := range rrs {
		saved[i] = rr.Header().Ttl
		setRecordTTL(rr, c.recordTTL(rr, ttl, now))
	}
}

// GetStaleResponse returns expired response if within stale-while-revalidate window.
// OPTIMISTIC CACHE (RFC 8767): This is used when cache is expired but still acceptable.
// staleTtl: stale window in seconds. 0 means never expire (always return stale response).
// Returns nil if cache is too stale (beyond staleTtl seconds).
// Caller should check refreshing flag and trigger background refresh if needed.
func (c *DnsCache) GetStaleResponse(now time.Time, staleTtl int) []byte {
	nowNano := now.UnixNano()
	deadlineNano := c.deadlineNano.Load()

	// Cache is not expired - should use GetPackedResponseWithApproximateTTL instead
	if deadlineNano > nowNano {
		return nil
	}

	// Check if within stale-while-revalidate window
	// staleTtl = 0 means never expire (always return stale response)
	if staleTtl > 0 {
		staleNano := deadlineNano + int64(staleTtl)*1e9
		if nowNano > staleNano {
			// Too stale, don't use
			return nil
		}
	}

	// Return stale response (better than nothing)
	packed := c.packedResponse.Load()
	if packed == nil {
		return nil
	}
	return packed.withTTL(now, 0)
}

// IsRefreshing checks if background refresh is in progress (optimistic cache).
// Returns true if this cache entry is expired and currently being refreshed.
func (c *DnsCache) IsRefreshing() bool {
	return c.refreshing.Load()
}

// MarkRefreshed marks the background refresh as complete (optimistic cache).
// This should be called after successfully refreshing the cache.
func (c *DnsCache) MarkRefreshed() {
	c.refreshing.Store(false)
}

// fillIntoWithTTLInPlace mutates req directly and should only be used when the
// caller has unique ownership of req and will not reuse it after the call,
// including on pack failure.
func (c *DnsCache) fillIntoWithTTLInPlace(req *dnsmessage.Msg, now time.Time) []byte {
	if req == nil {
		return nil
	}
	c.FillInto(req)
	remainingTTL := ttlFromDeadline(c.Deadline, now)
	for _, section := range [][]dnsmessage.RR{req.Answer, req.Ns, req.Extra} {
		for _, rr := range section {
			setRecordTTL(rr, c.recordTTL(rr, remainingTTL, now))
		}
	}

	req.Compress = true
	b, err := req.Pack()
	if err != nil {
		return nil
	}
	return b
}

// FillIntoWithTTL fills the DNS response with correct remaining TTL.
// This is the standard DNS cache behavior - TTL decreases over time.
// Returns the packed response bytes ready to send (with DNS ID = 0, caller should patch).
//
// This method preserves the caller's request on failure by operating on a copy.
// Hot paths that already own the message exclusively should use
// fillIntoWithTTLInPlace to avoid the extra allocation.
func (c *DnsCache) FillIntoWithTTL(req *dnsmessage.Msg, now time.Time) []byte {
	if req == nil {
		return nil
	}
	resp := req.Copy()
	if resp == nil {
		return nil
	}
	return c.fillIntoWithTTLInPlace(resp, now)
}

func (c *DnsCache) IncludeIp(ip netip.Addr) bool {
	for _, ans := range c.Answer {
		if a, ok := dnsAnswerIP(ans); ok && a == ip {
			return true
		}
	}
	return false
}

func dnsAnswerIP(rr dnsmessage.RR) (netip.Addr, bool) {
	switch body := rr.(type) {
	case *dnsmessage.A:
		return netip.AddrFromSlice(body.A)
	case *dnsmessage.AAAA:
		return netip.AddrFromSlice(body.AAAA)
	default:
		return netip.Addr{}, false
	}
}
