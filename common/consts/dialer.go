/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"net/netip"
	"time"
)

// IP protocol numbers from IANA protocol numbers registry.
const (
	// IPPROTO_TCP is the IP protocol number for TCP (RFC 793).
	IPPROTO_TCP = 6
	// IPPROTO_UDP is the IP protocol number for UDP (RFC 768).
	IPPROTO_UDP = 17
)

// DialerSelectionPolicy defines the strategy for selecting a dialer from a group.
type DialerSelectionPolicy string

const (
	// DialerSelectionPolicy_Random selects a dialer randomly.
	DialerSelectionPolicy_Random DialerSelectionPolicy = "random"
	// DialerSelectionPolicy_Fixed always selects the first dialer.
	DialerSelectionPolicy_Fixed DialerSelectionPolicy = "fixed"
	// DialerSelectionPolicy_MinAverage10Latencies selects the dialer with minimum average latency of last 10 checks.
	DialerSelectionPolicy_MinAverage10Latencies DialerSelectionPolicy = "min_avg10"
	// DialerSelectionPolicy_MinMovingAverageLatencies selects the dialer with minimum moving average latency.
	DialerSelectionPolicy_MinMovingAverageLatencies DialerSelectionPolicy = "min_moving_avg"
	// DialerSelectionPolicy_MinLastLatency selects the dialer with minimum last latency.
	DialerSelectionPolicy_MinLastLatency DialerSelectionPolicy = "min"
	// DialerSelectionPolicy_FirstAlive selects the first alive dialer in declaration order.
	DialerSelectionPolicy_FirstAlive DialerSelectionPolicy = "first_alive"
	// DialerSelectionPolicy_Fallback is Mihomo fallback: declaration order,
	// skipping dead nodes and preferring Alive over Degraded.
	DialerSelectionPolicy_Fallback DialerSelectionPolicy = "fallback"
	// DialerSelectionPolicy_UrlTest is Mihomo url-test: lowest quality score
	// among non-dead nodes, with check_tolerance applied to that score.
	DialerSelectionPolicy_UrlTest DialerSelectionPolicy = "url_test"
)

const (
	// UdpCheckLookupHost is the default host used for UDP connectivity checks.
	UdpCheckLookupHost = "connectivitycheck.gstatic.com."
	// DefaultDialTimeout is the default timeout for dialing.
	DefaultDialTimeout = 8 * time.Second
	// ResolveDNSTimeout is the budget for a node resolve_dns lookup.
	// It is independent of DefaultDialTimeout so a slow DNS query cannot
	// starve the subsequent proxy handshake. Sized for a US-node RTT plus a
	// couple of UDP retries, not a full 3s stall on the first packet.
	ResolveDNSTimeout = 800 * time.Millisecond
	// ResolveDNSUDPResendInterval is how often a UDP resolve_dns query is
	// resent while waiting for an answer. Must be well below ResolveDNSTimeout
	// so a lost packet can retry inside the budget.
	ResolveDNSUDPResendInterval = 400 * time.Millisecond
	// ResolveDNSCacheTTLMin / Max clamp a successful pin to the answer TTL.
	ResolveDNSCacheTTLMin = 30 * time.Second
	ResolveDNSCacheTTLMax = 2 * time.Minute
	// ResolveDNSCacheTTL is the pin lifetime when the answer has no usable TTL.
	ResolveDNSCacheTTL = ResolveDNSCacheTTLMin
	// ResolveDNSStaleTTL is how long an expired pin may still be served while a
	// background refresh runs. First packets after TTL expiry keep using the
	// old IP instead of blocking on resolve_dns.
	ResolveDNSStaleTTL = 5 * time.Minute
	// UdpEndpointFailureCacheTTL is the default UDP 4-tuple negative cache
	// after a cacheable create/dial failure.
	UdpEndpointFailureCacheTTL = 2 * time.Second
	// UdpEndpointFailureCacheTimeoutTTL is the negative cache for resolve_dns
	// lookup timeouts (netutils.ErrResolveTimeout). The caller already waited
	// ResolveDNSTimeout; a further 2s blackhole on the next datagram is worse
	// than a short retry. Handshake/select deadlines (DefaultDialTimeout) stay
	// on UdpEndpointFailureCacheTTL.
	UdpEndpointFailureCacheTimeoutTTL = 300 * time.Millisecond
)

// L4ProtoStr represents a layer 4 protocol as a string.
type L4ProtoStr string

const (
	// L4ProtoStr_TCP represents the TCP protocol.
	L4ProtoStr_TCP L4ProtoStr = "tcp"
	// L4ProtoStr_UDP represents the UDP protocol.
	L4ProtoStr_UDP L4ProtoStr = "udp"
)

func (l L4ProtoStr) ToL4Proto() uint8 {
	switch l {
	case L4ProtoStr_TCP:
		return IPPROTO_TCP
	case L4ProtoStr_UDP:
		return IPPROTO_UDP
	}
	panic("unsupported l4proto")
}

func (l L4ProtoStr) ToL4ProtoType() L4ProtoType {
	switch l {
	case L4ProtoStr_TCP:
		return L4ProtoType_TCP
	case L4ProtoStr_UDP:
		return L4ProtoType_UDP
	}
	panic("unsupported l4proto: " + l)
}

// IpVersionStr represents an IP version as a string.
type IpVersionStr string

const (
	// IpVersionStr_4 represents IPv4.
	IpVersionStr_4 IpVersionStr = "4"
	// IpVersionStr_6 represents IPv6.
	IpVersionStr_6 IpVersionStr = "6"
)

func (v IpVersionStr) ToIpVersion() uint8 {
	switch v {
	case IpVersionStr_4:
		return 4
	case IpVersionStr_6:
		return 6
	}
	panic("unsupported ipversion")
}

func (v IpVersionStr) ToIpVersionType() IpVersionType {
	switch v {
	case IpVersionStr_4:
		return IpVersion_4
	case IpVersionStr_6:
		return IpVersion_6
	}
	panic("unsupported ipversion")
}

func IpVersionFromAddr(addr netip.Addr) IpVersionStr {
	var ipversion IpVersionStr
	switch {
	case addr.Is4() || addr.Is4In6():
		ipversion = IpVersionStr_4
	case addr.Is6():
		ipversion = IpVersionStr_6
	}
	return ipversion
}
