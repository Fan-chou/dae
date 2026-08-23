/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// SiteKey maps a sniffed host or literal destination to the sticky subject.
// Domains use eTLD+1 (`www.youtube.com` → `youtube.com`). Unicast IPs use the
// canonical address (port stripped, IPv4-mapped unmapped). Empty means no
// sticky subject: loopback / unspecified / multicast / link-local, single-label
// hosts, and unparseable names all fall back to group-level selection.
func SiteKey(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" {
		return ""
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsValid() {
		return stickyIPKey(ip)
	}
	if parsed := net.ParseIP(host); parsed != nil {
		if ip, ok := netip.AddrFromSlice(parsed); ok {
			return stickyIPKey(ip)
		}
		return ""
	}
	etld, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || etld == "" {
		return ""
	}
	return strings.ToLower(etld)
}

func stickyIPKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return ""
	}
	return ip.String()
}
