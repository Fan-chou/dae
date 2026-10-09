/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

const defaultResolveDNSPort = 53

// normalizeResolveDNS accepts an IP address with an optional port (and an
// optional udp:// prefix and quotes) and returns "ip:port". A name is not
// accepted: the DNS server must be reachable without resolving anything.
func normalizeResolveDNS(value string) (string, error) {
	s := strings.Trim(strings.TrimSpace(value), `'"`)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "udp://"), "UDP://")
	if s == "" {
		return "", errors.New("resolve_dns must be an IP address")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if !ap.Addr().IsValid() || ap.Addr().IsUnspecified() {
			return "", fmt.Errorf("invalid resolve_dns address")
		}
		return ap.String(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", errors.New("resolve_dns must be an IP address")
	}
	if !addr.IsValid() || addr.IsUnspecified() {
		return "", fmt.Errorf("invalid resolve_dns address")
	}
	return netip.AddrPortFrom(addr, defaultResolveDNSPort).String(), nil
}

// withResolveDNS sets the resolve_dns query parameter on a node link,
// replacing any existing one.
func withResolveDNS(link, dns string) (string, error) {
	normalized, err := normalizeResolveDNS(dns)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(link)
	if err != nil || u == nil || u.Scheme == "" {
		return "", errors.New("cannot attach resolve_dns to generated link")
	}
	var kept []string
	if u.RawQuery != "" {
		for _, part := range strings.Split(u.RawQuery, "&") {
			name, _, _ := strings.Cut(part, "=")
			if decoded, err := url.QueryUnescape(name); err == nil {
				name = decoded
			}
			if name != "resolve_dns" {
				kept = append(kept, part)
			}
		}
	}
	kept = append(kept, "resolve_dns="+url.QueryEscape(normalized))
	u.RawQuery = strings.Join(kept, "&")
	return u.String(), nil
}
