/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
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
	s = strings.TrimPrefix(s, "tcp://")
	s = strings.TrimPrefix(s, "TCP://")
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
func extractLinkResolveDNS(link string) (stripped string, dns netip.AddrPort, err error) {
	u, err := url.Parse(link)
	if err != nil || u == nil {
		return link, netip.AddrPort{}, nil
	}
	q := u.Query()
	raw := q.Get(LinkQuery_ResolveDNS)
	if raw == "" {
		return link, netip.AddrPort{}, nil
	}
	dns, err = parseResolveDNS(raw)
	if err != nil {
		return "", netip.AddrPort{}, fmt.Errorf("node %s: %w", LinkQuery_ResolveDNS, err)
	}
	q.Del(LinkQuery_ResolveDNS)
	u.RawQuery = q.Encode()
	return u.String(), dns, nil
}
