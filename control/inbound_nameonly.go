/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Name-only flows ("resolve: deferred" on an inbound).
//
// A flow whose client sent a domain name is normally resolved first and then
// routed with the real IP. A name-only flow is routed by its name alone, the
// way a FakeIP flow is: rules that do not read the destination address are
// evaluated first, and the name is only resolved when a rule needs the
// address (dip, geoip, ipversion) or when the outbound dials a real address
// (direct). A decisive proxy or block verdict never touches DNS, and a proxy
// receives host:port.
//
// proxyDialParam.Dest carries nameOnlyPlaceholder until a real address is
// known. The placeholder is never dialed: chooseProxyDialer either replaces
// it with the resolved address or dials by name, and
// guardNameOnlyDialTarget fails the dial if neither happened.

// nameOnlyPlaceholder is the unspecified address; dialing it would reach this
// host itself, which is why guardNameOnlyDialTarget exists.
var nameOnlyPlaceholder = netip.IPv4Unspecified()

func nameOnlyDest(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(nameOnlyPlaceholder, port)
}

// nameOnlyPending reports whether p is a name-only flow whose destination is
// still the placeholder.
func (p *proxyDialParam) nameOnlyPending(dst netip.AddrPort) bool {
	return p != nil && p.NameOnly && dst.Addr().IsUnspecified()
}

// realIPForNameOnly resolves the on-wire address of a name: dae's DNS
// controller first, then the bootstrap resolvers so that a configuration
// without a dns section still works. The fake argument only selects the
// address family to prefer.
func (c *ControlPlane) realIPForNameOnly(ctx context.Context, domain string, fake netip.Addr) (netip.Addr, error) {
	ip, err := c.realIPForFakeIPRoute(ctx, domain, fake)
	if err == nil {
		return ip, nil
	}
	ip, bootErr := c.resolveInboundViaBootstrap(ctx, domain)
	if bootErr != nil {
		return netip.Addr{}, fmt.Errorf("resolve %v: %w (bootstrap resolvers: %v)", strings.TrimSuffix(domain, "."), err, bootErr)
	}
	return ip, nil
}

// nameOnlyDialTarget is the host:port a proxy is given for a name-only flow.
func nameOnlyDialTarget(domain string, port uint16) string {
	return net.JoinHostPort(strings.TrimSuffix(domain, "."), strconv.Itoa(int(port)))
}

// guardNameOnlyDialTarget refuses to dial a name-only flow whose target is
// still an unspecified address.
func guardNameOnlyDialTarget(p *proxyDialParam, res *proxyDialResult) error {
	if p == nil || !p.NameOnly || res == nil {
		return nil
	}
	if ip, err := parseDialTargetIP(res.DialTarget); err == nil && ip.IsUnspecified() {
		return fmt.Errorf("name-only flow to %q was left without a resolved address", p.Domain)
	}
	return nil
}
