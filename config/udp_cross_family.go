// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package config

import (
	"fmt"
	"net/netip"
)

// Both pools are explicit: automatically choosing a prefix could capture a LAN.
func (g Global) UDPCrossFamilyPrefixes(fake FakeIP) (v4, v6 netip.Prefix, err error) {
	if g.UDPCrossFamilyInet4Range == "" && g.UDPCrossFamilyInet6Range == "" {
		return
	}
	if g.UDPCrossFamilyInet4Range == "" || g.UDPCrossFamilyInet6Range == "" {
		return v4, v6, fmt.Errorf("UDP cross-family forwarding requires both mapping pools")
	}
	v4, err = parseFakeIPPrefix(g.UDPCrossFamilyInet4Range, true)
	if err != nil {
		return
	}
	v6, err = parseFakeIPPrefix(g.UDPCrossFamilyInet6Range, false)
	if err != nil {
		return
	}
	if v4.Bits() > 30 || v6.Bits() > 126 || v6.Addr().Is4In6() {
		return v4, v6, fmt.Errorf("UDP cross-family mapping pools require at least four native addresses")
	}
	if fake.Enable {
		f4, e := fake.Inet4Prefix()
		if e != nil {
			return v4, v6, e
		}
		f6, e := fake.Inet6Prefix()
		if e != nil {
			return v4, v6, e
		}
		if v4.Overlaps(f4) || v6.Overlaps(f6) {
			return v4, v6, fmt.Errorf("UDP cross-family mapping pools overlap DNS FakeIP pools")
		}
	}
	return
}
