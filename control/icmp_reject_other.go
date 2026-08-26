//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
)

func sendICMPAdminProhibited(_ []byte, client, dest netip.AddrPort, _ uint32) error {
	return fmt.Errorf("icmp admin-prohibited unsupported on this platform: client=%v dest=%v", client, dest)
}
