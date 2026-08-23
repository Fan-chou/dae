/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"strings"
)

// udpTransportFromProperty reports whether this node speaks a UDP/QUIC
// outbound (Hysteria, TUIC, Juicity). Inner TCP over those transports has a
// heavier RTT tail and Brutal-style CC, so TCP-slot Degraded/congestion is
// relaxed. Data-UDP health is unchanged.
func udpTransportFromProperty(p *Property) bool {
	if p == nil {
		return false
	}
	if udpTransportToken(p.Protocol) {
		return true
	}
	if p.Link == "" {
		return false
	}
	scheme, _, ok := strings.Cut(p.Link, "://")
	if !ok {
		return false
	}
	return udpTransportToken(scheme)
}

func udpTransportToken(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "hysteria", "hysteria1", "hysteria2", "hy", "hy2",
		"tuic", "tuic5", "juicity":
		return true
	default:
		return false
	}
}
