/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	// ClashCompatibleAdminPort is rejected so operators cannot point a
	// Clash dashboard at kdae by accident.
	ClashCompatibleAdminPort = 9090
)

// ValidateAdminListen checks the optional management bind address.
// An empty value disables the API and is valid. Unspecified addresses and
// port 9090 are rejected. Non-empty hosts must be loopback, link-local, or
// RFC1918/ULA private so the API is not advertised on a public address.
func ValidateAdminListen(listen string) error {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return nil
	}
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("admin_listen must be host:port: %w", err)
	}
	if host == "" || host == "*" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return fmt.Errorf("admin_listen must not bind an unspecified address")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("admin_listen port is invalid")
	}
	if port == ClashCompatibleAdminPort {
		return fmt.Errorf("admin_listen must not use port %d", ClashCompatibleAdminPort)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		// Hostnames are allowed (e.g. router.lan) so LuCI can inject a
		// LAN name without forcing an IP literal.
		return nil
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("admin_listen must not bind an unspecified address")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}
	return fmt.Errorf("admin_listen must bind a LAN/private address")
}
