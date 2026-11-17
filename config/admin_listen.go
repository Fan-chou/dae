/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	// ClashCompatibleAdminPort is rejected so operators cannot point a
	// Clash dashboard at kdae by accident.
	ClashCompatibleAdminPort = 9090

	adminListenResolveTimeout = 2 * time.Second
)

type adminIPLookupFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

// ValidateAdminListen checks the optional management bind address.
// An empty value disables the API and is valid. Unspecified addresses and
// port 9090 are rejected. Non-empty hosts must be loopback, link-local, or
// RFC1918/ULA private, and hostnames must resolve exclusively to those ranges.
func ValidateAdminListen(listen string) error {
	_, err := ResolveAndValidateAdminListen(context.Background(), listen)
	return err
}

// ResolveAndValidateAdminListen validates listen and resolves any hostname to
// a concrete, allowed IP:port so callers can bind the validated address directly
// without a DNS TOCTOU window.
func ResolveAndValidateAdminListen(ctx context.Context, listen string) (string, error) {
	return resolveAndValidateAdminListen(ctx, listen, net.DefaultResolver.LookupIPAddr)
}

func resolveAndValidateAdminListen(ctx context.Context, listen string, lookup adminIPLookupFunc) (string, error) {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return "", nil
	}
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("admin_listen must be host:port: %w", err)
	}
	if host == "" || host == "*" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return "", fmt.Errorf("admin_listen must not bind an unspecified address")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("admin_listen port is invalid")
	}
	if port == ClashCompatibleAdminPort {
		return "", fmt.Errorf("admin_listen must not use port %d", ClashCompatibleAdminPort)
	}
	cleanHost := strings.Trim(host, "[]")
	if addr, err := netip.ParseAddr(cleanHost); err == nil {
		unmapped := addr.Unmap()
		if unmapped.IsUnspecified() {
			return "", fmt.Errorf("admin_listen must not bind an unspecified address")
		}
		if !isAllowedAdminAddr(unmapped) {
			return "", fmt.Errorf("admin_listen must bind a LAN/private address")
		}
		if addr.Is4In6() {
			addr = unmapped
		}
		return net.JoinHostPort(addr.String(), portStr), nil
	}

	trimmedHost := strings.TrimSuffix(cleanHost, ".")
	if trimmedHost == "" {
		return "", fmt.Errorf("admin_listen host is invalid")
	}
	if strings.EqualFold(trimmedHost, "localhost") {
		return net.JoinHostPort("127.0.0.1", portStr), nil
	}
	if lookup == nil {
		return "", fmt.Errorf("admin_listen host %q resolver is unavailable", cleanHost)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lookupCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		lookupCtx, cancel = context.WithTimeout(ctx, adminListenResolveTimeout)
		defer cancel()
	}
	addrs, err := lookup(lookupCtx, cleanHost)
	if err != nil {
		return "", fmt.Errorf("admin_listen host %q resolution failed: %w", cleanHost, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("admin_listen host %q resolved to no addresses", cleanHost)
	}

	var chosen netip.Addr
	for _, ipAddr := range addrs {
		addr, ok := netipAddrFromIPAddr(ipAddr)
		if !ok {
			return "", fmt.Errorf("admin_listen host %q resolved to an invalid address", cleanHost)
		}
		unmapped := addr.Unmap()
		if unmapped.IsUnspecified() {
			return "", fmt.Errorf("admin_listen host %q must not resolve to an unspecified address", cleanHost)
		}
		if !isAllowedAdminAddr(unmapped) {
			return "", fmt.Errorf("admin_listen host %q resolved to non-private address %s", cleanHost, unmapped)
		}
		candidate := addr
		if addr.Is4In6() {
			candidate = unmapped
		}
		if !chosen.IsValid() || (chosen.Is6() && candidate.Is4()) {
			chosen = candidate
		}
	}
	return net.JoinHostPort(chosen.String(), portStr), nil
}

func isAllowedAdminAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

func netipAddrFromIPAddr(ipAddr net.IPAddr) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ipAddr.IP)
	if !ok {
		return netip.Addr{}, false
	}
	if ipAddr.Zone != "" && addr.Is6() {
		addr = addr.WithZone(ipAddr.Zone)
	}
	return addr, true
}
