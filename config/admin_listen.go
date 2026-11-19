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
	"net/url"
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

// CanonicalizeAdminOrigin validates and normalizes a single exact CORS/WS origin
// ("scheme://host[:port]"). Wildcards, paths, queries, fragments, credentials,
// and unsupported schemes are rejected. Error strings intentionally avoid "://".
func CanonicalizeAdminOrigin(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("origin cannot be empty")
	}
	if s == "*" || strings.Contains(s, "*") {
		return "", fmt.Errorf("admin_cors_origins must not contain wildcards")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("admin_cors_origins entry contains whitespace")
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("admin_cors_origins entry is not a valid origin")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("admin_cors_origins entry must not contain user credentials")
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https", "tauri", "app":
	default:
		return "", fmt.Errorf("admin_cors_origins scheme %q must be http, https, tauri, or app", parsed.Scheme)
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("admin_cors_origins entry must not contain a path, query, or fragment")
	}
	hostname := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if hostname == "" {
		return "", fmt.Errorf("admin_cors_origins entry is missing host")
	}
	port := parsed.Port()
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return "", fmt.Errorf("admin_cors_origins port %q is invalid", port)
		}
		if (scheme == "http" && p == 80) || (scheme == "https" && p == 443) {
			port = ""
		}
	} else if strings.HasSuffix(parsed.Host, ":") {
		return "", fmt.Errorf("admin_cors_origins entry has empty port")
	}
	hostPart := hostname
	if strings.Contains(hostname, ":") {
		hostPart = "[" + hostname + "]"
	}
	if port != "" {
		hostPart += ":" + port
	}
	return scheme + "://" + hostPart, nil
}

// ValidateAdminCorsOrigins validates and deduplicates configured extra CORS origins.
func ValidateAdminCorsOrigins(origins []string) ([]string, error) {
	if len(origins) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(origins))
	seen := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		canon, err := CanonicalizeAdminOrigin(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
