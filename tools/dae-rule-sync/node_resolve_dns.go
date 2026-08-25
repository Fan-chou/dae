package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

const defaultNodeResolveDNSPort = 53

func loadNodeResolveDNSOverlay(path string) (map[string]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read node resolve_dns overlay: %w", err)
	}
	var overlay map[string]string
	if err := json.Unmarshal(body, &overlay); err != nil {
		return nil, fmt.Errorf("parse node resolve_dns overlay: %w", err)
	}
	if overlay == nil {
		return map[string]string{}, nil
	}
	return overlay, nil
}

func normalizeResolveDNSQuery(val string) (string, error) {
	s := strings.TrimSpace(val)
	s = strings.Trim(s, `'"`)
	s = strings.TrimPrefix(s, "udp://")
	s = strings.TrimPrefix(s, "UDP://")
	if s == "" {
		return "", fmt.Errorf("resolve_dns must be an IP address")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if err := validateOverlayResolveDNSAddr(ap.Addr()); err != nil {
			return "", err
		}
		return ap.String(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("resolve_dns must be an IP address: %s", val)
	}
	if err := validateOverlayResolveDNSAddr(addr); err != nil {
		return "", err
	}
	return netip.AddrPortFrom(addr, defaultNodeResolveDNSPort).String(), nil
}

func validateOverlayResolveDNSAddr(addr netip.Addr) error {
	if !addr.IsValid() || addr.IsUnspecified() {
		return fmt.Errorf("invalid resolve_dns address: %s", addr)
	}
	return nil
}

func stripQueryParam(rawQuery, key string) string {
	if rawQuery == "" || key == "" {
		return rawQuery
	}
	parts := strings.Split(rawQuery, "&")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name, _, _ := strings.Cut(p, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		if decoded == key {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "&")
}

func appendQueryParam(rawQuery, key, value string) string {
	rawQuery = stripQueryParam(rawQuery, key)
	param := key + "=" + url.QueryEscape(value)
	if rawQuery == "" {
		return param
	}
	return rawQuery + "&" + param
}

func withResolveDNSQuery(link, dns string) (string, error) {
	normalized, err := normalizeResolveDNSQuery(dns)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(link)
	if err != nil || u == nil || u.Scheme == "" {
		return "", fmt.Errorf("cannot attach resolve_dns to generated link")
	}
	u.RawQuery = appendQueryParam(u.RawQuery, "resolve_dns", normalized)
	out := u.String()
	if err := validateDaeLiteral(out); err != nil {
		return "", fmt.Errorf("resolve_dns produced an invalid dae link")
	}
	return out, nil
}

func applyResolveDNSOverlay(link, originalName string, overlay map[string]string) (string, error) {
	if overlay == nil {
		return link, nil
	}
	dns, ok := overlay[originalName]
	if !ok || strings.TrimSpace(dns) == "" {
		return link, nil
	}
	return withResolveDNSQuery(link, dns)
}
