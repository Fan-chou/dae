package ruleprovider

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func safeTransport(roundTripper http.RoundTripper) (http.RoundTripper, error) {
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http transport must be *http.Transport")
	}
	clone := transport.Clone()
	originalDial := clone.DialContext
	if originalDial == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		originalDial = dialer.DialContext
	}
	clone.DialContext = safeDialContext(originalDial)
	if clone.MaxResponseHeaderBytes == 0 || clone.MaxResponseHeaderBytes > 1<<20 {
		clone.MaxResponseHeaderBytes = 1 << 20
	}
	return clone, nil
}

func safeDialContext(original func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("split provider address %q: %w", address, err)
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve provider host %q: %w", host, err)
		}
		var lastErr error
		for _, resolved := range ips {
			if blockedIP(resolved.IP) {
				lastErr = fmt.Errorf("resolved provider host %q to blocked address %s", host, resolved.IP)
				continue
			}
			conn, dialErr := original(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("provider host has no usable address")
		}
		return nil, lastErr
	}
}

func validatePublicURL(value *url.URL) error {
	if value == nil || (value.Scheme != "http" && value.Scheme != "https") || value.Host == "" {
		return fmt.Errorf("redirect URL is not a valid HTTP(S) URL")
	}
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || numericAddressLike(host) {
		return fmt.Errorf("redirect URL host %q is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil && blockedIP(ip) {
		return fmt.Errorf("redirect URL host %q is not allowed", host)
	}
	return nil
}

func numericAddressLike(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func blockedIP(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()
}
