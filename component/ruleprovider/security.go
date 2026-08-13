package ruleprovider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type providerSecurityError struct {
	err error
}

func (e *providerSecurityError) Error() string {
	if e == nil || e.err == nil {
		return "provider security policy rejected request"
	}
	return e.err.Error()
}

func (e *providerSecurityError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func securityError(err error) error {
	if err == nil {
		return nil
	}
	var existing *providerSecurityError
	if errors.As(err, &existing) {
		return err
	}
	return &providerSecurityError{err: err}
}

func isSecurityError(err error) bool {
	var securityErr *providerSecurityError
	return errors.As(err, &securityErr)
}

func safeTransport(roundTripper http.RoundTripper) (http.RoundTripper, error) {
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http transport must be *http.Transport")
	}
	clone := transport.Clone()
	clone.Proxy = nil
	clone.OnProxyConnectResponse = nil
	clone.ProxyConnectHeader = nil
	clone.GetProxyConnectHeader = nil
	// A custom DialTLSContext takes precedence over DialContext for HTTPS and
	// could otherwise bypass the resolved-address policy below.
	clone.DialTLSContext = nil
	clone.DialTLS = nil
	clone.Dial = nil
	// A custom alternate-protocol handler receives the original authority and
	// can establish its own connection without going through DialContext.
	clone.TLSNextProto = nil
	clone.ForceAttemptHTTP2 = false
	// Go 1.26 exposes protocol negotiation independently of TLSNextProto and
	// ForceAttemptHTTP2. Keep the provider transport explicitly HTTP/1-only so
	// HTTP/2 and unencrypted HTTP/2 cannot be re-enabled by the caller's clone.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	clone.Protocols = protocols
	if clone.TLSClientConfig != nil {
		tlsConfig := clone.TLSClientConfig.Clone()
		tlsConfig.InsecureSkipVerify = false
		tlsConfig.ServerName = ""
		tlsConfig.VerifyPeerCertificate = nil
		tlsConfig.VerifyConnection = nil
		clone.TLSClientConfig = tlsConfig
	}
	// Do not retain a caller-provided dial function: it could ignore the
	// already validated address and connect to a different endpoint.
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	clone.DialContext = safeDialContext(dialer.DialContext)
	if clone.MaxResponseHeaderBytes <= 0 || clone.MaxResponseHeaderBytes > maxResponseHeaderBytes {
		clone.MaxResponseHeaderBytes = maxResponseHeaderBytes
	}
	return clone, nil
}

func safeDialContext(original func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("split provider address %q: %w", address, err)
		}
		if strings.ContainsRune(host, '%') {
			return nil, securityError(fmt.Errorf("provider host %q has a zone", host))
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve provider host %q: %w", host, err)
		}
		var lastErr error
		for _, resolved := range ips {
			if resolved.Zone != "" {
				lastErr = securityError(fmt.Errorf("resolved provider host %q has a zone", host))
				continue
			}
			if blockedIP(resolved.IP) {
				lastErr = securityError(fmt.Errorf("resolved provider host %q to blocked address %s", host, resolved.IP))
				continue
			}
			conn, dialErr := original(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = errors.New("provider host has no usable address")
		}
		return nil, lastErr
	}
}

func validatePublicURL(value *url.URL) error {
	if value == nil || value.Host == "" {
		return fmt.Errorf("provider URL is not a valid HTTP(S) URL")
	}
	scheme := strings.ToLower(value.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("provider URL is not a valid HTTP(S) URL")
	}
	if value.User != nil {
		return fmt.Errorf("provider URL userinfo is not allowed")
	}
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" || host == "metadata" || strings.Contains(host, "%") || numericAddressLike(host) {
		return fmt.Errorf("provider URL host %q is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil && blockedIP(ip) {
		return fmt.Errorf("provider URL host %q is not allowed", host)
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

var blockedProviderNetworks = mustProviderNetworks([]string{
	"0.0.0.0/8",          // This network is never a public provider endpoint.
	"192.0.0.0/24",       // IETF protocol assignments.
	"192.88.99.0/24",     // 6to4 relay anycast addresses.
	"192.0.2.0/24",       // TEST-NET-1.
	"198.51.100.0/24",    // TEST-NET-2.
	"203.0.113.0/24",     // TEST-NET-3.
	"240.0.0.0/4",        // Reserved IPv4 class-E range.
	"100.64.0.0/10",      // CGNAT.
	"198.18.0.0/15",      // Benchmark/testing.
	"100.100.100.200/32", // Alibaba metadata.
	"168.63.129.16/32",   // Azure metadata.
	"169.254.169.254/32", // Common cloud metadata.
	"64:ff9b::/96",       // NAT64 IPv4-embedded well-known prefix.
	"64:ff9b:1::/48",     // NAT64 local-use prefix.
	"100::/64",           // IPv6 discard-only prefix.
	"100:0:0:1::/64",     // IANA Dummy IPv6 range.
	"5f00::/16",          // IPv6 SRv6 SID range.
	"2001:0::/32",        // Teredo.
	"2001:2::/48",        // Benchmarking.
	"2001:10::/28",       // ORCHIDv1.
	"2001:20::/28",       // ORCHIDv2.
	"2001:db8::/32",      // IPv6 documentation range.
	"2002::/16",          // 6to4 addresses can embed private/loopback IPv4.
	"3fff::/20",          // IPv6 documentation range.
	"fec0::/10",          // IPv6 site-local range.
})

func mustProviderNetworks(values []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}

func blockedIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range blockedProviderNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
