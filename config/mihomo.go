/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	MihomoDefaultInterval = time.Hour
	MihomoDefaultMaxSize  = 16 << 20
)

// Mihomo is the "mihomo" section: one complete Mihomo YAML routing source
// that is fetched in-process, validated, and lowered into nodes, groups and
// routing rules. The document is data only and is never executed.
//
// RoutingSubscription is a secret: it commonly embeds an access token in the
// query string. It must never be logged or returned in error messages; use
// RedactedSource for diagnostics.
type Mihomo struct {
	RoutingSubscription string        `mapstructure:"routing_subscription"`
	RoutingFile         string        `mapstructure:"routing_file"`
	Interval            time.Duration `mapstructure:"interval" default:"1h"`
	MaxSize             int64         `mapstructure:"max_size" default:"16777216"`

	// IsolateTransportGroups lists converted group names (the internal names
	// shown in dae) that get a private proxy transport per node.
	IsolateTransportGroups []string `mapstructure:"isolate_transport_groups"`
	// NodeResolveDNS maps an original Mihomo proxy name to a DNS server (IP,
	// optional port) used to resolve destinations through that node. Proxy
	// names are free text, so an entry is "name=server" (split at the last
	// "="); a plain identifier may also be written as a keyed entry:
	//
	//	node_resolve_dns {
	//	    'HK 01=8.8.8.8'
	//	    jp2: '1.1.1.1:5353'
	//	}
	NodeResolveDNS []KeyableString `mapstructure:"node_resolve_dns"`
}

// ResolveDNSMap returns NodeResolveDNS as a map from proxy name to server.
func (m Mihomo) ResolveDNSMap() map[string]string {
	if len(m.NodeResolveDNS) == 0 {
		return nil
	}
	out := make(map[string]string, len(m.NodeResolveDNS))
	for _, entry := range m.NodeResolveDNS {
		raw := string(entry)
		if i := strings.LastIndex(raw, "="); i >= 0 {
			out[raw[:i]] = raw[i+1:]
		} else if name, server, ok := strings.Cut(raw, ":"); ok {
			out[name] = server
		}
	}
	return out
}

// Enabled reports whether a routing source is configured.
func (m Mihomo) Enabled() bool {
	return m.RoutingSubscription != "" || m.RoutingFile != ""
}

// RedactedSource describes the configured source without any secret.
func (m Mihomo) RedactedSource() string {
	switch {
	case m.RoutingSubscription != "":
		return redactSubscription(m.RoutingSubscription)
	case m.RoutingFile != "":
		return m.RoutingFile
	}
	return ""
}

// Validate checks the section shape. It does not touch the network or disk.
func (m Mihomo) Validate() error {
	if m.RoutingSubscription != "" && m.RoutingFile != "" {
		return fmt.Errorf("mihomo: routing_subscription and routing_file are mutually exclusive")
	}
	if m.RoutingSubscription != "" {
		if strings.TrimSpace(m.RoutingSubscription) != m.RoutingSubscription {
			return fmt.Errorf("mihomo: routing_subscription has surrounding whitespace")
		}
		if err := validateRuleProviderURL(m.RoutingSubscription); err != nil {
			return fmt.Errorf("mihomo: routing_subscription: %w", err)
		}
	}
	if m.RoutingFile != "" {
		// Containment against the real config directory is enforced when the
		// file is read; here only reject absolute, NUL and escaping paths.
		clean := filepath.Clean(m.RoutingFile)
		if filepath.IsAbs(m.RoutingFile) || strings.IndexByte(m.RoutingFile, 0) >= 0 ||
			clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("mihomo: routing_file must be a relative path inside the config directory")
		}
	}
	for _, name := range m.IsolateTransportGroups {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("mihomo: isolate_transport_groups has an empty name")
		}
	}
	if len(m.NodeResolveDNS) > 0 && !m.Enabled() {
		return fmt.Errorf("mihomo: node_resolve_dns needs routing_subscription or routing_file")
	}
	if m.Interval < 0 {
		return fmt.Errorf("mihomo: interval cannot be negative")
	}
	if m.MaxSize < 0 || m.MaxSize > maxRuleProviderSize {
		return fmt.Errorf("mihomo: max_size is outside bounds")
	}
	return nil
}

// redactSubscription keeps only the scheme and host of a subscription URL.
// Both the path and the query commonly carry the access token.
func redactSubscription(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<invalid url>"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// ScrubSecrets removes the parts of the subscription URL that may carry a
// token from text that quotes it, such as the error of a failed fetch.
func (m Mihomo) ScrubSecrets(text string) string {
	raw := m.RoutingSubscription
	if raw == "" {
		return text
	}
	text = strings.ReplaceAll(text, raw, redactSubscription(raw))
	u, err := url.Parse(raw)
	if err != nil {
		return text
	}
	for _, secret := range []string{u.RawQuery, u.Path, u.EscapedPath()} {
		if len(secret) > 1 {
			text = strings.ReplaceAll(text, secret, "…")
		}
	}
	return text
}
