/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
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
}

// Enabled reports whether a routing source is configured.
func (m Mihomo) Enabled() bool {
	return m.RoutingSubscription != "" || m.RoutingFile != ""
}

// RedactedSource describes the configured source without any secret.
func (m Mihomo) RedactedSource() string {
	switch {
	case m.RoutingSubscription != "":
		return redactRuleProviderURL(m.RoutingSubscription)
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
	if m.Interval < 0 {
		return fmt.Errorf("mihomo: interval cannot be negative")
	}
	if m.MaxSize < 0 || m.MaxSize > maxRuleProviderSize {
		return fmt.Errorf("mihomo: max_size is outside bounds")
	}
	return nil
}
