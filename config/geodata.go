/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"strings"
	"time"
)

const (
	GeodataDefaultInterval = 7 * 24 * time.Hour
	GeodataDefaultMaxSize  = 64 << 20
)

// Geodata is the "geodata" section: where dae gets geoip.dat and geosite.dat
// from, for the geoip(geoip:cn) and domain(geosite:cn) functions. Each file is
// fetched in-process, checked to be a readable dat file, and kept beside the
// config; a failed or invalid download leaves the previous copy in place.
type Geodata struct {
	GeoIP    string        `mapstructure:"geoip"`
	GeoSite  string        `mapstructure:"geosite"`
	Interval time.Duration `mapstructure:"interval" default:"168h"`
	MaxSize  int64         `mapstructure:"max_size" default:"67108864"`
}

// Enabled reports whether any file is to be fetched.
func (g Geodata) Enabled() bool { return g.GeoIP != "" || g.GeoSite != "" }

// Validate checks the section shape. It does not touch the network or disk.
func (g Geodata) Validate() error {
	for name, raw := range map[string]string{"geoip": g.GeoIP, "geosite": g.GeoSite} {
		if raw == "" {
			continue
		}
		if strings.TrimSpace(raw) != raw {
			return fmt.Errorf("geodata: %s has surrounding whitespace", name)
		}
		if err := validateRuleProviderURL(raw); err != nil {
			return fmt.Errorf("geodata: %s: %w", name, err)
		}
	}
	if g.Interval < 0 {
		return fmt.Errorf("geodata: interval cannot be negative")
	}
	if g.MaxSize < 0 || g.MaxSize > maxRuleProviderSize {
		return fmt.Errorf("geodata: max_size is outside bounds")
	}
	return nil
}
