/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/daeuniverse/dae/component/outbound/quality"
)

// SpeedPolicy produces an immutable policy for a new observation generation.
func (g Group) SpeedPolicy() (quality.Policy, error) {
	severe, e1 := strconv.ParseFloat(g.SevereSpeedRatio, 64)
	recovery, e2 := strconv.ParseFloat(g.RecoverySpeedRatio, 64)
	improvement, e3 := strconv.ParseFloat(g.SpeedImprovementRatio, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		return quality.Policy{}, fmt.Errorf("speed ratios must be decimal numbers")
	}
	p := quality.Policy{SevereRatio: severe, RecoveryRatio: recovery,
		Window: g.QualityWindow, SevereWindows: g.SevereSpeedWindows, RecoveryWindows: g.RecoverySpeedWindows,
		EvidenceTTL: g.QualityEvidenceTTL, ImprovementRatio: improvement, ImprovementBytes: float64(g.SpeedImprovementBytes)}
	return p, p.Validate()
}

func patchQuality(c *Config) error {
	if c.Global.CaptureEnabled && (c.Global.CaptureSamplePermille == 0 || c.Global.CaptureSamplePermille > 1000) {
		return fmt.Errorf("capture_sample_permille must be 1..1000 when capture is enabled")
	}

	if c.Global.LayaMode != "shadow" && c.Global.LayaMode != "assist" {
		return fmt.Errorf("laya_mode must be shadow or assist")
	}
	if c.Global.LayaEnabled {
		u, err := url.Parse(c.Global.LayaEndpoint)
		if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("laya_endpoint must be an HTTPS origin without credentials, query or fragment")
		}
		if c.Global.LayaCAFile != "" && !filepath.IsAbs(c.Global.LayaCAFile) {
			return fmt.Errorf("laya_ca_file must be an absolute path")
		}
		if !filepath.IsAbs(c.Global.LayaCredentialFile) {
			return fmt.Errorf("laya_credential_file must be an absolute path")
		}

	}
	for _, g := range c.Group {
		if _, err := g.SpeedPolicy(); err != nil {
			return fmt.Errorf("group %q: %w", g.Name, err)
		}
		switch g.QualityMode {
		case "off", "observe", "enforce":
		default:
			return fmt.Errorf("group %q: quality_mode must be off, observe or enforce", g.Name)
		}
	}
	return nil
}
