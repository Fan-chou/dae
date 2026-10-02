/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"strings"
	"testing"
)

func qualityConfig(global, group string) (*Config, error) {
	sections, err := config_parser.Parse(fmt.Sprintf("global {\n%s\n}\ngroup {\n proxy {\n policy: fallback\n%s\n}\n}\nrouting {}", global, group))
	if err != nil {
		return nil, err
	}
	return New(sections)
}
func TestQualityConfigDefaultsAndRoundTrip(t *testing.T) {
	c, err := qualityConfig("laya_enabled: false", "severe_speed_ratio: 0.25\nrecovery_speed_ratio: 0.65")
	if err != nil {
		t.Fatal(err)
	}
	if c.Global.LayaEnabled || c.Global.LayaMode != "shadow" || c.Group[0].QualityMode != "off" {
		t.Fatal("unsafe defaults")
	}
	p, err := c.Group[0].SpeedPolicy()
	if err != nil || p.SevereRatio != .25 || p.RecoveryRatio != .65 {
		t.Fatalf("policy %+v: %v", p, err)
	}
	b, err := c.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	sections, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatal(err)
	}
	again, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.Group[0].SpeedPolicy()
	if err != nil || got != p || again.Global.LayaEnabled {
		t.Fatal("roundtrip lost configuration")
	}
}
func TestQualityConfigRejectsInvalid(t *testing.T) {
	for _, tc := range []struct{ global, group, want string }{
		{"", "severe_speed_ratio: 0", "ratios"},
		{"", "recovery_speed_ratio: 0.2", "ratios"},
		{"", "severe_speed_ratio: NaN", "ratios"},
		{"", "quality_window: 0s", "windows"},
		{"", "severe_speed_windows: 0", "windows"},

		{"laya_enabled: true\nlaya_endpoint: 'http://user:secret@localhost:8765'", "", "HTTPS origin"},
	} {
		_, err := qualityConfig(tc.global, tc.group)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%+v: %v", tc, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("credential leaked")
		}
	}
}

func TestQualityActivationParsesWithoutReadingCredentials(t *testing.T) {
	c, err := qualityConfig("laya_enabled: true\nlaya_endpoint: 'https://localhost:8765'\nlaya_credential_file: /does-not-exist", "quality_mode: enforce")
	if err != nil || !c.Global.LayaEnabled || c.Group[0].QualityMode != "enforce" {
		t.Fatalf("activation: %v", err)
	}
}

func TestAbsoluteFloorConfigurationRoundTrip(t *testing.T) {
	c, err := qualityConfig("", "quality_min_download_bytes: 262144")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	sections, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatal(err)
	}
	again, err := New(sections)
	if err != nil || again.Group[0].QualityMinDownloadBytes != 262144 {
		t.Fatalf("floor roundtrip: %v", err)
	}
	c, err = qualityConfig("", "")
	if err != nil || c.Group[0].QualityMinDownloadBytes != 0 {
		t.Fatal("floor must default disabled")
	}
	if _, err = qualityConfig("", "quality_min_download_bytes: -1"); err == nil {
		t.Fatal("negative floor accepted")
	}
}

func TestCaptureConfigIndependentDefaults(t *testing.T) {
	c, err := qualityConfig("", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Global.CaptureEnabled || c.Global.CaptureSamplePermille != 100 {
		t.Fatal("unsafe capture defaults")
	}
	c, err = qualityConfig("capture_enabled: true\ncapture_sample_permille: 25\ncapture_group: proxy", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Global.LayaEnabled || c.Group[0].QualityMode != "off" || c.Global.CaptureGroup != "proxy" {
		t.Fatal("capture changed model or quality settings")
	}
	for _, value := range []string{"0", "1001"} {
		if _, err := qualityConfig("capture_enabled: true\ncapture_sample_permille: "+value, ""); err == nil {
			t.Fatal("invalid sampling accepted")
		}
	}
}

func TestLayaCustomCAConfig(t *testing.T) {
	global := "laya_enabled: true\nlaya_endpoint: 'https://localhost:8765'\nlaya_credential_file: /does-not-exist\nlaya_ca_file: /also-does-not-exist"
	c, err := qualityConfig(global, "")
	if err != nil || c.Global.LayaCAFile != "/also-does-not-exist" {
		t.Fatalf("CA config: %v", err)
	}
	if _, err := qualityConfig(strings.Replace(global, "/also-does-not-exist", "relative.pem", 1), ""); err == nil {
		t.Fatal("relative CA accepted")
	}
}
