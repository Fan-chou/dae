/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestValidateAdminListen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		listen string
		ok     bool
	}{
		{listen: "", ok: true},
		{listen: "192.168.124.223:2025", ok: true},
		{listen: "10.0.0.1:2025", ok: true},
		{listen: "127.0.0.1:2025", ok: true},
		{listen: "[fd00::1]:2025", ok: true},
		{listen: "router.lan:2025", ok: true},
		{listen: "0.0.0.0:2025", ok: false},
		{listen: "[::]:2025", ok: false},
		{listen: "192.168.124.223:9090", ok: false},
		{listen: "8.8.8.8:2025", ok: false},
		{listen: "not-a-bind", ok: false},
	}
	for _, tc := range cases {
		err := ValidateAdminListen(tc.listen)
		if tc.ok && err != nil {
			t.Fatalf("ValidateAdminListen(%q) = %v, want nil", tc.listen, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("ValidateAdminListen(%q) = nil, want error", tc.listen)
		}
	}
}

func TestGlobalAdminDefaultsEmpty(t *testing.T) {
	t.Parallel()
	sections, err := config_parser.Parse(`
global {}
routing {
  fallback: direct
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Global.AdminListen != "" || conf.Global.AdminSecret != "" {
		t.Fatalf("admin defaults = listen %q secret %q, want empty", conf.Global.AdminListen, conf.Global.AdminSecret)
	}
}
