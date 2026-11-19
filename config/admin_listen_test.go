/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
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
		{listen: "localhost:2025", ok: true},
		{listen: "LOCALHOST.:2025", ok: true},
		{listen: "[fd00::1]:2025", ok: true},
		{listen: "[fe80::1%eth0]:2025", ok: true},
		{listen: "0.0.0.0:2025", ok: false},
		{listen: "[::]:2025", ok: false},
		{listen: "[::ffff:0.0.0.0]:2025", ok: false},
		{listen: "[::ffff:8.8.8.8]:2025", ok: false},
		{listen: "192.168.124.223:9090", ok: false},
		{listen: "localhost:9090", ok: false},
		{listen: "8.8.8.8:2025", ok: false},
		{listen: "nonexistent.invalid:2025", ok: false},
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

func TestResolveAndValidateAdminListenHostnames(t *testing.T) {
	t.Parallel()

	stubLookup := func(records map[string][]net.IPAddr, errs map[string]error) adminIPLookupFunc {
		return func(_ context.Context, host string) ([]net.IPAddr, error) {
			if err := errs[host]; err != nil {
				return nil, err
			}
			return records[host], nil
		}
	}

	lookup := stubLookup(
		map[string][]net.IPAddr{
			"router.lan": {
				{IP: net.ParseIP("fd00::1")},
				{IP: net.ParseIP("192.168.124.223")},
			},
			"link.lan": {
				{IP: net.ParseIP("169.254.10.2")},
			},
			"mixed.lan": {
				{IP: net.ParseIP("192.168.124.223")},
				{IP: net.ParseIP("8.8.8.8")},
			},
			"public.example.com": {
				{IP: net.ParseIP("93.184.216.34")},
			},
			"unspec.lan": {
				{IP: net.ParseIP("0.0.0.0")},
			},
			"empty.lan": nil,
		},
		map[string]error{
			"fail.lan": errors.New("dns unavailable"),
		},
	)

	got, err := resolveAndValidateAdminListen(context.Background(), "router.lan:2025", lookup)
	if err != nil || got != "192.168.124.223:2025" {
		t.Fatalf("router.lan = (%q, %v), want (192.168.124.223:2025, nil)", got, err)
	}

	got, err = resolveAndValidateAdminListen(context.Background(), "link.lan:2025", lookup)
	if err != nil || got != "169.254.10.2:2025" {
		t.Fatalf("link.lan = (%q, %v), want (169.254.10.2:2025, nil)", got, err)
	}

	got, err = resolveAndValidateAdminListen(context.Background(), "localhost:2025", stubLookup(nil, map[string]error{"localhost": errors.New("offline")}))
	if err != nil || got != "127.0.0.1:2025" {
		t.Fatalf("offline localhost = (%q, %v), want (127.0.0.1:2025, nil)", got, err)
	}

	for _, bad := range []string{
		"mixed.lan:2025",
		"public.example.com:2025",
		"unspec.lan:2025",
		"empty.lan:2025",
		"fail.lan:2025",
	} {
		if resolved, err := resolveAndValidateAdminListen(context.Background(), bad, lookup); err == nil {
			t.Fatalf("resolveAndValidateAdminListen(%q) = (%q, nil), want error", bad, resolved)
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
	if conf.Global.AdminListen != "" || conf.Global.AdminSecret != "" || len(conf.Global.AdminCorsOrigins) != 0 {
		t.Fatalf("admin defaults = listen %q secret %q cors %v, want empty", conf.Global.AdminListen, conf.Global.AdminSecret, conf.Global.AdminCorsOrigins)
	}
}

func TestValidateAdminCorsOrigins(t *testing.T) {
	t.Parallel()
	got, err := ValidateAdminCorsOrigins([]string{
		"HTTPS://Panel.Example.com:443",
		"https://panel.example.com",
		"http://192.168.1.10:3000",
		"http://[::1]:8080",
		"tauri://localhost",
		"app://fdae.local",
		"  ",
	})
	if err != nil {
		t.Fatalf("ValidateAdminCorsOrigins valid error = %v", err)
	}
	want := []string{
		"https://panel.example.com",
		"http://192.168.1.10:3000",
		"http://[::1]:8080",
		"tauri://localhost",
		"app://fdae.local",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ValidateAdminCorsOrigins = %v, want %v", got, want)
	}

	for _, bad := range []string{
		"*",
		"https://*",
		"https://*.example.com",
		"https://panel.example.com/",
		"https://panel.example.com/app",
		"https://panel.example.com?x=1",
		"https://user:pass@panel.example.com",
		"javascript://alert(1)",
		"ftp://example.com",
		"https://panel.example.com:99999",
		"panel.example.com",
	} {
		if _, err := ValidateAdminCorsOrigins([]string{bad}); err == nil {
			t.Fatalf("ValidateAdminCorsOrigins(%q) = nil, want error", bad)
		} else if strings.Contains(err.Error(), "://") {
			t.Fatalf("ValidateAdminCorsOrigins(%q) error %q should not contain ://", bad, err.Error())
		}
	}
}
