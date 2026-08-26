/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestHysteria2ClonePreservesSalamanderObfs(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     30 * time.Second,
	}
	src, err := dialer.NewFromLink(option, dialer.InstanceOption{DisableCheck: true},
		"hysteria2://user:pass@127.0.0.1:443?obfs=salamander&obfs-password=secret1#hy2-a", "")
	if err != nil {
		t.Fatalf("NewFromLink() error = %v", err)
	}
	defer src.Close()

	link := src.Property().Link
	if !strings.Contains(link, "obfs=salamander") || !strings.Contains(link, "obfs-password=secret1") {
		t.Fatalf("Property.Link = %q, want salamander obfs fields", link)
	}

	clone := src.Clone()
	defer clone.Close()
	clonedLink := clone.Property().Link
	if !strings.Contains(clonedLink, "obfs=salamander") || !strings.Contains(clonedLink, "obfs-password=secret1") {
		t.Fatalf("cloned Property.Link = %q, want salamander obfs fields", clonedLink)
	}

	other, err := dialer.NewFromLink(option, dialer.InstanceOption{DisableCheck: true},
		"hysteria2://user:pass@127.0.0.1:443?obfs=salamander&obfs-password=secret2#hy2-b", "")
	if err != nil {
		t.Fatalf("NewFromLink() other error = %v", err)
	}
	defer other.Close()
	if healthDialerIdentity(src) == healthDialerIdentity(other) {
		t.Fatalf("nodes that differ only in obfs-password share cache identity %q", healthDialerIdentity(src))
	}
}

func TestNewFromLinkResolveDNSAndClone(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     30 * time.Second,
	}
	src, err := dialer.NewFromLink(option, dialer.InstanceOption{DisableCheck: true},
		"hysteria2://pass@127.0.0.1:443?sni=example.com&resolve_dns=8.8.8.8#n", "")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	want := netip.MustParseAddrPort("8.8.8.8:53")
	if src.ResolveDNS() != want {
		t.Fatalf("ResolveDNS = %v, want %v", src.ResolveDNS(), want)
	}
	if src.Property() != nil && strings.Contains(src.Property().Link, "resolve_dns") {
		t.Fatalf("protocol link still has resolve_dns: %s", src.Property().Link)
	}
	clone := src.Clone()
	defer clone.Close()
	if clone.ResolveDNS() != want {
		t.Fatalf("clone ResolveDNS = %v, want %v", clone.ResolveDNS(), want)
	}
}

func TestNewFromLinkNamedNodeResolveDNS(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     30 * time.Second,
	}
	src, err := dialer.NewFromLink(option, dialer.InstanceOption{DisableCheck: true},
		"US_Dmit_LAX_Hysteria:hysteria2://pass@127.0.0.1:443?sni=example.com&resolve_dns=127.0.0.2%3A53", "")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	want := netip.MustParseAddrPort("127.0.0.2:53")
	if src.ResolveDNS() != want {
		t.Fatalf("ResolveDNS = %v, want %v (named node must not drop query)", src.ResolveDNS(), want)
	}
	if src.Property() == nil || src.Property().Name != "US_Dmit_LAX_Hysteria" {
		t.Fatalf("name = %v", src.Property())
	}
	if src.Property() != nil && strings.Contains(src.Property().Link, "resolve_dns") {
		t.Fatalf("protocol link still has resolve_dns: %s", src.Property().Link)
	}
}
