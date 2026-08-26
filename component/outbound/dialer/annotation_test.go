/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestParseResolveDNS(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		want    netip.AddrPort
		wantErr string
	}{
		{name: "bare ipv4", val: "8.8.8.8", want: netip.MustParseAddrPort("8.8.8.8:53")},
		{name: "ipv4 port", val: "8.8.8.8:5353", want: netip.MustParseAddrPort("8.8.8.8:5353")},
		{name: "udp scheme", val: "udp://1.1.1.1:53", want: netip.MustParseAddrPort("1.1.1.1:53")},
		{name: "quoted ipv6", val: "'2001:4860:4860::8888'", want: netip.MustParseAddrPort("[2001:4860:4860::8888]:53")},
		{name: "hostname", val: "dns.google", wantErr: "must be an IP address"},
		{name: "unspecified", val: "0.0.0.0", wantErr: "invalid resolve_dns"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseResolveDNS(tc.val)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExtractLinkResolveDNS(t *testing.T) {
	stripped, dns, err := extractLinkResolveDNS("hysteria2://pass@203.0.113.1:443?sni=example.com&resolve_dns=8.8.8.8#US")
	if err != nil {
		t.Fatal(err)
	}
	if dns != netip.MustParseAddrPort("8.8.8.8:53") {
		t.Fatalf("dns = %v", dns)
	}
	if strings.Contains(stripped, "resolve_dns") {
		t.Fatalf("stripped still has resolve_dns: %s", stripped)
	}
	if !strings.Contains(stripped, "sni=example.com") {
		t.Fatalf("stripped lost sni: %s", stripped)
	}

	preserved, dns, err := extractLinkResolveDNS("hysteria2://pass@203.0.113.1:443?obfs-password=a+b&pinSHA256=aa:bb:cc&resolve_dns=8.8.8.8#US")
	if err != nil {
		t.Fatal(err)
	}
	if dns != netip.MustParseAddrPort("8.8.8.8:53") {
		t.Fatalf("dns = %v", dns)
	}
	if strings.Contains(preserved, "resolve_dns") {
		t.Fatalf("stripped still has resolve_dns: %s", preserved)
	}
	if !strings.Contains(preserved, "obfs-password=a+b") {
		t.Fatalf("stripped re-encoded plus: %s", preserved)
	}
	if !strings.Contains(preserved, "pinSHA256=aa:bb:cc") {
		t.Fatalf("stripped re-encoded pinSHA256: %s", preserved)
	}

	encoded, dns, err := extractLinkResolveDNS("hysteria2://pass@203.0.113.1:443?sni=example.com&%72esolve_dns=8.8.8.8&resolve%5Fdns=1.1.1.1#US")
	if err != nil {
		t.Fatal(err)
	}
	if dns != netip.MustParseAddrPort("8.8.8.8:53") {
		t.Fatalf("encoded dns = %v", dns)
	}
	parsed, err := url.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("resolve_dns") != "" {
		t.Fatalf("encoded resolve_dns still present: %s", encoded)
	}
	if !strings.Contains(encoded, "sni=example.com") {
		t.Fatalf("encoded strip lost sni: %s", encoded)
	}

	plain, dns, err := extractLinkResolveDNS("hysteria2://pass@203.0.113.1:443?sni=example.com#US")
	if err != nil {
		t.Fatal(err)
	}
	if dns.IsValid() {
		t.Fatalf("unexpected dns %v", dns)
	}
	if plain != "hysteria2://pass@203.0.113.1:443?sni=example.com#US" {
		t.Fatalf("plain link rewritten: %s", plain)
	}

	_, _, err = extractLinkResolveDNS("socks5://127.0.0.1:1080?resolve_dns=dns.google")
	if err == nil {
		t.Fatal("expected invalid resolve_dns on node link")
	}

	named := "US_Dmit_LAX_Hysteria:hysteria2://pass@[2605:52c0::1]:443?sni=example.com&resolve_dns=127.0.0.2%3A53"
	stripped, dns, err = extractLinkResolveDNS(named)
	if err != nil {
		t.Fatal(err)
	}
	if dns != netip.MustParseAddrPort("127.0.0.2:53") {
		t.Fatalf("named dns = %v", dns)
	}
	if !strings.HasPrefix(stripped, "US_Dmit_LAX_Hysteria:hysteria2://") {
		t.Fatalf("named stripped lost tag: %s", stripped)
	}
	if strings.Contains(stripped, "resolve_dns") {
		t.Fatalf("named stripped still has resolve_dns: %s", stripped)
	}
	if !strings.Contains(stripped, "sni=example.com") {
		t.Fatalf("named stripped lost sni: %s", stripped)
	}
}

func TestNewAnnotationRejectsResolveDNS(t *testing.T) {
	_, err := NewAnnotation([]*config_parser.Param{{Key: "resolve_dns", Val: "8.8.8.8"}})
	if err == nil {
		t.Fatal("resolve_dns is a node link query, not a group filter annotation")
	}
}
