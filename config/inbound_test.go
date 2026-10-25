/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func parseInboundConfig(t *testing.T, text string) (*Config, error) {
	t.Helper()
	sections, err := config_parser.Parse(text)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, text)
	}
	return New(sections)
}

// inboundConf assembles a config; each argument is the body of its section.
func inboundConf(globalBody, inboundBody, routingBody string) string {
	if routingBody == "" {
		routingBody = "fallback: direct\n"
	}
	return "global {\n" + globalBody + "\n}\n" +
		"inbound {\n" + inboundBody + "\n}\n" +
		"routing {\n" + routingBody + "\n}\n"
}

func TestInboundParse(t *testing.T) {
	t.Parallel()
	conf, err := parseInboundConfig(t, inboundConf("", `
s1 {
  listen: '127.0.0.1:1080'
}
lan {
  listen: '192.168.1.1:1081'
  username: alice
  password: 's3cret'
  udp: false
  udp_advertise: '203.0.113.7'
}
`, `
inbound(s1) -> direct
inbound(lan) && domain(geosite:cn) -> direct
fallback: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Inbound) != 2 {
		t.Fatalf("got %d inbounds, want 2", len(conf.Inbound))
	}
	s1, lan := conf.Inbound[0], conf.Inbound[1]
	if s1.Name != "s1" || s1.Protocol != "socks5" || !s1.UDP || s1.HasAuth() {
		t.Fatalf("s1 = %+v", s1)
	}
	if lan.Name != "lan" || lan.UDP || !lan.HasAuth() || lan.Username != "alice" || lan.Password != "s3cret" || lan.UDPAdvertise != "203.0.113.7" {
		t.Fatalf("lan = %+v", lan)
	}
	ap, err := lan.ListenAddrPort()
	if err != nil || ap.String() != "192.168.1.1:1081" {
		t.Fatalf("ListenAddrPort = %v, %v", ap, err)
	}
}

func TestInboundOptional(t *testing.T) {
	t.Parallel()
	conf, err := parseInboundConfig(t, "global {\n}\nrouting {\n  fallback: direct\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Inbound) != 0 {
		t.Fatalf("got %d inbounds without an inbound section", len(conf.Inbound))
	}
}

func TestInboundMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	conf, err := parseInboundConfig(t, inboundConf("", `
s1 {
  listen: '[::1]:1080'
  username: bob
  password: 'p@ss word'
}
`, `
inbound(s1) -> direct
fallback: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	again, err := parseInboundConfig(t, string(b))
	if err != nil {
		t.Fatalf("re-parse marshalled config: %v\n%s", err, b)
	}
	if len(again.Inbound) != 1 || again.Inbound[0] != conf.Inbound[0] {
		t.Fatalf("round trip changed inbound: %+v vs %+v", again.Inbound, conf.Inbound)
	}
}

func TestInboundRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		global  string
		inbound string
		routing string
		want    string
	}{
		{"no listen", "", "s1 {\n  udp: true\n}", "", "listen"},
		{"hostname", "", "s1 {\n  listen: 'example.com:1080'\n}", "", "not an IP"},
		{"zero port", "", "s1 {\n  listen: '127.0.0.1:0'\n}", "", "port"},
		{"open proxy unspecified", "", "s1 {\n  listen: '0.0.0.0:1080'\n}", "", "open proxy"},
		{"open proxy public", "", "s1 {\n  listen: '8.8.8.8:1080'\n}", "", "open proxy"},
		{"user without password", "", "s1 {\n  listen: '127.0.0.1:1080'\n  username: a\n}", "", "together"},
		{"unsupported protocol", "", "s1 {\n  listen: '127.0.0.1:1080'\n  protocol: http\n}", "", "protocol"},
		{"duplicate listen", "", "a {\n  listen: '127.0.0.1:1080'\n}\nb {\n  listen: '127.0.0.1:1080'\n}", "", "conflicts"},
		{"wildcard conflict", "", "a {\n  listen: '0.0.0.0:1080'\n  username: u\n  password: p\n}\nb {\n  listen: '127.0.0.1:1080'\n}", "", "conflicts"},
		{"open proxy ipv6 unspecified", "", "s1 {\n  listen: '[::]:1080'\n}", "", "open proxy"},
		{"open proxy ipv6 public", "", "s1 {\n  listen: '[2001:db8::1]:1080'\n}", "", "open proxy"},
		{"open proxy mapped public", "", "s1 {\n  listen: '[::ffff:8.8.8.8]:1080'\n}", "", "open proxy"},
		{"ipv6 dual-stack wildcard covers v4", "", "a {\n  listen: '[::]:1080'\n  username: u\n  password: p\n}\nb {\n  listen: '127.0.0.1:1080'\n}", "", "conflicts"},
		{"ipv6 wildcard covers v6", "", "a {\n  listen: '[::]:1080'\n  username: u\n  password: p\n}\nb {\n  listen: '[::1]:1080'\n}", "", "conflicts"},
		{"v4 wildcard vs v6 wildcard", "", "a {\n  listen: '0.0.0.0:1080'\n  username: u\n  password: p\n}\nb {\n  listen: '[::]:1080'\n  username: u\n  password: p\n}", "", "conflicts"},
		{"mapped duplicate", "", "a {\n  listen: '127.0.0.1:1080'\n}\nb {\n  listen: '[::ffff:127.0.0.1]:1080'\n}", "", "conflicts"},
		{"bad udp_advertise v6", "", "a {\n  listen: '[::1]:1080'\n  udp_advertise: 'fe80::zz'\n}", "", "udp_advertise"},
		{"tproxy port", "tproxy_port: 1080", "a {\n  listen: '127.0.0.1:1080'\n}", "", "tproxy_port"},
		{"undefined reference", "", "a {\n  listen: '127.0.0.1:1080'\n}", "inbound(b) -> direct\nfallback: direct", "not defined"},
		{"reference without section", "", "", "inbound(a) -> direct\nfallback: direct", "not defined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseInboundConfig(t, inboundConf(tc.global, tc.inbound, tc.routing))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestInboundAllowsPublicBindWithAuth(t *testing.T) {
	t.Parallel()
	_, err := parseInboundConfig(t, inboundConf("", `
wan {
  listen: '0.0.0.0:1080'
  username: u
  password: p
}
`, `
inbound(wan) -> direct
fallback: direct
`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateInboundName(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"s1", "lan", "my-proxy_2", "A", strings.Repeat("a", 32)} {
		if err := ValidateInboundName(ok); err != nil {
			t.Errorf("ValidateInboundName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a.b", "-a", "a)", "a,b", "a:b", strings.Repeat("a", 33)} {
		if err := ValidateInboundName(bad); err == nil {
			t.Errorf("ValidateInboundName(%q) accepted", bad)
		}
	}
}

func TestInboundIDStable(t *testing.T) {
	t.Parallel()
	if consts.InboundID("s1") != consts.InboundID("s1") {
		t.Fatal("InboundID is not deterministic")
	}
	if consts.InboundID("s1") == consts.InboundID("s2") {
		t.Fatal("distinct names share an ID")
	}
	if consts.InboundID("") == 0 || consts.InboundID("s1") == 0 {
		t.Fatal("InboundID must never be 0")
	}
}

func TestInboundSniffOption(t *testing.T) {
	t.Parallel()
	conf, err := parseInboundConfig(t, inboundConf("", `
a { listen: '127.0.0.1:1080' }
b {
  listen: '127.0.0.1:1081'
  sniff: off
}
`, ""))
	if err != nil {
		t.Fatal(err)
	}
	if conf.Inbound[0].Sniff != "auto" || !conf.Inbound[0].SniffEnabled() {
		t.Fatalf("default sniff = %q, want auto", conf.Inbound[0].Sniff)
	}
	if conf.Inbound[1].SniffEnabled() {
		t.Fatal("sniff: off must disable sniffing")
	}
	if _, err := parseInboundConfig(t, inboundConf("", "a { listen: '127.0.0.1:1080'\n sniff: always }", "")); err == nil || !strings.Contains(err.Error(), "sniff") {
		t.Fatalf("sniff: always must be rejected, got %v", err)
	}
}

func TestInboundIPv6Accepted(t *testing.T) {
	t.Parallel()
	// 0.0.0.0 and a specific IPv6 address are different sockets: no conflict.
	conf, err := parseInboundConfig(t, inboundConf("", `
v4wild {
  listen: '0.0.0.0:1090'
  username: u
  password: p
}
v6lo { listen: '[::1]:1090' }
ula { listen: '[fd00::1]:1091' }
ll {
  listen: '[fe80::1%eth0]:1092'
  udp_advertise: '2001:db8::7'
}
`, ""))
	if err != nil {
		t.Fatalf("IPv6 listeners must be accepted: %v", err)
	}
	if len(conf.Inbound) != 4 {
		t.Fatalf("got %d inbounds, want 4", len(conf.Inbound))
	}
	ap, err := conf.Inbound[3].ListenAddrPort()
	if err != nil || ap.Addr().Zone() != "eth0" || ap.Port() != 1092 {
		t.Fatalf("link-local listen parsed as %v (%v)", ap, err)
	}
}

func TestInboundResolveOption(t *testing.T) {
	t.Parallel()
	conf, err := parseInboundConfig(t, inboundConf("", `
a { listen: '127.0.0.1:1080' }
b {
  listen: '127.0.0.1:1081'
  resolve: deferred
}
`, ""))
	if err != nil {
		t.Fatal(err)
	}
	if conf.Inbound[0].Resolve != "local" || conf.Inbound[0].DeferResolve() {
		t.Fatalf("default resolve = %q, want local", conf.Inbound[0].Resolve)
	}
	if !conf.Inbound[1].DeferResolve() {
		t.Fatal("resolve: deferred must enable deferred resolution")
	}
	if _, err := parseInboundConfig(t, inboundConf("", "a { listen: '127.0.0.1:1080'\n resolve: lazy }", "")); err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("resolve: lazy must be rejected, got %v", err)
	}
}
