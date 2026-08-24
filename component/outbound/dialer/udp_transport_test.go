/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"

	D "github.com/daeuniverse/outbound/dialer"
)

func TestUDPTransportFromProperty(t *testing.T) {
	cases := []struct {
		protocol string
		link     string
		want     bool
	}{
		{protocol: "hysteria2", want: true},
		{protocol: "HY2", want: true},
		{protocol: "tuic", want: true},
		{protocol: "juicity", want: true},
		{link: "hysteria2://pass@203.0.113.1:443#n", want: true},
		{link: "tuic://pass@203.0.113.1:443#n", want: true},
		{protocol: "vmess", want: false},
		{link: "vless://uuid@203.0.113.1:443#n", want: false},
		{want: false},
	}
	for _, tc := range cases {
		p := &Property{Property: D.Property{Protocol: tc.protocol, Link: tc.link}}
		if got := udpTransportFromProperty(p); got != tc.want {
			t.Fatalf("protocol=%q link=%q = %v, want %v", tc.protocol, tc.link, got, tc.want)
		}
	}
	if udpTransportFromProperty(nil) {
		t.Fatal("nil property must not be a UDP transport")
	}
}
