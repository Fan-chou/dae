/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"io"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestUdpForwardModeFromProperty(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		protocol string
		link     string
		want     UdpForwardMode
	}{
		{name: "direct", want: UdpForwardDatagram},
		{name: "block", want: UdpForwardNone},
		{protocol: "hysteria2", want: UdpForwardDatagram},
		{protocol: "tuic", want: UdpForwardDatagram},
		{protocol: "juicity", want: UdpForwardDatagram},
		{protocol: "shadowsocks", want: UdpForwardDatagram},
		{protocol: "socks5", want: UdpForwardDatagram},
		{protocol: "anytls", want: UdpForwardReliableOrdered},
		{protocol: "vless", want: UdpForwardReliableOrdered},
		{protocol: "vmess", want: UdpForwardReliableOrdered},
		{protocol: "trojan", want: UdpForwardReliableOrdered},
		{protocol: "http", want: UdpForwardNone},
		{protocol: "socks4", want: UdpForwardNone},
		{protocol: "hysteria2->vmess", want: UdpForwardReliableOrdered},
		{protocol: "tuic->shadowsocks", want: UdpForwardDatagram},
		{protocol: "tuic", link: "tuic://pass@203.0.113.1:443?udp_relay_mode=quic#n", want: UdpForwardDatagram},
		{protocol: "vless", link: "vless://uuid@203.0.113.1:443?type=ws&security=tls#n", want: UdpForwardReliableOrdered},
		{protocol: "shadowsocks", link: "ss://YTpiQDIwMy4wLjExMy4xOjQzOD8jcGx1Z2luPXYycmF5LXBsdWdpbg", want: UdpForwardDatagram},
		{protocol: "shadowsocks", link: "ss://pass@203.0.113.1:8388?plugin=v2ray-plugin;mode=websocket#n", want: UdpForwardDatagram},
		{protocol: "shadowsocks", link: "ss://pass@203.0.113.1:8388?plugin=xray-plugin;mode=websocket#n", want: UdpForwardDatagram},
		{protocol: "shadowsocks", link: "ss://pass@203.0.113.1:8388?plugin=obfs-local;obfs=http#n", want: UdpForwardDatagram},
		{protocol: "shadowsocks", link: "ss://pass@203.0.113.1:8388?plugin=shadow-tls;password=x;host=cdn.example.com#n", want: UdpForwardNone},
		{protocol: "shadowsocks", link: "ss://pass@203.0.113.1:8388?plugin=shadowtls;password=x#n", want: UdpForwardNone},
		{link: "hysteria2://pass@203.0.113.1:443#n", protocol: "hysteria2", want: UdpForwardDatagram},
		{protocol: "hysteria2->shadowsocks", link: "hysteria2://pass@203.0.113.1:443#n -> ss://pass@203.0.113.2:8388?plugin=v2ray-plugin;mode=websocket#n", want: UdpForwardDatagram},
		{protocol: "hysteria2->shadowsocks", link: "hysteria2://pass@203.0.113.1:443#n -> ss://pass@203.0.113.2:8388?plugin=shadow-tls;password=x#n", want: UdpForwardNone},
		{protocol: "unknown-proto", want: UdpForwardReliableOrdered},
	}
	for _, tc := range cases {
		p := &Property{Property: D.Property{Name: tc.name, Protocol: tc.protocol, Link: tc.link}}
		if got := udpForwardModeFromProperty(p); got != tc.want {
			t.Fatalf("name=%q protocol=%q link=%q = %v, want %v", tc.name, tc.protocol, tc.link, got, tc.want)
		}
	}
	if udpForwardModeFromProperty(nil) != UdpForwardNone {
		t.Fatal("nil property must be udp_unsupported")
	}
}

func TestUdpForwardModeCachedOnDialer(t *testing.T) {
	t.Parallel()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	d := NewDialer(
		nil,
		&GlobalOption{Log: logger, CheckInterval: time.Second},
		InstanceOption{DisableCheck: true},
		&Property{Property: D.Property{Name: "n", Protocol: "anytls"}},
	)
	if got := d.UdpForwardMode(); got != UdpForwardReliableOrdered {
		t.Fatalf("cached mode = %v, want reliable_ordered", got)
	}
	d.property.Protocol = "hysteria2"
	if got := d.UdpForwardMode(); got != UdpForwardReliableOrdered {
		t.Fatalf("mutating property must not change cached UDP capability, got %v", got)
	}
}

func TestUdpForwardModeString(t *testing.T) {
	t.Parallel()
	if UdpForwardDatagram.String() != "datagram_unreliable" {
		t.Fatal(UdpForwardDatagram.String())
	}
	if UdpForwardReliableOrdered.String() != "reliable_ordered" {
		t.Fatal(UdpForwardReliableOrdered.String())
	}
	if UdpForwardNone.String() != "udp_unsupported" {
		t.Fatal(UdpForwardNone.String())
	}
}
