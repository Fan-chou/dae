/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"net/url"
	"strings"
)

// UdpForwardMode is how this leaf's final proxy chain carries application UDP.
// Meet (worst hop) over a chain: none < reliable_ordered < datagram.
type UdpForwardMode uint8

const (
	// UdpForwardNone cannot carry UDP (HTTP proxy, SOCKS4, builtin block,
	// Shadowsocks+shadow-tls).
	UdpForwardNone UdpForwardMode = iota
	// UdpForwardReliableOrdered multiplexes UDP on a reliable ordered stream
	// (AnyTLS UoT, VLESS/VMess/Trojan, WS/gRPC, TUIC stream relay).
	UdpForwardReliableOrdered
	// UdpForwardDatagram is hop-by-hop unreliable datagram UDP (Hy2/TUIC
	// native/Juicity/SS-UDP including v2ray-plugin passthrough/SOCKS5/direct).
	UdpForwardDatagram
)

func (m UdpForwardMode) String() string {
	switch m {
	case UdpForwardDatagram:
		return "datagram_unreliable"
	case UdpForwardReliableOrdered:
		return "reliable_ordered"
	default:
		return "udp_unsupported"
	}
}

func (m UdpForwardMode) AllowsUnreliableDatagram() bool {
	return m == UdpForwardDatagram
}

func meetUdpForwardMode(a, b UdpForwardMode) UdpForwardMode {
	if a < b {
		return a
	}
	return b
}

// UdpForwardMode reports the final-chain UDP capability of this dialer.
func (d *Dialer) UdpForwardMode() UdpForwardMode {
	if d == nil {
		return UdpForwardNone
	}
	return d.udpForwardMode
}

func udpForwardModeFromProperty(p *Property) UdpForwardMode {
	if p == nil {
		return UdpForwardNone
	}
	protoHops := splitChainHops(p.Protocol)
	linkHops := splitChainHops(p.Link)
	if len(protoHops) == 0 && len(linkHops) == 0 {
		return udpForwardModeFromProtocolToken("", p.Name)
	}
	n := len(protoHops)
	if len(linkHops) > n {
		n = len(linkHops)
	}
	mode := UdpForwardDatagram
	for i := 0; i < n; i++ {
		tok := ""
		if i < len(protoHops) {
			tok = protoHops[i]
		}
		hopMode := udpForwardModeFromProtocolToken(tok, p.Name)
		if tok == "" && i < len(linkHops) {
			// Empty protocol token would otherwise become udp_unsupported
			// before the share-link scheme is considered.
			hopMode = UdpForwardDatagram
		}
		if i < len(linkHops) {
			hopMode = meetUdpForwardMode(hopMode, udpForwardModeFromLinkHop(linkHops[i], tok))
		}
		mode = meetUdpForwardMode(mode, hopMode)
	}
	return mode
}

func splitChainHops(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "->")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func udpForwardModeFromProtocolToken(token, name string) UdpForwardMode {
	tok := strings.ToLower(strings.TrimSpace(token))
	if tok == "" {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "direct":
			return UdpForwardDatagram
		case "block":
			return UdpForwardNone
		default:
			return UdpForwardNone
		}
	}
	switch tok {
	case "direct":
		return UdpForwardDatagram
	case "block":
		return UdpForwardNone
	case "hysteria", "hysteria1", "hysteria2", "hy", "hy2",
		"tuic", "tuic5", "juicity",
		"ss", "shadowsocks", "shadowsocksr", "ssr",
		"socks", "socks5":
		return UdpForwardDatagram
	case "http", "https", "naive", "naive+quic",
		"socks4", "socks4a":
		return UdpForwardNone
	case "shadow-tls", "shadowtls":
		return UdpForwardNone
	case "anytls",
		"vmess", "vless",
		"trojan", "trojan-go",
		"anytls-go":
		return UdpForwardReliableOrdered
	default:
		// Unknown hop: do not claim datagram UDP.
		return UdpForwardReliableOrdered
	}
}

func udpForwardModeFromLinkHop(link, protocolToken string) UdpForwardMode {
	link = strings.TrimSpace(link)
	if link == "" {
		return UdpForwardDatagram
	}
	lower := strings.ToLower(link)
	// outbound TUIC currently forces NATIVE datagram relay even when the
	// link sets udp_relay_mode=quic. Classify by actual forwarding, not the
	// unused flag, so block_quic does not reject datagram TUIC.
	u, err := url.Parse(link)
	if err != nil || u == nil {
		return udpForwardModeFromLooseLink(lower, protocolToken)
	}
	scheme := strings.ToLower(u.Scheme)
	ssFamily := isShadowsocksFamily(protocolToken, scheme)
	if ssFamily {
		if isShadowTLSPlugin(u.Query().Get("plugin")) ||
			strings.Contains(lower, "plugin=shadow-tls") ||
			strings.Contains(lower, "plugin=shadowtls") {
			// outbound shadow-tls DialContext rejects UDP; SS UDP then fails.
			return UdpForwardNone
		}
		// v2ray-plugin/xray-plugin/simple-obfs set passthroughUdp (or dial UDP
		// on the next hop). Application UDP is still native SS datagram.
		return UdpForwardDatagram
	}
	q := u.Query()
	if streamTransportValue(q.Get("type")) ||
		streamTransportValue(q.Get("network")) ||
		streamPluginValue(q.Get("plugin")) {
		return UdpForwardReliableOrdered
	}
	if mode := udpForwardModeFromLinkScheme(scheme); mode != UdpForwardDatagram {
		return mode
	}
	return udpForwardModeFromLooseLink(lower, protocolToken)
}

func udpForwardModeFromLinkScheme(scheme string) UdpForwardMode {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "ss", "ssr", "shadowsocks", "shadowsocksr",
		"hysteria", "hysteria1", "hysteria2", "hy", "hy2",
		"tuic", "tuic5", "juicity",
		"socks", "socks5", "direct":
		return UdpForwardDatagram
	case "http", "https", "naive", "naive+https", "socks4", "socks4a":
		return UdpForwardNone
	case "shadow-tls", "shadowtls":
		return UdpForwardNone
	case "vless", "vmess", "trojan", "trojan-go", "anytls", "anytls-go":
		return UdpForwardReliableOrdered
	default:
		return UdpForwardDatagram
	}
}

func udpForwardModeFromLooseLink(lowerLink, protocolToken string) UdpForwardMode {
	if isShadowsocksFamily(protocolToken, "") {
		if strings.Contains(lowerLink, "plugin=shadow-tls") ||
			strings.Contains(lowerLink, "plugin=shadowtls") ||
			strings.Contains(lowerLink, "shadow-tls") {
			return UdpForwardNone
		}
		return UdpForwardDatagram
	}
	if strings.Contains(lowerLink, "type=ws") ||
		strings.Contains(lowerLink, "type=grpc") ||
		strings.Contains(lowerLink, "type=httpupgrade") ||
		strings.Contains(lowerLink, "type=h2") ||
		strings.Contains(lowerLink, "type=meek") ||
		strings.Contains(lowerLink, "network=ws") ||
		strings.Contains(lowerLink, "network=grpc") ||
		strings.Contains(lowerLink, "v2ray-plugin") ||
		strings.Contains(lowerLink, "xray-plugin") {
		return UdpForwardReliableOrdered
	}
	return UdpForwardDatagram
}

func isShadowsocksFamily(protocolToken, scheme string) bool {
	for _, v := range []string{protocolToken, scheme} {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "ss", "ssr", "shadowsocks", "shadowsocksr":
			return true
		}
	}
	return false
}

func sip003PluginName(plugin string) string {
	plugin = strings.ToLower(strings.TrimSpace(plugin))
	if i := strings.IndexByte(plugin, ';'); i >= 0 {
		plugin = plugin[:i]
	}
	return strings.TrimSpace(plugin)
}

func isShadowTLSPlugin(plugin string) bool {
	switch sip003PluginName(plugin) {
	case "shadow-tls", "shadowtls":
		return true
	default:
		return false
	}
}

func streamTransportValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ws", "websocket", "grpc", "http", "h2", "httpupgrade", "http2",
		"meek", "mkcp", "kcp", "xhttp", "splithttp":
		return true
	default:
		return false
	}
}

func streamPluginValue(v string) bool {
	name := sip003PluginName(v)
	return strings.Contains(name, "v2ray-plugin") || strings.Contains(name, "xray-plugin")
}
