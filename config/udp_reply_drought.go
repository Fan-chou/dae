// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"net/netip"
)

// UDPReplyDroughtPolicy is a generation-local copy. A request_reply contract
// declares that this entire peer scope expects replies to client data; it is
// unsuitable for opaque, state-dependent game traffic such as CS2 SDR.
type UDPReplyDroughtPolicy struct {
	Observe, Enforce, RequestReply bool
	Group                          string
	Client                         netip.Addr
	Peers                          []netip.AddrPort
}

func (g Global) UDPReplyDroughtPolicy() (UDPReplyDroughtPolicy, error) {
	p := UDPReplyDroughtPolicy{Group: g.UDPReplyDroughtGroup}
	if g.UDPReplyDroughtClient != "" {
		client, err := netip.ParseAddr(g.UDPReplyDroughtClient)
		client = client.Unmap()
		if err != nil || client.Zone() != "" || client.IsUnspecified() || client.IsMulticast() {
			return p, fmt.Errorf("udp_reply_drought_client must be a unicast IP address")
		}
		p.Client = client
	}
	switch g.UDPReplyDroughtMode {
	case "", "off":
	case "observe":
		p.Observe = true
	case "enforce":
		p.Observe, p.Enforce = true, true
	default:
		return p, fmt.Errorf("udp_reply_drought_mode must be off, observe or enforce")
	}
	switch g.UDPReplyDroughtContract {
	case "", "unknown":
	case "request_reply":
		p.RequestReply = true
	default:
		return p, fmt.Errorf("udp_reply_drought_contract must be unknown or request_reply")
	}
	if len(g.UDPReplyDroughtPeers) > 256 {
		return p, fmt.Errorf("udp_reply_drought_peers exceeds 256 peers")
	}
	seen := make(map[netip.AddrPort]bool)
	for _, raw := range g.UDPReplyDroughtPeers {
		peer, err := netip.ParseAddrPort(raw)
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		if err != nil || peer.Port() == 0 || peer.Addr().Zone() != "" || peer.Addr().IsUnspecified() || peer.Addr().IsMulticast() {
			return p, fmt.Errorf("udp_reply_drought_peers must contain unicast IP:port peers")
		}
		if peer.Port() == 53 {
			return p, fmt.Errorf("udp_reply_drought_peers must exclude DNS")
		}
		if !seen[peer] {
			p.Peers = append(p.Peers, peer)
			seen[peer] = true
		}
	}
	if p.RequestReply && len(p.Peers) == 0 {
		return p, fmt.Errorf("request_reply requires an explicit udp_reply_drought_peers scope")
	}
	if p.Enforce && (!p.Client.IsValid() || p.Group == "" || !p.RequestReply || len(p.Peers) == 0) {
		return p, fmt.Errorf("udp_reply_drought_mode enforce requires a client IP, exact group, explicit peers and request_reply contract")
	}
	return p, nil
}

func patchUDPReplyDrought(c *Config) error {
	p, err := c.Global.UDPReplyDroughtPolicy()
	if err != nil {
		return err
	}
	if p.Group != "" {
		for _, g := range c.Group {
			if g.Name == p.Group {
				return nil
			}
		}
		return fmt.Errorf("udp_reply_drought_group refers to an unknown group")
	}
	return nil
}
