/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"strings"
)

// AdminKernelCloseRequest identifies a kernel flow 5-tuple to terminate best-effort.
type AdminKernelCloseRequest struct {
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
}

// AdminKernelCloseResult reports honestly which layers deleted the flow.
type AdminKernelCloseResult struct {
	ConntrackDeleted bool   `json:"conntrack_deleted"`
	BpfStateDeleted  bool   `json:"bpf_state_deleted"`
	UserspaceClosed  bool   `json:"userspace_closed"`
	Warning          string `json:"warning,omitempty"`
}

func parseKernelCloseTuple(req AdminKernelCloseRequest) (proto uint8, src netip.AddrPort, dst netip.AddrPort, err error) {
	switch strings.ToLower(strings.TrimSpace(req.Protocol)) {
	case "tcp":
		proto = 6
	case "udp":
		proto = 17
	default:
		return 0, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("protocol must be tcp or udp")
	}

	srcIP, err := netip.ParseAddr(strings.TrimSpace(req.SrcIP))
	if err != nil {
		return 0, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("invalid src_ip")
	}
	dstIP, err := netip.ParseAddr(strings.TrimSpace(req.DstIP))
	if err != nil {
		return 0, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("invalid dst_ip")
	}
	srcIP = srcIP.Unmap()
	dstIP = dstIP.Unmap()
	if srcIP.Is4() != dstIP.Is4() {
		return 0, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("src_ip and dst_ip must share an address family")
	}
	if req.SrcPort == 0 || req.DstPort == 0 {
		return 0, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("src_port and dst_port must be positive")
	}
	return proto, netip.AddrPortFrom(srcIP, req.SrcPort), netip.AddrPortFrom(dstIP, req.DstPort), nil
}
