//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// AdminCloseKernelConnection attempts best-effort termination of a 5-tuple across
// userspace flows (including Sockmap offload), Linux conntrack, and eBPF conn_state_map.
func (c *ControlPlane) AdminCloseKernelConnection(req AdminKernelCloseRequest) (AdminKernelCloseResult, error) {
	proto, src, dst, err := parseKernelCloseTuple(req)
	if err != nil {
		return AdminKernelCloseResult{}, err
	}

	var res AdminKernelCloseResult
	var warnings []string

	if c != nil {
		if manager, _ := c.controlPlaneSessionManager(); manager != nil {
			if manager.CloseConnectionsByTuple(proto, src, dst) > 0 {
				res.UserspaceClosed = true
			}
		}
	}

	family := netlink.InetFamily(unix.AF_INET)
	if src.Addr().Is6() {
		family = netlink.InetFamily(unix.AF_INET6)
	}
	filter := &netlink.ConntrackFilter{}
	if err := filter.AddProtocol(proto); err != nil {
		warnings = append(warnings, fmt.Sprintf("conntrack protocol filter: %v", err))
	} else if err := filter.AddIP(netlink.ConntrackOrigSrcIP, src.Addr().AsSlice()); err != nil {
		warnings = append(warnings, fmt.Sprintf("conntrack src filter: %v", err))
	} else if err := filter.AddIP(netlink.ConntrackOrigDstIP, dst.Addr().AsSlice()); err != nil {
		warnings = append(warnings, fmt.Sprintf("conntrack dst filter: %v", err))
	} else if err := filter.AddPort(netlink.ConntrackOrigSrcPort, src.Port()); err != nil {
		warnings = append(warnings, fmt.Sprintf("conntrack sport filter: %v", err))
	} else if err := filter.AddPort(netlink.ConntrackOrigDstPort, dst.Port()); err != nil {
		warnings = append(warnings, fmt.Sprintf("conntrack dport filter: %v", err))
	} else {
		deleted, ctErr := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, family, filter)
		if ctErr != nil {
			warnings = append(warnings, fmt.Sprintf("conntrack delete: %v", ctErr))
		} else if deleted > 0 {
			res.ConntrackDeleted = true
		}
	}

	if c != nil && c.core != nil {
		if objs := c.core.bpf.Load(); objs != nil && objs.ConnStateMap != nil {
			for _, key := range [2]bpfTuplesKey{
				bpfTuplesKeyFromAddrPorts(src, dst, proto),
				bpfTuplesKeyFromAddrPorts(dst, src, proto),
			} {
				delErr := objs.ConnStateMap.Delete(&key)
				if delErr == nil {
					res.BpfStateDeleted = true
				} else if !errors.Is(delErr, ebpf.ErrKeyNotExist) {
					warnings = append(warnings, fmt.Sprintf("bpf conn_state_map delete: %v", delErr))
				}
			}
		}
	}

	if !res.ConntrackDeleted && !res.BpfStateDeleted && !res.UserspaceClosed && len(warnings) == 0 {
		warnings = append(warnings, "no matching conntrack or bpf state entry found; existing bypass sockets may stay open until peer timeout")
	} else if res.ConntrackDeleted || res.BpfStateDeleted {
		if len(warnings) == 0 && !res.UserspaceClosed {
			warnings = append(warnings, "direct bypass kernel sockets do not receive local FIN/RST from conntrack deletion alone")
		}
	}
	res.Warning = strings.Join(warnings, "; ")
	return res, nil
}
