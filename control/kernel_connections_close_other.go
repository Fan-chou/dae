//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// AdminCloseKernelConnection returns an honest unsupported warning on non-Linux hosts.
func (c *ControlPlane) AdminCloseKernelConnection(req AdminKernelCloseRequest) (AdminKernelCloseResult, error) {
	if _, _, _, err := parseKernelCloseTuple(req); err != nil {
		return AdminKernelCloseResult{}, err
	}
	return AdminKernelCloseResult{
		Warning: "kernel connection close is only supported on Linux",
	}, nil
}
