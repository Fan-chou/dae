/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"

	"github.com/cilium/ebpf"
)

func (c *ControlPlane) syncFakeIPKernelPrefixes() {
	if c == nil || c.core == nil {
		return
	}
	store := c.fakeIPStore()
	if store == nil {
		return
	}
	bpf := c.core.bpf.Load()
	if bpf == nil || bpf.FakeipLpmMap == nil {
		return
	}
	active, retired := store.Prefixes()
	seen := map[netip.Prefix]struct{}{}
	var prefixes []netip.Prefix
	for _, p := range append(append([]netip.Prefix{}, active...), retired...) {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		prefixes = append(prefixes, p)
	}
	iter := bpf.FakeipLpmMap.Iterate()
	var key _bpfLpmKey
	var value uint32
	for iter.Next(&key, &value) {
		_ = bpf.FakeipLpmMap.Delete(key)
	}
	one := uint32(1)
	for _, prefix := range prefixes {
		k := cidrToBpfLpmKey(prefix)
		if err := bpf.FakeipLpmMap.Update(k, one, ebpf.UpdateAny); err != nil && c.log != nil {
			c.log.WithError(err).Warn("failed to program fakeip LPM prefix")
		}
	}
}
