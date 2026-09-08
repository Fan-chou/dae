/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

func (c *ControlPlane) syncFakeIPKernelPrefixes() error {
	if c == nil || c.core == nil {
		return nil
	}
	store := c.fakeIPStore()
	bpf := c.core.bpf.Load()
	if bpf == nil || bpf.FakeipLpmMap == nil {
		return nil
	}
	var active, retired []netip.Prefix
	if store != nil {
		active, retired = store.Prefixes()
	}
	if c.udpCrossFamily != nil {
		a, r := c.udpCrossFamily.store.Prefixes()
		active = append(active, a...)
		retired = append(retired, r...)
	}
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
	// Install before removing obsolete prefixes: clearing the shared map would
	// briefly send synthetic destinations down the ordinary WAN route on reload.
	wanted := make(map[_bpfLpmKey]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		key := cidrToBpfLpmKey(prefix)
		wanted[key] = struct{}{}
		if err := bpf.FakeipLpmMap.Update(key, uint32(1), ebpf.UpdateAny); err != nil {
			if c.udpCrossFamily != nil {
				return fmt.Errorf("program synthetic UDP prefix %s: %w", prefix, err)
			}
			if c.log != nil {
				c.log.WithError(err).Warn("failed to program fakeip LPM prefix")
			}
			return nil
		}
	}
	iter := bpf.FakeipLpmMap.Iterate()
	var key _bpfLpmKey
	var value uint32
	var obsolete []_bpfLpmKey
	for iter.Next(&key, &value) {
		if _, ok := wanted[key]; !ok {
			obsolete = append(obsolete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range obsolete {
		if err := bpf.FakeipLpmMap.Delete(key); err != nil {
			return err
		}
	}
	return nil
}
