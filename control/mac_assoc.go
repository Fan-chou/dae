/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"

	"github.com/daeuniverse/dae/pkg/trie"
)

const macAssocIPSlots = 8

type macAssocLookup func(mac [6]byte) []string

func newMacAssocLookup(bpf *bpfObjects) macAssocLookup {
	if bpf == nil || bpf.MacAssocMap == nil {
		return nil
	}
	m := bpf.MacAssocMap
	return func(mac [6]byte) []string {
		if (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0 {
			return nil
		}
		key := bpfMacAssocKey{Mac: mac}
		var entry bpfMacAssocEntry
		if err := m.Lookup(&key, &entry); err != nil {
			return nil
		}
		bins := make([]string, 0, macAssocIPSlots)
		for i := range entry.Ips {
			ip := entry.Ips[i].Ip
			if ip16Unspecified(ip) {
				continue
			}
			bins = append(bins, trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(ip), 128)))
		}
		return bins
	}
}

func ip16Unspecified(ip [16]uint8) bool {
	for _, b := range ip {
		if b != 0 {
			return false
		}
	}
	return true
}

func mac6FromRoutedMac(mac [16]uint8) [6]byte {
	var out [6]byte
	copy(out[:], mac[10:])
	return out
}
