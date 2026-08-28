/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// ErrUnnamedFakeIP is returned when a destination falls inside the FakeIP
// prefix but LookBack finds no name. Fail-closed: never dial the fake address.
var ErrUnnamedFakeIP = errors.New("unnamed FakeIP")

const unnamedFakeIPLogInterval = time.Minute
const unnamedFakeIPLogBuckets = 256

var (
	unnamedFakeIPUDPHits atomic.Uint64
	unnamedFakeIPTCPHits atomic.Uint64
)

type unnamedFakeIPLogSlot struct {
	addr     netip.Addr
	lastUnix int64
	hits     uint64
}

type unnamedFakeIPLogGate struct {
	mu    sync.Mutex
	slots [unnamedFakeIPLogBuckets]unnamedFakeIPLogSlot
}

func unnamedFakeIPLogBucket(addr netip.Addr) uint32 {
	sum := fnv.New32a()
	b := addr.As16()
	_, _ = sum.Write(b[:])
	return sum.Sum32() % unnamedFakeIPLogBuckets
}

func (g *unnamedFakeIPLogGate) allow(addr netip.Addr, now time.Time) (hits uint64, ok bool) {
	if !addr.IsValid() {
		return 0, true
	}
	idx := unnamedFakeIPLogBucket(addr)

	g.mu.Lock()
	defer g.mu.Unlock()
	slot := &g.slots[idx]
	nowUnix := now.UnixNano()
	if slot.lastUnix != 0 && nowUnix-slot.lastUnix < int64(unnamedFakeIPLogInterval) {
		slot.hits++
		return slot.hits, false
	}
	slot.addr = addr
	slot.lastUnix = nowUnix
	slot.hits = 1
	return slot.hits, true
}

var unnamedFakeIPLogs unnamedFakeIPLogGate

func unnamedFakeIPError(addr netip.Addr) error {
	if !addr.IsValid() {
		return ErrUnnamedFakeIP
	}
	return fmt.Errorf("%w %s", ErrUnnamedFakeIP, addr)
}

func (c *ControlPlane) logUnnamedFakeIP(proto string, src, dst netip.AddrPort, err error) {
	if proto == "udp" {
		unnamedFakeIPUDPHits.Add(1)
	} else {
		unnamedFakeIPTCPHits.Add(1)
	}
	hits, ok := unnamedFakeIPLogs.allow(dst.Addr(), time.Now())
	if c == nil || c.log == nil || !ok {
		return
	}
	if !c.log.IsLevelEnabled(logrus.WarnLevel) {
		return
	}
	fields := logrus.Fields{
		"src":       src.String(),
		"dst":       dst.String(),
		"proto":     proto,
		"sport":     src.Port(),
		"dport":     dst.Port(),
		"hit_count": hits,
		"error":     err.Error(),
	}
	if store := c.fakeIPStore(); store != nil {
		active, _ := store.Prefixes()
		if len(active) > 0 && active[0].IsValid() {
			fields["pool_v4"] = active[0].String()
		}
		if len(active) > 1 && active[1].IsValid() {
			fields["pool_v6"] = active[1].String()
		}
	}
	c.log.WithFields(fields).Warn("unnamed FakeIP")
}
