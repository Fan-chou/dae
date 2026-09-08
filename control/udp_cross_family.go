// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
)

// UDPCrossFamilyStore gives foreign-family peers stable, reversible identities.
// The store is process-owned, just like the DNS FakeIP store; endpoints retain it
// across control-plane generations. It never rewrites application payloads.
type UDPCrossFamilyStore struct {
	store *FakeIPStore
	// Entries never change identity; established flows avoid string parsing and
	// persistent-store bookkeeping on every datagram.
	forward      sync.Map // real netip.Addr -> alias netip.Addr
	reverse      sync.Map // alias netip.Addr -> real netip.Addr
	lastErrorLog atomic.Int64
}
type udpCrossFamilyContextKey struct{}

func NewUDPCrossFamilyStore(configDir, path string) *UDPCrossFamilyStore {
	if path == "" {
		path = "persist.d/udp-cross-family"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(configDir, path)
	}
	s := NewFakeIPStore(path, config.FakeIPHardMaxEntries)
	s.stableAliases = true
	return &UDPCrossFamilyStore{store: s}
}
func WithUDPCrossFamilyStore(ctx context.Context, s *UDPCrossFamilyStore) context.Context {
	return context.WithValue(ctx, udpCrossFamilyContextKey{}, s)
}
func (s *UDPCrossFamilyStore) Close() error { return s.store.Close() }
func (s *UDPCrossFamilyStore) decode(dst netip.AddrPort) (netip.AddrPort, bool, error) {
	if s == nil {
		return dst, false, nil
	}
	if real, ok := s.reverse.Load(dst.Addr()); ok {
		return netip.AddrPortFrom(real.(netip.Addr), dst.Port()), true, nil
	}
	if !s.store.Contains(dst.Addr()) {
		return dst, false, nil
	}
	name, ok := s.store.LookBack(dst.Addr())
	if !ok {
		return dst, true, fmt.Errorf("unassigned UDP peer alias: %s", dst)
	}
	addr, err := netip.ParseAddr(strings.TrimSuffix(name, "."))
	if err != nil {
		return dst, true, fmt.Errorf("invalid UDP peer mapping: %w", err)
	}
	addr = addr.Unmap()
	s.reverse.Store(dst.Addr(), addr)
	return netip.AddrPortFrom(addr, dst.Port()), true, nil
}
func (s *UDPCrossFamilyStore) reply(from, client netip.AddrPort) (netip.AddrPort, error) {
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	if from.Addr().Is4() == client.Addr().Unmap().Is4() {
		return from, nil
	}
	if s == nil {
		return from, fmt.Errorf("UDP cross-family peer mapping is disabled")
	}
	if alias, ok := s.forward.Load(from.Addr()); ok {
		return netip.AddrPortFrom(alias.(netip.Addr), from.Port()), nil
	}
	if s.store.Contains(from.Addr()) {
		return from, fmt.Errorf("upstream peer belongs to UDP mapping pool: %s", from)
	}
	name := from.Addr().String()
	v4, v6, ok := s.store.Lookup(name)
	if !ok {
		var err error
		v4, v6, _, err = s.store.Assign(name)
		if err != nil {
			return from, err
		}
	}
	addr := v6
	if client.Addr().Unmap().Is4() {
		addr = v4
	}
	s.reverse.Store(addr, from.Addr())
	s.forward.Store(from.Addr(), addr)
	return netip.AddrPortFrom(addr, from.Port()), nil
}
func (c *ControlPlane) initUDPCrossFamily(ctx context.Context, global *config.Global, dns *config.Dns) error {
	v4, v6, err := global.UDPCrossFamilyPrefixes(dns.FakeIP)
	if err != nil {
		return err
	}
	s, _ := ctx.Value(udpCrossFamilyContextKey{}).(*UDPCrossFamilyStore)
	if !v4.IsValid() {
		// Keep old aliases routable while retained sessions and clients still use them.
		if s != nil && s.store.Ready() {
			c.udpCrossFamily = s
		}
		return nil
	}
	owned := s == nil
	if owned {
		s = NewUDPCrossFamilyStore(".", global.UDPCrossFamilyPath)
	}
	// Validate before opening: sharing the DNS store path would overwrite a
	// different mapping namespace even when the configured prefixes are disjoint.
	if f := fakeIPStoreFromContext(ctx); f != nil {
		peerPath, _ := filepath.Abs(s.store.dir)
		dnsPath, _ := filepath.Abs(f.dir)
		if peerPath == dnsPath {
			return fmt.Errorf("UDP peer mappings and DNS FakeIP require separate storage paths")
		}
		a, r := f.Prefixes()
		for _, p := range append(a, r...) {
			if p.Overlaps(v4) || p.Overlaps(v6) {
				return fmt.Errorf("UDP mapping pool overlaps retained DNS FakeIP pool %s", p)
			}
		}
	}
	if !s.store.Ready() {
		err = s.store.Open(v4, v6)
	} else {
		// A live candidate must not mutate the mapping pool used by the serving
		// generation before its configuration has been accepted.
		active, _ := s.store.Prefixes()
		if len(active) != 2 || active[0] != v4 || active[1] != v6 {
			return fmt.Errorf("changing UDP mapping pools requires a restart; retain the mapping files")
		}
	}
	if err != nil {
		return err
	}
	if owned {
		c.deferFuncs = append(c.deferFuncs, s.Close)
	}
	c.udpCrossFamily = s
	return nil
}

// Resolve routing against the actual peer but keep the client tuple as the
// endpoint/conn-state identity. The kernel punt for an alias is not a reason to
// allocate a new destination-affine socket on an otherwise full-cone route.
func (c *ControlPlane) routeUDPAlias(src, dst netip.AddrPort, result *bpfRoutingResult) (*bpfRoutingResult, bool, error) {
	real, alias, err := c.udpCrossFamily.decode(dst)
	if err != nil || !alias {
		return result, alias, err
	}
	outbound, mark, must, err := c.Route(src, real, "", consts.L4ProtoType_UDP, result)
	if err != nil {
		return nil, true, err
	}
	copy := bpfRoutingResult{}
	if result != nil {
		copy = *result
	}
	copy.Outbound = uint8(outbound)
	copy.Mark = mark
	copy.Must = 0
	if must {
		copy.Must = 1
	}
	return &copy, true, nil
}

// Check both stores after loading, including prefixes retained from older files.
func (c *ControlPlane) validateUDPCrossFamilyPools() error {
	if c.udpCrossFamily == nil || c.fakeIPStore() == nil {
		return nil
	}
	a, r := c.udpCrossFamily.store.Prefixes()
	peers := append(a, r...)
	a, r = c.fakeIPStore().Prefixes()
	for _, peer := range peers {
		for _, dns := range append(a, r...) {
			if peer.Overlaps(dns) {
				return fmt.Errorf("UDP peer mapping pool %s overlaps DNS FakeIP pool %s", peer, dns)
			}
		}
	}
	return nil
}

func (s *UDPCrossFamilyStore) allowErrorLog() bool {
	now := time.Now().UnixNano()
	last := s.lastErrorLog.Load()
	return now-last >= int64(5*time.Second) && s.lastErrorLog.CompareAndSwap(last, now)
}
