// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
)

func TestUDPRebuildAlias(t *testing.T) {
	for _, tc := range []struct {
		name               string
		clientV6, peerV6   bool
		fullcone, readOnly bool
	}{
		{name: "target v4 to v6", peerV6: true},
		{name: "target v6 to v4", clientV6: true},
		{name: "fullcone v4 to v6", peerV6: true, fullcone: true},
		{name: "fullcone v6 to v4", clientV6: true, fullcone: true},
		{name: "readonly target", peerV6: true, readOnly: true},
		{name: "readonly fullcone", peerV6: true, fullcone: true, readOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ue, alias, store := newAliasRebuild(t, tc.clientV6, tc.peerV6, tc.fullcone, tc.readOnly)
			before := crossFamilyRecords(store)
			f.o.scan(qualifyAliasEvidence(t, f, ue, alias))
			slot := ue.rebuildPeer(f.b)
			waitRebuild(t, func() bool {
				owner := slot.owner.Load()
				return owner != nil && owner.endpoint != ue
			})
			next := slot.owner.Load().endpoint
			if next.DialTarget != f.b.String() || unmapPort(next.poolKey.Dst) != unmapPort(alias) {
				t.Fatalf("successor dial=%s key=%s, want %s/%s", next.DialTarget, next.poolKey.Dst, f.b, alias)
			}
			if next.crossFamily == nil || next.crossFamily.store != store.store || slot.aliasStore.Load() != store.store {
				t.Fatal("successor lost the inner mapping table")
			}
			if got := crossFamilyRecords(store); got != before {
				t.Fatalf("mapping records %d, want %d", got, before)
			}
			if fullcone := tc.fullcone; fullcone && ue.dead.Load() {
				t.Fatal("fullcone endpoint ended with one peer")
			}
			if tc.fullcone {
				assertFullConeAliasHandoff(t, f, ue, next, slot, alias)
			}
			sendAlias(t, f, ue, f.b, netip.AddrPort{}, alias, "B/alias/0", true)
			if r := sendAlias(t, f, ue, f.b, netip.AddrPort{}, alias, "B/alias/1", true); r.endpoint != next {
				t.Fatal("rebuilt peer did not follow the successor")
			}
			if !tc.fullcone {
				waitRebuild(t, func() bool { return ue.dead.Load() })
			}
			var got netip.AddrPort
			send := func(_ *logrus.Logger, _ []byte, from, to netip.AddrPort, _ udpEndpointResponseConnSlot) error {
				if to != ue.poolKey.Src {
					t.Fatalf("late reply sent to %s", to)
				}
				got = from
				return nil
			}
			if err := forwardUdpEndpointReplyToClient(nil, ue, []byte("late"), ue.canonicalReplyFrom(f.b), ue.poolKey.Src, send, nil); err != nil || got != alias {
				t.Fatalf("late reply %s: %v", got, err)
			}
			if tc.fullcone {
				f.relay.drop.Store(false)
				f.send(t, ue, f.a, "A/still", true)
				if ue.dead.Load() {
					t.Fatal("other fullcone peer ended the endpoint")
				}
			}
		})
	}
}

func TestUDPRebuildAliasStoreClosedCancels(t *testing.T) {
	f, ue, alias, store := newAliasRebuild(t, false, true, false, false)
	now := qualifyAliasEvidence(t, f, ue, alias)
	f.dial.onExtraDial = func() { _ = store.Close() }
	f.o.scan(now)
	waitRebuild(t, func() bool { return f.m.udpRebuild.Load().snapshot(time.Now()).Counts["alias_mapping_changed"] == 1 })
	if ue.rebuildPeer(f.b).owner.Load().endpoint != ue {
		t.Fatal("closed mapping published a successor")
	}
	f.relay.drop.Store(false)
	sendAlias(t, f, ue, f.b, netip.AddrPort{}, alias, "B/after-close", true)
}

func TestUDPRebuildAliasDifferentStoreCancels(t *testing.T) {
	f, ue, alias, _ := newAliasRebuild(t, false, true, true, false)
	other := openCrossFamilyTestStore(t, t.TempDir())
	saved := ue.crossFamily
	now := qualifyAliasEvidence(t, f, ue, alias)
	f.dial.onExtraDial = func() {
		ue.crossFamily = &UDPCrossFamilyStore{store: other.store, readOnly: true}
	}
	f.o.scan(now)
	waitRebuild(t, func() bool { return f.m.udpRebuild.Load().snapshot(time.Now()).Counts["alias_mapping_changed"] == 1 })
	if ue.rebuildPeer(f.b).owner.Load().endpoint != ue {
		t.Fatal("foreign mapping published a successor")
	}
	ue.crossFamily = saved
	f.relay.drop.Store(false)
	sendAlias(t, f, ue, f.b, alias, f.b, "B/after-swap", true)
	f.send(t, ue, f.a, "A/after-swap", true)
}

func TestUDPRebuildAliasOrdinarySuccessor(t *testing.T) {
	store := openCrossFamilyTestStore(t, t.TempDir())
	other := openCrossFamilyTestStore(t, t.TempDir())
	client := netip.MustParseAddrPort("192.0.2.201:32000")
	peer := netip.MustParseAddrPort("[2001:db8::20]:27015")
	alias, err := store.reply(peer, client)
	if err != nil {
		t.Fatal(err)
	}
	key := UdpEndpointKey{Src: client, Dst: alias}
	slot := &udpRebuildPeer{peer: peer, original: alias}
	slot.aliasStore.Store(store.store)
	slot.owner.Store(&udpRebuildOwnership{endpoint: &UdpEndpoint{}})
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)
	pool.rebuildOverrides.Store(key, slot)
	pool.hasRebuildOverrides.Store(true)
	same := &UdpEndpoint{poolKey: key, DialTarget: peer.String(), crossFamily: &UDPCrossFamilyStore{store: store.store, readOnly: true}}
	if !pool.prepareOrdinaryRebuildSuccessor(same, slot, &DialOption{}) {
		t.Fatal("empty-cache view of the same table was treated as a new flow")
	}
	if _, ok := pool.rebuildOverride(key); !ok {
		t.Fatal("matching ordinary successor dropped the claim")
	}
	foreign := &UdpEndpoint{poolKey: key, DialTarget: peer.String(), crossFamily: &UDPCrossFamilyStore{store: other.store, readOnly: true}}
	if foreign.inheritAliasRebuild(slot) {
		t.Fatal("different table inherited the claim")
	}
	moved := &UdpEndpoint{poolKey: key, DialTarget: "192.0.2.9:27015", crossFamily: same.crossFamily}
	if pool.prepareOrdinaryRebuildSuccessor(moved, slot, &DialOption{}) {
		t.Fatal("different peer inherited the claim")
	}
	if _, ok := pool.rebuildOverride(key); ok {
		t.Fatal("mismatched ordinary successor kept the claim")
	}
	_ = store.Close()
	closed := &UdpEndpoint{poolKey: key, DialTarget: peer.String(), crossFamily: same.crossFamily}
	slot.aliasStore.Store(store.store)
	if closed.inheritAliasRebuild(slot) {
		t.Fatal("closed table inherited the claim")
	}
	native := &udpRebuildPeer{peer: peer, original: peer}
	if !(&UdpEndpoint{}).inheritAliasRebuild(native) {
		t.Fatal("native claim was treated as an alias")
	}
}

func newAliasRebuild(t *testing.T, clientV6, peerV6, fullcone, readOnly bool) (*rebuildFixture, *UdpEndpoint, netip.AddrPort, *UDPCrossFamilyStore) {
	t.Helper()
	store := openCrossFamilyTestStore(t, t.TempDir())
	f := newRebuildFixtureFamilies(t, "shadowsocks", "enforce", false, store, clientV6, peerV6)
	alias, err := store.reply(f.b, f.old.poolKey.Src)
	if err != nil {
		t.Fatal(err)
	}
	view := store
	if readOnly {
		view = &UDPCrossFamilyStore{store: store.store, readOnly: true}
	}
	if fullcone {
		f.old.crossFamily = view
		return f, f.old, alias, store
	}
	opts := *f.options
	opts.crossFamily = view
	base := f.options.GetDialOption
	opts.GetDialOption = func(ctx context.Context) (*DialOption, error) {
		opt, err := base(ctx)
		if err != nil {
			return nil, err
		}
		opt.Target = f.b.String()
		return opt, nil
	}
	ue, _, err := f.pool.GetOrCreate(UdpEndpointKey{Src: f.old.poolKey.Src, Dst: alias}, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if ue.DialTarget != f.b.String() || ue.poolKey.Dst != alias {
		t.Fatalf("endpoint dial=%s dst=%s", ue.DialTarget, ue.poolKey.Dst)
	}
	return f, ue, alias, store
}

func qualifyAliasEvidence(t *testing.T, f *rebuildFixture, ue *UdpEndpoint, alias netip.AddrPort) time.Time {
	t.Helper()
	visible := netip.AddrPort{}
	history := alias
	if !ue.poolKey.Dst.IsValid() {
		visible = alias
		history = f.b
	}
	for i := 0; i < 3; i++ {
		sendAlias(t, f, ue, f.b, visible, history, fmt.Sprintf("B/history/%d", i), true)
	}
	if !ue.poolKey.Dst.IsValid() {
		f.send(t, ue, f.a, "A/before", true)
	}
	ue.TrackUdpConnStateTuplePair(ue.poolKey.Src, alias)
	f.relay.drop.Store(true)
	for i := 0; i < 61; i++ {
		sendAlias(t, f, ue, f.b, visible, netip.AddrPort{}, fmt.Sprintf("B/drought/%d", i), false)
	}
	waitRebuild(t, func() bool {
		f.relay.mu.Lock()
		defer f.relay.mu.Unlock()
		return len(f.relay.seen) >= 64
	})
	flow := ue.replyDrought
	now := time.Now()
	epoch := f.o.stamp(now) / int64(udpDroughtBucketDuration)
	flow.mu.Lock()
	p := flow.peers[f.b]
	if p == nil || p.writes != 64 || p.replies != 3 {
		t.Fatalf("real evidence: %+v", p)
	}
	p.first = (epoch - 7) * int64(udpDroughtBucketDuration)
	p.lastReply = p.first
	p.lastWrite = f.o.stamp(now)
	p.invalidatedAt = 0
	for i := int64(0); i < 7; i++ {
		e := epoch - i
		writes := 10
		if i == 0 {
			writes = 1
		}
		p.buckets[e%7] = udpDroughtBucket{epoch: e, writes: writes}
	}
	flow.mu.Unlock()
	return now
}

func sendAlias(t *testing.T, f *rebuildFixture, ue *UdpEndpoint, dial, visible, want netip.AddrPort, payload string, wantReply bool) rebuildReply {
	t.Helper()
	var err error
	if visible.IsValid() {
		_, err = ue.writeObserved([]byte(payload), dial.String(), visible)
	} else {
		_, err = ue.WriteTo([]byte(payload), dial.String())
	}
	if err != nil {
		t.Fatal(err)
	}
	if !wantReply {
		return rebuildReply{}
	}
	select {
	case r := <-f.replies:
		if r.payload != payload || r.peer != want {
			t.Fatalf("reply %+v, want %s from %s", r, payload, want)
		}
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("missing alias reply")
		return rebuildReply{}
	}
}

func crossFamilyRecords(s *UDPCrossFamilyStore) int {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	return len(s.store.names)
}

func assertFullConeAliasHandoff(t *testing.T, f *rebuildFixture, old, next *UdpEndpoint, slot *udpRebuildPeer, alias netip.AddrPort) {
	t.Helper()
	if old.rebuildPeerForOriginal(alias) != slot || !old.detachedRebuildPeer(alias) || !old.detachedRebuildPeer(f.b) {
		t.Fatal("old fullcone endpoint did not keep the client-visible address")
	}
	if next.rebuildPeerForOriginal(alias) != slot || next.detachedRebuildPeer(alias) {
		t.Fatal("successor refused its own client-visible address")
	}
	src := old.poolKey.Src
	before := aliasTupleRefs(f.m, src, alias)
	old.TrackUdpConnStateTuplePair(src, alias)
	if got := aliasTupleRefs(f.m, src, alias); got != before {
		t.Fatalf("old endpoint reclaimed alias tuples: %d -> %d", before, got)
	}
	old.UpdateCachedRoutingResult(alias, 17, &bpfRoutingResult{})
	if _, ok := old.GetBoundRoutingResult(alias, 17); ok {
		t.Fatal("old endpoint cached a route for the alias")
	}
	old.UpdateCachedRoutingResult(f.a, 17, &bpfRoutingResult{})
	if _, ok := old.GetBoundRoutingResult(f.a, 17); !ok {
		t.Fatal("old endpoint dropped another peer's route")
	}
	previous := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	t.Cleanup(func() {
		DefaultUdpEndpointPool.Close()
		DefaultUdpEndpointPool = previous
	})
	f.m.udpBySource.Store(src, &udpFlowSourceSnapshot{
		flows:       []*UDPFlowRuntime{{endpoint: old, binding: UdpFlowBinding{Route: UdpRouteBinding{PolicyEpoch: 1}}}},
		epochCounts: map[routing.PolicyEpoch]int{1: 1},
	})
	if _, ok := f.m.retainedUDPEndpoint(src, alias, nil, 2); ok {
		t.Fatal("reload kept the old endpoint for the alias")
	}
	if got, ok := f.m.retainedUDPEndpoint(src, f.a, nil, 2); !ok || got != old {
		t.Fatal("reload dropped another fullcone peer")
	}
	wantOriginal, wantPeer := "ipv4", "ipv6"
	if alias.Addr().Is6() {
		wantOriginal, wantPeer = "ipv6", "ipv4"
	}
	snap := f.c.AdminUDPRecovery(0, "")
	for _, e := range snap.Records {
		if e.Kind != "committed" || e.ActualPeer != f.b.String() {
			continue
		}
		if e.TargetKind != "peer_alias" || e.OriginalTarget != alias.String() || e.OriginalFamily != wantOriginal || e.ActualPeerFamily != wantPeer || e.DNSPinOwnerID != 0 || e.PinInherited {
			t.Fatalf("alias archive %+v", e)
		}
		return
	}
	t.Fatalf("missing alias commit in %+v", snap.Records)
}

func aliasTupleRefs(m *SessionManager, src, dst netip.AddrPort) int {
	m.udpStateMu.Lock()
	defer m.udpStateMu.Unlock()
	return m.pinnedUDP[bpfTuplesKeyFromAddrPorts(src, dst, 17)] + m.pinnedUDP[bpfTuplesKeyFromAddrPorts(dst, src, 17)]
}
