// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestUDPRebuildResolveDNSCrossFamilyRealProxy(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "shadowsocks2022", "socks5"} {
		for _, clientV6 := range []bool{false, true} {
			direction := "v4_to_v6"
			if clientV6 {
				direction = "v6_to_v4"
			}
			for _, view := range []string{"no_mapping", "writable", "read_only"} {
				t.Run(kind+"/"+direction+"/"+view, func(t *testing.T) {
					var store *UDPCrossFamilyStore
					if view != "no_mapping" {
						store = openCrossFamilyTestStore(t, t.TempDir())
						if view == "read_only" {
							store = &UDPCrossFamilyStore{store: store.store, readOnly: true}
						}
					}
					f := newPinnedRebuildFixtureFamilies(t, kind, clientV6, !clientV6, store)
					runUDPRebuildResolveDNSRealProxy(t, f)
					if store != nil {
						store.store.mu.RLock()
						count := len(store.store.names)
						store.store.mu.RUnlock()
						if count != 0 {
							t.Fatalf("fixed-target cross-family recovery allocated %d aliases", count)
						}
					}
				})
			}
		}
	}
}

func TestUDPRebuildResolveDNSCrossFamilyMappingExclusions(t *testing.T) {
	store := openCrossFamilyTestStore(t, t.TempDir())
	for _, tc := range []struct{ name, client, original, peer, want string }{
		{"native v4 to v6", "192.0.2.201:32000", "198.51.100.10:27015", "[2001:db8::20]:27015", ""},
		{"native v6 to v4", "[2001:db8::201]:32000", "[2001:db8::10]:27015", "203.0.113.20:27015", ""},
		{"original v4 alias", "192.0.2.201:32000", "198.19.0.1:27015", "[2001:db8::20]:27015", "peer_alias_unsupported"},
		{"original v6 alias", "[2001:db8::201]:32000", "[fd00:cafe::1]:27015", "203.0.113.20:27015", "peer_alias_unsupported"},
		{"actual v4 alias", "[2001:db8::201]:32000", "[2001:db8::10]:27015", "198.19.0.1:27015", "peer_alias_unsupported"},
		{"actual v6 alias", "192.0.2.201:32000", "198.51.100.10:27015", "[fd00:cafe::1]:27015", "peer_alias_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := netip.MustParseAddrPort(tc.peer)
			ue := &UdpEndpoint{poolKey: UdpEndpointKey{Src: netip.MustParseAddrPort(tc.client), Dst: netip.MustParseAddrPort(tc.original)}, DialTarget: tc.peer, SniffedDomain: "pinned.example", resolveDNSState: &udpResolveDNSState{}, crossFamily: store}
			ue.pinnedTarget = newUDPPinnedTarget(ue, &DialOption{Target: tc.peer, SniffedDomain: ue.SniffedDomain, ResolveDNSOriginalNative: true})
			if got := ue.pinnedDNSExclusion(peer); got != tc.want {
				t.Fatalf("exclusion=%q want %q", got, tc.want)
			}
			ue.pinnedTarget.native = false
			if got := ue.pinnedDNSExclusion(peer); got != "resolve_dns_fakeip_unleased" {
				t.Fatalf("DNS FakeIP was admitted by cross-family support: %q", got)
			}
		})
	}
}

// Fixed-target cross-family recovery relies on canonicalReplyFrom restoring
// the original target before the reply handler maps foreign peers. Exercise
// that production order directly: a raw actual peer would allocate an alias.
func TestUDPRebuildResolveDNSCrossFamilyReplyKeepsOriginal(t *testing.T) {
	for _, tc := range []struct{ name, client, original, peer string }{
		{"v4_to_v6", "192.0.2.201:32000", "198.51.100.10:27015", "[2001:db8::20]:27015"},
		{"v6_to_v4", "[2001:db8::201]:32000", "[2001:db8::10]:27015", "203.0.113.20:27015"},
	} {
		for _, view := range []string{"writable", "read_only"} {
			t.Run(tc.name+"/"+view, func(t *testing.T) {
				writable := openCrossFamilyTestStore(t, t.TempDir())
				store := writable
				if view == "read_only" {
					store = &UDPCrossFamilyStore{store: writable.store, readOnly: true}
				}
				client, original, peer := netip.MustParseAddrPort(tc.client), netip.MustParseAddrPort(tc.original), netip.MustParseAddrPort(tc.peer)
				ue := &UdpEndpoint{poolKey: UdpEndpointKey{Src: client, Dst: original}, DialTarget: tc.peer, SniffedDomain: "pinned.example", resolveDNSState: &udpResolveDNSState{}, crossFamily: store}
				ue.pinnedTarget = newUDPPinnedTarget(ue, &DialOption{Target: tc.peer, SniffedDomain: ue.SniffedDomain, ResolveDNSOriginalNative: true})
				if got := ue.pinnedDNSExclusion(peer); got != "" {
					t.Fatalf("exclusion=%q", got)
				}
				aliases := func() int {
					writable.store.mu.RLock()
					defer writable.store.mu.RUnlock()
					return len(writable.store.names)
				}
				drops := udpReplyReinjectionDrops.Load()
				var sent []netip.AddrPort
				send := func(_ *logrus.Logger, _ []byte, from, to netip.AddrPort, _ udpEndpointResponseConnSlot) error {
					if to != client {
						t.Fatalf("reply sent to %v, want %v", to, client)
					}
					sent = append(sent, from)
					return nil
				}
				if err := forwardUdpEndpointReplyToClient(nil, ue, []byte("reply"), ue.canonicalReplyFrom(peer), client, send, nil); err != nil {
					t.Fatal(err)
				}
				if len(sent) != 1 || sent[0] != original {
					t.Fatalf("client saw %v, want %v", sent, original)
				}
				if n := aliases(); n != 0 || udpReplyReinjectionDrops.Load() != drops {
					t.Fatalf("canonical reply allocated %d aliases or dropped", n)
				}
				// Guard the test itself: without canonicalization the
				// foreign peer reaches the mapper.
				sent = nil
				_ = forwardUdpEndpointReplyToClient(nil, ue, []byte("raw"), peer, client, send, nil)
				if view == "writable" && (aliases() != 1 || len(sent) != 1 || sent[0] == original) {
					t.Fatalf("raw actual peer was not mapped: %v aliases=%d", sent, aliases())
				}
				if view == "read_only" && (len(sent) != 0 || udpReplyReinjectionDrops.Load() == drops) {
					t.Fatalf("read-only raw actual peer was not dropped: %v", sent)
				}
			})
		}
	}
}

func TestUDPRebuildResolveDNSCrossFamilyWriteRetryKeepsPin(t *testing.T) {
	for _, clientV6 := range []bool{false, true} {
		name := "v4_to_v6"
		if clientV6 {
			name = "v6_to_v4"
		}
		t.Run(name, func(t *testing.T) {
			f := newPinnedRebuildFixtureFamilies(t, "shadowsocks", clientV6, !clientV6, nil)
			f.sendPin(t, f.pin, "pin/before-error", true)
			queries := f.queries.Load()
			f.pin.retire()
			_ = f.pool.removeForRetry(f.pin.poolKey, f.pin)
			f.dial.fail.Store(true)
			if _, _, err := f.pool.GetOrCreate(f.pin.poolKey, f.options); err == nil {
				t.Fatal("expected ordinary replacement dial to fail")
			}
			if r, ok := f.m.resolveDNSRecovery.lookup(f.pin.poolKey, f.initial, false); !ok || r.target != f.b {
				t.Fatal("failed dial discarded the cross-family pin")
			}
			f.dial.fail.Store(false)
			var next *UdpEndpoint
			waitRebuild(t, func() bool {
				var err error
				next, _, err = f.pool.GetOrCreate(f.pin.poolKey, f.options)
				return err == nil
			})
			if next.DialTarget != f.b.String() || f.queries.Load() != queries {
				t.Fatal("ordinary replacement resolved or changed the fixed peer")
			}
			f.sendPin(t, next, "pin/after-error", true)
			_ = f.pool.Remove(next.poolKey, next)
			if _, ok := f.m.resolveDNSRecovery.lookup(next.poolKey, f.initial, false); ok {
				t.Fatal("administrative removal retained the pin")
			}
		})
	}
}

func TestUDPRebuildResolveDNSCrossFamilyCancelDuringPrepare(t *testing.T) {
	for _, clientV6 := range []bool{false, true} {
		name := "v4_to_v6"
		if clientV6 {
			name = "v6_to_v4"
		}
		for _, reason := range []string{"reply", "reload", "unknown_initial", "new_initial", "store_busy"} {
			t.Run(name+"/"+reason, func(t *testing.T) {
				runUDPRebuildResolveDNSCancelDuringPrepare(t, newPinnedRebuildFixtureFamilies(t, "shadowsocks", clientV6, !clientV6, nil), reason)
			})
		}
	}
}

func TestUDPRebuildResolveDNSCrossFamilyPreparedReply(t *testing.T) {
	for _, clientV6 := range []bool{false, true} {
		name := "v4_to_v6"
		if clientV6 {
			name = "v6_to_v4"
		}
		t.Run(name, func(t *testing.T) {
			f := newPinnedRebuildFixtureFamilies(t, "socks5", clientV6, !clientV6, nil)
			f.sendPin(t, f.pin, "pin/before-prepare", true)
			next, err := f.o.execution.Load().prepare(context.Background(), f.pin, f.b)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = next.Close() })
			// Real socket I/O reaches P but the speculative receiver must not
			// expose this reply to the application or confirmation ledger.
			if _, err := next.conn.WriteTo([]byte("pin/speculative"), f.b.String()); err != nil {
				t.Fatal(err)
			}
			waitRebuild(t, func() bool { f.relay.mu.Lock(); defer f.relay.mu.Unlock(); return f.relay.seen["pin/speculative"] == 1 })
			select {
			case r := <-f.replies:
				t.Fatalf("prepared connection exposed reply %+v", r)
			case <-time.After(20 * time.Millisecond):
			}
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
			f.sendPin(t, f.pin, "pin/after-cancel", true)
		})
	}
}
