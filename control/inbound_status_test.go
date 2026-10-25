/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

func TestInboundManagerSnapshotReportsBindFailure(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	free.Close()

	m := NewInboundManager(logrus.New())
	defer m.Close()
	m.Apply([]config.Inbound{
		{Name: "ok", Protocol: "socks5", Listen: freeAddr, UDP: true, Sniff: "auto", Resolve: "local", Username: "u", Password: "secret"},
		{Name: "taken", Protocol: "socks5", Listen: busy.Addr().String(), UDP: true, Sniff: "auto", Resolve: "local"},
	})

	snap := m.Snapshot()
	if len(snap) != 2 || snap[0].Name != "ok" || snap[1].Name != "taken" {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap[0].State != InboundStateListening || snap[0].Since == "" || !snap[0].HasPassword || snap[0].Username != "u" {
		t.Errorf("ok = %+v", snap[0])
	}
	if snap[1].State != InboundStateFailed || snap[1].Error == "" {
		t.Errorf("taken = %+v", snap[1])
	}

	// Freeing the port and applying again recovers it and clears the error.
	busy.Close()
	m.Apply([]config.Inbound{
		{Name: "ok", Protocol: "socks5", Listen: freeAddr, UDP: true, Sniff: "auto", Resolve: "local", Username: "u", Password: "secret"},
		{Name: "taken", Protocol: "socks5", Listen: busy.Addr().String(), UDP: true, Sniff: "auto", Resolve: "local"},
	})
	if got := m.Snapshot()[1]; got.State != InboundStateListening || got.Error != "" {
		t.Errorf("taken after retry = %+v", got)
	}

	m.Apply(nil)
	if got := m.Snapshot(); len(got) != 0 {
		t.Errorf("removed inbounds still reported: %+v", got)
	}
}

func TestAdminConnectionsCarryTheInbound(t *testing.T) {
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })
	group := &outbound.DialerGroup{Name: "proxy"}
	adopt := func(id uint64, inbound string) *FlowRuntime {
		flow, err := manager.adoptTCP(&memoryLayoutConn{id: id}, nil,
			TcpFlowBinding{Inbound: inbound, Egress: TcpEgressBinding{Outbound: group, Target: "example.com:443"}},
			runtime, nil, netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("198.51.100.10:443"))
		if err != nil {
			t.Fatal(err)
		}
		return flow
	}
	a := adopt(1, "s1")
	b := adopt(2, "")
	defer a.finish()
	defer b.finish()

	all := manager.adminConnectionsSnapshot(256, adminConnectionFilter{})
	if all.Total != 2 {
		t.Fatalf("all = %+v", all)
	}
	only := manager.adminConnectionsSnapshot(256, adminConnectionFilter{inbound: "s1"})
	if only.Total != 1 || only.Connections[0].Inbound != "s1" {
		t.Fatalf("filtered = %+v", only)
	}
	if none := manager.adminConnectionsSnapshot(256, adminConnectionFilter{inbound: "nope"}); none.Total != 0 {
		t.Fatalf("unknown inbound matched: %+v", none)
	}
}

func TestMergeInboundUDPConnections(t *testing.T) {
	snap := AdminConnectionsSnapshot{Total: 1, Connections: []AdminConnection{{ID: "5", Upload: 1}}}
	udp := []AdminConnection{
		{ID: "i1", Network: "udp", Inbound: "s1", Upload: 100},
		{ID: "i2", Network: "udp", Inbound: "lan", Upload: 10},
	}
	got := mergeInboundUDPConnections(snap, udp, adminConnectionFilter{}, 256)
	if got.Total != 3 || len(got.Connections) != 3 || got.Connections[0].ID != "i1" {
		t.Fatalf("merged = %+v", got)
	}
	got = mergeInboundUDPConnections(snap, udp, adminConnectionFilter{inbound: "lan"}, 256)
	if got.Total != 2 || got.Connections[0].ID != "i2" {
		t.Fatalf("filtered = %+v", got)
	}
	got = mergeInboundUDPConnections(snap, udp, adminConnectionFilter{}, 2)
	if got.Total != 3 || len(got.Connections) != 2 || !got.Truncated {
		t.Fatalf("limit not applied: %+v", got)
	}
	// No inbound UDP sessions: the snapshot is returned as it was.
	if same := mergeInboundUDPConnections(snap, nil, adminConnectionFilter{}, 256); same.Total != 1 || same.Truncated {
		t.Fatalf("unchanged snapshot altered: %+v", same)
	}
}

func TestInboundUDPSessionListedOnceEstablished(t *testing.T) {
	r := &InboundUDPRelay{inbound: "s1", src: netip.MustParseAddrPort("127.0.0.1:50000"), sessions: map[string]*inboundUDPSession{}}
	s := &inboundUDPSession{relay: r, key: "k", target: InboundTarget{Domain: "example.com", Port: 53}, id: 7}
	r.sessions["k"] = s
	if got := r.appendConnections(nil); len(got) != 0 {
		t.Fatalf("a session still being dialed was listed: %+v", got)
	}
	s.mu.Lock()
	s.ready, s.outbound, s.dialer, s.domain, s.startUnixNano = true, "proxy", "n1", "example.com", 1700000000000000000
	s.mu.Unlock()
	s.upload.Add(5)
	s.download.Add(9)
	got := r.appendConnections(nil)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	c := got[0]
	if c.ID != "i7" || c.Network != "udp" || c.Inbound != "s1" || c.Src != "127.0.0.1:50000" || c.Dst != "example.com:53" ||
		c.Outbound != "proxy" || c.Dialer != "n1" || c.Upload != 5 || c.Download != 9 || c.Start == "" {
		t.Fatalf("connection = %+v", c)
	}
}
