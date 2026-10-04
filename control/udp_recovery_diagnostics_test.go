// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

func recoveryTestPlane(m *SessionManager, o *udpReplyDroughtObserver, epoch uint64) *ControlPlane {
	c := &ControlPlane{sessionManager: m, controlPlaneUDPRuntime: controlPlaneUDPRuntime{udpReplyDrought: o}}
	var err error
	c.policyIdentity, err = routing.NewPolicyIdentity(routing.PolicyEpoch(epoch), &routing.NormalizedProgram{})
	if err != nil {
		panic(err)
	}
	if o != nil {
		o.bindDiagnostics(m, c.PolicyEpoch())
	}
	return c
}

func recoveryTestEndpoint(t *testing.T, m *SessionManager, o *udpReplyDroughtObserver, epoch uint64, src, dst netip.AddrPort) *UdpEndpoint {
	t.Helper()
	d := newNamedTestEndpointDialer("proxy-node")
	d.Property().Address, d.Property().Protocol = "192.0.2.100:34564", "shadowsocks"
	g := newTestFixedOutboundGroup(d)
	g.Name = "game"
	t.Cleanup(func() { g.Close(); _ = d.Close() })
	ue := &UdpEndpoint{conn: &mockPacketConn{}, Dialer: d, Outbound: g, poolKey: UdpEndpointKey{Src: src, Dst: dst}}
	if dst.IsValid() {
		ue.DialTarget = dst.String()
	}
	if o != nil {
		ue.replyDrought = o.newFlow(src.String(), g.Name, d.Property().Name, true)
	}
	_, err := m.adoptUDP(ue, UdpFlowBinding{Route: UdpRouteBinding{PolicyEpoch: routing.PolicyEpoch(epoch)}, Egress: UdpEgressBinding{Dialer: d, Outbound: g}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ue.Close() })
	return ue
}

func TestUDPRecoveryJournalPreservesFinalEvidenceAcrossReload(t *testing.T) {
	m := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = m.Close() })
	o := testDroughtObserver(t, true)
	c := recoveryTestPlane(m, o, 11)
	ue := recoveryTestEndpoint(t, m, o, 11, netip.MustParseAddrPort("192.0.2.10:1234"), droughtTestPeer)
	base := time.Now().Truncate(5 * time.Second)
	fillDroughtWindow(ue.replyDrought, droughtTestPeer, base)
	// Record unsaturated counts above the eligibility threshold.
	ue.replyDrought.write(droughtTestPeer, 100, base.Add(26*time.Second))
	o.scan(base.Add(30 * time.Second))
	s := c.AdminUDPRecovery(0, "")
	if s.ExecutionImplemented || len(s.Records) != 2 || s.Records[1].Kind != "qualified" {
		t.Fatalf("events: %+v", s)
	}
	r := s.Records[1].Peer
	if r.RuntimeID != ue.sessionRuntime.id || r.PolicyEpoch != 11 || r.CandidateEpisode != 1 || len(r.Windows) != 7 {
		t.Fatalf("identity/window: %+v", r)
	}
	for i, w := range r.Windows[:6] {
		want := 10
		if i == 5 {
			want++
		}
		if !w.Present || !w.Complete || w.Invalid || w.NonemptyWrites != want {
			t.Fatalf("bucket %d: %+v", i, w)
		}
	}
	if r.Windows[6].Complete || r.Windows[6].Present {
		t.Fatal("partial current bucket claimed complete")
	}
	// Retiring observation must not retire the live process-owned socket.
	_ = o.Close()
	if ue.dead.Load() || m.udpCount.Load() != 1 {
		t.Fatal("diagnostics changed endpoint lifecycle")
	}
	next := testDroughtObserver(t, false)
	c2 := recoveryTestPlane(m, next, 12)
	s2 := c2.AdminUDPRecovery(s.NextSequence, s.Process)
	if s2.Process != s.Process || s2.CursorReset != "" || s2.EventCounts["observation_ended"] != 1 {
		t.Fatalf("reload: %+v", s2)
	}
	if s2.Coverage.States["retained_owner_not_observed"] != 1 || len(s2.Coverage.Flows) != 1 {
		t.Fatalf("coverage: %+v", s2.Coverage)
	}
	if s2.Coverage.Flows[0].RuntimeID != r.RuntimeID {
		t.Fatal("reload changed runtime identity")
	}
	for _, e := range s2.Records {
		if e.Kind == "observation_ended" && (e.Reason != "generation_closed" || e.Peer.SuccessfulWrites != 62 || e.Peer.Replies != 3) {
			t.Fatalf("lost final evidence: %+v", e)
		}
	}
	c2.AdminUDPRecovery(s2.NextSequence, s2.Process)
	if got := c2.AdminUDPRecovery(0, "").EventCounts["coverage_missing"]; got != 1 {
		t.Fatalf("coverage not deduplicated: %d", got)
	}
	// Turning off leaves history accessible without creating another observer.
	off := recoveryTestPlane(m, nil, 13).AdminUDPRecovery(0, "")
	if off.Mode != "off" || off.Observation != nil || off.EventCounts["qualified"] != 1 {
		t.Fatalf("off lost history: %+v", off)
	}
}

func TestUDPRecoveryCandidateEpisodesAndOriginalReply(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	o := testDroughtObserver(t, true)
	c := recoveryTestPlane(m, o, 1)
	f := o.newFlow("client", "game", "node", true)
	base := time.Now().Truncate(5 * time.Second)
	fillDroughtWindow(f, droughtTestPeer, base)
	o.scan(base.Add(30 * time.Second))
	f.reply(droughtTestPeer, base.Add(31*time.Second))
	fillDroughtWindow(f, droughtTestPeer, base.Add(40*time.Second))
	o.scan(base.Add(70 * time.Second))
	f.invalidate(base.Add(70 * time.Second))
	s := c.AdminUDPRecovery(0, "")
	if s.EventCounts["qualified"] != 2 || s.EventCounts["candidate_ended"] != 2 {
		t.Fatalf("episodes: %+v", s.EventCounts)
	}
	for _, e := range s.Records {
		if e.Kind == "candidate_ended" && e.Peer.CandidateEpisode == 1 && e.Reason != "reply_resumed_on_original" {
			t.Fatalf("wrong original reply evidence: %+v", e)
		}
		if e.Kind == "candidate_ended" && e.Peer.CandidateEpisode == 2 && (e.Reason != "local_window_invalidated" || !e.Peer.Windows[6].Invalid) {
			t.Fatalf("error window: %+v", e)
		}
		if e.Kind == "recovered" || e.Kind == "committed" {
			t.Fatal("observe fabricated an execution outcome")
		}
	}
}

func TestUDPRecoveryCursorLossPaginationAndProcessReset(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	o := testDroughtObserver(t, false)
	c := recoveryTestPlane(m, o, 1)
	for i := 0; i < udpRecoveryJournalLimit+5; i++ {
		o.recordDiagnostic(UDPRecoveryEvent{Kind: "observation_ended", AtMS: time.Now().UnixMilli()})
	}
	s := c.AdminUDPRecovery(0, "")
	if s.LostRecords != 6 || s.RingEvicted != 6 || len(s.Records) != udpRecoveryPageLimit || !s.HasMore {
		t.Fatalf("gap/page: %+v", s)
	}
	next := c.AdminUDPRecovery(s.NextSequence, s.Process)
	if next.LostRecords != 0 || next.HasMore || next.NextSequence != s.LatestSequence || len(next.Records) != udpRecoveryPageLimit {
		t.Fatalf("second page: %+v", next)
	}
	empty := c.AdminUDPRecovery(next.NextSequence, next.Process)
	if len(empty.Records) != 0 || empty.NextSequence != next.NextSequence {
		t.Fatal("empty page changed cursor")
	}
	reset := c.AdminUDPRecovery(next.NextSequence, "another-process")
	if reset.CursorReset != "process_changed" || len(reset.Records) != udpRecoveryPageLimit {
		t.Fatal("restart reused old cursor")
	}
	ahead := c.AdminUDPRecovery(next.NextSequence+1, next.Process)
	if ahead.CursorReset != "cursor_ahead" || len(ahead.Records) == 0 {
		t.Fatal("ahead cursor silently hid data")
	}
}

func TestUDPRecoveryColdOffDoesNotAllocateJournal(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	c := recoveryTestPlane(m, nil, 1)
	for i := 0; i < 5; i++ {
		c.AdminUDPRecovery(0, "")
	}
	if m.udpRecoveryDiagnostics.Load() != nil {
		t.Fatal("cold off allocated diagnostics")
	}
}

func TestUDPRecoveryCoverageScopesAndUnresolvedPeer(t *testing.T) {
	m := NewSessionManager(nil)
	t.Cleanup(func() { _ = m.Close() })
	o := testDroughtObserver(t, true)
	o.policy.Client = netip.MustParseAddr("192.0.2.10")
	c := recoveryTestPlane(m, o, 2)
	// Old full-cone endpoint's observed peers are unavailable, never infer
	// that its remembered first target is its only target.
	shared := recoveryTestEndpoint(t, m, nil, 1, netip.MustParseAddrPort("192.0.2.10:1234"), netip.AddrPort{})
	shared.DialTarget = "192.0.2.99:1000"
	recoveryTestEndpoint(t, m, nil, 1, netip.MustParseAddrPort("192.0.2.20:1234"), droughtTestPeer)
	recoveryTestEndpoint(t, m, nil, 1, netip.MustParseAddrPort("192.0.2.10:1235"), netip.MustParseAddrPort("192.0.2.99:1000"))
	observed := recoveryTestEndpoint(t, m, o, 2, netip.MustParseAddrPort("192.0.2.10:1236"), droughtTestPeer)
	observed.endpointNetworkType.L4Proto = consts.L4ProtoStr_UDP
	_, _ = observed.WriteTo([]byte{1}, droughtTestPeer.String())
	s := c.AdminUDPRecovery(0, "")
	if len(s.Coverage.Flows) != 2 || s.Coverage.States["retained_peer_scope_unresolved"] != 1 || s.Coverage.States["observed"] != 1 {
		t.Fatalf("scope: %+v", s.Coverage)
	}
	if shared.dead.Load() || shared.replyDrought != nil {
		t.Fatal("coverage adopted/retired old endpoint")
	}
}

func TestUDPRecoveryConcurrentCloseScanAndJSON(t *testing.T) {
	m := NewSessionManager(nil)
	defer m.Close()
	o := testDroughtObserver(t, true)
	c := recoveryTestPlane(m, o, 1)
	f := o.newFlow("client", "game", "node", true)
	var wg sync.WaitGroup
	for n := 0; n < 3; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				switch n {
				case 0:
					f.write(droughtTestPeer, 100, time.Now())
					f.reply(droughtTestPeer, time.Now())
				case 1:
					o.scan(time.Now())
				case 2:
					if _, err := json.Marshal(c.AdminUDPRecovery(0, "")); err != nil {
						t.Error(err)
					}
				}
			}
		}(n)
	}
	wg.Wait()
	f.Close()
	_ = o.Close()
	if s := c.AdminUDPRecovery(0, ""); s.EventCounts["generation_closed"] != 1 || s.EventCounts["observation_ended"] != 1 {
		t.Fatalf("once-only close: %+v", s.EventCounts)
	}
}

func TestUDPRecoveryUnattributedOnlyAssociationRemainsAuditable(t *testing.T) {
	m := NewSessionManager(nil)
	t.Cleanup(func() { _ = m.Close() })
	o := testDroughtObserver(t, false)
	c := recoveryTestPlane(m, o, 1)
	ue := recoveryTestEndpoint(t, m, o, 1, netip.MustParseAddrPort("192.0.2.10:1234"), netip.AddrPort{})
	_, _ = ue.WriteTo([]byte{1}, "target.example:1234")
	ue.replyDrought.reply(netip.AddrPort{}, time.Now())
	_ = ue.Close()
	s := c.AdminUDPRecovery(0, "")
	if s.EventCounts["association_unattributed"] != 2 || s.EventCounts["association_ended"] != 1 {
		t.Fatalf("missing unattributed evidence: %+v", s.EventCounts)
	}
	for _, e := range s.Records {
		if e.Kind == "association_ended" && (e.Association.RuntimeID != ue.sessionRuntime.id || e.Association.UnattributedWrites != 1 || e.Association.UnattributedReplies != 1) {
			t.Fatalf("association final counts: %+v", e.Association)
		}
		if e.Kind == "qualified" {
			t.Fatal("unknown peer fabricated a candidate")
		}
	}
}

func TestUDPRecoveryUnknownOnlyGenerationClosePreservesCumulativeCounters(t *testing.T) {
	for _, scenario := range []string{"unknown_writes", "unknown_replies", "evicted_peers"} {
		t.Run(scenario, func(t *testing.T) {
			testUnknownGenerationClose(t, scenario)
		})
	}
}

func testUnknownGenerationClose(t *testing.T, scenario string) {
	m := NewSessionManager(nil)
	t.Cleanup(func() { _ = m.Close() })
	o := testDroughtObserver(t, false)
	c := recoveryTestPlane(m, o, 1)
	ue := recoveryTestEndpoint(t, m, o, 1, netip.MustParseAddrPort("192.0.2.10:1234"), netip.AddrPort{})
	var writes, replies uint64
	for i := 0; i < 10; i++ {
		if scenario == "unknown_replies" {
			ue.replyDrought.reply(netip.AddrPort{}, time.Now())
			replies++
		} else {
			_, _ = ue.WriteTo([]byte{1}, "target.example:1234")
			writes++
		}
	}
	if scenario == "evicted_peers" {
		base := time.Now()
		ue.replyDrought.write(droughtTestPeer, 1, base)
		o.scan(base.Add(udpDroughtIdleTTL + time.Second))
		if o.peerCount != 0 || len(ue.replyDrought.peers) != 0 {
			t.Fatal("peer was not evicted")
		}
	}
	if s := o.snapshot(time.Now()); len(s.Associations) != 1 || s.Associations[0].UnattributedWrites != writes || s.Associations[0].UnattributedReplies != replies {
		t.Fatalf("unknown-only live counters: %+v", s.Associations)
	}
	_ = o.Close()
	if !ue.replyDrought.closed.Load() || ue.dead.Load() {
		t.Fatal("generation teardown missed observer or closed retained socket")
	}
	s := c.AdminUDPRecovery(0, "")
	if s.EventCounts["association_ended"] != 1 {
		t.Fatalf("missing generation final counters: %+v", s.EventCounts)
	}
	for _, e := range s.Records {
		if e.Kind == "association_ended" && (e.Reason != "generation_closed" || e.Association.UnattributedWrites != writes || e.Association.UnattributedReplies != replies) {
			t.Fatalf("wrong final evidence: %+v", e)
		}
	}
}

func TestUDPRecoveryUnknownAssociationStorageIsBounded(t *testing.T) {
	o := testDroughtObserver(t, false)
	for i := 0; i < udpDroughtPeerLimit+10; i++ {
		f := o.newFlow("client", "game", "node", true)
		f.write(netip.AddrPort{}, 1, time.Now())
	}
	s := o.snapshot(time.Now())
	if len(o.flowList()) != udpDroughtPeerLimit || len(s.Associations) != udpDroughtPeerLimit || s.Stats.AdmissionDropped != 10 {
		t.Fatalf("unbounded or silent admission loss: %+v", s.Stats)
	}
	if s.Stats.UnattributedWrites != udpDroughtPeerLimit+10 {
		t.Fatal("association capacity erased aggregate counters")
	}
}
