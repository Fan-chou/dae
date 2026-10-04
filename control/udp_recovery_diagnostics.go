// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/routing"
)

const (
	udpRecoveryJournalLimit    = 256
	udpRecoveryPageLimit       = 128
	udpDroughtBucketWriteLimit = 1 << 20
)

// This channel records observation, not an execution ledger. Its process ID
// and cursor survive reload. A process restart always requires a fresh cursor.
type udpRecoveryJournal struct {
	mu       sync.Mutex
	sequence uint64
	evicted  uint64
	records  []UDPRecoveryEvent
	counts   map[string]uint64
}

type udpDroughtDiagnosticsBinding struct {
	manager *SessionManager
	journal *udpRecoveryJournal
	epoch   routing.PolicyEpoch
}

type udpDroughtIdentity struct {
	RuntimeID   uint64 `json:"runtime_id"`
	PolicyEpoch uint64 `json:"policy_epoch"`
	StartedAtMS int64  `json:"started_at_ms"`
}

type UDPRecoveryEvent struct {
	Sequence    uint64                      `json:"sequence"`
	Generation  uint64                      `json:"generation"`
	PolicyEpoch uint64                      `json:"policy_epoch"`
	AtMS        int64                       `json:"at_ms"`
	Kind        string                      `json:"kind"`
	Reason      string                      `json:"reason,omitempty"`
	Peer        *UDPReplyDroughtPeer        `json:"peer,omitempty"`
	Coverage    *UDPRecoveryCoverageFlow    `json:"coverage,omitempty"`
	Association *UDPReplyDroughtAssociation `json:"association,omitempty"`
}

type UDPRecoveryCoverageFlow struct {
	RuntimeID      uint64 `json:"runtime_id"`
	PolicyEpoch    uint64 `json:"policy_epoch"`
	StartedAtMS    int64  `json:"started_at_ms"`
	Client         string `json:"client"`
	Group          string `json:"group"`
	Node           string `json:"node"`
	OriginalTarget string `json:"original_target,omitempty"`
	State          string `json:"state"`
}

type UDPRecoveryCoverage struct {
	Flows                  []UDPRecoveryCoverageFlow `json:"flows"`
	States                 map[string]int            `json:"states"`
	Truncated              bool                      `json:"truncated"`
	MissingEventsDedupFull bool                      `json:"missing_events_dedup_full"`
}

type UDPRecoveryThresholds struct {
	BucketMS             int64 `json:"bucket_ms"`
	FullBuckets          int   `json:"required_full_buckets"`
	WritesPerBucket      int   `json:"nonempty_writes_per_bucket"`
	ReplyHistory         int   `json:"required_reply_history"`
	ReplyDroughtMS       int64 `json:"reply_drought_ms"`
	RecentWriteMS        int64 `json:"recent_write_ms"`
	PeerLimit            int   `json:"peer_limit"`
	AssociationPeerLimit int   `json:"association_peer_limit"`
	JournalLimit         int   `json:"journal_limit"`
}

type UDPRecoverySnapshot struct {
	Schema               string                   `json:"schema"`
	Process              string                   `json:"process"`
	AtMS                 int64                    `json:"at_ms"`
	Mode                 string                   `json:"mode"`
	ExecutionImplemented bool                     `json:"execution_implemented"`
	Thresholds           UDPRecoveryThresholds    `json:"thresholds"`
	Observation          *UDPReplyDroughtSnapshot `json:"observation"`
	Coverage             UDPRecoveryCoverage      `json:"coverage"`
	Records              []UDPRecoveryEvent       `json:"records"`
	OldestSequence       uint64                   `json:"oldest_sequence"`
	LatestSequence       uint64                   `json:"latest_sequence"`
	NextSequence         uint64                   `json:"next_sequence"`
	HasMore              bool                     `json:"has_more"`
	CursorReset          string                   `json:"cursor_reset,omitempty"`
	LostRecords          uint64                   `json:"lost_records"`
	RingEvicted          uint64                   `json:"ring_evicted"`
	EventCounts          map[string]uint64        `json:"event_counts"`
}

func (m *SessionManager) recoveryJournal() *udpRecoveryJournal {
	if j := m.udpRecoveryDiagnostics.Load(); j != nil {
		return j
	}
	j := &udpRecoveryJournal{counts: make(map[string]uint64)}
	if !m.udpRecoveryDiagnostics.CompareAndSwap(nil, j) {
		j = m.udpRecoveryDiagnostics.Load()
	}
	return j
}

func (o *udpReplyDroughtObserver) bindDiagnostics(m *SessionManager, epoch routing.PolicyEpoch) {
	if o == nil || m == nil || o.closed.Load() {
		return
	}
	if previous := o.diagnostics.Load(); previous != nil && previous.manager == m && previous.epoch == epoch {
		return
	}
	b := &udpDroughtDiagnosticsBinding{manager: m, journal: m.recoveryJournal(), epoch: epoch}
	for {
		previous := o.diagnostics.Load()
		if previous != nil && previous.manager == m && previous.epoch == epoch {
			return
		}
		if o.diagnostics.CompareAndSwap(previous, b) {
			o.recordDiagnostic(UDPRecoveryEvent{Kind: "generation_opened", AtMS: time.Now().UnixMilli()})
			return
		}
	}
}

func (o *udpReplyDroughtObserver) recordDiagnostic(e UDPRecoveryEvent) {
	if o == nil {
		return
	}
	b := o.diagnostics.Load()
	if b == nil {
		return
	}
	e.Generation, e.PolicyEpoch = o.generation, uint64(b.epoch)
	j := b.journal
	j.mu.Lock()
	j.sequence++
	e.Sequence = j.sequence
	j.counts[e.Kind]++
	if len(j.records) == udpRecoveryJournalLimit {
		copy(j.records, j.records[1:])
		j.records = j.records[:len(j.records)-1]
		j.evicted++
	}
	j.records = append(j.records, e)
	j.mu.Unlock()
}

func (f *udpReplyDroughtFlow) associationSnapshot() UDPReplyDroughtAssociation {
	a := UDPReplyDroughtAssociation{Association: f.id, Client: f.client, Group: f.group, Node: f.node, UnattributedWrites: f.unattributedWrites.Load(), UnattributedReplies: f.unattributedReplies.Load()}
	if identity := f.identity.Load(); identity != nil {
		a.RuntimeID, a.PolicyEpoch, a.StartedAtMS = identity.RuntimeID, identity.PolicyEpoch, identity.StartedAtMS
	}
	return a
}

func (f *udpReplyDroughtFlow) recordUnattributed(reason string, now time.Time) {
	if f.observer.diagnostics.Load() == nil {
		return
	}
	a := f.associationSnapshot()
	f.observer.recordDiagnostic(UDPRecoveryEvent{Kind: "association_unattributed", Reason: reason, AtMS: f.observer.stamp(now) / int64(time.Millisecond), Association: &a})
}

func (f *udpReplyDroughtFlow) rowLocked(peer netip.AddrPort, p *udpDroughtPeerState, nano int64) UDPReplyDroughtPeer {
	completion := "local_write_completed"
	if !f.completionKnown {
		completion = "transport_acceptance_only"
	}
	r := UDPReplyDroughtPeer{Association: f.id, Client: f.client, Group: f.group, Node: f.node, Peer: peer.String(), WriteCompletion: completion, SuccessfulWrites: p.writes, Replies: p.replies, LastWriteMS: p.lastWrite / int64(time.Millisecond), LastReplyMS: p.lastReply / int64(time.Millisecond), AtMS: nano / int64(time.Millisecond), Eligibility: f.eligibility(p, nano), InvalidatedAtMS: p.invalidatedAt / int64(time.Millisecond)}
	r.CandidateEpisode = p.episode
	r.FirstObservedMS = p.first / int64(time.Millisecond)
	r.ReplyContract = "unknown"
	if f.observer.policy.RequestReply {
		r.ReplyContract = "configured_request_reply"
	}
	if identity := f.identity.Load(); identity != nil {
		r.RuntimeID, r.PolicyEpoch = identity.RuntimeID, identity.PolicyEpoch
	}
	epoch := nano / int64(udpDroughtBucketDuration)
	r.Windows = make([]UDPReplyDroughtWindow, 0, len(p.buckets))
	for i := int64(udpDroughtFullBuckets); i >= 0; i-- {
		e := epoch - i
		w := UDPReplyDroughtWindow{StartMS: e * int64(udpDroughtBucketDuration/time.Millisecond), EndMS: (e + 1) * int64(udpDroughtBucketDuration/time.Millisecond), Complete: i != 0}
		if e >= 0 {
			b := p.buckets[e%int64(len(p.buckets))]
			if b.epoch == e {
				w.Present, w.NonemptyWrites, w.Replies, w.Invalid = true, b.writes, b.replies, b.invalid
				w.Saturated = b.writes == udpDroughtBucketWriteLimit
			}
		}
		r.Windows = append(r.Windows, w)
	}
	return r
}

// This is a read-side coverage audit. It never transfers observation ownership
// or interprets bytes on an old endpoint as peer replies. Counts are lower
// bounds whenever the bounded output is truncated.
func (o *udpReplyDroughtObserver) coverage(now time.Time) UDPRecoveryCoverage {
	c := UDPRecoveryCoverage{Flows: []UDPRecoveryCoverageFlow{}, States: make(map[string]int)}
	if o == nil || o.closed.Load() {
		return c
	}
	b := o.diagnostics.Load()
	if b == nil {
		return c
	}
	b.manager.udpFlows.Range(func(_, value any) bool {
		f := value.(*UDPFlowRuntime)
		ue := f.endpoint
		if ue == nil || ue.dead.Load() || !isProxyBackedDialer(f.binding.Egress.Dialer) || f.binding.Egress.NetworkType.IsDns || f.binding.Egress.Outbound == nil {
			return true
		}
		group := f.binding.Egress.Outbound.Name
		if (o.policy.Client.IsValid() && f.src.Addr().Unmap() != o.policy.Client) || (o.policy.Group != "" && group != o.policy.Group) {
			return true
		}
		fixedPeer, _ := netip.ParseAddrPort(ue.DialTarget)
		fixedPeer = ue.droughtPeer(fixedPeer)
		if len(o.peers) > 0 && ue.poolKey.Dst.IsValid() && validDroughtPeer(fixedPeer) && !o.peers[fixedPeer] {
			return true
		}
		if len(c.Flows) >= udpDroughtPeerLimit {
			c.Truncated = true
			return false
		}
		row := UDPRecoveryCoverageFlow{RuntimeID: f.id, PolicyEpoch: uint64(f.binding.Route.PolicyEpoch), StartedAtMS: f.startUnixNano / int64(time.Millisecond), Client: f.src.String(), Group: group, Node: f.binding.Egress.Dialer.Property().Name}
		if ue.poolKey.Dst.IsValid() {
			row.OriginalTarget = ue.poolKey.Dst.String()
		}
		switch {
		case ue.replyDrought == nil || ue.replyDrought.observer != o || ue.replyDrought.closed.Load():
			row.State = "retained_owner_not_observed"
		case ue.replyDrought.unattributedWrites.Load() > 0:
			row.State = "peer_identity_incomplete"
		default:
			ue.replyDrought.mu.Lock()
			n := len(ue.replyDrought.peers)
			ue.replyDrought.mu.Unlock()
			row.State = "observed"
			if n == 0 {
				row.State = "no_peer_evidence_yet"
			}
		}
		// Source-only endpoints may serve peers outside an explicit scope.
		// Their old-generation coverage cannot be proven by a stored target.
		if row.State == "retained_owner_not_observed" && len(o.peers) > 0 && (!ue.poolKey.Dst.IsValid() || !validDroughtPeer(fixedPeer)) {
			row.State = "retained_peer_scope_unresolved"
		}
		c.Flows = append(c.Flows, row)
		c.States[row.State]++
		if row.State == "retained_owner_not_observed" || row.State == "retained_peer_scope_unresolved" {
			o.mu.Lock()
			_, seen := o.coverageSeen[f.id]
			admitted := len(o.coverageSeen) < udpDroughtPeerLimit
			if !seen && admitted {
				if o.coverageSeen == nil {
					o.coverageSeen = make(map[uint64]struct{})
				}
				o.coverageSeen[f.id] = struct{}{}
			}
			o.mu.Unlock()
			if !seen && admitted {
				o.recordDiagnostic(UDPRecoveryEvent{Kind: "coverage_missing", Reason: row.State, AtMS: now.UnixMilli(), Coverage: &row})
			} else if !seen {
				c.MissingEventsDedupFull = true
			}
		}
		return true
	})
	sort.Slice(c.Flows, func(i, j int) bool { return c.Flows[i].RuntimeID < c.Flows[j].RuntimeID })
	return c
}

func (c *ControlPlane) AdminUDPRecovery(after uint64, process string) UDPRecoverySnapshot {
	now := time.Now()
	s := UDPRecoverySnapshot{Schema: "kdae-udp-recovery-v1", AtMS: now.UnixMilli(), Mode: "off", Records: []UDPRecoveryEvent{}, EventCounts: make(map[string]uint64), Coverage: UDPRecoveryCoverage{Flows: []UDPRecoveryCoverageFlow{}, States: make(map[string]int)}, Thresholds: UDPRecoveryThresholds{BucketMS: 5000, FullBuckets: udpDroughtFullBuckets, WritesPerBucket: udpDroughtWritesPerBucket, ReplyHistory: 3, ReplyDroughtMS: 30000, RecentWriteMS: 5000, PeerLimit: udpDroughtPeerLimit, AssociationPeerLimit: udpDroughtAssociationPeerLimit, JournalLimit: udpRecoveryJournalLimit}}
	if c == nil {
		return s
	}
	m, _ := c.controlPlaneSessionManager()
	if m == nil {
		return s
	}
	s.Process = m.adminSnapshotID
	if o := c.udpReplyDrought; o != nil && !o.closed.Load() {
		s.Mode = "observe"
		s.Observation = o.snapshot(now)
		s.Coverage = o.coverage(now)
	}
	if process != "" && process != s.Process {
		s.CursorReset = "process_changed"
		after = 0
	}
	j := m.udpRecoveryDiagnostics.Load() // Off does not allocate a journal.
	if j == nil {
		if after > 0 {
			s.CursorReset = "cursor_ahead"
		}
		return s
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	s.LatestSequence, s.RingEvicted = j.sequence, j.evicted
	if after > j.sequence {
		s.CursorReset, after = "cursor_ahead", 0
	}
	s.NextSequence = after
	if len(j.records) > 0 {
		s.OldestSequence = j.records[0].Sequence
		if after < s.OldestSequence-1 {
			s.LostRecords = s.OldestSequence - 1 - after
		}
	}
	for k, n := range j.counts {
		s.EventCounts[k] = n
	}
	for _, e := range j.records {
		if e.Sequence <= after {
			continue
		}
		if len(s.Records) == udpRecoveryPageLimit {
			s.HasMore = true
			break
		}
		s.Records = append(s.Records, e)
		s.NextSequence = e.Sequence
	}
	return s
}
