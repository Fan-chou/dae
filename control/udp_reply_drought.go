// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
)

const (
	udpDroughtPeerLimit            = 256
	udpDroughtAssociationPeerLimit = 8
	udpDroughtBucketDuration       = 5 * time.Second
	udpDroughtFullBuckets          = 6
	udpDroughtWritesPerBucket      = 10
	udpDroughtIdleTTL              = 60 * time.Second
	udpDroughtEventLimit           = 32
)

var udpDroughtGeneration atomic.Uint64

// UDPReplyDroughtSnapshot contains observations only. Neither this ledger nor
// its scanner has access to endpoint retirement, node health or switch budgets.
type UDPReplyDroughtSnapshot struct {
	Mode         string                       `json:"mode"`
	Generation   uint64                       `json:"generation"`
	Group        string                       `json:"group"`
	Client       string                       `json:"client,omitempty"`
	Contract     string                       `json:"contract"`
	Stats        UDPReplyDroughtStats         `json:"stats"`
	Excluded     map[string]int               `json:"excluded"`
	Peers        []UDPReplyDroughtPeer        `json:"peers"`
	Associations []UDPReplyDroughtAssociation `json:"associations"`
	Events       []UDPReplyDroughtPeer        `json:"events"`
}

// Unattributed replies belong to an association, never an inferred peer.
type UDPReplyDroughtAssociation struct {
	RuntimeID           uint64 `json:"runtime_id"`
	PolicyEpoch         uint64 `json:"policy_epoch"`
	StartedAtMS         int64  `json:"started_at_ms"`
	Association         uint64 `json:"association"`
	Client              string `json:"client"`
	Group               string `json:"group"`
	Node                string `json:"node"`
	UnattributedWrites  uint64 `json:"unattributed_writes"`
	UnattributedReplies uint64 `json:"unattributed_replies"`
}

type UDPReplyDroughtStats struct {
	SuccessfulWrites    uint64 `json:"successful_writes"`
	Replies             uint64 `json:"replies"`
	UnattributedWrites  uint64 `json:"unattributed_writes"`
	UnattributedReplies uint64 `json:"unattributed_replies"`
	AdmissionDropped    uint64 `json:"admission_dropped"`
	InvalidatedWindows  uint64 `json:"invalidated_windows"`
	PeerEvicted         uint64 `json:"peer_evicted"`
	Candidates          uint64 `json:"candidates"`
	EventRateLimited    uint64 `json:"event_rate_limited"`
	EventEvicted        uint64 `json:"event_evicted"`
}

type UDPReplyDroughtPeer struct {
	OriginalTarget       string                  `json:"original_target,omitempty"`
	OriginalFamily       string                  `json:"original_family,omitempty"`
	ActualPeerFamily     string                  `json:"actual_peer_family,omitempty"`
	TargetKind           string                  `json:"target_kind,omitempty"`
	DNSPinOwnerID        uint64                  `json:"dns_pin_owner_id,omitempty"`
	FlowIdentityRevision uint64                  `json:"flow_identity_revision,omitempty"`
	LineageID            uint64                  `json:"lineage_id"`
	Revision             uint64                  `json:"ownership_revision"`
	RuntimeID            uint64                  `json:"runtime_id"`
	PolicyEpoch          uint64                  `json:"policy_epoch"`
	Association          uint64                  `json:"association"`
	Client               string                  `json:"client"`
	Group                string                  `json:"group"`
	Node                 string                  `json:"node"`
	Peer                 string                  `json:"peer"`
	WriteCompletion      string                  `json:"write_completion"`
	SuccessfulWrites     uint64                  `json:"successful_writes"`
	Replies              uint64                  `json:"replies"`
	LastWriteMS          int64                   `json:"last_write_ms"`
	LastReplyMS          int64                   `json:"last_reply_ms"`
	AtMS                 int64                   `json:"at_ms"`
	Eligibility          string                  `json:"eligibility"`
	InvalidatedAtMS      int64                   `json:"invalidated_at_ms,omitempty"`
	CandidateEpisode     uint64                  `json:"candidate_episode"`
	FirstObservedMS      int64                   `json:"first_observed_ms"`
	ReplyContract        string                  `json:"reply_contract"`
	Windows              []UDPReplyDroughtWindow `json:"windows"`
}

// Complete describes the time interval, Present describes recorded evidence.
// A missing bucket is not evidence of a completed, empty transport window.
type UDPReplyDroughtWindow struct {
	StartMS        int64  `json:"start_ms"`
	EndMS          int64  `json:"end_ms"`
	Complete       bool   `json:"complete"`
	Present        bool   `json:"present"`
	NonemptyWrites int    `json:"nonempty_successful_writes"`
	Replies        uint64 `json:"replies"`
	Invalid        bool   `json:"invalid"`
	Saturated      bool   `json:"writes_saturated"`
}

type udpDroughtBucket struct {
	epoch   int64
	writes  int
	replies uint64
	invalid bool
}
type udpDroughtPeerState struct {
	first, lastWrite, lastReply int64
	invalidatedAt               int64
	writes, replies             uint64
	buckets                     [udpDroughtFullBuckets + 1]udpDroughtBucket
	candidate                   bool
	episode                     uint64
}

type udpReplyDroughtObserver struct {
	execution                                                                     atomic.Pointer[udpRebuildExecutor]
	executionMu                                                                   sync.Mutex
	policy                                                                        config.UDPReplyDroughtPolicy
	peers                                                                         map[netip.AddrPort]bool
	generation                                                                    uint64
	clockOrigin                                                                   time.Time
	closed                                                                        atomic.Bool
	closeOnce                                                                     sync.Once
	stop, done                                                                    chan struct{}
	nextAssociation                                                               atomic.Uint64
	mu                                                                            sync.Mutex // admission and bounded event ring only; never scans under this lock
	flows                                                                         map[uint64]*udpReplyDroughtFlow
	peerCount                                                                     int
	events                                                                        []UDPReplyDroughtPeer
	rateMinute                                                                    int64
	rateCount                                                                     int
	diagnostics                                                                   atomic.Pointer[udpDroughtDiagnosticsBinding]
	coverageSeen                                                                  map[uint64]struct{}
	writes, replies, unattributedWrites, unattributedReplies                      atomic.Uint64
	admissionDropped, invalidated, evicted, candidates, rateLimited, eventEvicted atomic.Uint64
}

type udpReplyDroughtFlow struct {
	endpoint                                *UdpEndpoint // immutable before adoption
	observer                                *udpReplyDroughtObserver
	id                                      uint64
	client, group, node                     string
	completionKnown                         bool
	closed                                  atomic.Bool
	mu                                      sync.Mutex // one association; no I/O or output under this lock
	peers                                   map[netip.AddrPort]*udpDroughtPeerState
	unattributedWrites, unattributedReplies atomic.Uint64
	identity                                atomic.Pointer[udpDroughtIdentity]
	nextEpisode                             uint64 // association-local, under mu
}

func newUDPReplyDroughtObserver(policy config.UDPReplyDroughtPolicy) *udpReplyDroughtObserver {
	if !policy.Observe {
		return nil
	}
	o := &udpReplyDroughtObserver{policy: policy, generation: udpDroughtGeneration.Add(1), clockOrigin: time.Now(), peers: make(map[netip.AddrPort]bool), flows: make(map[uint64]*udpReplyDroughtFlow), stop: make(chan struct{}), done: make(chan struct{})}
	for _, p := range policy.Peers {
		o.peers[p] = true
	}
	go func() {
		defer close(o.done)
		ticker := time.NewTicker(udpDroughtBucketDuration)
		defer ticker.Stop()
		for {
			select {
			case <-o.stop:
				return
			case now := <-ticker.C:
				o.scan(now)
			}
		}
	}()
	return o
}

func (o *udpReplyDroughtObserver) Close() error {
	if o == nil {
		return nil
	}
	o.closeOnce.Do(func() {
		o.stopExecution()
		o.closed.Store(true)
		close(o.stop)
		<-o.done
		// Retained endpoints still hold their flow pointer after reload. Clear
		// each ledger outside the registry lock so those pointers retain no table.
		for _, f := range o.flowList() {
			f.closeWithReason("generation_closed")
		}
		o.recordDiagnostic(UDPRecoveryEvent{Kind: "generation_closed", AtMS: time.Now().UnixMilli()})
		o.mu.Lock()
		o.flows = nil
		o.peerCount = 0
		o.events = nil
		o.mu.Unlock()
	})
	return nil
}

func (o *udpReplyDroughtObserver) newFlow(client, group, node string, completionKnown bool) *udpReplyDroughtFlow {
	if o == nil || o.closed.Load() || (o.policy.Group != "" && o.policy.Group != group) {
		return nil
	}
	if o.policy.Client.IsValid() {
		peer, err := netip.ParseAddrPort(client)
		if err != nil || peer.Addr().Unmap() != o.policy.Client {
			return nil
		}
	}
	return &udpReplyDroughtFlow{observer: o, id: o.nextAssociation.Add(1), client: client, group: group, node: node, completionKnown: completionKnown}
}

func validDroughtPeer(p netip.AddrPort) bool {
	return p.IsValid() && p.Port() != 0 && p.Port() != 53 && p.Addr().Zone() == "" && !p.Addr().IsUnspecified() && !p.Addr().IsMulticast()
}

// Production callbacks and ticker values retain Go's monotonic clock. Anchor
// elapsed time once to keep positive bucket indices and approximate UTC fields.
func (o *udpReplyDroughtObserver) stamp(now time.Time) int64 {
	return o.clockOrigin.UnixNano() + now.Sub(o.clockOrigin).Nanoseconds()
}

func (p *udpDroughtPeerState) checkClock(nano int64) {
	last := max(p.lastWrite, p.lastReply)
	// Sub-second callback reordering is normal. A larger regression (including
	// synthetic timestamps without monotonic data) discards all prior evidence.
	if nano < last-int64(time.Second) {
		clear(p.buckets[:])
		p.invalidatedAt = max(p.invalidatedAt, last)
		p.first = last
		p.candidate = false
	}
}

// Admit intent before transport I/O so a fast reply cannot overtake peer
// registration. Intent never counts as a successful write or a full bucket.
func (f *udpReplyDroughtFlow) prepare(peer netip.AddrPort, now time.Time) {
	f.prepareVisible(peer, netip.AddrPort{}, now)
}

func (f *udpReplyDroughtFlow) prepareVisible(peer, visible netip.AddrPort, now time.Time) {
	if f == nil || f.closed.Load() || f.observer.closed.Load() {
		return
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if !validDroughtPeer(peer) || (len(f.observer.peers) > 0 && !f.observer.peers[peer]) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed.Load() && !f.observer.closed.Load() {
		f.admitLocked(peer, visible, now)
	}
}

// The flow lock protects this peer table; the registry lock only reserves
// bounded space. Rejected intent is counted once when its write completes.
func (f *udpReplyDroughtFlow) admitLocked(peer, visible netip.AddrPort, now time.Time) *udpDroughtPeerState {
	if p := f.peers[peer]; p != nil {
		return p
	}
	o := f.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed.Load() || o.peerCount >= udpDroughtPeerLimit || len(f.peers) >= udpDroughtAssociationPeerLimit || !o.registerFlowLocked(f) {
		return nil
	}
	o.peerCount++
	if f.peers == nil {
		f.peers = make(map[netip.AddrPort]*udpDroughtPeerState)
	}
	p := &udpDroughtPeerState{first: o.stamp(now)}
	if o.policy.Enforce && f.endpoint != nil {
		if f.endpoint.rebuildPeer(peer) == nil {
			ue := f.endpoint
			if ue.sessionRuntime == nil {
				o.peerCount--
				return nil
			}
			original := ue.rebuildOriginal(peer)
			if !ue.poolKey.Dst.IsValid() {
				if vis := unmapPort(visible); validDroughtPeer(vis) {
					client := ue.poolKey.Src.Addr().Unmap()
					if client.IsValid() && client.Is4() == vis.Addr().Is4() && vis.Addr().Is4() != peer.Addr().Is4() {
						original = vis
					}
				}
			}
			s := &udpRebuildPeer{peer: peer, original: original, lineageID: ue.rebuildLineage, manager: ue.sessionRuntime.manager, changed: make(chan struct{})}
			s.owner.Store(&udpRebuildOwnership{endpoint: ue, revision: ue.rebuildRevision})
			if !ue.installRebuildPeer(peer, s) {
				o.peerCount--
				return nil
			}
		}
	}
	f.peers[peer] = p
	return p
}

// Unknown-only associations also need generation teardown and final counters.
// Bound association storage independently of peer storage.
func (o *udpReplyDroughtObserver) registerFlowLocked(f *udpReplyDroughtFlow) bool {
	if _, exists := o.flows[f.id]; exists {
		return true
	}
	if o.closed.Load() || len(o.flows) >= udpDroughtPeerLimit {
		return false
	}
	o.flows[f.id] = f
	return true
}

func (f *udpReplyDroughtFlow) registerUnattributedLocked() {
	o := f.observer
	o.mu.Lock()
	if !o.registerFlowLocked(f) {
		o.admissionDropped.Add(1)
	}
	o.mu.Unlock()
}

func (f *udpReplyDroughtFlow) write(peer netip.AddrPort, size int, now time.Time) {
	if f == nil || f.closed.Load() || f.observer.closed.Load() {
		return
	}
	o := f.observer
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if !validDroughtPeer(peer) {
		f.mu.Lock()
		if f.closed.Load() || o.closed.Load() {
			f.mu.Unlock()
			return
		}
		f.registerUnattributedLocked()
		o.unattributedWrites.Add(1)
		first := f.unattributedWrites.Add(1) == 1
		f.mu.Unlock()
		if first {
			f.recordUnattributed("first_unattributed_write", now)
		}
		return
	}
	if len(o.peers) > 0 && !o.peers[peer] {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() || o.closed.Load() {
		return
	}
	p := f.admitLocked(peer, netip.AddrPort{}, now)
	if p == nil {
		o.admissionDropped.Add(1)
		return
	}
	p.writes++
	nano := o.stamp(now)
	p.checkClock(nano)
	p.lastWrite = max(p.lastWrite, nano)
	o.writes.Add(1)
	// Empty datagrams can be keepalives and never count toward qualification.
	if size > 0 {
		epoch := nano / int64(udpDroughtBucketDuration)
		b := &p.buckets[epoch%int64(len(p.buckets))]
		if b.epoch != epoch {
			*b = udpDroughtBucket{epoch: epoch}
		}
		// Keep actual activity for diagnostics, with an explicit lower-bound
		// flag at saturation. Qualification still uses the original threshold.
		if b.writes < udpDroughtBucketWriteLimit {
			b.writes++
		}
	}
}

func (f *udpReplyDroughtFlow) reply(peer netip.AddrPort, now time.Time) {
	if f == nil || f.closed.Load() || f.observer.closed.Load() {
		return
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	f.mu.Lock()
	if f.closed.Load() || f.observer.closed.Load() {
		f.mu.Unlock()
		return
	}
	p := f.peers[peer]
	if p == nil {
		f.registerUnattributedLocked()
		f.observer.unattributedReplies.Add(1)
		first := f.unattributedReplies.Add(1) == 1
		f.mu.Unlock()
		if first {
			f.recordUnattributed("first_unattributed_reply", now)
		}
		return
	}
	wasCandidate := p.candidate
	nano := f.observer.stamp(now)
	p.checkClock(nano)
	p.lastReply = max(p.lastReply, nano)
	p.replies++
	epoch := nano / int64(udpDroughtBucketDuration)
	b := &p.buckets[epoch%int64(len(p.buckets))]
	if b.epoch != epoch {
		*b = udpDroughtBucket{epoch: epoch}
	}
	b.replies++
	p.candidate = false
	f.observer.replies.Add(1)
	var ended UDPReplyDroughtPeer
	if wasCandidate {
		ended = f.rowLocked(peer, p, nano)
	}
	f.mu.Unlock()
	if wasCandidate {
		f.observer.recordDiagnostic(UDPRecoveryEvent{Kind: "candidate_ended", Reason: "reply_resumed_on_original", AtMS: ended.AtMS, Peer: &ended})
	}
}

// A partial flush or local backpressure makes this entire observation bucket
// unusable. Successful items remain counted, but cannot support a candidate.
func (f *udpReplyDroughtFlow) invalidate(now time.Time) {
	if f == nil || f.closed.Load() || f.observer.closed.Load() {
		return
	}
	f.mu.Lock()
	if f.closed.Load() || f.observer.closed.Load() {
		f.mu.Unlock()
		return
	}
	nano := f.observer.stamp(now)
	epoch := nano / int64(udpDroughtBucketDuration)
	var ended []UDPReplyDroughtPeer
	for peer, p := range f.peers {
		wasCandidate := p.candidate
		p.checkClock(nano)
		p.invalidatedAt = max(p.invalidatedAt, nano)
		b := &p.buckets[epoch%int64(len(p.buckets))]
		if b.epoch != epoch {
			*b = udpDroughtBucket{epoch: epoch}
		}
		b.invalid = true
		p.candidate = false
		if wasCandidate {
			ended = append(ended, f.rowLocked(peer, p, nano))
		}
	}
	f.observer.invalidated.Add(1)
	f.mu.Unlock()
	for i := range ended {
		f.observer.recordDiagnostic(UDPRecoveryEvent{Kind: "candidate_ended", Reason: "local_window_invalidated", AtMS: ended[i].AtMS, Peer: &ended[i]})
	}
}

func (f *udpReplyDroughtFlow) Close() {
	f.closeWithReason("endpoint_closed")
}

func (f *udpReplyDroughtFlow) closeWithReason(reason string) {
	if f == nil || f.closed.Swap(true) {
		return
	}
	f.mu.Lock()
	o := f.observer
	// Final evidence survives peer eviction, endpoint teardown and reload.
	rows := make([]UDPReplyDroughtPeer, 0, len(f.peers))
	nano := o.stamp(time.Now())
	for peer, p := range f.peers {
		rows = append(rows, f.rowLocked(peer, p, nano))
	}
	o.mu.Lock()
	if _, ok := o.flows[f.id]; ok {
		o.peerCount -= len(f.peers)
		delete(o.flows, f.id)
	}
	f.peers = nil
	o.mu.Unlock()
	f.mu.Unlock()
	association := f.associationSnapshot()
	for i := range rows {
		o.recordDiagnostic(UDPRecoveryEvent{Kind: "observation_ended", Reason: reason, AtMS: nano / int64(time.Millisecond), Peer: &rows[i], Association: &association})
	}
	if len(rows) == 0 && (association.UnattributedWrites > 0 || association.UnattributedReplies > 0) {
		o.recordDiagnostic(UDPRecoveryEvent{Kind: "association_ended", Reason: reason, AtMS: nano / int64(time.Millisecond), Association: &association})
	}
}

func (f *udpReplyDroughtFlow) eligibility(p *udpDroughtPeerState, now int64) string {
	if !f.observer.policy.RequestReply {
		return "unknown_reply_semantics"
	}
	if !f.completionKnown {
		return "transport_completion_unknown"
	}
	if now < p.lastWrite || now < p.lastReply || now < p.first {
		return "clock_uncertain"
	}
	if p.replies < 3 {
		return "reply_history_insufficient"
	}
	epoch := now / int64(udpDroughtBucketDuration)
	start := (epoch - udpDroughtFullBuckets) * int64(udpDroughtBucketDuration)
	if p.invalidatedAt >= start {
		return "incomplete_window"
	}
	if p.first > start {
		return "warming_up"
	}
	if p.lastReply > start || now-p.lastReply < int64(udpDroughtFullBuckets*udpDroughtBucketDuration) {
		return "recent_reply"
	}
	if now-p.lastWrite > int64(udpDroughtBucketDuration) {
		return "paused"
	}
	for i := int64(1); i <= udpDroughtFullBuckets; i++ {
		b := p.buckets[(epoch-i)%int64(len(p.buckets))]
		if b.epoch != epoch-i || b.invalid {
			return "incomplete_window"
		}
		if b.writes < udpDroughtWritesPerBucket {
			return "insufficient_activity"
		}
	}
	return "candidate"
}

func (o *udpReplyDroughtObserver) flowList() []*udpReplyDroughtFlow {
	o.mu.Lock()
	defer o.mu.Unlock()
	flows := make([]*udpReplyDroughtFlow, 0, len(o.flows))
	for _, f := range o.flows {
		flows = append(flows, f)
	}
	return flows
}

func (f *udpReplyDroughtFlow) rows(now time.Time, scan bool) (rows, events []UDPReplyDroughtPeer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() || f.observer.closed.Load() {
		return
	}
	nano := f.observer.stamp(now)
	for peer, p := range f.peers {
		last := max(p.first, p.lastWrite, p.lastReply)
		if scan && nano-last >= int64(udpDroughtIdleTTL) {
			ended := f.rowLocked(peer, p, nano)
			ended.Eligibility = "idle_peer_evicted"
			events = append(events, ended)
			delete(f.peers, peer)
			f.observer.mu.Lock()
			f.observer.peerCount--
			if len(f.peers) == 0 && f.unattributedWrites.Load() == 0 && f.unattributedReplies.Load() == 0 {
				delete(f.observer.flows, f.id)
			}
			f.observer.mu.Unlock()
			f.observer.evicted.Add(1)
			continue
		}
		row := f.rowLocked(peer, p, nano)
		rows = append(rows, row)
		if scan {
			candidate := row.Eligibility == "candidate"
			if candidate && !p.candidate {
				f.nextEpisode++
				p.episode = f.nextEpisode
				row.CandidateEpisode = p.episode
				events = append(events, row)
			} else if !candidate && p.candidate {
				events = append(events, row)
			}
			p.candidate = candidate
		}
		rows[len(rows)-1].CandidateEpisode = p.episode
	}
	return
}

func (o *udpReplyDroughtObserver) scan(now time.Time) {
	for _, f := range o.flowList() {
		rows, events := f.rows(now, true)
		if x := o.execution.Load(); x != nil {
			for _, row := range rows {
				if row.Eligibility == "candidate" {
					x.enqueue(f, row, now)
				}
			}
		}
		for _, e := range events {
			if e.Eligibility == "idle_peer_evicted" {
				o.recordDiagnostic(UDPRecoveryEvent{Kind: "observation_ended", Reason: e.Eligibility, AtMS: e.AtMS, Peer: &e})
				continue
			}
			if e.Eligibility != "candidate" {
				o.recordDiagnostic(UDPRecoveryEvent{Kind: "candidate_ended", Reason: e.Eligibility, AtMS: e.AtMS, Peer: &e})
				continue
			}
			// The process journal is independent of legacy event log limiting.
			o.recordDiagnostic(UDPRecoveryEvent{Kind: "qualified", AtMS: e.AtMS, Peer: &e})
			o.mu.Lock()
			if o.closed.Load() {
				o.mu.Unlock()
				return
			}
			o.candidates.Add(1)
			minute := now.Unix() / 60
			if o.rateMinute != minute {
				o.rateMinute, o.rateCount = minute, 0
			}
			if o.rateCount >= 20 {
				o.rateLimited.Add(1)
				o.mu.Unlock()
				continue
			}
			o.rateCount++
			if len(o.events) == udpDroughtEventLimit {
				copy(o.events, o.events[1:])
				o.events = o.events[:len(o.events)-1]
				o.eventEvicted.Add(1)
			}
			o.events = append(o.events, e)
			o.mu.Unlock()
		}
	}
}

func (o *udpReplyDroughtObserver) snapshot(now time.Time) *UDPReplyDroughtSnapshot {
	if o == nil || o.closed.Load() {
		return nil
	}
	contract := "unknown"
	if o.policy.RequestReply {
		contract = "configured_request_reply"
	}
	s := &UDPReplyDroughtSnapshot{Mode: "observe", Generation: o.generation, Group: o.policy.Group, Contract: contract, Excluded: make(map[string]int), Peers: []UDPReplyDroughtPeer{}, Associations: []UDPReplyDroughtAssociation{}, Events: []UDPReplyDroughtPeer{}}
	if o.policy.Enforce {
		s.Mode = "enforce"
	}
	if o.policy.Client.IsValid() {
		s.Client = o.policy.Client.String()
	}
	for _, f := range o.flowList() {
		rows, _ := f.rows(now, false)
		if (len(rows) > 0 || f.unattributedWrites.Load() > 0 || f.unattributedReplies.Load() > 0) && len(s.Associations) < udpDroughtPeerLimit {
			identity := f.identity.Load()
			s.Associations = append(s.Associations, UDPReplyDroughtAssociation{
				Association: f.id, Client: f.client, Group: f.group, Node: f.node,
				UnattributedWrites: f.unattributedWrites.Load(), UnattributedReplies: f.unattributedReplies.Load(),
			})
			if identity != nil {
				a := &s.Associations[len(s.Associations)-1]
				a.RuntimeID, a.PolicyEpoch, a.StartedAtMS = identity.RuntimeID, identity.PolicyEpoch, identity.StartedAtMS
			}
		}
		// A snapshot can span concurrent eviction/admission. Bound output as
		// well as live storage, even though rows are not a single atomic view.
		rows = rows[:min(len(rows), udpDroughtPeerLimit-len(s.Peers))]
		for _, row := range rows {
			if row.Eligibility != "candidate" {
				s.Excluded[row.Eligibility]++
			}
		}
		s.Peers = append(s.Peers, rows...)
	}
	sort.Slice(s.Peers, func(i, j int) bool {
		if s.Peers[i].Association == s.Peers[j].Association {
			return s.Peers[i].Peer < s.Peers[j].Peer
		}
		return s.Peers[i].Association < s.Peers[j].Association
	})
	sort.Slice(s.Associations, func(i, j int) bool { return s.Associations[i].Association < s.Associations[j].Association })
	o.mu.Lock()
	s.Events = append(s.Events, o.events...)
	o.mu.Unlock()
	s.Stats = UDPReplyDroughtStats{SuccessfulWrites: o.writes.Load(), Replies: o.replies.Load(), UnattributedWrites: o.unattributedWrites.Load(), UnattributedReplies: o.unattributedReplies.Load(), AdmissionDropped: o.admissionDropped.Load(), InvalidatedWindows: o.invalidated.Load(), PeerEvicted: o.evicted.Load(), Candidates: o.candidates.Load(), EventRateLimited: o.rateLimited.Load(), EventEvicted: o.eventEvicted.Load()}
	return s
}

func (ue *UdpEndpoint) droughtPeer(peer netip.AddrPort) netip.AddrPort {
	if ue.crossFamily != nil {
		if decoded, _, err := ue.crossFamily.decode(peer); err == nil {
			peer = decoded
		} else {
			return netip.AddrPort{}
		}
	}
	return peer
}

func (ue *UdpEndpoint) observeDroughtWrite(addr string, size int, now time.Time) {
	if ue.replyDrought == nil {
		return
	}
	peer, _ := netip.ParseAddrPort(addr)
	ue.replyDrought.write(ue.droughtPeer(peer), size, now)
}

func (ue *UdpEndpoint) prepareDroughtWrite(addr string) {
	ue.prepareDroughtWriteVisible(addr, netip.AddrPort{})
}

func (ue *UdpEndpoint) prepareDroughtWriteVisible(addr string, visible netip.AddrPort) {
	if ue.replyDrought == nil {
		return
	}
	peer, _ := netip.ParseAddrPort(addr)
	ue.replyDrought.prepareVisible(ue.droughtPeer(peer), visible, time.Now())
}

// Call before releasing the batch mutex: item addresses and payloads still
// belong to that batch. A partial success counts exactly its successful prefix.
func (ue *UdpEndpoint) observeDroughtBatch(items []netproxy.BatchItem, n int, err error, now time.Time) {
	if ue.replyDrought == nil {
		return
	}
	for _, item := range items[:max(0, min(n, len(items)))] {
		ue.observeDroughtWrite(item.Addr, len(item.Data), now)
	}
	if err != nil || n != len(items) {
		ue.replyDrought.invalidate(now)
	}
}
