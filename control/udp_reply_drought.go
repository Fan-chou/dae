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
	Mode       string                `json:"mode"`
	Generation uint64                `json:"generation"`
	Group      string                `json:"group"`
	Client     string                `json:"client,omitempty"`
	Contract   string                `json:"contract"`
	Stats      UDPReplyDroughtStats  `json:"stats"`
	Excluded   map[string]int        `json:"excluded"`
	Peers      []UDPReplyDroughtPeer `json:"peers"`
	Events     []UDPReplyDroughtPeer `json:"events"`
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
	Association      uint64 `json:"association"`
	Client           string `json:"client"`
	Group            string `json:"group"`
	Node             string `json:"node"`
	Peer             string `json:"peer"`
	WriteCompletion  string `json:"write_completion"`
	SuccessfulWrites uint64 `json:"successful_writes"`
	Replies          uint64 `json:"replies"`
	LastWriteMS      int64  `json:"last_write_ms"`
	LastReplyMS      int64  `json:"last_reply_ms"`
	AtMS             int64  `json:"at_ms"`
	Eligibility      string `json:"eligibility"`
}

type udpDroughtBucket struct {
	epoch   int64
	writes  int
	invalid bool
}
type udpDroughtPeerState struct {
	first, lastWrite, lastReply int64
	invalidatedAt               int64
	writes, replies             uint64
	buckets                     [udpDroughtFullBuckets + 1]udpDroughtBucket
	candidate                   bool
}

type udpReplyDroughtObserver struct {
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
	writes, replies, unattributedWrites, unattributedReplies                      atomic.Uint64
	admissionDropped, invalidated, evicted, candidates, rateLimited, eventEvicted atomic.Uint64
}

type udpReplyDroughtFlow struct {
	observer            *udpReplyDroughtObserver
	id                  uint64
	client, group, node string
	completionKnown     bool
	closed              atomic.Bool
	mu                  sync.Mutex // one association; no I/O or output under this lock
	peers               map[netip.AddrPort]*udpDroughtPeerState
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
		o.closed.Store(true)
		close(o.stop)
		<-o.done
		// Retained endpoints still hold their flow pointer after reload. Clear
		// each ledger outside the registry lock so those pointers retain no table.
		for _, f := range o.flowList() {
			f.Close()
		}
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

func (f *udpReplyDroughtFlow) write(peer netip.AddrPort, size int, now time.Time) {
	if f == nil || f.closed.Load() || f.observer.closed.Load() {
		return
	}
	o := f.observer
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if !validDroughtPeer(peer) {
		o.unattributedWrites.Add(1)
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
	p := f.peers[peer]
	if p == nil {
		o.mu.Lock()
		if o.closed.Load() || o.peerCount >= udpDroughtPeerLimit || len(f.peers) >= udpDroughtAssociationPeerLimit {
			o.mu.Unlock()
			o.admissionDropped.Add(1)
			return
		}
		o.flows[f.id] = f
		o.peerCount++
		o.mu.Unlock()
		if f.peers == nil {
			f.peers = make(map[netip.AddrPort]*udpDroughtPeerState)
		}
		p = &udpDroughtPeerState{first: o.stamp(now)}
		f.peers[peer] = p
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
		// Saturate: qualification does not need an unbounded packet counter.
		if b.writes < udpDroughtWritesPerBucket {
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
	defer f.mu.Unlock()
	if f.closed.Load() || f.observer.closed.Load() {
		return
	}
	p := f.peers[peer]
	if p == nil {
		f.observer.unattributedReplies.Add(1)
		return
	}
	nano := f.observer.stamp(now)
	p.checkClock(nano)
	p.lastReply = max(p.lastReply, nano)
	p.replies++
	p.candidate = false
	f.observer.replies.Add(1)
}

// A partial flush or local backpressure makes this entire observation bucket
// unusable. Successful items remain counted, but cannot support a candidate.
func (f *udpReplyDroughtFlow) invalidate(now time.Time) {
	if f == nil || f.closed.Load() || f.observer.closed.Load() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() || f.observer.closed.Load() {
		return
	}
	nano := f.observer.stamp(now)
	epoch := nano / int64(udpDroughtBucketDuration)
	for _, p := range f.peers {
		p.checkClock(nano)
		p.invalidatedAt = max(p.invalidatedAt, nano)
		b := &p.buckets[epoch%int64(len(p.buckets))]
		if b.epoch != epoch {
			*b = udpDroughtBucket{epoch: epoch}
		}
		b.invalid = true
		p.candidate = false
	}
	f.observer.invalidated.Add(1)
}

func (f *udpReplyDroughtFlow) Close() {
	if f == nil || f.closed.Swap(true) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.observer
	o.mu.Lock()
	if _, ok := o.flows[f.id]; ok {
		o.peerCount -= len(f.peers)
		delete(o.flows, f.id)
	}
	f.peers = nil
	o.mu.Unlock()
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
		last := max(p.lastWrite, p.lastReply)
		if scan && nano-last >= int64(udpDroughtIdleTTL) {
			delete(f.peers, peer)
			f.observer.mu.Lock()
			f.observer.peerCount--
			if len(f.peers) == 0 {
				delete(f.observer.flows, f.id)
			}
			f.observer.mu.Unlock()
			f.observer.evicted.Add(1)
			continue
		}
		completion := "local_write_completed"
		if !f.completionKnown {
			completion = "transport_acceptance_only"
		}
		row := UDPReplyDroughtPeer{Association: f.id, Client: f.client, Group: f.group, Node: f.node, Peer: peer.String(), WriteCompletion: completion, SuccessfulWrites: p.writes, Replies: p.replies, LastWriteMS: p.lastWrite / int64(time.Millisecond), LastReplyMS: p.lastReply / int64(time.Millisecond), AtMS: nano / int64(time.Millisecond), Eligibility: f.eligibility(p, nano)}
		rows = append(rows, row)
		if scan {
			candidate := row.Eligibility == "candidate"
			if candidate && !p.candidate {
				events = append(events, row)
			}
			p.candidate = candidate
		}
	}
	return
}

func (o *udpReplyDroughtObserver) scan(now time.Time) {
	for _, f := range o.flowList() {
		_, events := f.rows(now, true)
		for _, e := range events {
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
	s := &UDPReplyDroughtSnapshot{Mode: "observe", Generation: o.generation, Group: o.policy.Group, Contract: contract, Excluded: make(map[string]int), Peers: []UDPReplyDroughtPeer{}, Events: []UDPReplyDroughtPeer{}}
	if o.policy.Client.IsValid() {
		s.Client = o.policy.Client.String()
	}
	for _, f := range o.flowList() {
		rows, _ := f.rows(now, false)
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
