// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpRebuildLedgerLimit     = 256
	udpRebuildWindow          = time.Minute
	udpRebuildTicketTTL       = 10 * time.Second
	udpRebuildGroupLimit      = 2
	udpRebuildProcessLimit    = 8
	udpRebuildRequiredReplies = 3
)

type udpRebuildKey struct {
	src, original, peer netip.AddrPort
	group               string
}

type udpRebuildAttempt struct {
	at    time.Time
	group string
}
type udpRebuildRecord struct {
	key                  udpRebuildKey
	slot                 *udpRebuildPeer
	owners               map[*UdpEndpoint]struct{}
	lastAttempt, endedAt time.Time
	ticket               *udpRebuildTicket
	state                string
	commits, replies     uint64
}
type udpRebuildTicket struct {
	record                       *udpRebuildRecord
	expires                      time.Time
	started, committed, finished bool
}

// Only reserve, attempt, commit and lifecycle operations take this mutex.
// The normal packet path uses the per-peer claim, never the process ledger.
type udpRebuildLedger struct {
	claimRetry, lateReply, handoffTimeout atomic.Uint64
	mu                                    sync.Mutex
	records                               map[udpRebuildKey]*udpRebuildRecord
	attempts                              []udpRebuildAttempt
	counts                                map[string]uint64
}

type UDPRebuildRecordSnapshot struct {
	Client        string `json:"client"`
	Original      string `json:"original"`
	Peer          string `json:"peer"`
	Group         string `json:"group"`
	PolicyEpoch   uint64 `json:"policy_epoch"`
	RuntimeID     uint64 `json:"runtime_id"`
	Revision      uint64 `json:"ownership_revision"`
	LastAttemptMS int64  `json:"last_attempt_ms,omitempty"`
	RetryAtMS     int64  `json:"retry_at_ms,omitempty"`
	LineageID     uint64 `json:"lineage_id"`
	State         string `json:"state"`
	LiveOwners    int    `json:"live_owners"`
	Commits       uint64 `json:"commits"`
	FreshReplies  uint64 `json:"fresh_replies"`
}
type UDPRebuildSnapshot struct {
	PreparationWorkers   int                        `json:"preparation_workers"`
	QueueLimit           int                        `json:"queue_limit"`
	PreparationTimeoutMS int                        `json:"preparation_timeout_ms"`
	FenceTimeoutMS       int                        `json:"fence_timeout_ms"`
	TicketTTLMS          int                        `json:"ticket_ttl_ms"`
	Records              []UDPRebuildRecordSnapshot `json:"records"`
	Counts               map[string]uint64          `json:"counts"`
	AttemptsInWindow     int                        `json:"attempts_in_window"`
	Reserved             int                        `json:"reserved"`
	GroupAttempts        map[string]int             `json:"group_attempts_in_window"`
	RecordLimit          int                        `json:"record_limit"`
	PeerLimit            int                        `json:"peer_limit_per_minute"`
	GroupLimit           int                        `json:"group_limit_per_minute"`
	ProcessLimit         int                        `json:"process_limit_per_minute"`
	RequiredFreshReplies int                        `json:"required_fresh_replies"`
}

func (m *SessionManager) rebuildLedger() *udpRebuildLedger {
	l := m.udpRebuild.Load()
	if l == nil {
		candidate := &udpRebuildLedger{records: make(map[udpRebuildKey]*udpRebuildRecord), counts: make(map[string]uint64)}
		if m.udpRebuild.CompareAndSwap(nil, candidate) {
			l = candidate
		} else {
			l = m.udpRebuild.Load()
		}
	}
	return l
}

func (l *udpRebuildLedger) reserve(key udpRebuildKey, slot *udpRebuildPeer, old *UdpEndpoint, now time.Time) (*udpRebuildTicket, string) {
	// Close marks dead under this lock before its one-shot owner teardown.
	// Registration must either precede teardown or reject the closed endpoint.
	old.rebuildLifecycleMu.Lock()
	defer old.rebuildLifecycleMu.Unlock()
	if old.dead.Load() {
		return nil, "owner_changed"
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for k, r := range l.records {
		if len(r.owners) == 0 && r.ticket == nil && !r.endedAt.IsZero() && now.Sub(r.endedAt) >= udpRebuildWindow {
			owner := r.slot.owner.Load()
			if owner != nil && owner.endpoint.poolRef != nil {
				owner.endpoint.poolRef.rebuildOverrides.CompareAndDelete(owner.endpoint.poolKey, r.slot)
			}
			delete(l.records, k)
		}
	}
	r := l.records[key]
	if r != nil {
		if r.ticket != nil {
			return nil, "already_reserved"
		}
		if r.slot != slot {
			return nil, "lineage_conflict"
		}
		if r.commits > 0 && r.replies < udpRebuildRequiredReplies {
			return nil, "awaiting_replies"
		}
		if !r.lastAttempt.IsZero() && now.Sub(r.lastAttempt) < udpRebuildWindow {
			return nil, "peer_budget"
		}
	} else if len(l.records) >= udpRebuildLedgerLimit {
		return nil, "ledger_full"
	}
	process, group := 0, 0
	for _, a := range l.attempts {
		if now.Sub(a.at) < udpRebuildWindow {
			process++
			if a.group == key.group {
				group++
			}
		}
	}
	for _, existing := range l.records {
		if t := existing.ticket; t != nil && !t.started && !t.finished {
			process++
			if existing.key.group == key.group {
				group++
			}
		}
	}
	if process >= udpRebuildProcessLimit {
		return nil, "process_budget"
	}
	if group >= udpRebuildGroupLimit {
		return nil, "group_budget"
	}
	if r == nil {
		r = &udpRebuildRecord{key: key, slot: slot, owners: map[*UdpEndpoint]struct{}{old: {}}, state: "qualified"}
		l.records[key] = r
		slot.record.Store(r)
	}
	t := &udpRebuildTicket{record: r, expires: now.Add(udpRebuildTicketTTL)}
	r.ticket = t
	r.state = "reserved"
	l.counts["reserved"]++
	return t, ""
}

func (l *udpRebuildLedger) start(t *udpRebuildTicket, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.finished || t.started || t.record.ticket != t || !now.Before(t.expires) {
		return false
	}
	// Prune only at an actual attempt, without changing read-only snapshots.
	kept := l.attempts[:0]
	for _, a := range l.attempts {
		if now.Sub(a.at) < udpRebuildWindow {
			kept = append(kept, a)
		}
	}
	l.attempts = append(kept, udpRebuildAttempt{at: now, group: t.record.key.group})
	t.started = true
	t.record.lastAttempt = now
	t.record.state = "preparing"
	l.counts["attempt_started"]++
	return true
}

// Called with the peer fenced and the publication locks held. This must
// precede making the successor selectable or permitting its first real write.
func (l *udpRebuildLedger) commit(t *udpRebuildTicket, next *UdpEndpoint, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.commitLocked(t, next, now)
}

func (l *udpRebuildLedger) commitLocked(t *udpRebuildTicket, next *UdpEndpoint, now time.Time) bool {
	if t.finished || !t.started || t.committed || t.record.ticket != t || !now.Before(t.expires) {
		return false
	}
	t.committed = true
	t.record.commits++
	t.record.replies = 0
	t.record.state = "awaiting_replies"
	t.record.owners[next] = struct{}{}
	l.counts["committed"]++
	return true
}

func (l *udpRebuildLedger) finish(t *udpRebuildTicket, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.finished {
		return
	}
	t.finished = true
	if t.record.ticket == t {
		t.record.ticket = nil
	}
	if !t.committed {
		if len(t.record.owners) == 0 {
			t.record.state = "tombstone"
		} else {
			t.record.state = "qualified"
		}
	}
	if reason != "" {
		l.counts[reason]++
	}
}

func (l *udpRebuildLedger) endpointEnded(slot *udpRebuildPeer, ue *UdpEndpoint, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := slot.record.Load()
	if r == nil {
		return
	}
	delete(r.owners, ue)
	if len(r.owners) == 0 {
		r.endedAt = now
		r.state = "tombstone"
		expiry := now.Add(udpRebuildWindow)
		slot.tombstoneUntil.Store(&expiry)
	}
}

func (l *udpRebuildLedger) freshReply(slot *udpRebuildPeer, count uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := slot.record.Load()
	if r == nil || r.state != "awaiting_replies" {
		return false
	}
	r.replies = count
	if count >= udpRebuildRequiredReplies {
		r.state = "recovered"
		l.counts["recovered"]++
		return true
	}
	return false
}

func (l *udpRebuildLedger) count(reason string) {
	switch reason {
	case "claim_retry":
		l.claimRetry.Add(1)
		return
	case "late_reply":
		l.lateReply.Add(1)
		return
	case "handoff_wait_timeout":
		l.handoffTimeout.Add(1)
		return
	}
	l.mu.Lock()
	l.counts[reason]++
	l.mu.Unlock()
}
func (l *udpRebuildLedger) snapshot(now time.Time) *UDPRebuildSnapshot {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := &UDPRebuildSnapshot{PreparationWorkers: 2, QueueLimit: udpRebuildQueueLimit, PreparationTimeoutMS: 2000, FenceTimeoutMS: int(udpRebuildFenceTimeout / time.Millisecond), TicketTTLMS: int(udpRebuildTicketTTL / time.Millisecond), Records: []UDPRebuildRecordSnapshot{}, Counts: make(map[string]uint64), GroupAttempts: make(map[string]int), RecordLimit: udpRebuildLedgerLimit, PeerLimit: 1, GroupLimit: udpRebuildGroupLimit, ProcessLimit: udpRebuildProcessLimit, RequiredFreshReplies: udpRebuildRequiredReplies}
	s.Counts["claim_retry"] = l.claimRetry.Load()
	s.Counts["late_reply"] = l.lateReply.Load()
	s.Counts["handoff_wait_timeout"] = l.handoffTimeout.Load()
	for k, n := range l.counts {
		s.Counts[k] = n
	}
	for _, a := range l.attempts {
		if now.Sub(a.at) < udpRebuildWindow {
			s.AttemptsInWindow++
			s.GroupAttempts[a.group]++
		}
	}
	for _, r := range l.records {
		if t := r.ticket; t != nil && !t.started && !t.finished {
			s.Reserved++
		}
		row := UDPRebuildRecordSnapshot{Client: r.key.src.String(), Original: r.key.original.String(), Peer: r.key.peer.String(), Group: r.key.group, LineageID: r.slot.lineageID, State: r.state, LiveOwners: len(r.owners), Commits: r.commits, FreshReplies: r.replies}
		if owner := r.slot.owner.Load(); owner != nil {
			row.Revision = owner.revision
			if owner.endpoint.sessionRuntime != nil {
				row.RuntimeID = owner.endpoint.sessionRuntime.id
				row.PolicyEpoch = uint64(owner.endpoint.sessionRuntime.binding.Route.PolicyEpoch)
			}
		}
		if !r.lastAttempt.IsZero() {
			row.LastAttemptMS = r.lastAttempt.UnixMilli()
			row.RetryAtMS = r.lastAttempt.Add(udpRebuildWindow).UnixMilli()
		}
		s.Records = append(s.Records, row)
	}
	return s
}
