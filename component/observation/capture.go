// SPDX-License-Identifier: AGPL-3.0-only

// Package observation captures passive facts only. It cannot select a path,
// issue probes, or call a model. Missing facts are never successful probes.
package observation

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Schema      = "kdae-capture-v1"
	QueueLimit  = 256
	RecordLimit = 16 << 10
	RingLimit   = 8 << 20
	FlowLimit   = 512
	Window      = 15 * time.Second
)

type Totals func() (up, down uint64, ok bool)
type Scope struct {
	Site, Node, Group, Network, Path string
	PolicyEpoch                      uint64
}
type Identity struct {
	Site        string `json:"site_id"`
	Node        string `json:"node_id"`
	Group       string `json:"group_id"`
	Network     string `json:"network"`
	Path        string `json:"path"`
	PolicyEpoch uint64 `json:"policy_epoch"`
}
type Missing struct {
	Control      string `json:"control"`
	Dependency   string `json:"dependency"`
	Demand       string `json:"demand"`
	Active       string `json:"active_ms"`
	Backpressure string `json:"read_paused_ms"`
	Node         string `json:"node_bytes"`
	Bytes        string `json:"flow_bytes"`
}
type Record struct {
	FirstDownMS *int64   `json:"first_downstream_callback_ms"`
	Schema      string   `json:"schema"`
	Generation  string   `json:"generation"`
	ID          string   `json:"id"`
	Episode     string   `json:"episode_id"`
	Sequence    uint64   `json:"sequence"`
	Scope       Identity `json:"scope"`
	StartMS     int64    `json:"start_ms"`
	DurationMS  int64    `json:"duration_ms"`
	Partial     bool     `json:"partial"`
	Mode        string   `json:"measurement_mode"`
	Stage       string   `json:"stage"`
	Outcome     string   `json:"outcome"`
	Up          *uint64  `json:"up_bytes"`
	Down        *uint64  `json:"down_bytes"`
	NodeUp      *uint64  `json:"node_up_bytes"`
	NodeDown    *uint64  `json:"node_down_bytes"`
	Active      *int64   `json:"active_ms"`
	Paused      *int64   `json:"read_paused_ms"`
	Control     any      `json:"control"`
	Dependency  any      `json:"dependency"`
	Demand      any      `json:"demand"`
	Missing     Missing  `json:"missing_reason"`
	Probability float64  `json:"inclusion_probability"`
	Trigger     string   `json:"trigger"`
	Alignment   string   `json:"counter_alignment"`
	Adapter     string   `json:"adapter_status"`
}
type Stats struct {
	Considered        uint64 `json:"considered"`
	RouteConsidered   uint64 `json:"route_considered"`
	RouteSampled      uint64 `json:"route_sampled"`
	Sampled           uint64 `json:"sampled"`
	AdmissionDropped  uint64 `json:"admission_dropped"`
	QueueDropped      uint64 `json:"queue_dropped"`
	Oversize          uint64 `json:"oversize"`
	InvalidWindow     uint64 `json:"invalid_window"`
	OffloadUnmeasured uint64 `json:"offload_unmeasured"`
	Evicted           uint64 `json:"ring_evicted"`
}
type Snapshot struct {
	Enabled    bool              `json:"enabled"`
	Generation string            `json:"generation"`
	Stats      Stats             `json:"stats"`
	Records    []json.RawMessage `json:"records"`
	Next       uint64            `json:"next_sequence"`
	Oldest     uint64            `json:"oldest_sequence"`
}
type counters struct{ considered, sampled, admission, dropped, oversize, invalid, offload, routeConsidered, routeSampled atomic.Uint64 }
type stored struct {
	seq  uint64
	data json.RawMessage
}
type Collector struct {
	evidence          evidenceState
	key               [32]byte
	generation        string
	permille          uint16
	seq               atomic.Uint64
	counters          counters
	mu                sync.Mutex
	sampleMu          sync.Mutex
	flows             map[*Flow]struct{}
	queue             chan Record
	stop              chan struct{}
	done              chan struct{}
	once              sync.Once
	closed            atomic.Bool
	ringMu            sync.Mutex
	ring              []stored
	bytes             int
	exported, evicted uint64
}

// Flow uses atomic byte counters and records the first downstream callback
// time once. Sampling and serialization run on the collector worker; admission
// sheds load when the registration lock is busy.
type Flow struct {
	trace                    *Trace
	evidenceScope            Identity
	loadCounts               func() (int64, uint64, bool)
	firstDownNS              atomic.Int64
	owner                    *Collector
	scope                    Identity
	id                       string
	start, window            time.Time
	totals                   Totals
	nodeUp, nodeDown         uint64
	nodeOK                   bool
	up, down                 atomic.Uint64
	previousUp, previousDown uint64
	mode                     atomic.Uint32 // 0 pending offload, 1 userspace, 2 offloaded
	end                      atomic.Pointer[ending]
}
type ending struct {
	at      time.Time
	outcome string
}

func New(permille uint16) (*Collector, error) {
	if permille == 0 || permille > 1000 {
		return nil, fmt.Errorf("capture sampling must be 1..1000 permille")
	}
	c := &Collector{permille: permille, flows: make(map[*Flow]struct{}), queue: make(chan Record, QueueLimit), stop: make(chan struct{}), done: make(chan struct{})}
	if _, err := rand.Read(c.key[:]); err != nil {
		return nil, err
	}
	c.generation = c.hash("generation", "capture")
	c.evidence.initError = c.initEvidence()
	c.evidence.queue = make(chan Evidence, QueueLimit)
	go c.run()
	return c, nil
}
func (c *Collector) hash(kind, s string) string {
	if s == "" {
		return ""
	}
	m := hmac.New(sha256.New, c.key[:])
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil)[:16])
}
func (c *Collector) identity(s Scope) Identity {
	return Identity{c.hash("site", strings.TrimSuffix(strings.ToLower(s.Site), ".")), c.hash("node", s.Node), c.hash("group", s.Group), s.Network, s.Path, s.PolicyEpoch}
}
func (c *Collector) Start(s Scope, totals Totals) *Flow { return c.start(s, totals, nil, nil) }
func (c *Collector) StartLinked(s Scope, totals Totals, trace *Trace, counts func() (int64, uint64, bool)) *Flow {
	if trace == nil || trace.owner != c {
		return nil
	}
	return c.start(s, totals, trace, counts)
}
func (c *Collector) start(s Scope, totals Totals, trace *Trace, counts func() (int64, uint64, bool)) *Flow {
	if c == nil || c.closed.Load() {
		return nil
	}
	if trace == nil {
		c.counters.considered.Add(1)
	}
	if trace == nil && mathrand.Uint64N(1000) >= uint64(c.permille) {
		return nil
	}
	if !c.mu.TryLock() {
		c.counters.admission.Add(1)
		return nil
	}
	defer c.mu.Unlock()
	if c.closed.Load() || len(c.flows) >= FlowLimit {
		c.counters.admission.Add(1)
		return nil
	}
	now := time.Now()
	f := &Flow{evidenceScope: c.evidenceIdentity(s), trace: trace, loadCounts: counts, owner: c, scope: c.identity(s), id: fmt.Sprintf("%s-%d", c.generation, c.seq.Add(1)), start: now, window: now, totals: totals}
	if c.evidence.initError != nil {
		f.trace = nil
	}
	if totals != nil {
		f.nodeUp, f.nodeDown, f.nodeOK = totals()
	}
	c.flows[f] = struct{}{}
	c.counters.sampled.Add(1)
	return f
}
func (f *Flow) Add(up, down uint64) {
	if f != nil {
		if up > 0 {
			f.up.Add(up)
		}
		if down > 0 {
			f.down.Add(down)
		}
		if down > 0 && f.firstDownNS.Load() == 0 {
			f.firstDownNS.CompareAndSwap(0, time.Since(f.start).Nanoseconds()+1)
		}
	}
}
func (f *Flow) Userspace() {
	if f != nil {
		f.mode.Store(1)
	}
}
func (f *Flow) Offloaded() {
	if f != nil {
		f.mode.Store(2)
	}
}
func (f *Flow) Finish(outcome string) {
	if f != nil {
		f.end.CompareAndSwap(nil, &ending{time.Now(), outcome})
	}
}
func (c *Collector) submit(r Record) {
	select {
	case c.queue <- r:
	default:
		c.counters.dropped.Add(1)
	}
}
func (c *Collector) sample(now time.Time) {
	c.sampleMu.Lock()
	defer c.sampleMu.Unlock()
	c.mu.Lock()
	flows := make([]*Flow, 0, len(c.flows))
	for f := range c.flows {
		flows = append(flows, f)
	}
	c.mu.Unlock()
	for _, f := range flows {
		end := f.end.Load()
		at := now
		if end != nil {
			at = end.at
			if at.Before(f.window) {
				at = f.window
			}
		}
		if end == nil && (f.mode.Load() != 1 || now.Sub(f.window) < Window) {
			continue
		}
		mode := f.mode.Load()
		r := Record{Schema: Schema, Generation: c.generation, ID: f.id + fmt.Sprintf("-%d", f.window.Sub(f.start).Nanoseconds()), Episode: f.id, Scope: f.scope, StartMS: f.window.UnixMilli(), DurationMS: at.Sub(f.window).Milliseconds(), Partial: end != nil, Stage: "relay", Outcome: "open", Probability: float64(c.permille) / 1000, Trigger: "uniform_flow", Alignment: "best_effort_non_atomic_snapshots", Adapter: "adapter_abstain", Missing: Missing{Control: "independent_control_unavailable", Dependency: "dependency_not_instrumented", Demand: "application_demand_unobserved", Active: "application_activity_unobserved", Backpressure: "read_backpressure_unobserved"}}
		if first := f.firstDownNS.Load(); first > 0 {
			ms := (first - 1) / int64(time.Millisecond)
			r.FirstDownMS = &ms
		}
		if end != nil {
			r.Outcome = end.outcome
		}
		if r.DurationMS < 0 {
			c.counters.invalid.Add(1)
			c.removeFlow(f)
			continue
		}
		if mode == 1 {
			r.Mode = "userspace_accounting"
			up, down := f.up.Load(), f.down.Load()
			du, dd := up-f.previousUp, down-f.previousDown
			r.Up, r.Down = &du, &dd
			f.previousUp, f.previousDown = up, down
			nu, nd, ok := uint64(0), uint64(0), false
			if f.totals != nil {
				nu, nd, ok = f.totals()
			}
			r.Missing.Node = "node_counters_unavailable"
			if ok && f.nodeOK && end == nil {
				if nu >= f.nodeUp && nd >= f.nodeDown && nu-f.nodeUp >= du && nd-f.nodeDown >= dd {
					a, b := nu-f.nodeUp, nd-f.nodeDown
					r.NodeUp, r.NodeDown = &a, &b
					r.Missing.Node = ""
				} else {
					r.Missing.Node = "counter_reset_or_snapshot_skew"
					c.counters.invalid.Add(1)
				}
			}
			if end != nil {
				r.Missing.Node = "flow_ended_before_node_snapshot"
			}
			f.nodeUp, f.nodeDown, f.nodeOK = nu, nd, ok
		} else {
			r.Mode = "offload_or_unmeasured"
			r.Missing.Bytes = "offload_or_relay_not_started"
			r.Missing.Node = "flow_window_not_measured"
			c.counters.offload.Add(1)
		}
		c.submit(r)
		if f.trace != nil {
			load := &LoadWindow{OwnUp: r.Up, OwnDown: r.Down, Alignment: r.Alignment, Missing: r.Missing.Node}
			if r.NodeUp != nil && r.Up != nil {
				u, d := *r.NodeUp-*r.Up, *r.NodeDown-*r.Down
				load.OtherUp = &u
				load.OtherDown = &d
			}
			if f.loadCounts != nil {
				active, starts, ok := f.loadCounts()
				if ok {
					load.Active = &active
					load.Starts = &starts
				}
			}
			// Scope uses the same flow facts but the shared evidence identity namespace.
			c.emitEvidence(Evidence{Flow: f.trace.ID, Capture: f.id, Kind: "load_window", Scope: f.evidenceScope, StartMS: r.StartMS, DurationMS: r.DurationMS, Outcome: r.Outcome, Load: load})
		}
		f.window = at
		if end != nil {
			c.removeFlow(f)
		}
	}
}
func (c *Collector) removeFlow(f *Flow) {
	c.mu.Lock()
	delete(c.flows, f)
	c.mu.Unlock()
}

func (c *Collector) store(r Record) {
	c.ringMu.Lock()
	defer c.ringMu.Unlock()
	r.Sequence = c.exported + 1
	data, err := json.Marshal(r)
	if err != nil || len(data) > RecordLimit {
		c.counters.oversize.Add(1)
		return
	}
	c.exported++
	for c.bytes+len(data) > RingLimit && len(c.ring) > 0 {
		c.bytes -= len(c.ring[0].data)
		c.ring[0] = stored{}
		c.ring = c.ring[1:]
		c.evicted++
	}
	c.ring = append(c.ring, stored{r.Sequence, data})
	c.bytes += len(data)
}
func (c *Collector) run() {
	defer close(c.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case e := <-c.evidence.queue:
			c.storeEvidence(e)
		case r := <-c.queue:
			c.store(r)
		case <-ticker.C:
			c.sample(time.Now())
		case <-c.stop:
			return
		}
	}
}
func (c *Collector) Close() error {
	if c != nil {
		c.once.Do(func() {
			c.closed.Store(true)
			close(c.stop)
			<-c.done
			c.mu.Lock()
			clear(c.flows)
			c.mu.Unlock()
			// A retired collector stays reachable through any long-lived Flow or
			// Trace that still holds it as owner. Drop the rings (up to 12 MiB)
			// so those references pin only the small struct, not the history.
			c.ringMu.Lock()
			c.ring, c.bytes = nil, 0
			c.evidence.ring, c.evidence.bytes = nil, 0
			c.ringMu.Unlock()
		})
	}
	return nil
}

// Snapshot is non-destructive, bounded and cursor-based. A generation change
// or oldest_sequence > after+1 means an archive gap; never silently merge it.
func (c *Collector) Snapshot(after uint64) Snapshot {
	s := Snapshot{Records: []json.RawMessage{}}
	if c == nil {
		return s
	}
	s.Enabled = true
	s.Generation = c.generation
	s.Stats = Stats{Considered: c.counters.considered.Load(), RouteConsidered: c.counters.routeConsidered.Load(), RouteSampled: c.counters.routeSampled.Load(), Sampled: c.counters.sampled.Load(), AdmissionDropped: c.counters.admission.Load(), QueueDropped: c.counters.dropped.Load(), Oversize: c.counters.oversize.Load(), InvalidWindow: c.counters.invalid.Load(), OffloadUnmeasured: c.counters.offload.Load()}
	c.ringMu.Lock()
	defer c.ringMu.Unlock()
	s.Stats.Evicted = c.evicted
	s.Next = after
	if len(c.ring) > 0 {
		s.Oldest = c.ring[0].seq
	}
	for _, r := range c.ring {
		if r.seq > after {
			s.Records = append(s.Records, r.data)
			s.Next = r.seq
			if len(s.Records) == 256 {
				break
			}
		}
	}
	return s
}

// Route records the composite routing/resolution/dial operation, not a leaf
// handshake. A failure here must never become a node-specific dial failure.
func (c *Collector) Route(s Scope, start time.Time, outcome string) {
	if c == nil || c.closed.Load() {
		return
	}
	c.counters.routeConsidered.Add(1)
	if mathrand.Uint64N(1000) >= uint64(c.permille) {
		return
	}
	c.counters.routeSampled.Add(1)
	id := fmt.Sprintf("%s-route-%d", c.generation, c.seq.Add(1))
	c.submit(Record{Schema: Schema, Generation: c.generation, ID: id, Episode: id, Scope: c.identity(s), StartMS: start.UnixMilli(), DurationMS: time.Since(start).Milliseconds(), Partial: true, Stage: "route_resolve_dial", Outcome: outcome, Mode: "stage_only", Probability: float64(c.permille) / 1000, Trigger: "uniform_route", Alignment: "not_applicable", Adapter: "adapter_abstain", Missing: Missing{Control: "independent_control_unavailable", Dependency: "dependency_not_instrumented", Demand: "application_demand_unobserved", Active: "application_activity_unobserved", Backpressure: "read_backpressure_unobserved", Node: "stage_only", Bytes: "stage_only"}})
}
