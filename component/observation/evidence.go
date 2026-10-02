// SPDX-License-Identifier: AGPL-3.0-only
package observation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const EvidenceSchema = "kdae-evidence-events-v1"
const EvidenceRingLimit = 4 << 20

// Facts describe only the observing resolver's hop. Cache/filter status of a
// remote resolver is never inferred from an empty answer or a fast response.
type DNSFacts struct {
	QType     uint16   `json:"qtype"`
	RCode     *int     `json:"rcode"`
	AnswerIPs int      `json:"answer_ips"`
	FakeIPs   int      `json:"fake_ips"`
	Truncated *bool    `json:"truncated"`
	Cache     string   `json:"cache_status"`
	Filter    string   `json:"filter_reason"`
	Upstream  string   `json:"upstream_id"`
	Answers   []string `json:"answer_ids"`
}
type LoadWindow struct {
	OwnUp     *uint64 `json:"own_up_bytes"`
	OwnDown   *uint64 `json:"own_down_bytes"`
	OtherUp   *uint64 `json:"other_up_bytes"`
	OtherDown *uint64 `json:"other_down_bytes"`
	Active    *int64  `json:"active_connections_at_snapshot"`
	Starts    *uint64 `json:"starts_total_at_snapshot"`
	Alignment string  `json:"alignment"`
	Missing   string  `json:"missing_reason"`
}
type ErrorFacts struct {
	Class string `json:"class"`
	Stage string `json:"stage"`
}

// ErrorClass exports bounded categories only, never error text or addresses.
func ErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if ErrorOutcome(err) == "timeout" {
		return "timeout"
	}
	for _, item := range []struct {
		err   error
		class string
	}{{syscall.ECONNRESET, "connection_reset"}, {syscall.ECONNREFUSED, "connection_refused"}, {syscall.ENETUNREACH, "network_unreachable"}, {syscall.EHOSTUNREACH, "host_unreachable"}, {syscall.EPIPE, "broken_pipe"}, {net.ErrClosed, "closed"}} {
		if errors.Is(err, item.err) {
			return item.class
		}
	}
	return "unknown"
}

type Evidence struct {
	Error         *ErrorFacts `json:"error_facts,omitempty"`
	Source        string      `json:"source"`
	SamplingFrame string      `json:"sampling_frame"`
	TargetKind    string      `json:"target_kind"`
	Load          *LoadWindow `json:"load"`
	Schema        string      `json:"schema"`
	Generation    string      `json:"generation"`
	Sequence      uint64      `json:"sequence"`
	ID            string      `json:"id"`
	Flow          string      `json:"flow_id"`
	Capture       string      `json:"capture_episode_id"`
	Kind          string      `json:"kind"`
	Scope         Identity    `json:"scope"`
	Target        string      `json:"target_id"`
	Client        string      `json:"client_id"`
	StartMS       int64       `json:"start_ms"`
	DurationMS    int64       `json:"duration_ms"`
	Outcome       string      `json:"outcome"`
	DNS           *DNSFacts   `json:"dns"`
	Probability   float64     `json:"inclusion_probability"`
}
type EvidenceSnapshot struct {
	Enabled    bool              `json:"enabled"`
	Generation string            `json:"generation"`
	Records    []json.RawMessage `json:"records"`
	Next       uint64            `json:"next_sequence"`
	Oldest     uint64            `json:"oldest_sequence"`
	Dropped    uint64            `json:"queue_dropped"`
	Oversize   uint64            `json:"oversize"`
	Evicted    uint64            `json:"ring_evicted"`
}
type evidenceState struct {
	key               [32]byte
	initError         error
	queue             chan Evidence
	ring              []stored
	bytes             int
	exported, evicted uint64
	dropped           atomic.Uint64
	oversize          atomic.Uint64
}

// Trace is sampled once per connection; all its stages share the same ID.
type Trace struct {
	owner *Collector
	ID    string
}

func (c *Collector) NewTrace() *Trace {
	if c == nil || c.evidence.initError != nil {
		return nil
	}
	return c.newTrace()
}

// NewFlowTrace counts each attempted TCP connection once and keeps capture-v1
// sampling available when the shared evidence key cannot be loaded.
func (c *Collector) NewFlowTrace() *Trace {
	if c == nil || c.closed.Load() {
		return nil
	}
	c.counters.considered.Add(1)
	return c.newTrace()
}

func (c *Collector) newTrace() *Trace {
	if c == nil || c.closed.Load() || mathrand.Uint64N(1000) >= uint64(c.permille) {
		return nil
	}
	return &Trace{c, fmt.Sprintf("%s-e-%d", c.generation, c.seq.Add(1))}
}
func ErrorOutcome(err error) string {
	if err == nil {
		return "success"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return "error"
}
func (c *Collector) initEvidence() error {
	c.evidence.key = c.key
	if path := os.Getenv("KDAE_EVIDENCE_KEY_FILE"); path != "" {
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() {
			return fmt.Errorf("evidence identity key must be a regular file")
		}
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("evidence identity key unavailable")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() || info.Size() > 66 || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("evidence identity key must be a private regular file (0600)")
		}
		b, err := io.ReadAll(io.LimitReader(f, 66))
		if err != nil {
			return fmt.Errorf("evidence identity key unavailable")
		}
		if len(b) != 32 {
			b, err = hex.DecodeString(strings.TrimSpace(string(b)))
		}
		if err != nil || len(b) != 32 {
			return fmt.Errorf("evidence identity key must contain 32 raw bytes or 64 hex digits")
		}
		copy(c.evidence.key[:], b)
	}
	return nil
}
func (c *Collector) evidenceHash(kind, s string) string {
	if s == "" {
		return ""
	}
	m := hmac.New(sha256.New, c.evidence.key[:])
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(s))
	return fmt.Sprintf("%x", m.Sum(nil)[:16])
}
func (c *Collector) evidenceIdentity(s Scope) Identity {
	return Identity{c.evidenceHash("site", strings.TrimSuffix(strings.ToLower(s.Site), ".")), c.evidenceHash("node", s.Node), c.evidenceHash("group", s.Group), s.Network, s.Path, s.PolicyEpoch}
}
func targetKind(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "unknown"
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "ip"
	}
	return "name"
}
func (t *Trace) Stage(s Scope, target, client, kind string, start time.Time, outcome, capture string) {
	t.StageError(s, target, client, kind, start, outcome, capture, nil)
}

func (t *Trace) StageError(s Scope, target, client, kind string, start time.Time, outcome, capture string, facts *ErrorFacts) {
	if t == nil || t.owner.evidence.initError != nil {
		return
	}
	c := t.owner
	c.emitEvidence(Evidence{Error: facts, Flow: t.ID, Capture: capture, Kind: kind, Scope: c.evidenceIdentity(s), Target: c.evidenceHash("target", target), TargetKind: targetKind(target), Client: c.evidenceHash("client", client), StartMS: start.UnixMilli(), DurationMS: time.Since(start).Milliseconds(), Outcome: outcome})
}
func (f *Flow) EpisodeID() string {
	if f == nil {
		return ""
	}
	return f.id
}
func (c *Collector) DNS(kind, site, upstream, client string, start time.Time, outcome string, facts DNSFacts, answers []string) {
	t := c.NewTrace()
	if t == nil {
		return
	}
	t.DNS(kind, site, upstream, client, start, outcome, facts, answers)
}

// DNS publishes an already sampled event; decoding and answer extraction can
// be deferred until NewTrace has accepted it.
func (t *Trace) DNS(kind, site, upstream, client string, start time.Time, outcome string, facts DNSFacts, answers []string) {
	if t == nil {
		return
	}
	c := t.owner
	facts.Upstream = c.evidenceHash("upstream", upstream)
	facts.Answers = make([]string, 0, len(answers))
	for _, a := range answers {
		if len(facts.Answers) >= 32 {
			break
		}
		facts.Answers = append(facts.Answers, c.evidenceHash("address", a))
	}
	c.emitEvidence(Evidence{Flow: t.ID, Kind: kind, Scope: c.evidenceIdentity(Scope{Site: strings.TrimSuffix(strings.ToLower(site), "."), Network: "dns", Path: "unknown"}), Client: c.evidenceHash("client", client), StartMS: start.UnixMilli(), DurationMS: time.Since(start).Milliseconds(), Outcome: outcome, DNS: &facts})
}
func (c *Collector) emitEvidence(e Evidence) {
	if c.evidence.initError != nil || c.closed.Load() {
		return
	}
	e.Source = "kdae"
	e.SamplingFrame = "uniform_trace"
	if strings.HasPrefix(e.Kind, "dns_") {
		e.SamplingFrame = "uniform_dns_event"
	}
	e.Schema = EvidenceSchema
	e.Generation = c.generation
	e.Probability = float64(c.permille) / 1000
	select {
	case c.evidence.queue <- e:
	default:
		c.evidence.dropped.Add(1)
	}
}
func (c *Collector) storeEvidence(e Evidence) {
	c.ringMu.Lock()
	defer c.ringMu.Unlock()
	s := &c.evidence
	e.Sequence = s.exported + 1
	e.ID = fmt.Sprintf("%s-event-%d", c.generation, e.Sequence)
	b, err := json.Marshal(e)
	if err != nil || len(b) > RecordLimit {
		s.oversize.Add(1)
		return
	}
	s.exported++
	for s.bytes+len(b) > EvidenceRingLimit && len(s.ring) > 0 {
		s.bytes -= len(s.ring[0].data)
		s.ring[0] = stored{}
		s.ring = s.ring[1:]
		s.evicted++
	}
	s.ring = append(s.ring, stored{e.Sequence, b})
	s.bytes += len(b)
}
func (c *Collector) EvidenceSnapshot(after uint64) EvidenceSnapshot {
	out := EvidenceSnapshot{Records: []json.RawMessage{}, Next: after}
	if c == nil {
		return out
	}
	out.Enabled = c.evidence.initError == nil
	out.Generation = c.generation
	out.Dropped = c.evidence.dropped.Load()
	out.Oversize = c.evidence.oversize.Load()
	c.ringMu.Lock()
	defer c.ringMu.Unlock()
	out.Evicted = c.evidence.evicted
	if len(c.evidence.ring) > 0 {
		out.Oldest = c.evidence.ring[0].seq
	}
	for _, r := range c.evidence.ring {
		if r.seq > after {
			out.Records = append(out.Records, r.data)
			out.Next = r.seq
			if len(out.Records) == 256 {
				break
			}
		}
	}
	return out
}

// EvidenceError reports initialization failure independently of capture-v1.
func (c *Collector) EvidenceError() error {
	if c == nil {
		return nil
	}
	return c.evidence.initError
}
