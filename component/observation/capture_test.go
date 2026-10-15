// SPDX-License-Identifier: AGPL-3.0-only
package observation

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// Keep the worker stopped in arithmetic tests so window boundaries are exact.
func fixture() *Collector {
	return &Collector{permille: 1000, generation: "test", flows: make(map[*Flow]struct{}), queue: make(chan Record, QueueLimit)}
}
func TestWindowFactsAndMissingEvidence(t *testing.T) {
	c := fixture()
	up, down := uint64(100), uint64(200)
	f := c.Start(Scope{Site: "private.example", Node: "secret-node", Group: "secret-group", Network: "tcp4", Path: "proxy"}, func() (uint64, uint64, bool) { return up, down, true })
	f.Userspace()
	f.Add(40, 80)
	up += 90
	down += 180
	c.sample(f.start.Add(Window))
	r := <-c.queue
	if *r.Up != 40 || *r.Down != 80 || *r.NodeUp != 90 || *r.NodeDown != 180 {
		t.Fatalf("bad window: %+v", r)
	}
	if r.Active != nil || r.Demand != nil || r.Control != nil || r.Dependency != nil || r.Adapter != "adapter_abstain" || r.FirstDownMS == nil {
		t.Fatalf("fabricated/missing fact: %+v", r)
	}
	raw, _ := json.Marshal(r)
	for _, secret := range []string{"private.example", "secret-node", "secret-group"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("raw identity leaked")
		}
	}
	f.Add(10, 20)
	up += 10
	down += 20
	c.sample(f.start.Add(2 * Window))
	r = <-c.queue
	if *r.Up != 10 || *r.Down != 20 || *r.NodeUp != 10 || *r.NodeDown != 20 {
		t.Fatalf("cumulative values leaked into next window: %+v", r)
	}
	// Counter reset is missing, never unsigned underflow or zero-as-valid.
	up, down = 0, 0
	c.sample(f.start.Add(3 * Window))
	r = <-c.queue
	if r.NodeUp != nil || r.NodeDown != nil || r.Missing.Node != "counter_reset_or_snapshot_skew" {
		t.Fatal(r)
	}
}
func TestOffloadAndAbandonDoNotBecomeFailures(t *testing.T) {
	for _, outcome := range []string{"relay_ended", "adopt_abandoned", "canceled"} {
		c := fixture()
		f := c.Start(Scope{}, nil)
		f.Add(100, 200)
		if outcome == "relay_ended" {
			f.Offloaded()
		}
		f.Finish(outcome)
		f.Finish("relay_error")
		c.sample(time.Now())
		r := <-c.queue
		if r.Up != nil || r.Down != nil || r.Outcome != outcome || len(c.flows) != 0 {
			t.Fatal(r)
		}
	}
}
func TestBoundedHotPathAndCursor(t *testing.T) {
	c := fixture()
	c.mu.Lock()
	if c.Start(Scope{}, nil) != nil {
		t.Fatal("contended admission must drop")
	}
	c.mu.Unlock()
	for i := 0; i < QueueLimit+7; i++ {
		c.submit(Record{})
	}
	if c.counters.dropped.Load() != 7 {
		t.Fatal("queue was not bounded")
	}
	for i := 0; i < 1000; i++ {
		c.store(Record{ID: strings.Repeat("a", 9000)})
	}
	if c.bytes > RingLimit || c.evicted == 0 {
		t.Fatal("ring exceeded budget")
	}
	s := c.Snapshot(0)
	if len(s.Records) != 256 || s.Oldest <= 1 || s.Next <= s.Oldest {
		t.Fatal("bad cursor", s.Oldest, s.Next)
	}
	s2 := c.Snapshot(s.Next)
	if s2.Next <= s.Next {
		t.Fatal("cursor failed to advance")
	}
	c.store(Record{ID: strings.Repeat("a", RecordLimit)})
	if c.counters.oversize.Load() != 1 {
		t.Fatal("oversize accepted")
	}
}
func TestConcurrentFinishSnapshotAndClose(t *testing.T) {
	c, err := New(1000)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				f := c.Start(Scope{}, nil)
				f.Userspace()
				f.Add(1, 2)
				f.Finish("canceled")
				c.Snapshot(0)
			}
		}()
	}
	wg.Wait()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if c.Start(Scope{}, nil) != nil || len(c.flows) != 0 {
		t.Fatal("closed collector retained flows")
	}
	var disabled *Collector
	if disabled.Start(Scope{}, nil) != nil || disabled.Snapshot(0).Enabled {
		t.Fatal("disabled collector active")
	}
}

func TestFinishedWindowDoesNotBorrowLaterNodeTraffic(t *testing.T) {
	c := fixture()
	node := uint64(0)
	f := c.Start(Scope{}, func() (uint64, uint64, bool) { return node, node, true })
	f.Userspace()
	f.Add(10, 10)
	node = 10
	f.Finish("relay_ended")
	node = 1000000 // Other flows ran after this flow ended, before the sampler.
	c.sample(time.Now())
	r := <-c.queue
	if r.NodeUp != nil || r.NodeDown != nil || r.Missing.Node != "flow_ended_before_node_snapshot" || *r.Down != 10 {
		t.Fatal(r)
	}
}

func TestSamplerReleasesAdmissionLockBeforeReadingCounters(t *testing.T) {
	c := fixture()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	first := true
	f := c.Start(Scope{}, func() (uint64, uint64, bool) {
		if first {
			first = false
		} else {
			close(entered)
			<-release
		}
		return 0, 0, true
	})
	f.Userspace()
	go func() { c.sample(f.start.Add(Window)); close(done) }()
	<-entered
	admitted := c.Start(Scope{}, nil)
	close(release)
	<-done
	if admitted == nil {
		t.Fatal("sampler blocked admission while computing a window")
	}
}
func TestFinishCannotProduceNegativeWindow(t *testing.T) {
	c := fixture()
	f := c.Start(Scope{}, nil)
	f.Userspace()
	c.sample(f.start.Add(Window))
	<-c.queue
	f.Finish("relay_ended") // End was recorded before the preceding sample boundary.
	c.sample(time.Now())
	r := <-c.queue
	if r.DurationMS != 0 || r.Outcome != "relay_ended" || c.counters.invalid.Load() != 0 {
		t.Fatal(r)
	}
}
func TestCaptureSiteNormalizationAndSeparateCounters(t *testing.T) {
	c := fixture()
	if c.identity(Scope{Site: "EXAMPLE.test."}).Site != c.identity(Scope{Site: "example.test"}).Site {
		t.Fatal("site normalization")
	}
	trace := c.NewFlowTrace()
	c.Route(Scope{}, time.Now(), "success")
	if c.StartLinked(Scope{}, nil, trace, nil) == nil {
		t.Fatal("flow missing")
	}
	s := c.Snapshot(0).Stats
	if s.Considered != 1 || s.Sampled != 1 || s.RouteConsidered != 1 || s.RouteSampled != 1 {
		t.Fatal(s)
	}
}

// A closed collector can outlive its control plane through long-lived flows
// that keep it as owner; Close must release the record history it buffered.
func TestCloseReleasesRings(t *testing.T) {
	c, err := New(1000)
	if err != nil {
		t.Fatal(err)
	}
	c.store(Record{})
	c.storeEvidence(Evidence{})
	if len(c.ring) == 0 || len(c.evidence.ring) == 0 {
		t.Fatal("expected buffered records before Close")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if len(c.ring) != 0 || c.bytes != 0 || len(c.evidence.ring) != 0 || c.evidence.bytes != 0 {
		t.Fatalf("rings not released: capture=%d/%d evidence=%d/%d", len(c.ring), c.bytes, len(c.evidence.ring), c.evidence.bytes)
	}
	if s := c.Snapshot(0); len(s.Records) != 0 {
		t.Fatalf("closed collector returned %d records", len(s.Records))
	}
}
