// SPDX-License-Identifier: AGPL-3.0-only
package observation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func evidenceRecords(t *testing.T, c *Collector, n int) []Evidence {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := c.EvidenceSnapshot(0)
		if len(s.Records) >= n {
			out := []Evidence{}
			for _, r := range s.Records {
				var e Evidence
				if err := json.Unmarshal(r, &e); err != nil {
					t.Fatal(err)
				}
				out = append(out, e)
			}
			return out
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("evidence worker failed to publish")
	return nil
}
func TestEvidenceLinkedSamplingAndAlignedLoad(t *testing.T) {
	c, err := New(1000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	trace := c.NewTrace()
	up, down := uint64(100), uint64(200)
	scope := Scope{Site: "EXAMPLE.test.", Node: "secret-node", Network: "tcp4", Path: "proxy"}
	f := c.StartLinked(scope, func() (uint64, uint64, bool) { return up, down, true }, trace, func() (int64, uint64, bool) { return 4, 9, true })
	if f == nil {
		t.Fatal("selected trace lost its flow")
	}
	trace.Stage(scope, "1.2.3.4:443", "192.168.1.2", "dial", time.Now(), "success", f.EpisodeID())
	f.Userspace()
	f.Add(10, 20)
	up += 30
	down += 70
	c.sample(f.start.Add(Window))
	rs := evidenceRecords(t, c, 2)
	for _, e := range rs {
		if e.Flow != trace.ID || e.Capture != f.EpisodeID() {
			t.Fatal("correlation broken")
		}
		b, _ := json.Marshal(e)
		for _, secret := range []string{"EXAMPLE.test", "secret-node", "1.2.3.4", "192.168.1.2"} {
			if strings.Contains(string(b), secret) {
				t.Fatal("raw identity leaked")
			}
		}
		if e.Kind == "load_window" && (e.Load.OtherUp == nil || *e.Load.OtherUp != 20 || *e.Load.OtherDown != 50) {
			t.Fatalf("wrong aligned subtraction: %+v", e.Load)
		}
	}
	if c.StartLinked(scope, nil, nil, nil) != nil {
		t.Fatal("unsampled flow admitted")
	}
}
func TestEvidenceMissingAndCancellation(t *testing.T) {
	c, _ := New(1000)
	defer c.Close()
	f := c.StartLinked(Scope{}, nil, c.NewTrace(), nil)
	f.Offloaded()
	f.Finish("canceled")
	c.sample(time.Now())
	e := evidenceRecords(t, c, 1)[0]
	if e.Load.OwnDown != nil || e.Load.OtherDown != nil || e.Outcome != "canceled" {
		t.Fatal("invented counters/failure")
	}
	if ErrorOutcome(context.Canceled) != "canceled" || ErrorOutcome(context.DeadlineExceeded) != "timeout" {
		t.Fatal("cancellation classification")
	}
}
func TestEvidenceSharedKeyKeepsGenerationsDistinct(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	os.WriteFile(p, make([]byte, 32), 0600)
	t.Setenv("KDAE_EVIDENCE_KEY_FILE", p)
	a, _ := New(1000)
	defer a.Close()
	b, _ := New(1000)
	defer b.Close()
	if a.generation == b.generation || a.evidenceHash("site", "example.test") != b.evidenceHash("site", "example.test") {
		t.Fatal("identity/generation separation")
	}
	os.WriteFile(p, []byte("bad"), 0600)
	c, err := New(1000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.EvidenceError() == nil || c.NewTrace() != nil || c.EvidenceSnapshot(0).Enabled {
		t.Fatal("invalid key accepted for evidence")
	}
	if !c.Snapshot(0).Enabled || c.Start(Scope{}, nil) == nil {
		t.Fatal("evidence key failure disabled capture-v1")
	}
}
func TestEvidenceQueueBoundAndPagination(t *testing.T) {
	c := &Collector{permille: 1000}
	c.evidence.queue = make(chan Evidence, 1)
	c.emitEvidence(Evidence{})
	c.emitEvidence(Evidence{})
	if c.evidence.dropped.Load() != 1 {
		t.Fatal("queue did not shed")
	}
	for range 300 {
		c.storeEvidence(Evidence{Schema: EvidenceSchema})
	}
	first := c.EvidenceSnapshot(0)
	second := c.EvidenceSnapshot(first.Next)
	if len(first.Records) != 256 || len(second.Records) != 44 || second.Next != 300 {
		t.Fatal("cursor loss")
	}
}

func TestEvidenceKeyHexAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	key := strings.Repeat("ab", 32) + "\n"
	if err := os.WriteFile(path, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KDAE_EVIDENCE_KEY_FILE", path)
	c, err := New(1000)
	if err != nil {
		t.Fatal(err)
	}
	if c.EvidenceError() != nil || c.evidence.key[0] != 0xab || c.NewTrace() == nil {
		t.Fatal("hex key rejected")
	}
	c.Close()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	c, err = New(1000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.EvidenceError() == nil || c.EvidenceSnapshot(0).Enabled || !c.Snapshot(0).Enabled {
		t.Fatal("public key permissions accepted or capture-v1 disabled")
	}
}

func TestEvidenceFIFOAndSymlinkRejectedAndFlowCaptureSurvives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{path, link} {
		t.Setenv("KDAE_EVIDENCE_KEY_FILE", key)
		c, err := New(1000)
		if err != nil {
			t.Fatal(err)
		}
		if c.EvidenceError() == nil {
			t.Fatal("special key accepted")
		}
		trace := c.NewFlowTrace()
		f := c.StartLinked(Scope{}, nil, trace, nil)
		if f == nil || f.trace != nil || c.NewTrace() != nil {
			t.Fatal("invalid key affected flow capture")
		}
		c.Close()
	}
}
func TestEvidenceOversizeIsSeparateFromQueueDrops(t *testing.T) {
	c := fixture()
	c.storeEvidence(Evidence{Flow: strings.Repeat("a", RecordLimit)})
	s := c.EvidenceSnapshot(0)
	if s.Oversize != 1 || s.Dropped != 0 || len(s.Records) != 0 {
		t.Fatal(s)
	}
}
