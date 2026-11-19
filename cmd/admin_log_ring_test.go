/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestAdminLogRingWraparoundFilterCursorAndScrubbing(t *testing.T) {
	t.Parallel()
	ring := newAdminLogRing()

	// Fill past capacity to test ring wraparound.
	for i := 1; i <= adminLogRingCapacity+25; i++ {
		lvl := logrus.InfoLevel
		if i%10 == 0 {
			lvl = logrus.WarnLevel
		}
		err := ring.Fire(&logrus.Entry{
			Time:    time.Unix(1_700_000_000+int64(i), 0),
			Level:   lvl,
			Message: fmt.Sprintf("msg-%d vless://secret@example.com:443", i),
			Data: logrus.Fields{
				"admin_secret": "do-not-leak",
				"outbound":     "proxy",
				"uri":          "hy2://pass@node:443",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	entries, latest := ring.Snapshot(5, logrus.InfoLevel, 0)
	if latest != adminLogRingCapacity+25 {
		t.Fatalf("latest seq = %d, want %d", latest, adminLogRingCapacity+25)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	if entries[0].Seq != latest-4 || entries[4].Seq != latest {
		t.Fatalf("unexpected seq window: first=%d last=%d latest=%d", entries[0].Seq, entries[4].Seq, latest)
	}
	for _, e := range entries {
		if strings.Contains(e.Message, "://") {
			t.Fatalf("message leaked URI scheme: %q", e.Message)
		}
		if _, leaked := e.Fields["admin_secret"]; leaked {
			t.Fatalf("sensitive field leaked: %+v", e.Fields)
		}
		if uriField, ok := e.Fields["uri"].(string); !ok || strings.Contains(uriField, "://") {
			t.Fatalf("URI field leaked: %+v", e.Fields)
		}
	}

	// Cursor afterSeq filters older entries; minLevel=Warn filters info entries.
	warns, _ := ring.Snapshot(100, logrus.WarnLevel, latest-30)
	for _, w := range warns {
		if w.Seq <= latest-30 || w.Level != "warning" {
			t.Fatalf("unexpected filtered entry: %+v", w)
		}
	}
}

func TestAdminLogRingNonBlockingOnFullSubscriber(t *testing.T) {
	t.Parallel()
	ring := newAdminLogRing()
	ch, cancel := ring.Subscribe(logrus.InfoLevel)
	defer cancel()

	// Fire more entries than subscriber channel buffer without reading.
	for i := 0; i < adminLogSubBufferSize+50; i++ {
		if err := ring.Fire(&logrus.Entry{
			Level:   logrus.InfoLevel,
			Message: fmt.Sprintf("burst-%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(ch) != adminLogSubBufferSize {
		t.Fatalf("expected full channel %d, got %d", adminLogSubBufferSize, len(ch))
	}
	if ring.dropped.Load() != 50 {
		t.Fatalf("expected 50 dropped subscriber frames, got %d", ring.dropped.Load())
	}
}
