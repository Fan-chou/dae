/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
)

const (
	adminLogRingCapacity  = 1024
	adminLogMaxMsgBytes   = 2048
	adminLogMaxFields     = 16
	adminLogDefaultLimit  = 200
	adminLogMaxLimit      = 500
	adminLogSubBufferSize = 128
)

var anyURISchemePattern = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'"` + "`" + `<>\]\)]+`)

// AdminLogEntry is one bounded, scrubbed structured log entry served by /api/v1/logs and WS logs.
type AdminLogEntry struct {
	Seq     uint64         `json:"seq"`
	Time    string         `json:"time"`
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type logRingSubscriber struct {
	minLevel logrus.Level
	ch       chan AdminLogEntry
}

// adminLogRing is a non-blocking logrus.Hook backed by a fixed-size ring buffer.
type adminLogRing struct {
	mu        sync.Mutex
	entries   [adminLogRingCapacity]AdminLogEntry
	head      int
	count     int
	nextSeq   uint64
	subs      map[uint64]*logRingSubscriber
	nextSubID uint64
	dropped   atomic.Uint64
}

func newAdminLogRing() *adminLogRing {
	return &adminLogRing{
		subs: make(map[uint64]*logRingSubscriber),
	}
}

func (r *adminLogRing) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (r *adminLogRing) Fire(entry *logrus.Entry) error {
	if r == nil || entry == nil {
		return nil
	}
	ts := entry.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	msg := truncateUTF8WithEllipsis(sanitizeLogString(entry.Message), adminLogMaxMsgBytes)
	fields := sanitizeLogFields(entry.Data)
	lvl := entry.Level

	var targets []chan AdminLogEntry

	r.mu.Lock()
	r.nextSeq++
	item := AdminLogEntry{
		Seq:     r.nextSeq,
		Time:    ts.UTC().Format(time.RFC3339Nano),
		Level:   lvl.String(),
		Message: msg,
		Fields:  fields,
	}
	idx := (r.head + r.count) % len(r.entries)
	if r.count == len(r.entries) {
		r.entries[r.head] = item
		r.head = (r.head + 1) % len(r.entries)
	} else {
		r.entries[idx] = item
		r.count++
	}
	if len(r.subs) > 0 {
		for _, sub := range r.subs {
			if lvl <= sub.minLevel {
				targets = append(targets, sub.ch)
			}
		}
	}
	r.mu.Unlock()

	for _, ch := range targets {
		select {
		case ch <- item:
		default:
			r.dropped.Add(1)
		}
	}
	return nil
}

// Snapshot returns entries matching minLevel with Seq > afterSeq, capped to limit newest items.
func (r *adminLogRing) Snapshot(limit int, minLevel logrus.Level, afterSeq uint64) ([]AdminLogEntry, uint64) {
	if r == nil {
		return []AdminLogEntry{}, 0
	}
	if limit <= 0 {
		limit = adminLogDefaultLimit
	}
	if limit > adminLogMaxLimit {
		limit = adminLogMaxLimit
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	latest := r.nextSeq
	if r.count == 0 {
		return []AdminLogEntry{}, latest
	}
	matched := make([]AdminLogEntry, 0, min(limit, r.count))
	for i := 0; i < r.count; i++ {
		e := r.entries[(r.head+i)%len(r.entries)]
		if e.Seq <= afterSeq {
			continue
		}
		lvl, err := logrus.ParseLevel(e.Level)
		if err == nil && lvl > minLevel {
			continue
		}
		matched = append(matched, e)
	}
	if len(matched) > limit {
		matched = matched[len(matched)-limit:]
	}
	return matched, latest
}

// Subscribe attaches a non-blocking subscriber channel filtered at minLevel.
func (r *adminLogRing) Subscribe(minLevel logrus.Level) (<-chan AdminLogEntry, func()) {
	if r == nil {
		ch := make(chan AdminLogEntry)
		close(ch)
		return ch, func() {}
	}
	sub := &logRingSubscriber{
		minLevel: minLevel,
		ch:       make(chan AdminLogEntry, adminLogSubBufferSize),
	}
	r.mu.Lock()
	r.nextSubID++
	id := r.nextSubID
	r.subs[id] = sub
	r.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subs, id)
			r.mu.Unlock()
		})
	}
	return sub.ch, cancel
}

func (r *adminLogRing) SubscriberCount() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.subs)
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	i := maxBytes
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}

func truncateUTF8WithEllipsis(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 3 {
		return truncateUTF8Bytes(s, maxBytes)
	}
	return truncateUTF8Bytes(s, maxBytes-3) + "..."
}

func sanitizeLogString(raw string) string {
	if !strings.Contains(raw, "://") {
		return raw
	}
	sanitized := anyURISchemePattern.ReplaceAllString(raw, "[redacted-uri]")
	if strings.Contains(sanitized, "://") {
		sanitized = strings.ReplaceAll(sanitized, "://", ":")
	}
	return sanitized
}

func isSensitiveLogKey(k string) bool {
	lower := strings.ToLower(strings.TrimSpace(k))
	switch {
	case strings.Contains(lower, "password"),
		strings.Contains(lower, "passwd"),
		strings.Contains(lower, "secret"),
		strings.Contains(lower, "token"),
		strings.Contains(lower, "authorization"),
		strings.Contains(lower, "cookie"),
		strings.Contains(lower, "private_key"),
		lower == "auth",
		lower == "link",
		lower == "key":
		return true
	default:
		return false
	}
}

func sanitizeLogFields(data logrus.Fields) map[string]any {
	if len(data) == 0 {
		return nil
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		if isSensitiveLogKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	if len(keys) > adminLogMaxFields {
		keys = keys[:adminLogMaxFields]
	}
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		v := data[k]
		switch val := v.(type) {
		case string:
			out[k] = truncateUTF8WithEllipsis(sanitizeLogString(val), 512)
		case error:
			out[k] = truncateUTF8WithEllipsis(sanitizeLogString(val.Error()), 512)
		case fmt.Stringer:
			out[k] = truncateUTF8WithEllipsis(sanitizeLogString(val.String()), 512)
		default:
			out[k] = v
		}
	}
	return out
}
