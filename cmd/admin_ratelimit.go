/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	adminAuthFailWindow   = time.Minute
	adminAuthMaxFailures  = 20
	adminAuthMaxTrackedIP = 256
)

type adminAuthFailEntry struct {
	windowStart time.Time
	count       int
}

// adminAuthLimiter bounds repeated bad-secret attempts per source IP without
// adding lock contention on normal authenticated requests.
type adminAuthLimiter struct {
	hasFailures atomic.Bool
	mu          sync.Mutex
	entries     map[string]adminAuthFailEntry
	now         func() time.Time
}

func newAdminAuthLimiter() *adminAuthLimiter {
	return &adminAuthLimiter{
		now: time.Now,
	}
}

func (l *adminAuthLimiter) currentTime() time.Time {
	if l != nil && l.now != nil {
		return l.now()
	}
	return time.Now()
}

func normalizeAdminRemoteIP(remoteAddr string) string {
	raw := strings.TrimSpace(remoteAddr)
	if raw == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.Unmap().String()
	}
	return raw
}

// allow checks whether remoteAddr is currently rate-limited. When no failure
// entries exist, it avoids taking the mutex completely.
func (l *adminAuthLimiter) allow(remoteAddr string) (ok bool, retryAfterSec int) {
	if l == nil || !l.hasFailures.Load() {
		return true, 0
	}
	ip := normalizeAdminRemoteIP(remoteAddr)
	now := l.currentTime()

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.entries[ip]
	if !exists {
		return true, 0
	}
	elapsed := now.Sub(entry.windowStart)
	if elapsed >= adminAuthFailWindow {
		delete(l.entries, ip)
		l.hasFailures.Store(len(l.entries) > 0)
		return true, 0
	}
	if entry.count < adminAuthMaxFailures {
		return true, 0
	}
	remaining := adminAuthFailWindow - elapsed
	sec := int((remaining + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	return false, sec
}

func (l *adminAuthLimiter) recordFailure(remoteAddr string) {
	if l == nil {
		return
	}
	ip := normalizeAdminRemoteIP(remoteAddr)
	now := l.currentTime()

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.entries == nil {
		l.entries = make(map[string]adminAuthFailEntry, 8)
	}
	if len(l.entries) >= adminAuthMaxTrackedIP {
		for k, v := range l.entries {
			if now.Sub(v.windowStart) >= adminAuthFailWindow {
				delete(l.entries, k)
			}
		}
		if len(l.entries) >= adminAuthMaxTrackedIP {
			var oldestKey string
			var oldestAt time.Time
			first := true
			for k, v := range l.entries {
				if first || v.windowStart.Before(oldestAt) {
					oldestKey = k
					oldestAt = v.windowStart
					first = false
				}
			}
			if oldestKey != "" {
				delete(l.entries, oldestKey)
			}
		}
	}

	entry, exists := l.entries[ip]
	if !exists || now.Sub(entry.windowStart) >= adminAuthFailWindow {
		l.entries[ip] = adminAuthFailEntry{windowStart: now, count: 1}
	} else {
		entry.count++
		l.entries[ip] = entry
	}
	l.hasFailures.Store(true)
}

func (l *adminAuthLimiter) recordSuccess(remoteAddr string) {
	if l == nil || !l.hasFailures.Load() {
		return
	}
	ip := normalizeAdminRemoteIP(remoteAddr)

	l.mu.Lock()
	delete(l.entries, ip)
	l.hasFailures.Store(len(l.entries) > 0)
	l.mu.Unlock()
}
