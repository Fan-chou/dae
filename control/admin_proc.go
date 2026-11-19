/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"bytes"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"sync"
	"time"
)

const selfProcessStatsTTL = 2 * time.Second

type selfProcessStats struct {
	RSSBytes   uint64
	FDCount    int
	HeapBytes  uint64
	Goroutines int
}

var selfProcessCache = struct {
	mu       sync.Mutex
	cachedAt time.Time
	stats    selfProcessStats
}{}

func readSelfProcessStats() selfProcessStats {
	now := time.Now()

	selfProcessCache.mu.Lock()
	if !selfProcessCache.cachedAt.IsZero() && now.Sub(selfProcessCache.cachedAt) < selfProcessStatsTTL {
		stats := selfProcessCache.stats
		selfProcessCache.mu.Unlock()
		return stats
	}
	selfProcessCache.mu.Unlock()

	fresh := readSelfProcessStatsUncached()

	selfProcessCache.mu.Lock()
	selfProcessCache.cachedAt = time.Now()
	selfProcessCache.stats = fresh
	selfProcessCache.mu.Unlock()

	return fresh
}

func readSelfProcessStatsUncached() selfProcessStats {
	var stats selfProcessStats

	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Bytes()
			if !bytes.HasPrefix(line, []byte("VmRSS:")) {
				continue
			}
			fields := bytes.Fields(line)
			if len(fields) < 2 {
				break
			}
			if kb, parseErr := strconv.ParseUint(string(fields[1]), 10, 64); parseErr == nil {
				stats.RSSBytes = kb * 1024
			}
			break
		}
	}

	if fdDir, err := os.Open("/proc/self/fd"); err == nil {
		if names, dirErr := fdDir.Readdirnames(-1); dirErr == nil {
			stats.FDCount = len(names)
		}
		_ = fdDir.Close()
	}

	samples := [1]metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(samples[:])
	if samples[0].Value.Kind() == metrics.KindUint64 {
		stats.HeapBytes = samples[0].Value.Uint64()
	}
	stats.Goroutines = runtime.NumGoroutine()
	return stats
}

func readSelfRSSAndFDs() (rssBytes uint64, fdCount int) {
	stats := readSelfProcessStats()
	return stats.RSSBytes, stats.FDCount
}
