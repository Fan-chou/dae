/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxRuntimeHistorySeconds = 60 * 60
	defaultRuntimeWindowSec  = 30 * 60
	defaultRuntimeMaxPoints  = 180
	runtimeBucketDuration    = 250 * time.Millisecond
	minRateSampleBaseline    = 800 * time.Millisecond
	minRateSampleFallback    = 200 * time.Millisecond
	minRateSampleAppendGap   = 250 * time.Millisecond
)

type runtimeRateSample struct {
	at            time.Time
	uploadTotal   uint64
	downloadTotal uint64
}

// RuntimeTrafficSample contains one upload/download rate point.
type RuntimeTrafficSample struct {
	Timestamp    time.Time
	UploadRate   uint64
	DownloadRate uint64
}

// RuntimeStatsSnapshot preserves the traffic-latency branch's exported API.
type RuntimeStatsSnapshot struct {
	UpdatedAt         time.Time
	UploadRate        uint64
	DownloadRate      uint64
	UploadTotal       uint64
	DownloadTotal     uint64
	ActiveConnections int
	UDPSessions       int
	Samples           []RuntimeTrafficSample
}

type runtimeBucket struct {
	Timestamp     time.Time
	UploadBytes   uint64
	DownloadBytes uint64
	Duration      time.Duration
}

type runtimeStats struct {
	mu sync.Mutex

	currentBucketStartUnixNano atomic.Int64
	currentUploadBytes         atomic.Uint64
	currentDownloadBytes       atomic.Uint64

	uploadTotal   atomic.Uint64
	downloadTotal atomic.Uint64
	history       []runtimeBucket
	historyStart  int
	historyLen    int

	rateRing [16]runtimeRateSample
	rateHead int
	rateLen  int
}

var (
	globalRuntimeStats = newRuntimeStats()
	activeRuntimeStats atomic.Pointer[runtimeStats]
)

func newRuntimeStats() *runtimeStats {
	return &runtimeStats{}
}

func maxRuntimeHistoryBuckets() int {
	return int((time.Duration(maxRuntimeHistorySeconds) * time.Second) / runtimeBucketDuration)
}

func currentRuntimeStatsStore() *runtimeStats {
	if active := activeRuntimeStats.Load(); active != nil {
		return active
	}
	return globalRuntimeStats
}

func publishRuntimeStatsStore(s *runtimeStats) {
	if s == nil {
		return
	}
	activeRuntimeStats.Store(s)
}

func unpublishRuntimeStatsStore(s *runtimeStats) {
	if s == nil {
		return
	}
	activeRuntimeStats.CompareAndSwap(s, nil)
}

// RecordUploadTraffic records upload bytes into the global runtime history.
func RecordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	if store := currentRuntimeStatsStore(); store != nil {
		store.record(uint64(n), 0)
	}
}

// RecordDownloadTraffic records download bytes into the global runtime history.
func RecordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	if store := currentRuntimeStatsStore(); store != nil {
		store.record(0, uint64(n))
	}
}

func (c *ControlPlane) publishRuntimeStats() {
	if c == nil {
		return
	}
	publishRuntimeStatsStore(c.runtimeStats)
}

func (c *ControlPlane) unpublishRuntimeStats() {
	if c == nil {
		return
	}
	unpublishRuntimeStatsStore(c.runtimeStats)
}

func (s *runtimeStats) record(upload uint64, download uint64) {
	if s == nil {
		return
	}
	if upload > 0 {
		s.currentUploadBytes.Add(upload)
		s.uploadTotal.Add(upload)
	}
	if download > 0 {
		s.currentDownloadBytes.Add(download)
		s.downloadTotal.Add(download)
	}
}

// startRoller was removed: rollLocked is fully lazy. The bucket window only
// advances when traffic is recorded or a snapshot is requested, so no
// periodic goroutine is needed. An empty-window ticker previously woke up
// ~4x/second on idle just to perform a no-op rotation.

func (s *runtimeStats) scalars(activeConnections int, udpSessions int, now time.Time) RuntimeStatsSnapshot {
	if s == nil {
		return RuntimeStatsSnapshot{
			UpdatedAt:         now,
			ActiveConnections: activeConnections,
			UDPSessions:       udpSessions,
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.scalarsLocked(activeConnections, udpSessions, now)
}

func (s *runtimeStats) scalarsLocked(activeConnections int, udpSessions int, now time.Time) RuntimeStatsSnapshot {
	s.rollLocked(now)

	upTotal := s.uploadTotal.Load()
	downTotal := s.downloadTotal.Load()
	uploadRate, downloadRate := s.computeRatesLocked(now, upTotal, downTotal)
	s.appendRateSampleLocked(now, upTotal, downTotal)

	return RuntimeStatsSnapshot{
		UpdatedAt:         now,
		UploadRate:        uploadRate,
		DownloadRate:      downloadRate,
		UploadTotal:       upTotal,
		DownloadTotal:     downTotal,
		ActiveConnections: activeConnections,
		UDPSessions:       udpSessions,
	}
}

func (s *runtimeStats) computeRatesLocked(now time.Time, upTotal uint64, downTotal uint64) (uint64, uint64) {
	if s.rateLen == 0 {
		return 0, 0
	}

	var baseline *runtimeRateSample
	var fallback *runtimeRateSample

	// rateRing stores entries oldest -> newest starting at (rateHead - rateLen).
	for offset := 1; offset <= s.rateLen; offset++ {
		idx := (s.rateHead - offset + len(s.rateRing)) % len(s.rateRing)
		candidate := &s.rateRing[idx]
		age := now.Sub(candidate.at)
		if age <= 0 {
			continue
		}
		if age >= minRateSampleBaseline {
			baseline = candidate
			break
		}
		if age >= minRateSampleFallback {
			fallback = candidate
		}
	}

	if baseline == nil {
		baseline = fallback
	}
	if baseline == nil {
		return 0, 0
	}

	elapsed := now.Sub(baseline.at)
	if elapsed < minRateSampleFallback {
		return 0, 0
	}

	var dUp, dDown uint64
	if upTotal >= baseline.uploadTotal {
		dUp = upTotal - baseline.uploadTotal
	}
	if downTotal >= baseline.downloadTotal {
		dDown = downTotal - baseline.downloadTotal
	}
	return rateFromBytes(dUp, elapsed), rateFromBytes(dDown, elapsed)
}

func (s *runtimeStats) appendRateSampleLocked(now time.Time, upTotal uint64, downTotal uint64) {
	if s.rateLen > 0 {
		newestIdx := (s.rateHead - 1 + len(s.rateRing)) % len(s.rateRing)
		gap := now.Sub(s.rateRing[newestIdx].at)
		if gap < minRateSampleAppendGap {
			return
		}
	}

	s.rateRing[s.rateHead] = runtimeRateSample{
		at:            now,
		uploadTotal:   upTotal,
		downloadTotal: downTotal,
	}
	s.rateHead = (s.rateHead + 1) % len(s.rateRing)
	if s.rateLen < len(s.rateRing) {
		s.rateLen++
	}
}

func (s *runtimeStats) snapshot(activeConnections int, udpSessions int, windowSec int, maxPoints int, now time.Time) RuntimeStatsSnapshot {
	if s == nil {
		return RuntimeStatsSnapshot{
			UpdatedAt:         now,
			ActiveConnections: activeConnections,
			UDPSessions:       udpSessions,
		}
	}
	if windowSec <= 0 {
		windowSec = defaultRuntimeWindowSec
	}
	if maxPoints <= 0 {
		maxPoints = defaultRuntimeMaxPoints
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	snap := s.scalarsLocked(activeConnections, udpSessions, now)

	startTime := now.Add(-time.Duration(windowSec) * time.Second)

	buckets := make([]runtimeBucket, 0, s.historyLen+1)
	for i := 0; i < s.historyLen; i++ {
		bucket := s.history[(s.historyStart+i)%len(s.history)]
		if !bucket.Timestamp.Before(startTime) {
			buckets = append(buckets, bucket)
		}
	}

	curUp := s.currentUploadBytes.Load()
	curDown := s.currentDownloadBytes.Load()
	if len(buckets) == 0 || curUp > 0 || curDown > 0 {
		currentBucketStart := s.currentBucketStartLocked()
		currentDuration := now.Sub(currentBucketStart)
		if currentDuration <= 0 {
			currentDuration = runtimeBucketDuration
		}
		buckets = append(buckets, runtimeBucket{
			Timestamp:     now,
			UploadBytes:   curUp,
			DownloadBytes: curDown,
			Duration:      currentDuration,
		})
	}

	snap.Samples = bucketizeRuntimeSamples(samplesFromBuckets(buckets), maxPoints)
	return snap
}

func (s *runtimeStats) currentBucketStartLocked() time.Time {
	return timeFromUnixNano(s.currentBucketStartUnixNano.Load())
}

func (s *runtimeStats) rollLocked(now time.Time) {
	targetBucketStart := bucketStart(now)
	currentBucketStart := s.currentBucketStartLocked()
	if currentBucketStart.IsZero() {
		s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
		return
	}
	if !targetBucketStart.After(currentBucketStart) {
		return
	}

	uploadBytes := s.currentUploadBytes.Swap(0)
	downloadBytes := s.currentDownloadBytes.Swap(0)
	if uploadBytes == 0 && downloadBytes == 0 && s.historyLen == 0 {
		s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
		return
	}

	steps := int(targetBucketStart.Sub(currentBucketStart) / runtimeBucketDuration)
	if steps <= 0 {
		s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
		return
	}

	maxHist := maxRuntimeHistoryBuckets()
	if uploadBytes == 0 && downloadBytes == 0 && steps >= maxHist {
		s.historyStart = 0
		s.historyLen = 0
		s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
		return
	}

	perUp := uploadBytes / uint64(steps)
	remUp := int(uploadBytes % uint64(steps))
	perDown := downloadBytes / uint64(steps)
	remDown := int(downloadBytes % uint64(steps))

	startStep := 0
	if steps > maxHist {
		startStep = steps - maxHist
		s.historyStart = 0
		s.historyLen = 0
	}

	remStartStep := steps - remUp
	downRemStartStep := steps - remDown
	for step := startStep; step < steps; step++ {
		nextBucketStart := currentBucketStart.Add(time.Duration(step+1) * runtimeBucketDuration)
		u := perUp
		if step >= remStartStep {
			u++
		}
		d := perDown
		if step >= downRemStartStep {
			d++
		}
		s.pushHistoryBucket(runtimeBucket{
			Timestamp:     nextBucketStart,
			UploadBytes:   u,
			DownloadBytes: d,
			Duration:      runtimeBucketDuration,
		})
	}
	s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
}

func (s *runtimeStats) pushHistoryBucket(bucket runtimeBucket) {
	if s == nil {
		return
	}
	if len(s.history) == 0 {
		s.history = make([]runtimeBucket, maxRuntimeHistoryBuckets())
	}
	if s.historyLen < len(s.history) {
		idx := (s.historyStart + s.historyLen) % len(s.history)
		s.history[idx] = bucket
		s.historyLen++
		return
	}
	s.history[s.historyStart] = bucket
	s.historyStart = (s.historyStart + 1) % len(s.history)
}

func timeFromUnixNano(unixNano int64) time.Time {
	if unixNano == 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano)
}

func (c *ControlPlane) runtimeStatsStore() *runtimeStats {
	if c == nil || c.runtimeStats == nil {
		return globalRuntimeStats
	}
	return c.runtimeStats
}

func (c *ControlPlane) runtimeUploadRecorder() func(int64) {
	return c.recordUploadTraffic
}

func (c *ControlPlane) runtimeDownloadRecorder() func(int64) {
	return c.recordDownloadTraffic
}

func (c *ControlPlane) recordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	c.runtimeStatsStore().record(uint64(n), 0)
}

func (c *ControlPlane) recordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	c.runtimeStatsStore().record(0, uint64(n))
}

// SnapshotRuntimeScalars returns aggregate counters and monotonic 1s rates in O(1) without scanning history buckets.
func (c *ControlPlane) SnapshotRuntimeScalars() RuntimeStatsSnapshot {
	tcpConnections := 0
	udpSessions := 0
	if c != nil {
		tcpConnections = c.ActiveTCPConnections()
		udpSessions = DefaultUdpEndpointPool.Len()
	}
	return c.runtimeStatsStore().scalars(tcpConnections+udpSessions, udpSessions, time.Now())
}

// SnapshotRuntimeHistory returns downsampled rate history buckets alongside current scalars.
func (c *ControlPlane) SnapshotRuntimeHistory(windowSec int, maxPoints int) RuntimeStatsSnapshot {
	return c.SnapshotRuntimeStats(windowSec, maxPoints)
}

func (c *ControlPlane) SnapshotRuntimeStats(windowSec int, maxPoints int) RuntimeStatsSnapshot {
	tcpConnections := 0
	udpSessions := 0
	if c != nil {
		tcpConnections = c.ActiveTCPConnections()
		udpSessions = DefaultUdpEndpointPool.Len()
	}
	return c.runtimeStatsStore().snapshot(tcpConnections+udpSessions, udpSessions, windowSec, maxPoints, time.Now())
}

func bucketizeRuntimeSamples(samples []RuntimeTrafficSample, maxPoints int) []RuntimeTrafficSample {
	if len(samples) <= maxPoints {
		return samples
	}

	bucketSize := int(math.Ceil(float64(len(samples)) / float64(maxPoints)))
	result := make([]RuntimeTrafficSample, 0, maxPoints)

	for start := 0; start < len(samples); start += bucketSize {
		end := start + bucketSize
		if end > len(samples) {
			end = len(samples)
		}
		bucket := samples[start:end]
		last := bucket[len(bucket)-1]

		maxUpload := last.UploadRate
		maxDownload := last.DownloadRate
		for _, sample := range bucket[:len(bucket)-1] {
			if sample.UploadRate > maxUpload {
				maxUpload = sample.UploadRate
			}
			if sample.DownloadRate > maxDownload {
				maxDownload = sample.DownloadRate
			}
		}

		result = append(result, RuntimeTrafficSample{
			Timestamp:    last.Timestamp,
			UploadRate:   maxUpload,
			DownloadRate: maxDownload,
		})
	}

	return result
}

func bucketStart(now time.Time) time.Time {
	return now.Truncate(runtimeBucketDuration)
}

func rateFromBytes(bytes uint64, duration time.Duration) uint64 {
	if duration <= 0 {
		return 0
	}
	return uint64(float64(bytes) * float64(time.Second) / float64(duration))
}

func samplesFromBuckets(buckets []runtimeBucket) []RuntimeTrafficSample {
	samples := make([]RuntimeTrafficSample, 0, len(buckets))
	for _, bucket := range buckets {
		samples = append(samples, RuntimeTrafficSample{
			Timestamp:    bucket.Timestamp,
			UploadRate:   rateFromBytes(bucket.UploadBytes, bucket.Duration),
			DownloadRate: rateFromBytes(bucket.DownloadBytes, bucket.Duration),
		})
	}
	return samples
}
