/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	closedFlowRingCapacity = 2048
	closedFlowDefaultLimit = 100
	closedFlowMaxLimit     = 500
	trafficSummaryDefaultN = 50
	trafficSummaryMaxN     = 200

	dimCapSrcIP    = 256
	dimCapMac      = 256
	dimCapDomain   = 512
	dimCapRule     = 256
	dimCapOutbound = 64
	dimCapDialer   = 256
	dimCapInbound  = 32
	dimCapProcess  = 128

	flowCloseNormal   int32 = 0
	flowCloseAborted  int32 = 1
	flowCloseReload   int32 = 2
	flowCloseShutdown int32 = 3
)

func flowCloseReasonString(code int32) string {
	switch code {
	case flowCloseAborted:
		return "aborted"
	case flowCloseReload:
		return "reload"
	case flowCloseShutdown:
		return "shutdown"
	default:
		return "normal"
	}
}

// AdminClosedFlow is one completed or interrupted connection kept in the bounded ring.
type AdminClosedFlow struct {
	Seq           uint64           `json:"seq"`
	ID            string           `json:"id"`
	Network       string           `json:"network"`
	Inbound       string           `json:"inbound,omitempty"`
	SrcIP         string           `json:"src_ip"`
	SrcPort       uint16           `json:"src_port"`
	DstIP         string           `json:"dst_ip"`
	DstPort       uint16           `json:"dst_port"`
	Target        string           `json:"target,omitempty"`
	Domain        string           `json:"domain,omitempty"`
	SniffedDomain string           `json:"sniffed_domain,omitempty"`
	StickySite    string           `json:"sticky_site,omitempty"`
	Mac           string           `json:"mac,omitempty"`
	Process       string           `json:"process,omitempty"`
	Rule          *RoutingRuleMeta `json:"rule,omitempty"`
	Outbound      string           `json:"outbound"`
	Dialer        string           `json:"dialer,omitempty"`
	Chain         []string         `json:"chain,omitempty"`
	Policy        string           `json:"policy,omitempty"`
	Offloaded     bool             `json:"offloaded,omitempty"`
	StartTime     string           `json:"start_time,omitempty"`
	EndTime       string           `json:"end_time"`
	DurationMs    int64            `json:"duration_ms"`
	Upload        uint64           `json:"upload"`
	Download      uint64           `json:"download"`
	CloseReason   string           `json:"close_reason"`
}

// Matches reports whether f satisfies filter (including close_reason and offloaded).
func (f AdminClosedFlow) Matches(filter AdminConnectionFilter) bool {
	return f.matches(filter.normalized())
}

func (f AdminClosedFlow) matches(filter AdminConnectionFilter) bool {
	if filter.CloseReason != "" && !strings.EqualFold(f.CloseReason, filter.CloseReason) {
		return false
	}
	sub := filter
	sub.CloseReason = ""
	return AdminConnection{
		ID:        f.ID,
		Network:   f.Network,
		Inbound:   f.Inbound,
		SrcIP:     f.SrcIP,
		SrcPort:   f.SrcPort,
		DstIP:     f.DstIP,
		DstPort:   f.DstPort,
		Target:    f.Target,
		Domain:    f.Domain,
		Mac:       f.Mac,
		Process:   f.Process,
		Rule:      f.Rule,
		Outbound:  f.Outbound,
		Dialer:    f.Dialer,
		Offloaded: f.Offloaded,
	}.matches(sub)
}

// AdminClosedFlowsSnapshot is returned by GET /api/v1/flows/closed.
type AdminClosedFlowsSnapshot struct {
	Total        int               `json:"total"`
	Truncated    bool              `json:"truncated"`
	Flows        []AdminClosedFlow `json:"flows"`
	SnapshotAtMs int64             `json:"snapshot_at_ms"`
}

// AdminTrafficBucket aggregates traffic volume and flow count for one dimension key.
type AdminTrafficBucket struct {
	Key         string `json:"key"`
	Upload      uint64 `json:"upload"`
	Download    uint64 `json:"download"`
	Connections uint64 `json:"connections"`
}

// AdminTrafficSummary aggregates multi-dimensional traffic across closed and active flows.
type AdminTrafficSummary struct {
	Since             string               `json:"since"`
	SnapshotAtMs      int64                `json:"snapshot_at_ms"`
	UploadTotal       uint64               `json:"upload_total"`
	DownloadTotal     uint64               `json:"download_total"`
	ActiveConnections int                  `json:"active_connections"`
	ClosedConnections uint64               `json:"closed_connections"`
	BySrcIP           []AdminTrafficBucket `json:"by_src_ip"`
	ByMac             []AdminTrafficBucket `json:"by_mac"`
	ByDomain          []AdminTrafficBucket `json:"by_domain"`
	ByRule            []AdminTrafficBucket `json:"by_rule"`
	ByOutbound        []AdminTrafficBucket `json:"by_outbound"`
	ByDialer          []AdminTrafficBucket `json:"by_dialer"`
	ByInbound         []AdminTrafficBucket `json:"by_inbound"`
	ByProcess         []AdminTrafficBucket `json:"by_process"`
}

type trafficCounter struct {
	upload      uint64
	download    uint64
	connections uint64
}

type boundedDimMap struct {
	cap     int
	entries map[string]trafficCounter
	other   trafficCounter
}

func newBoundedDimMap(cap int) boundedDimMap {
	return boundedDimMap{
		cap:     cap,
		entries: make(map[string]trafficCounter),
	}
}

func (m *boundedDimMap) add(key string, upload, download uint64, conns uint64) {
	if m == nil {
		return
	}
	if key == "" {
		key = "(none)"
	}
	if cur, ok := m.entries[key]; ok {
		cur.upload += upload
		cur.download += download
		cur.connections += conns
		m.entries[key] = cur
		return
	}
	if len(m.entries) < m.cap {
		m.entries[key] = trafficCounter{
			upload:      upload,
			download:    download,
			connections: conns,
		}
		return
	}
	m.other.upload += upload
	m.other.download += download
	m.other.connections += conns
}

func (m *boundedDimMap) cloneInto() boundedDimMap {
	c := boundedDimMap{
		cap:     m.cap,
		entries: make(map[string]trafficCounter, len(m.entries)+8),
		other:   m.other,
	}
	for k, v := range m.entries {
		c.entries[k] = v
	}
	return c
}

func (m *boundedDimMap) clear() {
	m.entries = make(map[string]trafficCounter)
	m.other = trafficCounter{}
}

func (m *boundedDimMap) sortedTop(topN int) []AdminTrafficBucket {
	buckets := make([]AdminTrafficBucket, 0, len(m.entries)+1)
	for k, v := range m.entries {
		buckets = append(buckets, AdminTrafficBucket{
			Key:         k,
			Upload:      v.upload,
			Download:    v.download,
			Connections: v.connections,
		})
	}
	sort.Slice(buckets, func(i, j int) bool {
		ti := buckets[i].Upload + buckets[i].Download
		tj := buckets[j].Upload + buckets[j].Download
		if ti != tj {
			return ti > tj
		}
		if buckets[i].Connections != buckets[j].Connections {
			return buckets[i].Connections > buckets[j].Connections
		}
		return buckets[i].Key < buckets[j].Key
	})

	other := m.other
	if topN > 0 && len(buckets) > topN {
		for _, b := range buckets[topN:] {
			other.upload += b.Upload
			other.download += b.Download
			other.connections += b.Connections
		}
		buckets = buckets[:topN]
	}
	if other.connections > 0 || other.upload > 0 || other.download > 0 {
		buckets = append(buckets, AdminTrafficBucket{
			Key:         "other",
			Upload:      other.upload,
			Download:    other.download,
			Connections: other.connections,
		})
	}
	return buckets
}

type flowTrafficBaseline struct {
	upload   uint64
	download uint64
}

type trafficDimSet struct {
	srcIP    boundedDimMap
	mac      boundedDimMap
	domain   boundedDimMap
	rule     boundedDimMap
	outbound boundedDimMap
	dialer   boundedDimMap
	inbound  boundedDimMap
	process  boundedDimMap
}

func newTrafficDimSet() trafficDimSet {
	return trafficDimSet{
		srcIP:    newBoundedDimMap(dimCapSrcIP),
		mac:      newBoundedDimMap(dimCapMac),
		domain:   newBoundedDimMap(dimCapDomain),
		rule:     newBoundedDimMap(dimCapRule),
		outbound: newBoundedDimMap(dimCapOutbound),
		dialer:   newBoundedDimMap(dimCapDialer),
		inbound:  newBoundedDimMap(dimCapInbound),
		process:  newBoundedDimMap(dimCapProcess),
	}
}

func (s *trafficDimSet) addFlow(srcIP, mac, domain string, rule *RoutingRuleMeta, outbound, dialer, inbound, process string, upload, download uint64) {
	ruleKey := "(unattributed)"
	if rule != nil && rule.Raw != "" {
		if rule.Index > 0 {
			ruleKey = "#" + strconv.Itoa(rule.Index) + ": " + rule.Raw
		} else {
			ruleKey = rule.Raw
		}
	}
	domainKey := domain
	if domainKey == "" {
		domainKey = "(ip-only)"
	}
	s.srcIP.add(srcIP, upload, download, 1)
	s.mac.add(mac, upload, download, 1)
	s.domain.add(domainKey, upload, download, 1)
	s.rule.add(ruleKey, upload, download, 1)
	s.outbound.add(outbound, upload, download, 1)
	s.dialer.add(dialer, upload, download, 1)
	s.inbound.add(inbound, upload, download, 1)
	s.process.add(process, upload, download, 1)
}

func (s *trafficDimSet) clone() trafficDimSet {
	return trafficDimSet{
		srcIP:    s.srcIP.cloneInto(),
		mac:      s.mac.cloneInto(),
		domain:   s.domain.cloneInto(),
		rule:     s.rule.cloneInto(),
		outbound: s.outbound.cloneInto(),
		dialer:   s.dialer.cloneInto(),
		inbound:  s.inbound.cloneInto(),
		process:  s.process.cloneInto(),
	}
}

// TrafficAccounting tracks recently closed flows and bounded multi-dimensional cumulative traffic.
type TrafficAccounting struct {
	mu       sync.Mutex
	ring     []AdminClosedFlow
	ringHead int
	ringLen  int
	nextSeq  uint64

	since           time.Time
	closedTotalUp   uint64
	closedTotalDown uint64
	closedCount     uint64
	dims            trafficDimSet
	activeBaselines map[string]flowTrafficBaseline

	observer func(AdminClosedFlow)
}

func NewTrafficAccounting() *TrafficAccounting {
	return &TrafficAccounting{
		ring:            make([]AdminClosedFlow, closedFlowRingCapacity),
		since:           time.Now().UTC(),
		dims:            newTrafficDimSet(),
		activeBaselines: make(map[string]flowTrafficBaseline),
	}
}

func (a *TrafficAccounting) SetClosedFlowObserver(fn func(AdminClosedFlow)) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.observer = fn
	a.mu.Unlock()
}

func (a *TrafficAccounting) RecordClosed(flow AdminClosedFlow) {
	a.RecordClosedWithMark(flow, nil)()
}

// RecordClosedWithMark appends flow to cumulative accounting, clears any active
// reset baseline, invokes onRecorded while holding a.mu, and returns a callback
// that notifies the closed-flow observer outside the accounting lock.
func (a *TrafficAccounting) RecordClosedWithMark(flow AdminClosedFlow, onRecorded func()) func() {
	if a == nil {
		if onRecorded != nil {
			onRecorded()
		}
		return func() {}
	}
	a.mu.Lock()
	a.nextSeq++
	flow.Seq = a.nextSeq
	if flow.EndTime == "" {
		flow.EndTime = time.Now().UTC().Format(time.RFC3339)
	}
	if flow.CloseReason == "" {
		flow.CloseReason = "normal"
	}

	idx := (a.ringHead + a.ringLen) % len(a.ring)
	if a.ringLen == len(a.ring) {
		a.ring[a.ringHead] = flow
		a.ringHead = (a.ringHead + 1) % len(a.ring)
	} else {
		a.ring[idx] = flow
		a.ringLen++
	}

	up := flow.Upload
	down := flow.Download
	if base, ok := a.activeBaselines[flow.ID]; ok {
		if up >= base.upload {
			up -= base.upload
		} else {
			up = 0
		}
		if down >= base.download {
			down -= base.download
		} else {
			down = 0
		}
		delete(a.activeBaselines, flow.ID)
	}

	a.closedTotalUp += up
	a.closedTotalDown += down
	a.closedCount++
	a.dims.addFlow(flow.SrcIP, flow.Mac, flow.Domain, flow.Rule, flow.Outbound, flow.Dialer, flow.Inbound, flow.Process, up, down)

	obs := a.observer
	if onRecorded != nil {
		onRecorded()
	}
	a.mu.Unlock()

	if obs == nil {
		return func() {}
	}
	return func() {
		obs(flow)
	}
}

func clampClosedFlowLimit(limit int) int {
	if limit <= 0 {
		return closedFlowDefaultLimit
	}
	if limit > closedFlowMaxLimit {
		return closedFlowMaxLimit
	}
	return limit
}

func clampTrafficTopN(topN int) int {
	if topN <= 0 {
		return trafficSummaryDefaultN
	}
	if topN > trafficSummaryMaxN {
		return trafficSummaryMaxN
	}
	return topN
}

// SnapshotClosed returns closed flows newest-first matching filter.
func (a *TrafficAccounting) SnapshotClosed(limit int, filter AdminConnectionFilter) AdminClosedFlowsSnapshot {
	return a.SnapshotClosedAfter(limit, filter, 0)
}

// SnapshotClosedAfter returns closed flows newest-first with Seq > afterSeq matching filter.
func (a *TrafficAccounting) SnapshotClosedAfter(limit int, filter AdminConnectionFilter, afterSeq uint64) AdminClosedFlowsSnapshot {
	nowMs := time.Now().UnixMilli()
	if a == nil {
		return AdminClosedFlowsSnapshot{Flows: []AdminClosedFlow{}, SnapshotAtMs: nowMs}
	}
	limit = clampClosedFlowLimit(limit)
	filter = filter.normalized()

	a.mu.Lock()
	matchedTotal := 0
	out := make([]AdminClosedFlow, 0, min(limit, a.ringLen))
	// Walk newest -> oldest. Seq increases strictly monotonically, so once we
	// reach Seq <= afterSeq all older entries can be skipped.
	for i := a.ringLen - 1; i >= 0; i-- {
		flow := a.ring[(a.ringHead+i)%len(a.ring)]
		if afterSeq > 0 && flow.Seq <= afterSeq {
			break
		}
		if !filter.IsEmpty() && !flow.matches(filter) {
			continue
		}
		matchedTotal++
		if len(out) < limit {
			out = append(out, flow)
		}
	}
	a.mu.Unlock()

	return AdminClosedFlowsSnapshot{
		Total:        matchedTotal,
		Truncated:    matchedTotal > len(out),
		Flows:        out,
		SnapshotAtMs: nowMs,
	}
}

// Summary combines closed cumulative accounting with live active flows.
func (a *TrafficAccounting) Summary(active []AdminConnection, topN int) AdminTrafficSummary {
	return a.SummaryWithCollector(func() []AdminConnection { return active }, topN)
}

// SummaryWithCollector snapshots closed accounting and runs collectActive under
// a.mu so flows finishing concurrently are never double-counted or missed.
func (a *TrafficAccounting) SummaryWithCollector(collectActive func() []AdminConnection, topN int) AdminTrafficSummary {
	now := time.Now()
	if a == nil {
		return AdminTrafficSummary{
			Since:        now.UTC().Format(time.RFC3339),
			SnapshotAtMs: now.UnixMilli(),
			BySrcIP:      []AdminTrafficBucket{},
			ByMac:        []AdminTrafficBucket{},
			ByDomain:     []AdminTrafficBucket{},
			ByRule:       []AdminTrafficBucket{},
			ByOutbound:   []AdminTrafficBucket{},
			ByDialer:     []AdminTrafficBucket{},
			ByInbound:    []AdminTrafficBucket{},
			ByProcess:    []AdminTrafficBucket{},
		}
	}
	topN = clampTrafficTopN(topN)

	a.mu.Lock()
	dims := a.dims.clone()
	upTotal := a.closedTotalUp
	downTotal := a.closedTotalDown
	closedCount := a.closedCount
	since := a.since
	baselines := make(map[string]flowTrafficBaseline, len(a.activeBaselines))
	for k, v := range a.activeBaselines {
		baselines[k] = v
	}
	var active []AdminConnection
	if collectActive != nil {
		active = collectActive()
	}
	a.mu.Unlock()

	for _, c := range active {
		up := c.Upload
		down := c.Download
		if base, ok := baselines[c.ID]; ok {
			if up >= base.upload {
				up -= base.upload
			} else {
				up = 0
			}
			if down >= base.download {
				down -= base.download
			} else {
				down = 0
			}
		}
		upTotal += up
		downTotal += down
		dims.addFlow(c.SrcIP, c.Mac, c.Domain, c.Rule, c.Outbound, c.Dialer, c.Inbound, c.Process, up, down)
	}

	return AdminTrafficSummary{
		Since:             since.UTC().Format(time.RFC3339),
		SnapshotAtMs:      now.UnixMilli(),
		UploadTotal:       upTotal,
		DownloadTotal:     downTotal,
		ActiveConnections: len(active),
		ClosedConnections: closedCount,
		BySrcIP:           dims.srcIP.sortedTop(topN),
		ByMac:             dims.mac.sortedTop(topN),
		ByDomain:          dims.domain.sortedTop(topN),
		ByRule:            dims.rule.sortedTop(topN),
		ByOutbound:        dims.outbound.sortedTop(topN),
		ByDialer:          dims.dialer.sortedTop(topN),
		ByInbound:         dims.inbound.sortedTop(topN),
		ByProcess:         dims.process.sortedTop(topN),
	}
}

// Reset clears cumulative summary counters and snapshots current active byte baselines.
func (a *TrafficAccounting) Reset(active []AdminConnection) {
	a.ResetWithCollector(func() []AdminConnection { return active })
}

// ResetWithCollector clears cumulative summary counters and captures active
// baselines under a.mu so concurrently finishing flows do not leave orphan keys.
func (a *TrafficAccounting) ResetWithCollector(collectActive func() []AdminConnection) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.since = time.Now().UTC()
	a.closedTotalUp = 0
	a.closedTotalDown = 0
	a.closedCount = 0
	a.dims.srcIP.clear()
	a.dims.mac.clear()
	a.dims.domain.clear()
	a.dims.rule.clear()
	a.dims.outbound.clear()
	a.dims.dialer.clear()
	a.dims.inbound.clear()
	a.dims.process.clear()
	var active []AdminConnection
	if collectActive != nil {
		active = collectActive()
	}
	a.activeBaselines = make(map[string]flowTrafficBaseline, len(active))
	for _, c := range active {
		if c.ID != "" {
			a.activeBaselines[c.ID] = flowTrafficBaseline{
				upload:   c.Upload,
				download: c.Download,
			}
		}
	}
	a.mu.Unlock()
}

func (f *FlowRuntime) toClosedFlow(now time.Time) AdminClosedFlow {
	item := adminConnectionFromTCPAt(f, now)
	return AdminClosedFlow{
		ID:            item.ID,
		Network:       item.Network,
		Inbound:       item.Inbound,
		SrcIP:         item.SrcIP,
		SrcPort:       item.SrcPort,
		DstIP:         item.DstIP,
		DstPort:       item.DstPort,
		Target:        item.Target,
		Domain:        item.Domain,
		SniffedDomain: item.SniffedDomain,
		StickySite:    item.StickySite,
		Mac:           item.Mac,
		Process:       item.Process,
		Rule:          item.Rule,
		Outbound:      item.Outbound,
		Dialer:        item.Dialer,
		Chain:         item.Chain,
		Policy:        item.Policy,
		Offloaded:     item.Offloaded,
		StartTime:     item.StartTime,
		EndTime:       now.UTC().Format(time.RFC3339),
		DurationMs:    item.DurationMs,
		Upload:        item.Upload,
		Download:      item.Download,
		CloseReason:   flowCloseReasonString(f.closeReason.Load()),
	}
}

func (f *UDPFlowRuntime) toClosedFlow(now time.Time) AdminClosedFlow {
	item := adminConnectionFromUDPAt(f, now)
	return AdminClosedFlow{
		ID:            item.ID,
		Network:       item.Network,
		Inbound:       item.Inbound,
		SrcIP:         item.SrcIP,
		SrcPort:       item.SrcPort,
		DstIP:         item.DstIP,
		DstPort:       item.DstPort,
		Target:        item.Target,
		Domain:        item.Domain,
		SniffedDomain: item.SniffedDomain,
		StickySite:    item.StickySite,
		Mac:           item.Mac,
		Process:       item.Process,
		Rule:          item.Rule,
		Outbound:      item.Outbound,
		Dialer:        item.Dialer,
		Chain:         item.Chain,
		Policy:        item.Policy,
		Offloaded:     false,
		StartTime:     item.StartTime,
		EndTime:       now.UTC().Format(time.RFC3339),
		DurationMs:    item.DurationMs,
		Upload:        item.Upload,
		Download:      item.Download,
		CloseReason:   flowCloseReasonString(f.closeReason.Load()),
	}
}

func formatRuleBucketNote(r *RoutingRuleMeta) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%d:%s", r.Index, r.Raw)
}

var _ = formatRuleBucketNote
