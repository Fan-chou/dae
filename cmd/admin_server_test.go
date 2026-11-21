/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type stubAdminPlane struct {
	sysInfo       control.AdminSystemInfo
	metrics       control.AdminMetricsSnapshot
	history       []control.AdminTrafficSample
	groups        []control.AdminGroup
	setErr        error
	setGroup      string
	setMember     string
	delayErr      error
	delayFor      string
	delayAllCount int
	delayMember   string
	stickyEntries []outbound.SiteStickyEntrySnapshot
	stickyGroup   string
	stickyNetwork string
	stickyQuery   string
	stickyLimit   int
	stickyCleared int
	stickySite    string
	connLimit     int
	connections   control.AdminConnectionsSnapshot
	closedFlows   control.AdminClosedFlowsSnapshot
	closedAfter   uint64
	summary       control.AdminTrafficSummary
	resetCalled   bool
	closedID      string
	closedOK        bool
	batchFilter     control.AdminConnectionFilter
	batchClosed     int
	closeOtherGroup string
	closeOtherKeep  string

	kernelCalls          int
	kernelLimit          int
	kernelSrc            string
	kernelMac            string
	kernelResolveDomains bool
	kernelCloseReq       control.AdminKernelCloseRequest
	kernelCloseRes       control.AdminKernelCloseResult
	kernelCloseErr       error
	flowObserverMu       sync.Mutex
	flowObserver         func(control.AdminClosedFlow)
}

func (s *stubAdminPlane) AdminSystemInfo(version string) control.AdminSystemInfo {
	info := s.sysInfo
	if info.Version == "" {
		info.Version = version
	}
	info.Running = true
	return info
}

func (s *stubAdminPlane) AdminMetricsSnapshot() control.AdminMetricsSnapshot {
	return s.metrics
}

func (s *stubAdminPlane) AdminMetricsHistory(windowSec, maxPoints int) []control.AdminTrafficSample {
	if s.history == nil {
		return []control.AdminTrafficSample{}
	}
	return s.history
}

func (s *stubAdminPlane) AdminGroups() []control.AdminGroup { return s.groups }

func (s *stubAdminPlane) SetGroupSelection(groupName, memberName string) error {
	s.setGroup = groupName
	s.setMember = memberName
	return s.setErr
}

func (s *stubAdminPlane) TriggerLatencyChecksForGroup(groupName string) error {
	s.delayFor = groupName
	return s.delayErr
}

func (s *stubAdminPlane) TriggerLatencyChecksAllGroups() int {
	if s.delayAllCount > 0 {
		return s.delayAllCount
	}
	return len(s.groups)
}

func (s *stubAdminPlane) TriggerLatencyChecksForMember(groupName, memberName string) error {
	s.delayFor = groupName
	s.delayMember = memberName
	return s.delayErr
}

func (s *stubAdminPlane) AdminGroupSticky(groupName, network, query string, limit int) ([]outbound.SiteStickyEntrySnapshot, int, error) {
	s.stickyGroup = groupName
	s.stickyNetwork = network
	s.stickyQuery = query
	s.stickyLimit = limit
	if s.stickyEntries == nil {
		return []outbound.SiteStickyEntrySnapshot{}, 0, nil
	}
	return s.stickyEntries, len(s.stickyEntries), nil
}

func (s *stubAdminPlane) AdminClearGroupSticky(groupName, site, network string) (int, error) {
	s.stickyGroup = groupName
	s.stickySite = site
	s.stickyNetwork = network
	return s.stickyCleared, nil
}

func (s *stubAdminPlane) AdminConnections(limit int, _ control.AdminConnectionFilter) control.AdminConnectionsSnapshot {
	s.connLimit = limit
	if s.connections.Connections == nil {
		return control.AdminConnectionsSnapshot{Connections: []control.AdminConnection{}}
	}
	return s.connections
}

func (s *stubAdminPlane) AdminAllActiveConnections() control.AdminConnectionsSnapshot {
	if s.connections.Connections == nil {
		return control.AdminConnectionsSnapshot{Connections: []control.AdminConnection{}}
	}
	return s.connections
}

func (s *stubAdminPlane) AdminClosedFlows(limit int, filter control.AdminConnectionFilter) control.AdminClosedFlowsSnapshot {
	return s.AdminClosedFlowsAfter(limit, filter, 0)
}

func (s *stubAdminPlane) AdminClosedFlowsAfter(_ int, filter control.AdminConnectionFilter, afterSeq uint64) control.AdminClosedFlowsSnapshot {
	s.closedAfter = afterSeq
	if s.closedFlows.Flows == nil {
		return control.AdminClosedFlowsSnapshot{Flows: []control.AdminClosedFlow{}}
	}
	if filter.IsEmpty() && afterSeq == 0 {
		return s.closedFlows
	}
	filtered := make([]control.AdminClosedFlow, 0, len(s.closedFlows.Flows))
	for _, f := range s.closedFlows.Flows {
		if afterSeq > 0 && f.Seq <= afterSeq {
			continue
		}
		if filter.CloseReason != "" && !strings.EqualFold(f.CloseReason, filter.CloseReason) {
			continue
		}
		if filter.Offloaded != nil && f.Offloaded != *filter.Offloaded {
			continue
		}
		filtered = append(filtered, f)
	}
	return control.AdminClosedFlowsSnapshot{
		Total: len(filtered),
		Flows: filtered,
	}
}

func (s *stubAdminPlane) AdminTrafficSummary(_ int) control.AdminTrafficSummary {
	return s.summary
}

func (s *stubAdminPlane) AdminResetTrafficSummary() {
	s.resetCalled = true
}

func (s *stubAdminPlane) AdminCloseConnection(id string) bool {
	s.closedID = id
	return s.closedOK
}

func (s *stubAdminPlane) AdminCloseConnections(filter control.AdminConnectionFilter) int {
	s.batchFilter = filter
	return s.batchClosed
}

func (s *stubAdminPlane) AdminCloseGroupOtherConnections(groupName, keepMember string) int {
	s.closeOtherGroup = groupName
	s.closeOtherKeep = keepMember
	return s.batchClosed
}

func (s *stubAdminPlane) AdminKernelConnections(limit int, src, mac string, resolveDomains bool) control.AdminKernelConnectionsSnapshot {
	s.kernelCalls++
	s.kernelLimit = limit
	s.kernelSrc = src
	s.kernelMac = mac
	s.kernelResolveDomains = resolveDomains
	if mac == "bad" {
		return control.AdminKernelConnectionsSnapshot{Available: true, Error: "invalid mac", Connections: []control.AdminKernelConnection{}}
	}
	if src == "bad" {
		return control.AdminKernelConnectionsSnapshot{Available: true, Error: "invalid src", Connections: []control.AdminKernelConnection{}}
	}
	return control.AdminKernelConnectionsSnapshot{
		Available:   true,
		Accounting:  true,
		Total:       1,
		Connections: []control.AdminKernelConnection{{ID: "udp:a>b", Network: "udp", Src: "192.168.124.200:1", Dst: "1.1.1.1:2", Upload: 7}},
	}
}

func (s *stubAdminPlane) AdminCloseKernelConnection(req control.AdminKernelCloseRequest) (control.AdminKernelCloseResult, error) {
	s.kernelCloseReq = req
	return s.kernelCloseRes, s.kernelCloseErr
}

func (s *stubAdminPlane) SetClosedFlowObserver(fn func(control.AdminClosedFlow)) {
	s.flowObserverMu.Lock()
	s.flowObserver = fn
	s.flowObserverMu.Unlock()
}

func (s *stubAdminPlane) getClosedFlowObserver() func(control.AdminClosedFlow) {
	s.flowObserverMu.Lock()
	fn := s.flowObserver
	s.flowObserverMu.Unlock()
	return fn
}

func (s *stubAdminPlane) AdminQuality(group, host string) []map[string]any { return []map[string]any{} }

func TestAdminStrictCORSPNAAndAuthRateLimit(t *testing.T) {
	t.Parallel()
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane {
		return &stubAdminPlane{sysInfo: control.AdminSystemInfo{Version: "test"}}
	}, func() bool { return true })
	server.secret = "test-token"
	server.corsOrigins = buildCorsOriginSet([]string{"HTTPS://Panel.Example.com:443"})
	handler := server.withSecurityHeaders(server.withAdminCORS(server.buildMux()))

	// Disallowed Origin returns 403 even on OPTIONS.
	badPre := httptest.NewRequest(http.MethodOptions, "/api/v1/system", nil)
	badPre.Header.Set("Origin", "http://192.168.1.5")
	badPre.Header.Set("Access-Control-Request-Private-Network", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, badPre)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed Origin preflight status = %d, want 403", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disallowed Origin leaked ACAO header")
	}

	// Allowed Origin receives PNA, Max-Age, Expose-Headers, and security headers.
	goodPre := httptest.NewRequest(http.MethodOptions, "/api/v1/system", nil)
	goodPre.Header.Set("Origin", "https://panel.example.com")
	goodPre.Header.Set("Access-Control-Request-Private-Network", "true")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, goodPre)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight status = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://panel.example.com" ||
		rec.Header().Get("Access-Control-Allow-Private-Network") != "true" ||
		rec.Header().Get("Access-Control-Max-Age") != "600" ||
		rec.Header().Get("Access-Control-Expose-Headers") != "ETag" ||
		rec.Header().Get("Cache-Control") != "no-store" ||
		rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("unexpected CORS/security headers: %+v", rec.Header())
	}

	// Legacy header X-Kdae-Authorization is no longer accepted; only Authorization: Bearer works.
	legacyReq := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	legacyReq.Header.Set("X-Kdae-Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, legacyReq)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("X-Kdae-Authorization status = %d, want 401", rec.Code)
	}

	// Unknown / legacy paths yield JSON 404 when authed.
	notFound := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	notFound.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, notFound)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("removed /v1/status code = %d, want 404", rec.Code)
	}

	// Auth failure rate limiter locks out after repeated failures from same IP.
	for i := 0; i < adminAuthMaxFailures; i++ {
		badAuth := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
		badAuth.RemoteAddr = "192.168.1.99:5555"
		badAuth.Header.Set("Authorization", "Bearer wrong")
		rRec := httptest.NewRecorder()
		handler.ServeHTTP(rRec, badAuth)
		if rRec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d code = %d, want 401", i, rRec.Code)
		}
	}
	locked := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	locked.RemoteAddr = "192.168.1.99:5556"
	locked.Header.Set("Authorization", "Bearer test-token")
	lRec := httptest.NewRecorder()
	handler.ServeHTTP(lRec, locked)
	if lRec.Code != http.StatusTooManyRequests || lRec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 + Retry-After, got %d (%+v)", lRec.Code, lRec.Header())
	}
}

func TestAdminGroupSelectionProbeCooldownAndPathEscaping(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{}
	reloaded := false
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, func() bool {
		reloaded = true
		return true
	})
	server.secret = "test-token"
	handler := server.withSecurityHeaders(server.buildMux())

	req := httptest.NewRequest(http.MethodPut, "/api/v1/groups/proxy/selection", strings.NewReader(`{"member":"Cherry_Proxy"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || reloaded || plane.setGroup != "proxy" || plane.setMember != "Cherry_Proxy" {
		t.Fatalf("selection PUT code=%d reloaded=%v group=%q member=%q body=%s", rec.Code, reloaded, plane.setGroup, plane.setMember, rec.Body.String())
	}

	// First probe succeeds (202); immediate repeat triggers 3s cooldown (429).
	probeReq := httptest.NewRequest(http.MethodPost, "/api/v1/groups/AI/probe", nil)
	probeReq.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, probeReq)
	if rec.Code != http.StatusAccepted || plane.delayFor != "AI" {
		t.Fatalf("first probe code=%d group=%q body=%s", rec.Code, plane.delayFor, rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, probeReq)
	if rec2.Code != http.StatusTooManyRequests || rec2.Header().Get("Retry-After") == "" {
		t.Fatalf("second probe expected 429 cooldown, got %d", rec2.Code)
	}

	if name, action, err := parseAdminGroupPath("/api/v1/groups/a%2Fb/selection"); err != nil || name != "a/b" || action != "selection" {
		t.Fatalf("escaped slash should decode once, got name=%q action=%q err=%v", name, action, err)
	}
	if name, action, err := parseAdminGroupPath("/api/v1/groups/a/b/selection"); err == nil {
		t.Fatalf("unescaped slash should be rejected, got name=%q action=%q", name, action)
	}
	if _, _, err := parseAdminGroupPath("/api/v1/groups/bad%00name/selection"); err == nil {
		t.Fatal("control char %00 in group name should be rejected")
	}
	if _, _, err := parseAdminGroupPath("/api/v1/groups/bad%0Aname/selection"); err == nil {
		t.Fatal("control char %0A in group name should be rejected")
	}
}

func TestAdminConnectionsFilterCloseClosedFlowsAndTrafficSummary(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{
		connections: control.AdminConnectionsSnapshot{
			Total: 2,
			Connections: []control.AdminConnection{
				{
					ID:       "tcp:1",
					Network:  "tcp",
					SrcIP:    "192.168.124.202",
					SrcPort:  44321,
					DstIP:    "198.51.100.10",
					DstPort:  443,
					Target:   "api2.cursor.sh:443",
					Domain:   "api2.cursor.sh",
					Mac:      "3e:0a:a5:de:ae:a3",
					Process:  "curl",
					Rule:     &control.RoutingRuleMeta{Index: 2, Raw: "domain(suffix:cursor.sh) -> AI"},
					Outbound: "AI",
					Dialer:   "US_Dmit_LAX_Hysteria",
					Policy:   "fixed",
					Upload:   32,
				},
				{
					ID:       "udp:2",
					Network:  "udp",
					SrcIP:    "192.168.124.50",
					SrcPort:  53000,
					DstIP:    "8.8.8.8",
					DstPort:  53,
					Outbound: "direct",
					Upload:   12,
				},
			},
		},
		closedOK:    true,
		batchClosed: 2,
		closedFlows: control.AdminClosedFlowsSnapshot{
			Total: 1,
			Flows: []control.AdminClosedFlow{{ID: "tcp:9", Outbound: "AI", CloseReason: "aborted"}},
		},
		summary: control.AdminTrafficSummary{UploadTotal: 99, DownloadTotal: 199},
	}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.secret = "test-token"
	handler := server.withSecurityHeaders(server.buildMux())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/connections?outbound=AI&src_ip=192.168.124.202&process=curl&mac=3e:0a&limit=64", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/connections = %d body=%s", rec.Code, rec.Body.String())
	}
	var snap control.AdminConnectionsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Total != 1 || snap.Connections[0].ID != "tcp:1" {
		t.Fatalf("filtered connections = %+v", snap)
	}

	// Single close by ID.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/connections/tcp:1", nil)
	delReq.Header.Set("Authorization", "Bearer test-token")
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK || plane.closedID != "tcp:1" {
		t.Fatalf("DELETE connection code=%d id=%q body=%s", delRec.Code, plane.closedID, delRec.Body.String())
	}

	// Batch close requires non-empty filter or all=true.
	emptyClose := httptest.NewRequest(http.MethodPost, "/api/v1/connections/close", strings.NewReader(`{}`))
	emptyClose.Header.Set("Authorization", "Bearer test-token")
	emptyRec := httptest.NewRecorder()
	handler.ServeHTTP(emptyRec, emptyClose)
	if emptyRec.Code != http.StatusBadRequest {
		t.Fatalf("empty batch close code=%d, want 400", emptyRec.Code)
	}

	batchClose := httptest.NewRequest(http.MethodPost, "/api/v1/connections/close", strings.NewReader(`{"outbound":"AI"}`))
	batchClose.Header.Set("Authorization", "Bearer test-token")
	batchRec := httptest.NewRecorder()
	handler.ServeHTTP(batchRec, batchClose)
	if batchRec.Code != http.StatusOK || plane.batchFilter.Outbound != "AI" {
		t.Fatalf("batch close code=%d filter=%+v body=%s", batchRec.Code, plane.batchFilter, batchRec.Body.String())
	}

	// Closed flows, traffic summary, and reset.
	cfReq := httptest.NewRequest(http.MethodGet, "/api/v1/flows/closed?limit=10", nil)
	cfReq.Header.Set("Authorization", "Bearer test-token")
	cfRec := httptest.NewRecorder()
	handler.ServeHTTP(cfRec, cfReq)
	if cfRec.Code != http.StatusOK || !strings.Contains(cfRec.Body.String(), `"close_reason":"aborted"`) {
		t.Fatalf("closed flows code=%d body=%s", cfRec.Code, cfRec.Body.String())
	}

	sumReq := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/summary", nil)
	sumReq.Header.Set("Authorization", "Bearer test-token")
	sumRec := httptest.NewRecorder()
	handler.ServeHTTP(sumRec, sumReq)
	if sumRec.Code != http.StatusOK || !strings.Contains(sumRec.Body.String(), `"upload_total":99`) {
		t.Fatalf("summary code=%d body=%s", sumRec.Code, sumRec.Body.String())
	}

	rstReq := httptest.NewRequest(http.MethodPost, "/api/v1/traffic/reset", nil)
	rstReq.Header.Set("Authorization", "Bearer test-token")
	rstRec := httptest.NewRecorder()
	handler.ServeHTTP(rstRec, rstReq)
	if rstRec.Code != http.StatusOK || !plane.resetCalled {
		t.Fatalf("reset code=%d resetCalled=%v", rstRec.Code, plane.resetCalled)
	}
}

func TestAdminKernelConnectionsEndpoint(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{
		kernelCloseRes: control.AdminKernelCloseResult{ConntrackDeleted: true},
	}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.secret = "test-token"
	handler := server.withSecurityHeaders(server.buildMux())

	get := func(target string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer test-token")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := get("/api/v1/connections/kernel", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", rec.Code)
	}
	rec := get("/api/v1/connections/kernel?limit=64&src=192.168.124.200&mac=3e:0a:a5:de:ae:a3", true)
	if rec.Code != http.StatusOK || plane.kernelResolveDomains || plane.kernelLimit != 64 {
		t.Fatalf("status=%d resolveDomains=%v limit=%d", rec.Code, plane.kernelResolveDomains, plane.kernelLimit)
	}
	rec = get("/api/v1/connections/kernel?resolve_domains=true", true)
	if rec.Code != http.StatusOK || !plane.kernelResolveDomains {
		t.Fatalf("expected resolve_domains=true to propagate, status=%d", rec.Code)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/connections/kernel", strings.NewReader(`{"protocol":"tcp","src_ip":"192.168.1.2","src_port":5000,"dst_ip":"1.1.1.1","dst_port":443}`))
	delReq.Header.Set("Authorization", "Bearer test-token")
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK || plane.kernelCloseReq.SrcPort != 5000 {
		t.Fatalf("DELETE kernel code=%d req=%+v body=%s", delRec.Code, plane.kernelCloseReq, delRec.Body.String())
	}
}

func TestAdminSystemMetricsLogsLogLevelAndSourcesRefresh(t *testing.T) {
	t.Parallel()
	log := logrus.New()
	log.SetLevel(logrus.InfoLevel)
	ring := newAdminLogRing()
	log.AddHook(ring)
	plane := &stubAdminPlane{
		metrics: control.AdminMetricsSnapshot{UploadRate: 1024, DownloadRate: 2048},
		history: []control.AdminTrafficSample{{TimestampMs: 1000, UploadRate: 100, DownloadRate: 200}},
	}
	server := newAdminServer(log, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.setLogRing(ring)
	server.secret = "test-token"
	server.setSourcesRefresher(func(context.Context) (adminSourcesRefreshResult, error) {
		return adminSourcesRefreshResult{Changed: true, ReloadQueued: true}, nil
	})
	handler := server.withSecurityHeaders(server.buildMux())

	log.Info("hello ring")

	do := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(http.MethodGet, "/api/v1/metrics", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"upload_rate":1024`) {
		t.Fatalf("metrics code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, "/api/v1/metrics/history?window=60&points=10", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"points":1`) {
		t.Fatalf("history code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodPut, "/api/v1/system/log-level", `{"level":"debug"}`); rec.Code != http.StatusOK || log.GetLevel() != logrus.DebugLevel {
		t.Fatalf("log-level PUT code=%d level=%v body=%s", rec.Code, log.GetLevel(), rec.Body.String())
	}
	if rec := do(http.MethodPut, "/api/v1/system/log-level", `{"level":"bogus"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid log-level code=%d", rec.Code)
	}
	if rec := do(http.MethodGet, "/api/v1/logs?limit=10", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"hello ring"`) {
		t.Fatalf("logs GET code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodPost, "/api/v1/sources/refresh", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"reload_queued":true`) {
		t.Fatalf("sources refresh code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, "/api/v1/debug/quality?group=test", ""); rec.Code != http.StatusOK {
		t.Fatalf("debug/quality code=%d", rec.Code)
	}
}

func TestAdminSourcesRefreshSanitizesPartialAndFullErrors(t *testing.T) {
	t.Parallel()
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return &stubAdminPlane{} }, nil)
	server.secret = "test-token"
	t.Cleanup(server.shutdown)

	ts := httptest.NewServer(server.withSecurityHeaders(server.buildMux()))
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer wsConn.Close()
	if err := wsConn.WriteJSON(wsClientFrame{Type: "auth", Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
	var authOK wsServerFrame
	if err := wsConn.ReadJSON(&authOK); err != nil || authOK.Type != "auth_ok" {
		t.Fatalf("auth_ok failed: %+v err=%v", authOK, err)
	}
	if err := wsConn.WriteJSON(wsClientFrame{Type: "sub", Topic: "events"}); err != nil {
		t.Fatal(err)
	}

	server.setSourcesRefresher(func(context.Context) (adminSourcesRefreshResult, error) {
		return adminSourcesRefreshResult{
			Changed: true,
			Warning: "failed https://user:secret@sub.example.com/path?token=abc",
		}, nil
	})

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sources/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var partialBody struct {
		Warning string `json:"warning"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&partialBody); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("partial refresh status = %d", resp.StatusCode)
	}
	if strings.Contains(partialBody.Warning, "secret") || strings.Contains(partialBody.Warning, "token=abc") || strings.Contains(partialBody.Warning, "://") || !strings.Contains(partialBody.Warning, "[redacted-uri]") {
		t.Fatalf("partial warning not sanitized: %q", partialBody.Warning)
	}

	_ = wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var ev wsServerFrame
	for {
		if err := wsConn.ReadJSON(&ev); err != nil {
			t.Fatalf("expected sources_refreshed WS event: %v", err)
		}
		if ev.Type == "event" && ev.Event == "sources_refreshed" {
			break
		}
	}
	evData, ok := ev.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected WS event data: %#v", ev.Data)
	}
	wsWarning, _ := evData["warning"].(string)
	if strings.Contains(wsWarning, "secret") || strings.Contains(wsWarning, "token=abc") || strings.Contains(wsWarning, "://") || !strings.Contains(wsWarning, "[redacted-uri]") {
		t.Fatalf("WS sources_refreshed warning not sanitized: %q", wsWarning)
	}

	server.setSourcesRefresher(func(context.Context) (adminSourcesRefreshResult, error) {
		return adminSourcesRefreshResult{}, errors.New("get https://user:secret@sub.example.com/sub: timeout")
	})
	req2, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sources/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", "Bearer test-token")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	var errBody adminAPIErrorBody
	if err := json.NewDecoder(resp2.Body).Decode(&errBody); err != nil {
		_ = resp2.Body.Close()
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusInternalServerError || errBody.Error.Code != "refresh_failed" {
		t.Fatalf("full failure status=%d body=%+v", resp2.StatusCode, errBody)
	}
	if strings.Contains(errBody.Error.Message, "secret") || strings.Contains(errBody.Error.Message, "://") || errBody.Error.Message == "config validation failed" || !strings.Contains(errBody.Error.Message, "[redacted-uri]") {
		t.Fatalf("unexpected sanitized full refresh error: %q", errBody.Error.Message)
	}
}

func reserveTestLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func readTestAdminSnapshot(t *testing.T, dir string) *adminConfigSnapshot {
	t.Helper()
	snapshot, err := readAdminConfigSnapshot(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &snapshot
}

func TestAdminReloadSnapshotKeepsLoadedFilesAfterManualEdit(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	routingPath := filepath.Join(dir, "routing.dae")
	loadedConfig := "include { routing.dae }\nglobal { log_level: info }\n"
	loadedRouting := "routing { fallback: direct }\n"
	writeRestrictedDae(t, configPath, loadedConfig)
	writeRestrictedDae(t, routingPath, loadedRouting)
	conf, _, snapshot, err := readConfigWithAdminSnapshot(configPath, readValidate)
	if err != nil {
		t.Fatal(err)
	}
	manualConfig := "include { routing.dae }\nglobal { log_level: debug }\n"
	writeRestrictedDae(t, configPath, manualConfig)
	writeRestrictedDae(t, routingPath, "routing { fallback: block }\n")
	server := newAdminServer(nil, "", dir, nil, nil)
	applyPublishedReloadAdmin(server, conf, nil, false, snapshot)
	if server.reloadStatusSnapshot().configInSync {
		t.Fatal("manual edit was mistaken for the loaded configuration")
	}
	for path, want := range map[string]string{configPath: loadedConfig, routingPath: loadedRouting} {
		got, err := os.ReadFile(path + ".admin-last-good")
		if err != nil || string(got) != want {
			t.Fatalf("last-good %s = %q, error=%v; want loaded bytes %q", path, got, err, want)
		}
	}
	if got, _ := os.ReadFile(configPath); string(got) != manualConfig {
		t.Fatal("successful publication overwrote the manual edit")
	}
	writeRestrictedDae(t, configPath, "global { log_level: warn }\nrouting { fallback: direct }\n")
	adminConfigWriteMu.Lock()
	server.recordPendingAdminWriteLocked()
	adminConfigWriteMu.Unlock()
	server.handleAsyncReloadFailure("prepare failed")
	if got, _ := os.ReadFile(configPath); string(got) != loadedConfig {
		t.Fatalf("rollback restored %q instead of loaded config", got)
	}
	if !server.reloadStatusSnapshot().configInSync {
		t.Fatal("restored loaded snapshot should be in sync")
	}
}

func TestAdminSystemReloadSyncAndLastGoodRollback(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	routingPath := filepath.Join(dir, "routing.dae")
	origCfg := "global {\n    log_level: info\n}\nrouting { fallback: direct }\n"
	origRouting := "routing {\n    dip(1.1.1.1) -> direct\n}\n"
	writeRestrictedDae(t, configPath, origCfg)
	writeRestrictedDae(t, routingPath, origRouting)

	rm := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	server := newAdminServer(nil, "", dir, func() adminPlane {
		return &stubAdminPlane{sysInfo: control.AdminSystemInfo{Version: "test"}}
	}, func() bool { return true })
	server.secret = "test-token"
	server.setReloadManager(rm)
	server.captureActiveSnapshot(readTestAdminSnapshot(t, dir))
	handler := server.withSecurityHeaders(server.buildMux())

	getSystem := func() adminSystemBody {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("system = %d body %s", rec.Code, rec.Body.String())
		}
		var out adminSystemBody
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	st := getSystem()
	if !st.ConfigInSync || st.LastReloadError != "" || st.ReloadPending {
		t.Fatalf("initial status = %+v, want in sync with no error", st)
	}
	if _, err := os.Stat(configPath + ".admin-last-good"); err != nil {
		t.Fatalf("expected .admin-last-good snapshot at startup: %v", err)
	}

	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/config", strings.NewReader(`{"config":"global { log_level: warn }\nrouting { fallback: direct }\n","routing":"routing { dip(8.8.8.8) -> direct }\n"}`))
	putReq.Header.Set("Authorization", "Bearer test-token")
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/config status = %d body %s", putRec.Code, putRec.Body.String())
	}

	st = getSystem()
	if st.ConfigInSync {
		t.Fatalf("expected config_in_sync=false while disk has pending edit: %+v", st)
	}

	rm.setReloadError(errors.New("dialer failed for hy2://secret@example.com"))
	server.handleAsyncReloadFailure("dialer failed for hy2://secret@example.com")

	gotCfg, _ := os.ReadFile(configPath)
	gotRouting, _ := os.ReadFile(routingPath)
	if string(gotCfg) != origCfg || string(gotRouting) != origRouting {
		t.Fatalf("last-good rollback failed:\ncfg=%s\nrouting=%s", gotCfg, gotRouting)
	}
	st = getSystem()
	if !st.ConfigInSync || !st.LastReloadRolledBack || st.LastReloadError == "" || strings.Contains(st.LastReloadError, "hy2://") {
		t.Fatalf("post-rollback status = %+v", st)
	}
}

func TestAdminServerRefreshResolvesOnceAndHotReloadsListenAndSecret(t *testing.T) {
	addr1 := reserveTestLoopbackAddr(t)
	addr2 := reserveTestLoopbackAddr(t)

	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane {
		return &stubAdminPlane{sysInfo: control.AdminSystemInfo{Version: "test"}}
	}, nil)
	t.Cleanup(server.shutdown)

	resolveCalls := 0
	server.resolveListenFn = func(_ context.Context, listen string) (string, error) {
		if listen == "router.lan:2025" {
			resolveCalls++
			if resolveCalls > 1 {
				return "", errors.New("unexpected re-resolution")
			}
			return addr1, nil
		}
		if listen == "public.example.com:2025" {
			return "", errors.New("admin_listen host \"public.example.com\" resolved to non-private address 8.8.8.8")
		}
		return config.ResolveAndValidateAdminListen(context.Background(), listen)
	}

	server.refresh("public.example.com:2025", "sec1")
	server.mu.Lock()
	if server.http != nil {
		server.mu.Unlock()
		t.Fatal("expected public hostname refresh to fail without starting HTTP server")
	}
	server.mu.Unlock()

	server.refresh("router.lan:2025", "sec1")
	server.mu.Lock()
	bound1 := server.boundAddr
	srv1 := server.http
	server.mu.Unlock()
	if srv1 == nil || bound1 != addr1 || resolveCalls != 1 {
		t.Fatalf("srv1=%v bound1=%q addr1=%q resolveCalls=%d", srv1 != nil, bound1, addr1, resolveCalls)
	}

	client := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	doSystem := func(addr, secret string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/api/v1/system", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		return client.Do(req)
	}

	resp, err := doSystem(addr1, "sec1")
	if err != nil {
		t.Fatalf("GET on initial resolved listener failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial status code = %d, want 200", resp.StatusCode)
	}

	applyPublishedReloadAdmin(server, &config.Config{Global: config.Global{AdminListen: addr2, AdminSecret: "sec2"}}, errors.New("reload failed"), true, nil)
	server.mu.Lock()
	if server.boundAddr != addr1 || server.suspended {
		suspended := server.suspended
		bound := server.boundAddr
		server.mu.Unlock()
		t.Fatalf("failed reload must not rebind or suspend adminHTTP, bound=%q suspended=%v", bound, suspended)
	}
	server.mu.Unlock()

	applyPublishedReloadAdmin(server, &config.Config{Global: config.Global{AdminListen: addr2, AdminSecret: "sec2"}}, nil, true, nil)
	server.mu.Lock()
	if server.boundAddr != addr1 || !server.suspended {
		suspended := server.suspended
		bound := server.boundAddr
		server.mu.Unlock()
		t.Fatalf("suspend must mark suspended and not rebind adminHTTP, bound=%q suspended=%v", bound, suspended)
	}
	server.mu.Unlock()

	handoff := newStagedReloadHandoff(&runtimeGeneration{}, &runtimeGeneration{}, false, false)
	applyPublishedReloadAdmin(server, &config.Config{Global: config.Global{AdminListen: addr2, AdminSecret: "sec2"}}, nil, handoff.isSuspend, nil)
	server.mu.Lock()
	bound2 := server.boundAddr
	stillSuspended := server.suspended
	server.mu.Unlock()
	if bound2 != addr2 || stillSuspended {
		t.Fatalf("hot reload boundAddr = %q (want %q), suspended = %v (want false)", bound2, addr2, stillSuspended)
	}

	if respOld, err := doSystem(addr1, "sec1"); err == nil {
		_ = respOld.Body.Close()
		t.Fatalf("old listener %s still accepted connection after hot reload", addr1)
	}
	respWrongSecret, err := doSystem(addr2, "sec1")
	if err != nil {
		t.Fatalf("GET on new listener with old secret failed: %v", err)
	}
	_ = respWrongSecret.Body.Close()
	if respWrongSecret.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old secret on new listener = %d, want 401", respWrongSecret.StatusCode)
	}
	respNew, err := doSystem(addr2, "sec2")
	if err != nil {
		t.Fatalf("GET on new listener with new secret failed: %v", err)
	}
	_ = respNew.Body.Close()
	if respNew.StatusCode != http.StatusOK {
		t.Fatalf("new listener status = %d, want 200", respNew.StatusCode)
	}
}

func TestAdminP0ProbesStickySelectionCloseExistingAndSuspend(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{
		groups: []control.AdminGroup{
			{
				Name:     "proxy",
				Policy:   "fixed",
				Selected: "hk-01",
				Members: []control.AdminGroupMember{
					{Name: "hk-01", Kind: "node"},
					{Name: "sg-01", Kind: "node"},
				},
			},
		},
		stickyEntries: []outbound.SiteStickyEntrySnapshot{
			{Site: "youtube.com", Network: "tcp", Leaf: "hk-01"},
		},
		stickyCleared: 1,
		batchClosed:   3,
		connections: control.AdminConnectionsSnapshot{
			Total: 2,
			Connections: []control.AdminConnection{
				{ID: "tcp:1", Network: "tcp4", Outbound: "proxy", Dialer: "hk-01", Offloaded: true},
				{ID: "tcp:2", Network: "tcp4", Outbound: "proxy", Dialer: "sg-01", Offloaded: false},
			},
		},
		closedFlows: control.AdminClosedFlowsSnapshot{
			Total: 2,
			Flows: []control.AdminClosedFlow{
				{Seq: 10, ID: "tcp:8", Outbound: "proxy", CloseReason: "normal"},
				{Seq: 12, ID: "tcp:9", Outbound: "proxy", CloseReason: "aborted", Offloaded: true},
			},
		},
	}

	var suspendedAbort *bool
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, func() bool { return true })
	server.secret = "p0-token"
	server.suspend = func(abort bool) bool {
		v := abort
		suspendedAbort = &v
		return true
	}
	handler := server.withSecurityHeaders(server.buildMux())

	do := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer p0-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// All-groups probe + 3s cooldown
	rec := do(http.MethodPost, "/api/v1/groups/probe", "")
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"groups":1`) {
		t.Fatalf("all-groups probe code=%d body=%s", rec.Code, rec.Body.String())
	}
	rec2 := do(http.MethodPost, "/api/v1/groups/probe", "")
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("all-groups probe cooldown code=%d, want 429", rec2.Code)
	}

	// Per-member probe + 2s cooldown
	mRec := do(http.MethodPost, "/api/v1/groups/proxy/members/hk-01/probe", "")
	if mRec.Code != http.StatusAccepted || plane.delayFor != "proxy" || plane.delayMember != "hk-01" {
		t.Fatalf("member probe code=%d group=%q member=%q body=%s", mRec.Code, plane.delayFor, plane.delayMember, mRec.Body.String())
	}
	mRec2 := do(http.MethodPost, "/api/v1/groups/proxy/members/hk-01/probe", "")
	if mRec2.Code != http.StatusTooManyRequests || mRec2.Header().Get("Retry-After") != "2" {
		t.Fatalf("member probe cooldown code=%d retry=%q", mRec2.Code, mRec2.Header().Get("Retry-After"))
	}

	// Sticky GET + DELETE site + DELETE all
	sRec := do(http.MethodGet, "/api/v1/groups/proxy/sticky?network=tcp&q=you&limit=50", "")
	if sRec.Code != http.StatusOK || plane.stickyGroup != "proxy" || plane.stickyNetwork != "tcp" || plane.stickyQuery != "you" || plane.stickyLimit != 50 || !strings.Contains(sRec.Body.String(), `"youtube.com"`) {
		t.Fatalf("sticky GET code=%d body=%s", sRec.Code, sRec.Body.String())
	}
	dRec := do(http.MethodDelete, "/api/v1/groups/proxy/sticky/youtube.com?network=tcp", "")
	if dRec.Code != http.StatusOK || plane.stickySite != "youtube.com" || !strings.Contains(dRec.Body.String(), `"cleared":1`) {
		t.Fatalf("sticky DELETE site code=%d body=%s", dRec.Code, dRec.Body.String())
	}
	dAll := do(http.MethodDelete, "/api/v1/groups/proxy/sticky", "")
	if dAll.Code != http.StatusOK || plane.stickySite != "" {
		t.Fatalf("sticky DELETE all code=%d site=%q", dAll.Code, plane.stickySite)
	}

	// Selection with close_existing delegates to AdminCloseGroupOtherConnections
	selRec := do(http.MethodPut, "/api/v1/groups/proxy/selection", `{"member":"sg-01","close_existing":true}`)
	if selRec.Code != http.StatusOK || plane.setMember != "sg-01" || plane.closeOtherGroup != "proxy" || plane.closeOtherKeep != "sg-01" || !strings.Contains(selRec.Body.String(), `"closed_connections":3`) {
		t.Fatalf("selection close_existing code=%d group=%q keep=%q body=%s", selRec.Code, plane.closeOtherGroup, plane.closeOtherKeep, selRec.Body.String())
	}

	// Connections offloaded filter + closed flows close_reason & after_seq
	offRec := do(http.MethodGet, "/api/v1/connections?offloaded=true", "")
	if offRec.Code != http.StatusOK || !strings.Contains(offRec.Body.String(), `"tcp:1"`) || strings.Contains(offRec.Body.String(), `"tcp:2"`) {
		t.Fatalf("offloaded filter body=%s", offRec.Body.String())
	}
	cfRec := do(http.MethodGet, "/api/v1/flows/closed?close_reason=aborted&after_seq=10", "")
	if cfRec.Code != http.StatusOK || plane.closedAfter != 10 || !strings.Contains(cfRec.Body.String(), `"tcp:9"`) || strings.Contains(cfRec.Body.String(), `"tcp:8"`) {
		t.Fatalf("closed flows filter body=%s", cfRec.Body.String())
	}

	// Invalid offloaded query param returns 400 invalid_param on both connections & closed flows.
	if badOff := do(http.MethodGet, "/api/v1/connections?offloaded=abc", ""); badOff.Code != http.StatusBadRequest || !strings.Contains(badOff.Body.String(), `"invalid_param"`) {
		t.Fatalf("connections offloaded=abc code=%d body=%s", badOff.Code, badOff.Body.String())
	}
	if badCFOff := do(http.MethodGet, "/api/v1/flows/closed?offloaded=abc", ""); badCFOff.Code != http.StatusBadRequest || !strings.Contains(badCFOff.Body.String(), `"invalid_param"`) {
		t.Fatalf("flows/closed offloaded=abc code=%d body=%s", badCFOff.Code, badCFOff.Body.String())
	}

	// close_reason-only batch close returns 400 filter_required.
	if crOnly := do(http.MethodPost, "/api/v1/connections/close", `{"close_reason":"aborted"}`); crOnly.Code != http.StatusBadRequest || !strings.Contains(crOnly.Body.String(), `"filter_required"`) {
		t.Fatalf("close_reason-only batch close code=%d body=%s", crOnly.Code, crOnly.Body.String())
	}

	// Suspend endpoint & system suspended field
	suspRec := do(http.MethodPost, "/api/v1/system/suspend", `{"abort":true}`)
	if suspRec.Code != http.StatusAccepted || suspendedAbort == nil || !*suspendedAbort {
		t.Fatalf("suspend code=%d abort=%v body=%s", suspRec.Code, suspendedAbort, suspRec.Body.String())
	}
	server.markSuspended()
	sysRec := do(http.MethodGet, "/api/v1/system", "")
	if sysRec.Code != http.StatusOK || !strings.Contains(sysRec.Body.String(), `"suspended":true`) {
		t.Fatalf("system suspended body=%s", sysRec.Body.String())
	}
}

func TestAdminGroupPathEscapingAndProbeCooldownIsolation(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.secret = "escape-token"
	handler := server.withSecurityHeaders(server.buildMux())

	do := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer escape-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Member containing '%'
	rec := do(http.MethodPost, "/api/v1/groups/proxy/members/HK%2001%20%7C%2050%25/probe", "")
	if rec.Code != http.StatusAccepted || plane.delayFor != "proxy" || plane.delayMember != "HK 01 | 50%" {
		t.Fatalf("percent member probe code=%d group=%q member=%q body=%s", rec.Code, plane.delayFor, plane.delayMember, rec.Body.String())
	}

	// Member containing literal '%20' must not double-unescape to space
	rec = do(http.MethodPost, "/api/v1/groups/proxy/members/HK%2001%20%2520/probe", "")
	if rec.Code != http.StatusAccepted || plane.delayMember != "HK 01 %20" {
		t.Fatalf("literal %%20 member probe code=%d member=%q body=%s", rec.Code, plane.delayMember, rec.Body.String())
	}

	// Member containing encoded '/'
	rec = do(http.MethodPost, "/api/v1/groups/proxy/members/HK%2001%20%2F%20IEPL/probe", "")
	if rec.Code != http.StatusAccepted || plane.delayMember != "HK 01 / IEPL" {
		t.Fatalf("slash member probe code=%d member=%q body=%s", rec.Code, plane.delayMember, rec.Body.String())
	}

	// Group containing encoded '/'
	rec = do(http.MethodPut, "/api/v1/groups/HK%2FIEPL/selection", `{"member":"hk-01"}`)
	if rec.Code != http.StatusOK || plane.setGroup != "HK/IEPL" || plane.setMember != "hk-01" {
		t.Fatalf("slash group selection code=%d group=%q member=%q body=%s", rec.Code, plane.setGroup, plane.setMember, rec.Body.String())
	}

	// All-groups probe cooldown must not block a user group literally named "*"
	allRec := do(http.MethodPost, "/api/v1/groups/probe", "")
	if allRec.Code != http.StatusAccepted {
		t.Fatalf("all-groups probe code=%d body=%s", allRec.Code, allRec.Body.String())
	}
	starRec := do(http.MethodPost, "/api/v1/groups/*/probe", "")
	if starRec.Code != http.StatusAccepted || plane.delayFor != "*" {
		t.Fatalf("star group probe code=%d delayFor=%q body=%s", starRec.Code, plane.delayFor, starRec.Body.String())
	}
}
