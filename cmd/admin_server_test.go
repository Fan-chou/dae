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
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

type stubAdminPlane struct {
	status       control.AdminStatus
	groups       []control.AdminGroup
	setErr       error
	setGroup     string
	setMember    string
	delayErr     error
	delayFor     string
	connLimit    int
	connOutbound string
	connSrc      string
	connMac      string
	connections  control.AdminConnectionsSnapshot

	kernelCalls int
	kernelLimit int
	kernelSrc   string
	kernelMac   string
}

func (s *stubAdminPlane) AdminGroups() []control.AdminGroup { return s.groups }
func (s *stubAdminPlane) AdminStatusSnapshot(version string) control.AdminStatus {
	status := s.status
	if status.Version == "" {
		status.Version = version
	}
	status.Running = true
	return status
}
func (s *stubAdminPlane) SetGroupSelection(groupName, memberName string) error {
	s.setGroup = groupName
	s.setMember = memberName
	return s.setErr
}
func (s *stubAdminPlane) TriggerLatencyChecksForGroup(groupName string) error {
	s.delayFor = groupName
	return s.delayErr
}
func (s *stubAdminPlane) AdminKernelConnections(limit int, src, mac string) control.AdminKernelConnectionsSnapshot {
	s.kernelCalls++
	s.kernelLimit = limit
	s.kernelSrc = src
	s.kernelMac = mac
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

func (s *stubAdminPlane) AdminConnections(limit int, outbound, src, mac, inbound string) control.AdminConnectionsSnapshot {
	s.connLimit = limit
	s.connOutbound = outbound
	s.connSrc = src
	s.connMac = mac
	if s.connections.Connections == nil {
		return control.AdminConnectionsSnapshot{Connections: []control.AdminConnection{}}
	}
	return s.connections
}

func TestAdminBearerAndCORS(t *testing.T) {
	t.Parallel()
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane {
		return &stubAdminPlane{status: control.AdminStatus{Version: "test"}}
	}, func() bool { return true })
	server.secret = "test-token"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", server.withAdminAuth(server.handleStatus))
	handler := server.withAdminCORS(mux)

	req := httptest.NewRequest(http.MethodOptions, "/v1/status", nil)
	req.Header.Set("Origin", "http://192.168.124.223")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://192.168.124.223" {
		t.Fatalf("CORS origin = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authed status = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestAdminPutGroupSelectionDoesNotReload(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{}
	reloaded := false
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, func() bool {
		reloaded = true
		return true
	})
	server.secret = "test-token"

	req := httptest.NewRequest(http.MethodPut, "/v1/groups/proxy", strings.NewReader(`{"member":"Cherry_Proxy"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.withAdminAuth(server.handleGroup)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d body %s", rec.Code, rec.Body.String())
	}
	if reloaded {
		t.Fatal("PUT /v1/groups must not trigger a full reload")
	}
	if plane.setGroup != "proxy" || plane.setMember != "Cherry_Proxy" {
		t.Fatalf("SetGroupSelection(%q, %q)", plane.setGroup, plane.setMember)
	}
}

func TestAdminLogsOmitsMissingFile(t *testing.T) {
	t.Parallel()
	server := newAdminServer(nil, filepath.Join(t.TempDir(), "missing.log"), "", nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/logs", nil)
	rec := httptest.NewRecorder()
	server.handleLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body adminLogsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Lines == nil {
		t.Fatal("lines should be an empty slice")
	}
}

func TestAdminGroupNameFromPath(t *testing.T) {
	t.Parallel()
	name, err := adminGroupNameFromPath("/v1/groups/proxy")
	if err != nil || name != "proxy" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	name, err = adminGroupNameFromPath("/v1/groups/a%2Fb")
	if err == nil {
		t.Fatalf("escaped slash should be rejected, got %q", name)
	}
}

func TestAdminOriginRejectedForPublicHosts(t *testing.T) {
	t.Parallel()
	if adminOriginAllowed("http://8.8.8.8") {
		t.Fatal("public origin must be rejected")
	}
	if !adminOriginAllowed("http://192.168.124.223") {
		t.Fatal("LAN origin must be allowed")
	}
}

func TestTailLogLinesKeepsLastN(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "dae.log")
	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := tailLogLines(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "b,c" {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestAdminPostGroupDelayDoesNotReload(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{}
	reloaded := false
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, func() bool {
		reloaded = true
		return true
	})
	server.secret = "test-token"
	req := httptest.NewRequest(http.MethodPost, "/v1/groups/AI/delay", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.withAdminAuth(server.handleGroup)(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST delay status = %d body %s", rec.Code, rec.Body.String())
	}
	if reloaded {
		t.Fatal("POST delay must not trigger a full reload")
	}
	if plane.delayFor != "AI" {
		t.Fatalf("delay group = %q", plane.delayFor)
	}
	if strings.Contains(rec.Body.String(), "://") {
		t.Fatalf("delay JSON leaked a URI: %s", rec.Body.String())
	}
}

func TestAdminGetConnectionsForwardsFiltersAndOmitsURI(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{
		connections: control.AdminConnectionsSnapshot{
			Total: 1,
			Connections: []control.AdminConnection{{
				ID:       "1",
				Network:  "tcp",
				Src:      "192.168.124.202:44321",
				Dst:      "api2.cursor.sh:443",
				Mac:      "3e:0a:a5:de:ae:a3",
				Outbound: "AI",
				Dialer:   "US_Dmit_LAX_Hysteria",
				Policy:   "fixed",
				Upload:   32,
			}},
		},
	}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.secret = "test-token"
	req := httptest.NewRequest(http.MethodGet, "/v1/connections?outbound=AI&src=192.168.124.202&mac=3e:0a&limit=64", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.withAdminAuth(server.handleConnections)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET connections status = %d body %s", rec.Code, rec.Body.String())
	}
	if plane.connLimit != 64 || plane.connOutbound != "AI" || plane.connSrc != "192.168.124.202" || plane.connMac != "3e:0a" {
		t.Fatalf("filters limit=%d outbound=%q src=%q mac=%q", plane.connLimit, plane.connOutbound, plane.connSrc, plane.connMac)
	}
	if strings.Contains(rec.Body.String(), "://") {
		t.Fatalf("connections JSON leaked a URI: %s", rec.Body.String())
	}
	var snap control.AdminConnectionsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Total != 1 || len(snap.Connections) != 1 || snap.Connections[0].Outbound != "AI" || snap.Connections[0].Dialer != "US_Dmit_LAX_Hysteria" {
		t.Fatalf("snap = %+v", snap)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/connections?limit=nope", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	server.withAdminAuth(server.handleConnections)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit status = %d", rec.Code)
	}
}

func TestAdminKernelConnectionsEndpoint(t *testing.T) {
	t.Parallel()
	plane := &stubAdminPlane{}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.secret = "test-token"
	get := func(target string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer test-token")
		}
		rec := httptest.NewRecorder()
		server.withAdminAuth(server.handleKernelConnections)(rec, req)
		return rec
	}

	if rec := get("/v1/kernel-connections", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", rec.Code)
	}
	if plane.kernelCalls != 0 {
		t.Fatal("unauthenticated request reached the conntrack reader")
	}

	rec := get("/v1/kernel-connections?limit=64&src=192.168.124.200&mac=3e:0a:a5:de:ae:a3", true)
	if rec.Code != http.StatusOK || plane.kernelLimit != 64 || plane.kernelSrc != "192.168.124.200" || plane.kernelMac != "3e:0a:a5:de:ae:a3" {
		t.Fatalf("status=%d limit=%d src=%q body=%s", rec.Code, plane.kernelLimit, plane.kernelSrc, rec.Body.String())
	}
	var snap control.AdminKernelConnectionsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if !snap.Available || !snap.Accounting || len(snap.Connections) != 1 || snap.Connections[0].Upload != 7 {
		t.Fatalf("snap = %+v", snap)
	}

	if rec := get("/v1/kernel-connections?limit=nope", true); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit status = %d", rec.Code)
	}
	if rec := get("/v1/kernel-connections?src=bad", true); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid src status = %d", rec.Code)
	}
	if rec := get("/v1/kernel-connections?mac=bad", true); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid mac status = %d", rec.Code)
	}

	// The default connection list must never read conntrack.
	before := plane.kernelCalls
	req := httptest.NewRequest(http.MethodGet, "/v1/connections", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	server.withAdminAuth(server.handleConnections)(httptest.NewRecorder(), req)
	if plane.kernelCalls != before {
		t.Fatal("/v1/connections triggered a conntrack read")
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/kernel-connections", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	server.withAdminAuth(server.handleKernelConnections)(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", rec.Code)
	}
}

func TestTailLogLinesBlockBoundaryAndUnterminatedUTF8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.log")
	content := strings.Repeat("old entry\n", 5000) + strings.Repeat("中", 6000) + "\nlast"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := tailLogLines(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != strings.Repeat("中", 6000) || got[1] != "last" {
		t.Fatal("tail lost UTF-8 boundary or final line")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 2<<20)), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = tailLogLines(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("must not return partial oversized line")
	}
}

func (s *stubAdminPlane) AdminQuality(group, host string) []map[string]any { return []map[string]any{} }

func TestAdminQualityRequiresAuthAndIsReadOnly(t *testing.T) {
	plane := &stubAdminPlane{}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.secret = "test-token"
	for _, tc := range []struct {
		method, auth string
		status       int
	}{{"GET", "", http.StatusUnauthorized}, {"POST", "Bearer test-token", http.StatusMethodNotAllowed}, {"GET", "Bearer test-token", http.StatusOK}} {
		req := httptest.NewRequest(tc.method, "/v1/quality?group=test&host=a.example.com", nil)
		req.Header.Set("Authorization", tc.auth)
		rec := httptest.NewRecorder()
		server.withAdminAuth(server.handleQuality)(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("%s => %d %s", tc.method, rec.Code, rec.Body.String())
		}
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

func TestAdminStatusReloadSyncAndLastGoodRollback(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	routingPath := filepath.Join(dir, "routing.dae")
	origCfg := "global {\n    log_level: info\n}\nrouting { fallback: direct }\n"
	origRouting := "routing {\n    dip(1.1.1.1) -> direct\n}\n"
	writeRestrictedDae(t, configPath, origCfg)
	writeRestrictedDae(t, routingPath, origRouting)

	rm := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	server := newAdminServer(nil, "", dir, func() adminPlane {
		return &stubAdminPlane{status: control.AdminStatus{Version: "test"}}
	}, func() bool { return true })
	server.secret = "test-token"
	server.setReloadManager(rm)
	server.captureActiveSnapshot()

	getStatus := func() adminStatusBody {
		req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		server.withAdminAuth(server.handleStatus)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
		}
		var out adminStatusBody
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	st := getStatus()
	if !st.ConfigInSync || st.LastReloadError != "" || st.ReloadPending {
		t.Fatalf("initial status = %+v, want in sync with no error", st)
	}
	if _, err := os.Stat(configPath + ".admin-last-good"); err != nil {
		t.Fatalf("expected .admin-last-good snapshot at startup: %v", err)
	}

	// Simulate PUT /v1/config writing a new config whose async reload fails.
	putReq := httptest.NewRequest(http.MethodPut, "/v1/config", strings.NewReader(`{"config":"global { log_level: warn }\nrouting { fallback: direct }\n","routing":"routing { dip(8.8.8.8) -> direct }\n"}`))
	putReq.Header.Set("Authorization", "Bearer test-token")
	putRec := httptest.NewRecorder()
	server.withAdminAuth(server.handleConfig)(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT /v1/config status = %d body %s", putRec.Code, putRec.Body.String())
	}

	// Before reload completes, disk differs from running state.
	st = getStatus()
	if st.ConfigInSync {
		t.Fatalf("expected config_in_sync=false while disk has pending edit: %+v", st)
	}

	// Async reload failure restores .admin-last-good and surfaces sanitized last_reload_error.
	rm.setReloadError(errors.New("dialer failed for hy2://secret@example.com"))
	server.handleAsyncReloadFailure("dialer failed for hy2://secret@example.com")

	gotCfg, _ := os.ReadFile(configPath)
	gotRouting, _ := os.ReadFile(routingPath)
	if string(gotCfg) != origCfg || string(gotRouting) != origRouting {
		t.Fatalf("last-good rollback failed:\ncfg=%s\nrouting=%s", gotCfg, gotRouting)
	}
	st = getStatus()
	if !st.ConfigInSync || !st.LastReloadRolledBack || st.LastReloadError == "" || strings.Contains(st.LastReloadError, "hy2://") {
		t.Fatalf("post-rollback status = %+v", st)
	}

	// External disk edit is NOT overwritten by async reload failure and reports out-of-sync.
	rm.setReloadError(nil)
	server.markReloadSucceeded()
	if err := os.WriteFile(configPath, []byte("global {\n    log_level: debug\n}\nrouting { fallback: direct }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rm.setReloadError(errors.New("prepare staged reload: invalid runtime"))
	server.handleAsyncReloadFailure("prepare staged reload: invalid runtime")
	st = getStatus()
	if st.ConfigInSync || st.LastReloadRolledBack || st.LastReloadError != "prepare staged reload: invalid runtime" {
		t.Fatalf("external-edit status = %+v", st)
	}
	gotCfg, _ = os.ReadFile(configPath)
	if !strings.Contains(string(gotCfg), "log_level: debug") {
		t.Fatalf("external edit was overwritten: %s", gotCfg)
	}
}

func TestAdminServerRefreshResolvesOnceAndHotReloadsListenAndSecret(t *testing.T) {
	addr1 := reserveTestLoopbackAddr(t)
	addr2 := reserveTestLoopbackAddr(t)

	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane {
		return &stubAdminPlane{status: control.AdminStatus{Version: "test"}}
	}, nil)
	t.Cleanup(server.shutdown)

	resolveCalls := 0
	server.resolveListenFn = func(_ context.Context, listen string) (string, error) {
		resolveCalls++
		if listen == "router.lan:2025" {
			// Verify TOCTOU resistance: even if a second call returned public IP,
			// refresh must only resolve once and pass the validated IP listener to Serve.
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

	// Rejected public hostname does not start listener.
	server.refresh("public.example.com:2025", "sec1")
	server.mu.Lock()
	if server.http != nil {
		server.mu.Unlock()
		t.Fatal("expected public hostname refresh to fail without starting HTTP server")
	}
	server.mu.Unlock()

	// Private hostname resolves once and binds concrete IP:port directly.
	server.refresh("router.lan:2025", "sec1")
	server.mu.Lock()
	bound1 := server.boundAddr
	srv1 := server.http
	server.mu.Unlock()
	if srv1 == nil || bound1 != addr1 || resolveCalls != 1 {
		t.Fatalf("srv1=%v bound1=%q addr1=%q resolveCalls=%d", srv1 != nil, bound1, addr1, resolveCalls)
	}

	client := &http.Client{Timeout: time.Second}
	doStatus := func(addr, secret string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/v1/status", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		return client.Do(req)
	}

	resp, err := doStatus(addr1, "sec1")
	if err != nil {
		t.Fatalf("GET on initial resolved listener failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial status code = %d, want 200", resp.StatusCode)
	}

	// Failed reload (even when isSuspend is false-positive on legacy rollback) does NOT refresh adminHTTP or mark suspended.
	applyPublishedReloadAdmin(server, &config.Config{Global: config.Global{AdminListen: addr2, AdminSecret: "sec2"}}, errors.New("reload failed"), true)
	server.mu.Lock()
	if server.boundAddr != addr1 || server.suspended {
		suspended := server.suspended
		bound := server.boundAddr
		server.mu.Unlock()
		t.Fatalf("failed reload must not rebind or suspend adminHTTP, bound=%q suspended=%v", bound, suspended)
	}
	server.mu.Unlock()

	// Suspend reload does NOT refresh adminHTTP and marks suspended.
	applyPublishedReloadAdmin(server, &config.Config{Global: config.Global{AdminListen: addr2, AdminSecret: "sec2"}}, nil, true)
	server.mu.Lock()
	if server.boundAddr != addr1 || !server.suspended {
		suspended := server.suspended
		bound := server.boundAddr
		server.mu.Unlock()
		t.Fatalf("suspend must mark suspended and not rebind adminHTTP, bound=%q suspended=%v", bound, suspended)
	}
	server.mu.Unlock()

	// Successful unsuspend / hot reload clears suspended and switches both admin_listen and admin_secret.
	handoff := newStagedReloadHandoff(&runtimeGeneration{}, &runtimeGeneration{}, false, false)
	if handoff.isSuspend {
		t.Fatal("default stagedReloadHandoff.isSuspend should be false")
	}
	applyPublishedReloadAdmin(server, &config.Config{Global: config.Global{AdminListen: addr2, AdminSecret: "sec2"}}, nil, handoff.isSuspend)
	server.mu.Lock()
	bound2 := server.boundAddr
	stillSuspended := server.suspended
	server.mu.Unlock()
	if bound2 != addr2 || stillSuspended {
		t.Fatalf("hot reload boundAddr = %q (want %q), suspended = %v (want false)", bound2, addr2, stillSuspended)
	}

	if respOld, err := doStatus(addr1, "sec1"); err == nil {
		_ = respOld.Body.Close()
		t.Fatalf("old listener %s still accepted connection after hot reload", addr1)
	}
	respWrongSecret, err := doStatus(addr2, "sec1")
	if err != nil {
		t.Fatalf("GET on new listener with old secret failed: %v", err)
	}
	_ = respWrongSecret.Body.Close()
	if respWrongSecret.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old secret on new listener = %d, want 401", respWrongSecret.StatusCode)
	}
	respNew, err := doStatus(addr2, "sec2")
	if err != nil {
		t.Fatalf("GET on new listener with new secret failed: %v", err)
	}
	_ = respNew.Body.Close()
	if respNew.StatusCode != http.StatusOK {
		t.Fatalf("new listener status = %d, want 200", respNew.StatusCode)
	}
}
