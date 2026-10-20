/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func (s *stubAdminPlane) AdminConnections(limit int, outbound, src, mac string) control.AdminConnectionsSnapshot {
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
