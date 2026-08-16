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
	status    control.AdminStatus
	groups    []control.AdminGroup
	setErr    error
	setGroup  string
	setMember string
	delayErr  error
	delayFor  string
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
