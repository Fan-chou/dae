// SPDX-License-Identifier: AGPL-3.0-only
package cmd

import (
	"github.com/daeuniverse/dae/component/observation"
	"net/http/httptest"
	"testing"
)

type captureAdminPlane struct {
	stubAdminPlane
	after uint64
}

func (p *captureAdminPlane) AdminCapture(after uint64) observation.Snapshot {
	p.after = after
	return observation.Snapshot{}
}
func TestAdminCaptureAuthenticationAndCursor(t *testing.T) {
	plane := &captureAdminPlane{}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.secret = "capture-test"
	for _, tc := range []struct {
		method, path, token string
		code                int
	}{
		{"GET", "/v1/capture", "", 401},
		{"POST", "/v1/capture", "capture-test", 405},
		{"GET", "/v1/capture?after=-1", "capture-test", 400},
		{"GET", "/v1/capture?after=42", "capture-test", 200},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		rec := httptest.NewRecorder()
		server.withAdminAuth(server.handleCapture).ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Fatalf("%s %s: %d", tc.method, tc.path, rec.Code)
		}
	}
	if plane.after != 42 {
		t.Fatal("cursor lost")
	}
}

func (p *captureAdminPlane) AdminEvidence(after uint64) observation.EvidenceSnapshot {
	p.after = after
	return observation.EvidenceSnapshot{}
}
func TestAdminEvidenceAuthenticationAndCursor(t *testing.T) {
	plane := &captureAdminPlane{}
	server := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return plane }, nil)
	server.secret = "test"
	for _, tc := range []struct {
		path, token string
		code        int
	}{
		{"/v1/evidence", "", 401}, {"/v1/evidence?after=-1", "test", 400}, {"/v1/evidence?after=42", "test", 200},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		rec := httptest.NewRecorder()
		server.withAdminAuth(server.handleEvidence).ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Fatal(rec.Code)
		}
	}
	if plane.after != 42 {
		t.Fatal("cursor lost")
	}
}
