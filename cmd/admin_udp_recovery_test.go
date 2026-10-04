// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daeuniverse/dae/control"
)

type recoveryAdminPlane struct {
	stubAdminPlane
	after   uint64
	process string
}

func (p *recoveryAdminPlane) AdminUDPRecovery(after uint64, process string) control.UDPRecoverySnapshot {
	p.after, p.process = after, process
	return control.UDPRecoverySnapshot{Schema: "kdae-udp-recovery-v1", Mode: "observe"}
}

func TestAdminUDPRecoveryAuthReadOnlyAndCursor(t *testing.T) {
	for _, tc := range []struct {
		method, token, query string
		status               int
	}{
		{"GET", "", "", http.StatusUnauthorized},
		{"POST", "Bearer test", "", http.StatusMethodNotAllowed},
		{"GET", "Bearer test", "?after=-1", http.StatusBadRequest},
		{"GET", "Bearer test", "?after=18446744073709551616", http.StatusBadRequest},
		{"GET", "Bearer test", "?after=128&process=12345", http.StatusOK},
	} {
		p := &recoveryAdminPlane{}
		s := newAdminServer(nil, "", t.TempDir(), func() adminPlane { return p }, nil)
		s.secret = "test"
		r := httptest.NewRequest(tc.method, "/v1/udp-recovery"+tc.query, nil)
		r.Header.Set("Authorization", tc.token)
		w := httptest.NewRecorder()
		s.withAdminAuth(s.handleUDPRecovery)(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s %s => %d %s", tc.method, tc.query, w.Code, w.Body.String())
		}
		if tc.status == http.StatusOK && (p.after != 128 || p.process != "12345" || p.setGroup != "") {
			t.Fatalf("read changed state or cursor: %+v", p)
		}
	}
}
