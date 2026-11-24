/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
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
	"github.com/gorilla/websocket"
)

func TestAdminServerExternalWebDirServingAndSecurity(t *testing.T) {
	webDir := t.TempDir()
	outsideDir := t.TempDir()
	secretFile := filepath.Join(outsideDir, "host-secret.txt")
	if err := os.WriteFile(secretFile, []byte("TOP-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(webDir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(webDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<!doctype html><html>fdae-web</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "assets", "app.js"), []byte("console.log('fdae');"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, ".env"), []byte("SECRET=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, ".git", "HEAD"), []byte("ref: refs/heads/fdae"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(secretFile, filepath.Join(webDir, "escape-link.txt"))

	// 1. When admin_web_dir is empty, / and /web/ behave as unconfigured (require Bearer auth -> 401/404).
	disabledSrv := newAdminServer(nil, "", t.TempDir(), func() adminPlane {
		return &stubAdminPlane{sysInfo: control.AdminSystemInfo{Version: "test"}}
	}, nil)
	disabledSrv.secret = "sec"
	disabledHandler := disabledSrv.withSecurityHeaders(disabledSrv.withAdminCORS(disabledSrv.buildMux()))
	for _, path := range []string{"/", "/web", "/web/"} {
		rec := httptest.NewRecorder()
		disabledHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("disabled web %s without auth = %d, want 401", path, rec.Code)
		}
	}

	// 2. When admin_web_dir is set over a real TCP listener, /web/, SPA fallback, root assets,
	// security boundaries, same-origin API + WS, and system metadata all work cleanly.
	addr := reserveTestLoopbackAddr(t)
	srv := newAdminServer(nil, "", t.TempDir(), func() adminPlane {
		return &stubAdminPlane{sysInfo: control.AdminSystemInfo{Version: "test"}}
	}, nil)
	t.Cleanup(srv.shutdown)
	srv.refreshWithOptions(addr, "web-secret", nil, webDir)

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	baseURL := "http://" + addr

	// / and /web redirect to /web/
	for _, p := range []string{"/", "/web"} {
		resp, err := client.Get(baseURL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/web/" {
			t.Fatalf("GET %s = (%d, %q), want (302, /web/)", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	// /web/ serves index.html with no-store & X-Frame-Options: DENY
	resp, err := client.Get(baseURL + "/web/")
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, _ := os.ReadFile(filepath.Join(webDir, "index.html"))
	var gotBuf [256]byte
	n, _ := resp.Body.Read(gotBuf[:])
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(gotBuf[:n]) != string(bodyBytes) {
		t.Fatalf("GET /web/ = %d body=%q", resp.StatusCode, string(gotBuf[:n]))
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET /web/ headers = %+v", resp.Header)
	}

	// SPA route fallback
	resp, err = client.Get(baseURL + "/web/groups")
	if err != nil {
		t.Fatal(err)
	}
	n, _ = resp.Body.Read(gotBuf[:])
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(gotBuf[:n]), "fdae-web") {
		t.Fatalf("SPA fallback /web/groups = %d body=%q", resp.StatusCode, string(gotBuf[:n]))
	}

	// Static JS asset under /web/assets/ AND root /assets/ (Vite base: '/')
	for _, assetPath := range []string{"/web/assets/app.js", "/assets/app.js"} {
		r, err := client.Get(baseURL + assetPath)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusOK ||
			!strings.Contains(r.Header.Get("Content-Type"), "javascript") ||
			r.Header.Get("Cache-Control") != "no-cache" {
			t.Fatalf("GET %s = (%d, ct=%q cc=%q)", assetPath, r.StatusCode, r.Header.Get("Content-Type"), r.Header.Get("Cache-Control"))
		}
	}

	// Missing asset with extension must NOT return index.html
	if r, err := client.Get(baseURL + "/web/assets/missing.js"); err != nil {
		t.Fatal(err)
	} else {
		_ = r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Fatalf("missing asset = %d, want 404", r.StatusCode)
		}
	}

	// Dotfiles, dotdirs, traversal, and symlink escape must all be 404
	for _, blocked := range []string{"/web/.env", "/web/.git/HEAD", "/web/escape-link.txt"} {
		r, err := client.Get(baseURL + blocked)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Fatalf("blocked path %s = %d, want 404", blocked, r.StatusCode)
		}
	}
	followClient := &http.Client{}
	for _, trav := range []string{"/web/../host-secret.txt", "/web/%2e%2e/host-secret.txt"} {
		r, err := followClient.Get(baseURL + trav)
		if err != nil {
			t.Fatal(err)
		}
		var tb [256]byte
		tn, _ := r.Body.Read(tb[:])
		_ = r.Body.Close()
		if r.StatusCode != http.StatusNotFound || strings.Contains(string(tb[:tn]), "TOP-SECRET") {
			t.Fatalf("traversal path %s = (%d, %q), want 404 without secret", trav, r.StatusCode, string(tb[:tn]))
		}
	}
	directRec := httptest.NewRecorder()
	serveAdminWebDir(directRec, httptest.NewRequest(http.MethodGet, "/web/../host-secret.txt", nil), webDir, "../host-secret.txt", true)
	if directRec.Code != http.StatusNotFound {
		t.Fatalf("direct serveAdminWebDir traversal = %d, want 404", directRec.Code)
	}

	// Unknown /api/* still requires auth (401 without token) and returns JSON 404 (not HTML)
	if r, err := client.Get(baseURL + "/api/v1/nonexistent"); err != nil {
		t.Fatal(err)
	} else {
		_ = r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthed /api/v1/nonexistent = %d, want 401", r.StatusCode)
		}
	}

	// Same-origin API request succeeds without admin_cors_origins, and /api/v1/system omits disk path.
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/system", nil)
	req.Header.Set("Authorization", "Bearer web-secret")
	req.Header.Set("Origin", baseURL)
	sysResp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sysBody adminSystemBody
	if err := json.NewDecoder(sysResp.Body).Decode(&sysBody); err != nil {
		_ = sysResp.Body.Close()
		t.Fatal(err)
	}
	_ = sysResp.Body.Close()
	if sysResp.StatusCode != http.StatusOK || !sysBody.WebEnabled || sysBody.WebPath != "/web/" {
		t.Fatalf("same-origin /api/v1/system = (%d, %+v)", sysResp.StatusCode, sysBody)
	}

	// Cross-origin request is still blocked with 403.
	evilReq, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/system", nil)
	evilReq.Header.Set("Authorization", "Bearer web-secret")
	evilReq.Header.Set("Origin", "https://evil.example.com")
	evilResp, err := client.Do(evilReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = evilResp.Body.Close()
	if evilResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin request = %d, want 403", evilResp.StatusCode)
	}

	// Same-origin WebSocket connection succeeds without admin_cors_origins.
	wsConn, _, err := websocket.DefaultDialer.Dial("ws://"+addr+"/api/v1/ws", http.Header{"Origin": []string{baseURL}})
	if err != nil {
		t.Fatalf("same-origin WS dial failed: %v", err)
	}
	defer wsConn.Close()
	if err := wsConn.WriteJSON(wsClientFrame{Type: "auth", Token: "web-secret"}); err != nil {
		t.Fatal(err)
	}
	var authFrame wsServerFrame
	if err := wsConn.ReadJSON(&authFrame); err != nil || authFrame.Type != "auth_ok" {
		t.Fatalf("same-origin WS auth failed: %+v err=%v", authFrame, err)
	}
}
