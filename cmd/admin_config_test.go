/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeRestrictedDae(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func strPtr(v string) *string { return &v }

func TestExtractNamedSectionsKeepsGlobalAndRouting(t *testing.T) {
	src := `
include {
    current/nodes.dae
    routing.dae
}
global {
    log_level: info
    admin_secret: 'keep-me'
    tcp_check_url: 'http://cp.cloudflare.com/generate_204'
}
dns {
    upstream { homedns: 'udp://127.0.0.1:53' }
}
routing {
    fallback: direct
}
`
	got, err := extractNamedSections(src, "global", "routing")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "nodes.dae") || strings.Contains(got, "dns") {
		t.Fatalf("extracted leaked other sections: %s", got)
	}
	if !strings.Contains(got, "log_level") || !strings.Contains(got, "fallback: direct") {
		t.Fatalf("extracted missing sections: %s", got)
	}
}

func TestLoadAdminConfigRedactsSecretAndOmitsNodes(t *testing.T) {
	dir := t.TempDir()
	writeRestrictedDae(t, filepath.Join(dir, "config.dae"), `
include { current/nodes.dae }
global {
    log_level: info
    admin_secret: 'keep-me'
}
routing { fallback: direct }
`)
	writeRestrictedDae(t, filepath.Join(dir, "routing.dae"), "routing {\n    dip(1.1.1.1) -> direct\n}\n")
	body, err := loadAdminConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body.Config, "keep-me") || strings.Contains(body.Config, "nodes.dae") {
		t.Fatalf("GET leaked secret or nodes: %+v", body)
	}
	if !strings.Contains(body.Config, adminSecretPlaceholder) {
		t.Fatalf("secret placeholder missing: %s", body.Config)
	}
	if !strings.Contains(body.Routing, "dip(1.1.1.1)") {
		t.Fatalf("routing missing: %s", body.Routing)
	}
}

func TestApplyAdminConfigKeepsSecretAndRejectsNodeURI(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	routingPath := filepath.Join(dir, "routing.dae")
	writeRestrictedDae(t, configPath, `global {
    log_level: info
    admin_secret: 'keep-me'
}
routing { fallback: direct }
`)
	writeRestrictedDae(t, routingPath, "routing {\n    fallback: direct\n}\n")

	reloaded := false
	incoming := `global {
    log_level: warn
    admin_secret: '***'
}
routing { fallback: direct }
`
	queued, err := applyAdminConfig(dir, adminConfigBody{Config: strPtr(incoming)}, func() bool {
		reloaded = true
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if !queued || !reloaded {
		t.Fatalf("queued=%v reloaded=%v", queued, reloaded)
	}
	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "keep-me") || !strings.Contains(string(saved), "log_level: warn") {
		t.Fatalf("saved = %s", saved)
	}

	before := string(saved)
	_, err = applyAdminConfig(dir, adminConfigBody{
		Routing: strPtr("routing {\n    hy2://secret@example.com\n}\n"),
	}, func() bool { t.Fatal("reload on reject"); return true })
	if err == nil {
		t.Fatal("node URI should be rejected")
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != before {
		t.Fatal("rejected PUT mutated config.dae")
	}
	routing, err := os.ReadFile(routingPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(routing), "hy2://") {
		t.Fatal("rejected PUT wrote a node URI")
	}
}

func TestApplyAdminConfigRollsBackInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	original := `global {
    log_level: info
}
routing { fallback: direct }
`
	writeRestrictedDae(t, configPath, original)
	_, err := applyAdminConfig(dir, adminConfigBody{
		Config: strPtr("global {\n    tproxy_port: 'nope'\n}\nrouting { fallback: direct }\n"),
	}, func() bool { t.Fatal("reload on invalid"); return true })
	if err == nil {
		t.Fatal("invalid config should fail validate")
	}
	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != original {
		t.Fatalf("rollback failed: %s", saved)
	}
}

func TestAdminConfigHTTPRedactsAndRejectsURI(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRestrictedDae(t, filepath.Join(dir, "config.dae"), `global {
    log_level: info
    admin_secret: 'keep-me'
}
routing { fallback: direct }
`)
	writeRestrictedDae(t, filepath.Join(dir, "routing.dae"), "routing { fallback: direct }\n")
	reloaded := false
	server := newAdminServer(nil, "", dir, nil, func() bool {
		reloaded = true
		return true
	})
	server.secret = "test-token"

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.withAdminAuth(server.handleConfig)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET config status = %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("GET /api/v1/config missing ETag header")
	}
	if strings.Contains(rec.Body.String(), "keep-me") || strings.Contains(rec.Body.String(), "hy2://") {
		t.Fatalf("GET leaked secret or URI: %s", rec.Body.String())
	}
	var body adminConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.Config, adminSecretPlaceholder) {
		t.Fatalf("placeholder missing: %+v", body)
	}

	staleReq := httptest.NewRequest(http.MethodPut, "/api/v1/config", strings.NewReader(`{"routing":"routing { fallback: direct }"}`))
	staleReq.Header.Set("Authorization", "Bearer test-token")
	staleReq.Header.Set("If-Match", `"stale-etag"`)
	staleRec := httptest.NewRecorder()
	server.withAdminAuth(server.handleConfig)(staleRec, staleReq)
	if staleRec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match status = %d, want 412", staleRec.Code)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/v1/config", strings.NewReader(`{"routing":"routing { hy2://x }"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	server.withAdminAuth(server.handleConfig)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT URI status = %d body %s", rec.Code, rec.Body.String())
	}
	if reloaded {
		t.Fatal("rejected PUT must not reload")
	}
	if strings.Contains(rec.Body.String(), "://") {
		t.Fatalf("error leaked a URI: %s", rec.Body.String())
	}
}

func TestApplyAdminConfigRollsBackTrailingComma(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	original := `global {
    log_level: info
}
routing { fallback: direct }
`
	writeRestrictedDae(t, configPath, original)
	_, err := applyAdminConfig(dir, adminConfigBody{
		Config: strPtr(`global { log_level: info }
routing {
    !sip(
        match_mac: '192.168.124.129/32',
    ) -> must_direct
    fallback: direct
}
`),
	}, func() bool { t.Fatal("reload on trailing comma"); return true })
	if err == nil {
		t.Fatal("trailing comma should fail validate")
	}
	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != original {
		t.Fatalf("rollback failed: %s", saved)
	}
}

func TestHandleReloadRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	writeRestrictedDae(t, filepath.Join(dir, "config.dae"), `global { log_level: info }
routing {
    !sip(match_mac: '192.168.124.129/32',) -> must_direct
}
`)
	reloaded := false
	server := newAdminServer(nil, "", dir, nil, func() bool {
		reloaded = true
		return true
	})
	server.secret = "test-token"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/reload", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.withAdminAuth(server.handleReload)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reload invalid status = %d body %s", rec.Code, rec.Body.String())
	}
	if reloaded {
		t.Fatal("invalid config must not reload")
	}
	if strings.Contains(rec.Body.String(), "panic") {
		t.Fatalf("error should not mention panic: %s", rec.Body.String())
	}
}

func TestHandleReloadAcceptsValidConfig(t *testing.T) {
	dir := t.TempDir()
	writeRestrictedDae(t, filepath.Join(dir, "config.dae"), `global { log_level: info }
routing { fallback: direct }
`)
	reloaded := false
	server := newAdminServer(nil, "", dir, nil, func() bool {
		reloaded = true
		return true
	})
	server.secret = "test-token"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/reload", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.withAdminAuth(server.handleReload)(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("reload valid status = %d body %s", rec.Code, rec.Body.String())
	}
	if !reloaded {
		t.Fatal("valid config should queue reload")
	}
}

func TestApplyAdminConfigRollsBackWhenReloadQueueFullOrNil(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	routingPath := filepath.Join(dir, "routing.dae")
	origConfig := "global {\n    log_level: info\n    admin_secret: 'keep-me'\n}\nrouting { fallback: direct }\n"
	origRouting := "routing {\n    dip(1.1.1.1) -> direct\n}\n"
	writeRestrictedDae(t, configPath, origConfig)
	writeRestrictedDae(t, routingPath, origRouting)

	newConfig := "global {\n    log_level: warn\n    admin_secret: '***'\n}\nrouting { fallback: direct }\n"
	newRouting := "routing {\n    dip(8.8.8.8) -> direct\n}\n"

	for name, reloadFn := range map[string]adminReloadFunc{
		"queue full": func() bool { return false },
		"nil reload": nil,
	} {
		queued, err := applyAdminConfig(dir, adminConfigBody{
			Config:  strPtr(newConfig),
			Routing: strPtr(newRouting),
		}, reloadFn)
		if queued || !errors.Is(err, errAdminReloadQueueFull) {
			t.Fatalf("%s: got (queued=%v, err=%v), want (false, errAdminReloadQueueFull)", name, queued, err)
		}
		gotCfg, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotCfg) != origConfig {
			t.Fatalf("%s: config.dae not restored:\n%s", name, gotCfg)
		}
		gotRouting, err := os.ReadFile(routingPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotRouting) != origRouting {
			t.Fatalf("%s: routing.dae not restored:\n%s", name, gotRouting)
		}
		if _, err := os.Stat(configPath + ".admin-bak"); !os.IsNotExist(err) {
			t.Fatalf("%s: config.dae.admin-bak left behind: %v", name, err)
		}
		if _, err := os.Stat(routingPath + ".admin-bak"); !os.IsNotExist(err) {
			t.Fatalf("%s: routing.dae.admin-bak left behind: %v", name, err)
		}
	}
}

func TestApplyAdminConfigRemovesAbsentRoutingOnQueueFullRollback(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	routingPath := filepath.Join(dir, "routing.dae")
	origConfig := "global {\n    log_level: info\n}\nrouting { fallback: direct }\n"
	writeRestrictedDae(t, configPath, origConfig)

	queued, err := applyAdminConfig(dir, adminConfigBody{
		Routing: strPtr("routing {\n    dip(1.1.1.1) -> direct\n}\n"),
	}, func() bool { return false })
	if queued || !errors.Is(err, errAdminReloadQueueFull) {
		t.Fatalf("got (%v, %v), want (false, errAdminReloadQueueFull)", queued, err)
	}
	if _, err := os.Stat(routingPath); !os.IsNotExist(err) {
		t.Fatalf("newly created routing.dae was not removed on rollback: %v", err)
	}
	gotCfg, _ := os.ReadFile(configPath)
	if string(gotCfg) != origConfig {
		t.Fatalf("config.dae altered: %s", gotCfg)
	}
}

func TestHandleConfigReturns409WhenReloadQueueFull(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	origConfig := "global {\n    log_level: info\n}\nrouting { fallback: direct }\n"
	writeRestrictedDae(t, configPath, origConfig)

	server := newAdminServer(nil, "", dir, nil, func() bool { return false })
	server.secret = "test-token"

	req := httptest.NewRequest(http.MethodPut, "/api/v1/config", strings.NewReader(`{"config":"global { log_level: warn }\nrouting { fallback: direct }\n"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.withAdminAuth(server.handleConfig)(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT /api/v1/config queue full status = %d body %s, want 409", rec.Code, rec.Body.String())
	}
	var errBody adminAPIErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody.Error.Code == "" || errBody.Error.Message == "" {
		t.Fatalf("expected structured JSON error body, got %s (%v)", rec.Body.String(), err)
	}
	gotCfg, _ := os.ReadFile(configPath)
	if string(gotCfg) != origConfig {
		t.Fatalf("config.dae mutated on 409: %s", gotCfg)
	}
}

func TestAdminConfigWriteMuSerializesConfigAndInboundsWrites(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.dae")
	writeRestrictedDae(t, configPath, "global {\n    tproxy_port: 12345\n    log_level: info\n    wan_interface: auto\n    lan_interface: lo\n}\nrouting {\n    fallback: direct\n}\n")

	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	server := newAdminServer(nil, "", dir, nil, func() bool {
		cur := inFlight.Add(1)
		for {
			prev := maxInFlight.Load()
			if cur <= prev || maxInFlight.CompareAndSwap(prev, cur) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		inFlight.Add(-1)
		return true
	})
	server.secret = "test-token"

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(iter int) {
			defer wg.Done()
			level := "info"
			if iter%2 == 1 {
				level = "warn"
			}
			body := `{"config":"global { tproxy_port: 12345\n log_level: ` + level + `\n wan_interface: auto\n lan_interface: lo }\nrouting { fallback: direct }\n"}`
			req := httptest.NewRequest(http.MethodPut, "/api/v1/config", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer test-token")
			rec := httptest.NewRecorder()
			server.withAdminAuth(server.handleConfig)(rec, req)
			if rec.Code != http.StatusOK {
				errs <- errors.New("config PUT status " + rec.Body.String())
			}
		}(i)

		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPut, "/api/v1/inbounds", strings.NewReader(`{"inbounds":[{"name":"s1","listen":"127.0.0.1:11080"}]}`))
			req.Header.Set("Authorization", "Bearer test-token")
			rec := httptest.NewRecorder()
			server.withAdminAuth(server.handleInbounds)(rec, req)
			if rec.Code != http.StatusOK {
				errs <- errors.New("inbounds PUT status " + rec.Body.String())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if maxInFlight.Load() != 1 {
		t.Fatalf("concurrent config/inbounds writers overlapped: maxInFlight=%d", maxInFlight.Load())
	}
	if err := validateLoadedAdminConfig(dir); err != nil {
		t.Fatalf("final config invalid after concurrent writes: %v", err)
	}
	if _, err := os.Stat(configPath + ".admin-bak"); !os.IsNotExist(err) {
		t.Fatalf("backup left behind: %v", err)
	}
}
