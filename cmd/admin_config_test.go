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

	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.withAdminAuth(server.handleConfig)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET config status = %d body %s", rec.Code, rec.Body.String())
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

	req = httptest.NewRequest(http.MethodPut, "/v1/config", strings.NewReader(`{"routing":"routing { hy2://x }"}`))
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
