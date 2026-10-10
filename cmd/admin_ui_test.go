package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminUIServesPanelWithoutSecretAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"index.html": "<html>panel</html>", "assets/app.js": "js"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(secret, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FDAE_UI_DIR", dir)
	mux := http.NewServeMux()
	registerAdminUI(mux)

	get := func(method, target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
		return rec
	}
	if rec := get(http.MethodGet, "/fdae-ui/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "panel") {
		t.Fatalf("index = %d %q", rec.Code, rec.Body.String())
	} else if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("index cache = %q", rec.Header().Get("Cache-Control"))
	}
	if rec := get(http.MethodGet, "/fdae-ui/assets/app.js"); rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset = %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if rec := get(http.MethodGet, "/fdae-ui/assets/"); rec.Code != 404 {
		t.Fatalf("directory listing = %d, want 404", rec.Code)
	}
	for _, p := range []string{"/fdae-ui/../secret.txt", "/fdae-ui/%2e%2e/secret.txt", "/fdae-ui/..%2fsecret.txt"} {
		if rec := get(http.MethodGet, p); rec.Code == 200 && strings.Contains(rec.Body.String(), "nope") {
			t.Fatalf("%s escaped the panel directory", p)
		}
	}
	if rec := get(http.MethodPost, "/fdae-ui/"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", rec.Code)
	}
	if rec := get(http.MethodGet, "/"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/fdae-ui/" {
		t.Fatalf("root = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(http.MethodGet, "/v1/status"); rec.Code != 404 {
		t.Fatalf("/v1/status is not registered here, got %d", rec.Code)
	}
}
