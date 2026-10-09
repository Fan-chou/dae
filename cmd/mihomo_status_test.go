package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMihomoWarning(t *testing.T) {
	cases := []struct {
		name string
		in   MihomoStatus
		want string // substring; "" means no warning
	}{
		{"disabled", MihomoStatus{Error: "x"}, ""},
		{"healthy", MihomoStatus{Enabled: true}, ""},
		{"last good", MihomoStatus{Enabled: true, UsedLastGood: true}, "last good"},
		{"failed with copy", MihomoStatus{Enabled: true, UsedLastGood: true, Error: "boom"}, "boom"},
		{"failed", MihomoStatus{Enabled: true, Error: "boom"}, "failed: boom"},
	}
	for _, c := range cases {
		got := mihomoWarning(c.in)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want containing %q", c.name, got, c.want)
		}
	}
}

func TestMihomoStatusCommandReadsRunningDaemon(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/config/effective" {
			_ = json.NewEncoder(w).Encode(EffectiveConfig{Nodes: []EffectiveNode{
				{Tag: "HK_01", DisplayName: "🇭🇰 HK 01", Origin: originMihomo},
				{Tag: "plain", Origin: originMihomo},
				{Tag: "mine", Origin: originConfig},
			}})
			return
		}
		if r.URL.Path != "/v1/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"generation":   "g1",
			"sync_warning": "careful",
			"mihomo":       MihomoStatus{Enabled: true, Nodes: 3},
		})
	}))
	defer srv.Close()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.dae")
	body := "global {\n    admin_listen: '" + strings.TrimPrefix(srv.URL, "http://") + "'\n    admin_secret: 's3cret'\n}\nrouting {}\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := mihomoStatus(context.Background(), cfg, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"mine"`) {
		t.Errorf("a node from the configuration is listed as a Mihomo node:\n%s", out.String())
	}
	for _, want := range []string{`"generation": "g1"`, `"sync_warning": "careful"`, `"nodes": 3`, `"🇭🇰 HK 01": "HK_01"`, `"plain": "plain"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %s:\n%s", want, out.String())
		}
	}
}
