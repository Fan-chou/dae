package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeResolveDNSQuery(t *testing.T) {
	got, err := normalizeResolveDNSQuery("8.8.8.8")
	if err != nil {
		t.Fatalf("normalizeResolveDNSQuery() error = %v", err)
	}
	if got != "8.8.8.8:53" {
		t.Fatalf("got %q, want 8.8.8.8:53", got)
	}
	if _, err := normalizeResolveDNSQuery("dns.google"); err == nil {
		t.Fatal("expected error for hostname")
	}
	if _, err := normalizeResolveDNSQuery("0.0.0.0"); err == nil {
		t.Fatal("expected error for unspecified")
	}
}

func TestLoadNodeResolveDNSOverlay(t *testing.T) {
	overlay, err := loadNodeResolveDNSOverlay("")
	if err != nil || overlay != nil {
		t.Fatalf("empty path = %v, %v", overlay, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, []byte(`{"🇺🇸 US | Hysteria2":"8.8.8.8"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay, err = loadNodeResolveDNSOverlay(path)
	if err != nil {
		t.Fatalf("loadNodeResolveDNSOverlay() error = %v", err)
	}
	if overlay["🇺🇸 US | Hysteria2"] != "8.8.8.8" {
		t.Fatalf("overlay = %#v", overlay)
	}
}

func TestGenerateMihomoNodesWithResolveDNSOverlay(t *testing.T) {
	config := MihomoConfig{Proxies: []MihomoProxy{
		{
			Name:     "🇺🇸 US | Hysteria2",
			Type:     "hysteria2",
			Server:   "127.0.0.1",
			Port:     443,
			Password: "hy2-secret",
			SNI:      "us.example",
		},
		{
			Name:   "local-socks",
			Type:   "socks5",
			Server: "127.0.0.1",
			Port:   1080,
		},
	}}
	overlay := map[string]string{
		"🇺🇸 US | Hysteria2": "8.8.8.8",
		"gone-node":          "1.1.1.1",
	}
	nodes, report, err := GenerateMihomoNodesWithResolveDNS(config, overlay)
	if err != nil {
		t.Fatalf("GenerateMihomoNodesWithResolveDNS() error = %v", err)
	}
	if report.Converted != 2 {
		t.Fatalf("converted = %d", report.Converted)
	}
	if strings.Count(nodes, "resolve_dns=") != 1 {
		t.Fatalf("nodes = %q, want resolve_dns on one node", nodes)
	}
	for _, line := range strings.Split(nodes, "\n") {
		if !strings.Contains(line, "hysteria2://") {
			continue
		}
		start := strings.Index(line, "'")
		end := strings.LastIndex(line, "'")
		if start < 0 || end <= start {
			t.Fatalf("unquoted hy2 line: %s", line)
		}
		parsed, err := url.Parse(line[start+1 : end])
		if err != nil {
			t.Fatalf("url.Parse() error = %v", err)
		}
		if got := parsed.Query().Get("resolve_dns"); got != "8.8.8.8:53" {
			t.Fatalf("resolve_dns = %q, want 8.8.8.8:53", got)
		}
	}
	if strings.Contains(nodes, "socks5://") && strings.Contains(nodes[strings.Index(nodes, "socks5://"):], "resolve_dns=") {
		// socks5 line must not include resolve_dns; the hy2 line already counted.
		socksLine := ""
		for _, line := range strings.Split(nodes, "\n") {
			if strings.Contains(line, "socks5://") {
				socksLine = line
			}
		}
		if strings.Contains(socksLine, "resolve_dns") {
			t.Fatalf("unselected node has resolve_dns: %s", socksLine)
		}
	}
}

func TestGenerateMihomoNodesWithResolveDNSRejectsHostname(t *testing.T) {
	config := MihomoConfig{Proxies: []MihomoProxy{{
		Name:     "us-hy2",
		Type:     "hysteria2",
		Server:   "127.0.0.1",
		Port:     443,
		Password: "hy2-secret",
		SNI:      "us.example",
	}}}
	_, _, err := GenerateMihomoNodesWithResolveDNS(config, map[string]string{"us-hy2": "dns.google"})
	if err == nil {
		t.Fatal("expected invalid resolve_dns error")
	}
}
