package main

import (
	"strings"
	"testing"
)

func TestParseManifestAcceptsProviderAndRoute(t *testing.T) {
	manifest, err := ParseManifest([]byte(`
providers:
  - name: openai
    type: http
    url: https://example.com/openai.yaml
    behavior: domain
    format: yaml
    interval: 2h
    max_size: 8MiB
routes:
  - provider: openai
    outbound: ai
    kind: domain
`))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if len(manifest.Providers) != 1 || manifest.Providers[0].Name != "openai" {
		t.Fatalf("providers = %#v", manifest.Providers)
	}
	if manifest.Providers[0].MaxSize != 8*1024*1024 {
		t.Fatalf("MaxSize = %d, want %d", manifest.Providers[0].MaxSize, 8*1024*1024)
	}
	if len(manifest.Routes) != 1 || manifest.Routes[0].Outbound != "ai" {
		t.Fatalf("routes = %#v", manifest.Routes)
	}
}

func TestValidateManifestRejectsDuplicateAndUnsafeProviders(t *testing.T) {
	manifest, err := ParseManifest([]byte(`
providers:
  - name: duplicate
    type: http
    url: https://example.com/a
    behavior: domain
    format: yaml
  - name: duplicate
    type: http
    url: http://127.0.0.1/secret
    behavior: unknown
    format: yaml
`))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if err := ValidateManifest(manifest, t.TempDir()); err == nil {
		t.Fatal("ValidateManifest() error = nil, want validation error")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("ValidateManifest() error = %v, want duplicate diagnostic", err)
	}
}

func TestValidateManifestRejectsPathTraversalAndInvalidLimits(t *testing.T) {
	manifest, err := ParseManifest([]byte(`
providers:
  - name: p
    type: file
    path: ../outside.yaml
    behavior: domain
    format: yaml
    interval: 1s
    max_size: 1
`))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if err := ValidateManifest(manifest, t.TempDir()); err == nil {
		t.Fatal("ValidateManifest() error = nil, want validation error")
	} else if !strings.Contains(err.Error(), "path") {
		t.Fatalf("ValidateManifest() error = %v, want path diagnostic", err)
	}
}

func TestValidateManifestRejectsUnsupportedRouteKind(t *testing.T) {
	manifest := Manifest{
		Providers: []ProviderSpec{{
			Name:     "p",
			Type:     "file",
			Path:     "p.yaml",
			Behavior: "domain",
			Format:   "yaml",
		}},
		Routes: []RouteSpec{{Provider: "p", Outbound: "proxy", Kind: "classical"}},
	}
	if err := ValidateManifest(manifest, t.TempDir()); err == nil {
		t.Fatal("ValidateManifest() error = nil, want validation error")
	} else if !strings.Contains(err.Error(), "route") {
		t.Fatalf("ValidateManifest() error = %v, want route diagnostic", err)
	}
}
