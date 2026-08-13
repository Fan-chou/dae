package main

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeMihomoRuleProvidersPreservesOrderAndMetadata(t *testing.T) {
	document := MihomoRoutingDocument{
		ProviderOrder: []string{"中文 provider", "local"},
		ProviderValues: []MihomoRuleProvider{
			{Name: "中文 provider", Type: "HTTP", URL: "https://rules.example.test/rules.yaml?token=secret", Path: "cache/remote.yaml", Behavior: "DOMAIN", Interval: 2 * time.Hour, SourceIndex: 7},
			{Name: "local", Type: "file", Path: "rules.txt", Behavior: "classical", Format: "text", SourceIndex: 8},
		},
	}

	got, err := NormalizeMihomoRuleProviders(document, t.TempDir())
	if err != nil {
		t.Fatalf("NormalizeMihomoRuleProviders() error = %v", err)
	}
	if len(got.Providers) != 2 || got.Providers[0].Name != got.NameMap["中文 provider"] || got.Providers[1].Name != "local" {
		t.Fatalf("provider order or names = %#v, map = %#v", got.Providers, got.NameMap)
	}
	if got.Providers[0].URL != "https://rules.example.test/rules.yaml?token=secret" || got.Providers[0].Path != "cache/remote.yaml" || got.Providers[0].Interval != 2*time.Hour {
		t.Fatalf("remote fields were not preserved: %#v", got.Providers[0])
	}
	if got.Providers[0].Behavior != "domain" || got.Providers[0].Format != "yaml" || got.Providers[1].Format != "text" {
		t.Fatalf("normalized behavior/format = %#v", got.Providers)
	}
	if got.ReverseNameMap[got.NameMap["中文 provider"]] != "中文 provider" || got.SourceIndex["中文 provider"] != 7 {
		t.Fatalf("metadata = %#v / %#v / %#v", got.NameMap, got.ReverseNameMap, got.SourceIndex)
	}
}

func TestNormalizeMihomoRuleProvidersRejectsUnsupportedAndUnsafeDefinitions(t *testing.T) {
	tests := []struct {
		name     string
		provider MihomoRuleProvider
		want     string
	}{
		{name: "mrs", provider: MihomoRuleProvider{Name: "p", Type: "file", Path: "p", Behavior: "domain", Format: "mrs"}, want: "unsupported format"},
		{name: "missing path", provider: MihomoRuleProvider{Name: "p", Type: "file", Behavior: "domain"}, want: "requires path"},
		{name: "bad interval", provider: MihomoRuleProvider{Name: "p", Type: "http", URL: "https://example.test/p", Behavior: "domain", Interval: -time.Second}, want: "negative interval"},
		{name: "secret redaction", provider: MihomoRuleProvider{Name: "p", Type: "http", URL: "https://example.test/%zz?token=secret", Behavior: "domain"}, want: "[redacted-url]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizeMihomoRuleProviders(MihomoRoutingDocument{ProviderValues: []MihomoRuleProvider{test.provider}}, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
			if test.name == "secret redaction" && strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaked URL query token: %v", err)
			}
		})
	}
}

func TestNormalizeMihomoRuleProvidersDetectsSafeNameCollision(t *testing.T) {
	first := "普通 provider"
	second := safeMihomoProviderName(first)
	document := MihomoRoutingDocument{ProviderValues: []MihomoRuleProvider{
		{Name: first, Type: "file", Path: "first", Behavior: "domain"},
		{Name: second, Type: "file", Path: "second", Behavior: "domain"},
	}}
	if _, err := NormalizeMihomoRuleProviders(document, t.TempDir()); err == nil || !strings.Contains(err.Error(), "same safe provider name") {
		t.Fatalf("error = %v, want safe-name collision", err)
	}
}
