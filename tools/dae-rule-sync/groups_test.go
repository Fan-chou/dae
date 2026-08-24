package main

import (
	"strings"
	"testing"
)

func TestParseMihomoSubsetReadsProxiesAndGroups(t *testing.T) {
	config, err := ParseMihomoConfig([]byte(`
proxies:
  - name: hk-1
    type: anytls
  - name: us-1
    type: socks5
proxy-groups:
  - name: Proxy
    type: fallback
    proxies: [hk-1, us-1]
`))
	if err != nil {
		t.Fatalf("ParseMihomoConfig() error = %v", err)
	}
	if len(config.Proxies) != 2 || len(config.Groups) != 1 {
		t.Fatalf("config = %#v", config)
	}
	if config.Groups[0].Proxies[0] != "hk-1" {
		t.Fatalf("group proxies = %#v", config.Groups[0].Proxies)
	}
}

func TestGenerateFlatDaeGroupsMapsSimplePolicies(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "hk-1"}, {Name: "us-1"}},
		Groups: []MihomoGroup{
			{Name: "Proxy", Type: "fallback", Proxies: []string{"hk-1", "us-1"}},
		},
	}
	output, report, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("GenerateFlatDaeGroups() error = %v", err)
	}
	if report.Converted != 1 || report.Approximated != 1 || len(report.Unsupported) != 0 {
		t.Fatalf("report = %#v, want fallback marked approximate", report)
	}
	if !strings.Contains(output, "group {") || !strings.Contains(output, "filter: name('hk-1')\n        filter: name('us-1')") || !strings.Contains(output, "policy: fallback") {
		t.Fatalf("output = %q, want fallback mapped to ordered fallback filters", output)
	}
}

func TestGenerateFlatDaeGroupsPreservesNestedAndSpecialMembers(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "hk-1"}},
		Groups: []MihomoGroup{
			{
				Name: "Inner", Type: "select", Proxies: []string{"hk-1"},
				URL: mihomoStringPtr("https://example.com/check"), Interval: mihomoInt64Ptr(30),
				Lazy: boolPtr(true), Tolerance: mihomoInt64Ptr(5),
			},
			{Name: "Outer", Type: "select", Proxies: []string{"Inner", "DIRECT", "REJECT"}},
		},
	}
	output, report, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("GenerateFlatDaeGroups() error = %v", err)
	}
	if report.Converted != 2 || report.Approximated != 2 || len(report.Unsupported) != 0 {
		t.Fatalf("report = %#v", report)
	}
	if !strings.Contains(output, "filter: group('Inner')\n        filter: group('direct')\n        filter: group('block')") {
		t.Fatalf("output = %q", output)
	}
	if !strings.Contains(output, "tcp_check_url: 'https://example.com/check'") {
		t.Fatalf("output = %q, child health option was not preserved", output)
	}
	for _, field := range []string{"check_interval: 30s", "check_tolerance: 5ms", "lazy: true"} {
		if !strings.Contains(output, field) {
			t.Fatalf("output = %q, child option %q was not preserved", output, field)
		}
	}
}

func TestGenerateFlatDaeGroupsPreservesSpecialMemberOrder(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "hk-1"}, {Name: "us-1"}},
		Groups: []MihomoGroup{
			{Name: "Proxy", Type: "select", Proxies: []string{"hk-1", "DIRECT", "us-1", "REJECT"}},
		},
	}
	output, report, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("GenerateFlatDaeGroups() error = %v", err)
	}
	if report.Converted != 1 || len(report.Unsupported) != 0 {
		t.Fatalf("report = %#v", report)
	}
	want := "filter: name('hk-1')\n        filter: group('direct')\n        filter: name('us-1')\n        filter: group('block')"
	if !strings.Contains(output, want) {
		t.Fatalf("output = %q, want ordered members %q", output, want)
	}
}

func TestGenerateFlatDaeGroupsConvertsSpecialOnlyGroup(t *testing.T) {
	config := MihomoConfig{
		Groups: []MihomoGroup{{Name: "DirectOnly", Type: "select", Proxies: []string{"DIRECT", "REJECT"}}},
	}
	output, report, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("GenerateFlatDaeGroups() error = %v", err)
	}
	if report.Converted != 1 || len(report.Unsupported) != 0 {
		t.Fatalf("report = %#v", report)
	}
	if !strings.Contains(output, "filter: group('direct')\n        filter: group('block')") {
		t.Fatalf("output = %q", output)
	}
}

func TestGenerateFlatDaeGroupsUsesDeterministicSafeNames(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "hk-1"}},
		Groups:  []MihomoGroup{{Name: "❤️ Proxy", Type: "select", Proxies: []string{"hk-1"}}},
	}
	first, _, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("first conversion error = %v", err)
	}
	second, _, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("second conversion error = %v", err)
	}
	if first != second {
		t.Fatalf("conversion is not deterministic:\nfirst=%q\nsecond=%q", first, second)
	}
}

func TestGenerateFlatDaeGroupsPreservesSelectMemberIdentities(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "hk-1"}, {Name: "us-1"}},
		Groups:  []MihomoGroup{{Name: "Proxy", Type: "select", Proxies: []string{"hk-1", "us-1", "DIRECT"}}},
	}
	output, _, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("GenerateFlatDaeGroups() error = %v", err)
	}
	if !strings.Contains(output, `selection_members: 'hk-1,us-1,direct'`) {
		t.Fatalf("output = %q, want stable select member identities", output)
	}
}

func TestGenerateFlatDaeGroupsRejectsUnknownMember(t *testing.T) {
	config := MihomoConfig{Groups: []MihomoGroup{{Name: "Proxy", Type: "select", Proxies: []string{"missing"}}}}
	if _, _, err := GenerateFlatDaeGroups(config); err == nil {
		t.Fatal("GenerateFlatDaeGroups() error = nil for unknown member")
	}
}

func TestGenerateFlatDaeGroupsRejectsEmptyGroup(t *testing.T) {
	config := MihomoConfig{Groups: []MihomoGroup{{Name: "Empty", Type: "select"}}}
	if _, _, err := GenerateFlatDaeGroups(config); err == nil {
		t.Fatal("GenerateFlatDaeGroups() error = nil for empty group")
	}
}

func TestGenerateFlatDaeGroupsRejectsUnsafeMemberLiteral(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "a'\"b"}},
		Groups:  []MihomoGroup{{Name: "Proxy", Type: "select", Proxies: []string{"a'\"b"}}},
	}
	if _, _, err := GenerateFlatDaeGroups(config); err == nil {
		t.Fatal("GenerateFlatDaeGroups() error = nil for unsafe member")
	}
}

func TestParseMihomoGroupHealthOptionsPreservesExplicitValues(t *testing.T) {
	config, err := ParseMihomoConfig([]byte(`
proxy-groups:
  - name: Proxy
    type: select
    proxies: [node]
    url: https://www.gstatic.com/generate_204
    interval: 300
    lazy: false
    tolerance: 0
`))
	if err != nil {
		t.Fatalf("ParseMihomoConfig() error = %v", err)
	}
	group := config.Groups[0]
	if group.URL == nil || *group.URL != "https://www.gstatic.com/generate_204" {
		t.Fatalf("URL = %#v", group.URL)
	}
	if group.Interval == nil || *group.Interval != 300 {
		t.Fatalf("Interval = %#v", group.Interval)
	}
	if group.Lazy == nil || *group.Lazy {
		t.Fatalf("Lazy = %#v, want explicit false", group.Lazy)
	}
	if group.Tolerance == nil || *group.Tolerance != 0 {
		t.Fatalf("Tolerance = %#v, want explicit zero", group.Tolerance)
	}
}

func TestGenerateFlatDaeGroupsConvertsGroupHealthOptions(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "node"}},
		Groups: []MihomoGroup{{
			Name:      "Proxy",
			Type:      "select",
			Proxies:   []string{"node"},
			URL:       mihomoStringPtr("https://www.gstatic.com/generate_204"),
			Interval:  mihomoInt64Ptr(300),
			Lazy:      boolPtr(true),
			Tolerance: mihomoInt64Ptr(50),
		}},
	}
	output, _, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("GenerateFlatDaeGroups() error = %v", err)
	}
	for _, want := range []string{
		"tcp_check_url: 'https://www.gstatic.com/generate_204'",
		"check_interval: 300s",
		"check_tolerance: 50ms",
		"lazy: true",
		"policy: fixed(0)",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output = %q, missing %q", output, want)
		}
	}
}

func TestGenerateFlatDaeGroupsRejectsInvalidHealthOptions(t *testing.T) {
	tests := map[string]MihomoGroup{
		"unsupported scheme": {
			Name: "Proxy", Type: "select", Proxies: []string{"node"},
			URL: mihomoStringPtr("ftp://example.com/check"),
		},
		"missing host": {
			Name: "Proxy", Type: "select", Proxies: []string{"node"},
			URL: mihomoStringPtr("https:///check"),
		},
		"negative interval": {
			Name: "Proxy", Type: "select", Proxies: []string{"node"},
			Interval: mihomoInt64Ptr(-1),
		},
		"interval overflow": {
			Name: "Proxy", Type: "select", Proxies: []string{"node"},
			Interval: mihomoInt64Ptr(int64(1<<63 - 1)),
		},
		"negative tolerance": {
			Name: "Proxy", Type: "select", Proxies: []string{"node"},
			Tolerance: mihomoInt64Ptr(-1),
		},
		"tolerance overflow": {
			Name: "Proxy", Type: "select", Proxies: []string{"node"},
			Tolerance: mihomoInt64Ptr(int64(1<<63 - 1)),
		},
	}
	for name, group := range tests {
		t.Run(name, func(t *testing.T) {
			config := MihomoConfig{
				Proxies: []MihomoProxy{{Name: "node"}},
				Groups:  []MihomoGroup{group},
			}
			if _, _, err := GenerateFlatDaeGroups(config); err == nil {
				t.Fatal("GenerateFlatDaeGroups() error = nil")
			}
		})
	}
}

func TestGenerateFlatDaeGroupsRetainsNestedParentHealthOptions(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "node"}},
		Groups: []MihomoGroup{
			{Name: "Inner", Type: "select", Proxies: []string{"node"}, URL: mihomoStringPtr("https://example.com/check")},
			{Name: "Outer", Type: "fallback", Proxies: []string{"Inner"}, URL: mihomoStringPtr("https://outer.example/check"), Interval: mihomoInt64Ptr(30), Tolerance: mihomoInt64Ptr(5), Lazy: mihomoBoolPtr(true)},
		},
	}
	output, _, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("GenerateFlatDaeGroups() error = %v", err)
	}
	for _, want := range []string{
		"tcp_check_url: 'https://outer.example/check'",
		"check_interval: 30s",
		"check_tolerance: 5ms",
		"lazy: true",
		"filter: group('Inner')",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output = %q, missing %q", output, want)
		}
	}
}

func TestGenerateFullMihomoGroupsTreatsSingleDirectURLTestAsFixed(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "node"}},
		Groups: []MihomoGroup{{
			Name:    "KeepAlive",
			Type:    "url-test",
			Proxies: []string{"DIRECT"},
			URL:     mihomoStringPtr("http://example.com/generate_204"),
		}},
	}
	output, report, err := generateFullMihomoGroups(config, map[string]string{"node": "node"})
	if err != nil {
		t.Fatalf("generateFullMihomoGroups() error = %v", err)
	}
	if report.Approximated != 0 || len(report.Unsupported) != 0 {
		t.Fatalf("report = %#v, want single DIRECT url-test treated as lossless fixed(0)", report)
	}
	if !strings.Contains(output, "policy: fixed(0)") {
		t.Fatalf("output = %q, missing fixed single-member policy", output)
	}
	if !strings.Contains(output, "selection_members: 'direct'") {
		t.Fatalf("output = %q, missing fixed single-member metadata", output)
	}
}

func TestGenerateFullMihomoGroupsEmitsOneFallbackFilterPerMember(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "🇭🇰 DMIT.HK | Hysteria"}, {Name: "🇭🇰 GG.IPLC -> Dmit.HK"}},
		Groups: []MihomoGroup{{
			Name:    "🍒",
			Type:    "fallback",
			Proxies: []string{"🇭🇰 GG.IPLC -> Dmit.HK", "🇭🇰 DMIT.HK | Hysteria"},
		}},
	}
	output, report, err := generateFullMihomoGroups(config, map[string]string{
		"🇭🇰 DMIT.HK | Hysteria": "HK_DMIT_HK_Hysteria",
		"🇭🇰 GG.IPLC -> Dmit.HK": "HK_GG_IPLC_Dmit_HK",
	})
	if err != nil {
		t.Fatalf("generateFullMihomoGroups() error = %v", err)
	}
	if report.Approximated != 0 {
		t.Fatalf("report = %#v, want native fallback treated as lossless", report)
	}
	want := "filter: name('HK_GG_IPLC_Dmit_HK')\n        filter: name('HK_DMIT_HK_Hysteria')"
	if !strings.Contains(output, want) {
		t.Fatalf("output = %q, want declared fallback order %q", output, want)
	}
	if !strings.Contains(output, "policy: fallback") {
		t.Fatalf("output = %q, want fallback policy", output)
	}
}

func TestGenerateFullMihomoGroupsEmitsUrlTestPolicy(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "hk-1"}, {Name: "us-1"}},
		Groups: []MihomoGroup{{
			Name:    "Auto",
			Type:    "url-test",
			Proxies: []string{"hk-1", "us-1"},
			URL:     mihomoStringPtr("http://example.com/generate_204"),
		}},
	}
	output, report, err := generateFullMihomoGroups(config, map[string]string{"hk-1": "hk_1", "us-1": "us_1"})
	if err != nil {
		t.Fatalf("generateFullMihomoGroups() error = %v", err)
	}
	if report.Approximated != 0 || len(report.Unsupported) != 0 {
		t.Fatalf("report = %#v, want native url_test treated as lossless", report)
	}
	if !strings.Contains(output, "policy: url_test") {
		t.Fatalf("output = %q, want url_test policy", output)
	}
}

func mihomoStringPtr(value string) *string { return &value }

func mihomoInt64Ptr(value int64) *int64 { return &value }

func mihomoBoolPtr(value bool) *bool { return &value }
