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
		t.Fatalf("report = %#v", report)
	}
	if !strings.Contains(output, "group {") || !strings.Contains(output, "filter: name('hk-1', 'us-1')") || !strings.Contains(output, "policy: min_moving_avg") {
		t.Fatalf("output = %q", output)
	}
}

func TestGenerateFlatDaeGroupsReportsNestedAndSpecialMembers(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "hk-1"}},
		Groups: []MihomoGroup{
			{Name: "Inner", Type: "select", Proxies: []string{"hk-1"}},
			{Name: "Outer", Type: "select", Proxies: []string{"Inner", "DIRECT", "REJECT"}},
		},
	}
	_, report, err := GenerateFlatDaeGroups(config)
	if err != nil {
		t.Fatalf("GenerateFlatDaeGroups() error = %v", err)
	}
	if report.Converted != 1 || len(report.Unsupported) != 1 {
		t.Fatalf("report = %#v", report)
	}
	if !strings.Contains(report.Unsupported[0].Reason, "nested") || !strings.Contains(report.Unsupported[0].Reason, "DIRECT") {
		t.Fatalf("unsupported = %#v", report.Unsupported)
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
