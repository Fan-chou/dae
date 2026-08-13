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

func TestGenerateFlatDaeGroupsPreservesNestedAndSpecialMembers(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{{Name: "hk-1"}},
		Groups: []MihomoGroup{
			{Name: "Inner", Type: "select", Proxies: []string{"hk-1"}},
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
