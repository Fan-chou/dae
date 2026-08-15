package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestParseDomainProviderPreservesDomainKindsAndOrder(t *testing.T) {
	rules, err := ParseProvider([]byte(`payload:
  - example.com
  - DOMAIN,full.example.com
  - DOMAIN-SUFFIX,suffix.example.com
  - DOMAIN-KEYWORD,keyword
  - DOMAIN-REGEX,^cdn\.
  - +.plus.example.com
`), ProviderSpec{Name: "p", Behavior: "domain", Format: "yaml"})
	if err != nil {
		t.Fatalf("ParseProvider() error = %v", err)
	}
	want := []DomainRule{
		{Kind: DomainSuffix, Value: "example.com"},
		{Kind: DomainFull, Value: "full.example.com"},
		{Kind: DomainSuffix, Value: "suffix.example.com"},
		{Kind: DomainKeyword, Value: "keyword"},
		{Kind: DomainRegex, Value: `^cdn\.`},
		{Kind: DomainSuffix, Value: "plus.example.com"},
	}
	if len(rules.Domains) != len(want) {
		t.Fatalf("domains = %#v, want %#v", rules.Domains, want)
	}
	for i := range want {
		if rules.Domains[i] != want[i] {
			t.Fatalf("domains[%d] = %#v, want %#v", i, rules.Domains[i], want[i])
		}
	}
}

func TestParseIPCIDRProviderParsesYamlAndTextForms(t *testing.T) {
	rules, err := ParseProvider([]byte(`payload:
  - 192.0.2.0/24
  - IP-CIDR,198.51.100.0/24,no-resolve
  - IP-CIDR6,2001:db8::/32
`), ProviderSpec{Name: "p", Behavior: "ipcidr", Format: "yaml"})
	if err != nil {
		t.Fatalf("ParseProvider() error = %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(rules.Prefixes) != len(want) {
		t.Fatalf("prefixes = %#v, want %#v", rules.Prefixes, want)
	}
	for i := range want {
		if rules.Prefixes[i] != want[i] {
			t.Fatalf("prefixes[%d] = %v, want %v", i, rules.Prefixes[i], want[i])
		}
	}
}

func TestParseClassicalProviderReportsUnsupportedRules(t *testing.T) {
	rules, err := ParseProvider([]byte("DOMAIN-SUFFIX,example.com\nPROCESS-NAME,foo\nIP-ASN,13335\n"), ProviderSpec{Name: "p", Behavior: "classical", Format: "text"})
	if err != nil {
		t.Fatalf("ParseProvider() error = %v", err)
	}
	if len(rules.Domains) != 1 || rules.Domains[0] != (DomainRule{Kind: DomainSuffix, Value: "example.com"}) {
		t.Fatalf("domains = %#v", rules.Domains)
	}
	if len(rules.Unsupported) != 2 {
		t.Fatalf("unsupported = %#v", rules.Unsupported)
	}
	if !strings.Contains(rules.Unsupported[0].Reason, "PROCESS-NAME") {
		t.Fatalf("unsupported[0] = %#v", rules.Unsupported[0])
	}
}

func TestParseDomainProviderLowercasesKeyword(t *testing.T) {
	rules, err := ParseProvider([]byte("DOMAIN-KEYWORD,Torrent\n"), ProviderSpec{Name: "p", Behavior: "domain", Format: "text"})
	if err != nil {
		t.Fatalf("ParseProvider() error = %v", err)
	}
	if len(rules.Domains) != 1 || rules.Domains[0] != (DomainRule{Kind: DomainKeyword, Value: "torrent"}) {
		t.Fatalf("domains = %#v, want lowercase keyword", rules.Domains)
	}
}

func TestParseProviderRejectsInvalidCIDR(t *testing.T) {
	_, err := ParseProvider([]byte("payload:\n  - 192.0.2.0/99\n"), ProviderSpec{Name: "p", Behavior: "ipcidr", Format: "yaml"})
	if err == nil {
		t.Fatal("ParseProvider() error = nil, want invalid CIDR error")
	}
}

func TestGenerateDaeRoutesEscapesValuesAndPreservesRouteOrder(t *testing.T) {
	manifest := Manifest{Routes: []RouteSpec{
		{Provider: "first", Outbound: "proxy", Kind: "domain"},
		{Provider: "second", Outbound: "direct", Kind: "ipcidr"},
	}}
	sets := map[string]ParsedRuleSet{
		"first":  {Domains: []DomainRule{{Kind: DomainFull, Value: "a'b.example"}}},
		"second": {Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
	}
	output, report, err := GenerateDaeRoutes(manifest, sets, true)
	if err != nil {
		t.Fatalf("GenerateDaeRoutes() error = %v", err)
	}
	if report.Generated != 2 || report.Skipped != 0 {
		t.Fatalf("report = %#v", report)
	}
	want := "domain(full: \"a'b.example\") -> proxy\ndip('192.0.2.0/24') -> direct\n"
	if output != want {
		t.Fatalf("output = %q, want %q", output, want)
	}
}

func TestGenerateDaeRoutesRoundTripsBackslashesThroughKdaeParser(t *testing.T) {
	manifest := Manifest{Routes: []RouteSpec{{Provider: "p", Outbound: "proxy", Kind: "domain"}}}
	sets := map[string]ParsedRuleSet{"p": {Domains: []DomainRule{{Kind: DomainRegex, Value: `^cdn\\.`}}}}
	output, _, err := GenerateDaeRoutes(manifest, sets, true)
	if err != nil {
		t.Fatalf("GenerateDaeRoutes() error = %v", err)
	}
	sections, err := config_parser.Parse("global {}\nrouting {\n" + output + "  fallback: direct\n}\n")
	if err != nil {
		t.Fatalf("generated routes do not parse: %v; output=%q", err, output)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("config.New() error = %v; output=%q", err, output)
	}
	got := conf.Routing.Rules[0].AndFunctions[0].Params[0].Val
	if got != `^cdn\\.` {
		t.Fatalf("round-tripped regex = %q, want %q", got, `^cdn\\.`)
	}
}

func TestGenerateDaeRoutesRejectsControlAndOutboundInjection(t *testing.T) {
	manifest := Manifest{Routes: []RouteSpec{{Provider: "p", Outbound: "proxy\nfallback: direct", Kind: "domain"}}}
	sets := map[string]ParsedRuleSet{"p": {Domains: []DomainRule{{Kind: DomainSuffix, Value: "example.com\nother"}}}}
	if _, _, err := GenerateDaeRoutes(manifest, sets, true); err == nil {
		t.Fatal("GenerateDaeRoutes() error = nil for injected values")
	}
}

func TestGenerateDaeRoutesRejectsClassicalProviderRouteKindMismatchEvenWhenAnotherProviderGeneratesRules(t *testing.T) {
	manifest := Manifest{
		Providers: []ProviderSpec{
			{Name: "classical-ip", Behavior: "classical"},
			{Name: "domain", Behavior: "domain"},
		},
		Routes: []RouteSpec{
			{Provider: "classical-ip", Outbound: "proxy", Kind: "domain"},
			{Provider: "domain", Outbound: "direct", Kind: "domain"},
		},
	}
	sets := map[string]ParsedRuleSet{
		"classical-ip": {Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		"domain":       {Domains: []DomainRule{{Kind: DomainSuffix, Value: "example.com"}}},
	}

	if _, _, err := GenerateDaeRoutes(manifest, sets, true); err == nil {
		t.Fatal("GenerateDaeRoutes() error = nil for classical provider route-kind mismatch")
	} else if !strings.Contains(err.Error(), `classical-ip`) {
		t.Fatalf("GenerateDaeRoutes() error = %v, want classical provider diagnostic", err)
	}
}
