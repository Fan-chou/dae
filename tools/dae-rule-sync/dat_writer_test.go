package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func datWriterReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if len(raw) == 0 {
		t.Fatalf("DAT %q is empty", path)
	}
	return raw
}

func datWriterMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	return raw
}

func datWriterAssertReport(t *testing.T, report DATWriteReport, code string, generated, skipped int, raw []byte) {
	t.Helper()
	if report.Code != code {
		t.Fatalf("report.Code = %q, want %q", report.Code, code)
	}
	if report.Generated != generated {
		t.Fatalf("report.Generated = %d, want %d", report.Generated, generated)
	}
	if report.Skipped != skipped {
		t.Fatalf("report.Skipped = %d, want %d", report.Skipped, skipped)
	}
	if report.SHA256 == "" {
		t.Fatal("report.SHA256 is empty")
	}
	digest := sha256.Sum256(raw)
	wantSHA256 := hex.EncodeToString(digest[:])
	if report.SHA256 != wantSHA256 {
		t.Fatalf("report.SHA256 = %q, want SHA-256 of published DAT %q", report.SHA256, wantSHA256)
	}
}

func datWriterAssertOnlyEntries(t *testing.T, dir string, allowed ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", dir, err)
	}
	want := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		want[name] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := want[entry.Name()]; !ok {
			t.Errorf("unexpected sibling artifact %q after DAT write", entry.Name())
		}
		delete(want, entry.Name())
	}
	for name := range want {
		t.Errorf("expected output %q to exist", name)
	}
}

func datWriterAssertUnchanged(t *testing.T, path string, want []byte) {
	t.Helper()
	got := datWriterReadFile(t, path)
	if !bytes.Equal(got, want) {
		t.Fatalf("existing output %q changed after rejected write", path)
	}
}

func datWriterSection(t *testing.T, sections []*config_parser.Section, name string) *config_parser.Section {
	t.Helper()
	for _, section := range sections {
		if section.Name == name {
			return section
		}
	}
	t.Fatalf("section %q not found in parsed config", name)
	return nil
}

func datWriterFindFunction(t *testing.T, rules []*config_parser.RoutingRule, name, outbound string) *config_parser.Function {
	t.Helper()
	for _, rule := range rules {
		if rule.Outbound.Name != outbound {
			continue
		}
		for _, function := range rule.AndFunctions {
			if function.Name == name {
				return function
			}
		}
	}
	t.Fatalf("function %q for outbound %q not found in normalized rules", name, outbound)
	return nil
}

func datWriterCanonicalPrefixes(t *testing.T, cidrs []*geodata.CIDR) []string {
	t.Helper()
	got := make([]string, 0, len(cidrs))
	seen := make(map[string]struct{}, len(cidrs))
	for _, cidr := range cidrs {
		addr, ok := netip.AddrFromSlice(cidr.Ip)
		if !ok {
			t.Fatalf("AddrFromSlice(%v) failed", cidr.Ip)
		}
		prefix := netip.PrefixFrom(addr, int(cidr.Prefix)).Masked().String()
		if _, ok := seen[prefix]; ok {
			t.Fatalf("duplicate prefix in decoded GeoIP: %q", prefix)
		}
		seen[prefix] = struct{}{}
		got = append(got, prefix)
	}
	sort.Strings(got)
	return got
}

func TestWriteGeoSiteDATRoundTripsAllDomainKinds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geosite.dat")
	const code = "provider"
	rules := []DomainRule{
		{Kind: DomainFull, Value: "full.example.com"},
		{Kind: DomainSuffix, Value: "suffix.example.com"},
		{Kind: DomainKeyword, Value: "keyword-marker"},
		{Kind: DomainRegex, Value: `^regex[0-9]+\\.example$`},
	}

	report, err := writeGeoSiteDAT(path, code, rules)
	if err != nil {
		t.Fatalf("writeGeoSiteDAT() error = %v", err)
	}
	raw := datWriterReadFile(t, path)
	var list geodata.GeoSiteList
	if err := proto.Unmarshal(raw, &list); err != nil {
		t.Fatalf("proto.Unmarshal(GeoSiteList) error = %v", err)
	}
	if len(list.Entry) != 1 {
		t.Fatalf("decoded GeoSiteList entries = %d, want 1", len(list.Entry))
	}

	decoded, err := geodata.UnmarshalGeoSite(logrus.New(), path, code)
	if err != nil {
		t.Fatalf("UnmarshalGeoSite() error = %v", err)
	}
	if decoded.CountryCode != code {
		t.Fatalf("decoded country code = %q, want %q", decoded.CountryCode, code)
	}
	if len(decoded.Domain) != len(rules) {
		t.Fatalf("decoded domain count = %d, want %d", len(decoded.Domain), len(rules))
	}
	wantTypes := []geodata.Domain_Type{
		geodata.Domain_Full,
		geodata.Domain_RootDomain,
		geodata.Domain_Plain,
		geodata.Domain_Regex,
	}
	for i, want := range rules {
		if decoded.Domain[i].Type != wantTypes[i] {
			t.Errorf("domain %d type = %v, want %v", i, decoded.Domain[i].Type, wantTypes[i])
		}
		if decoded.Domain[i].Value != want.Value {
			t.Errorf("domain %d value = %q, want %q", i, decoded.Domain[i].Value, want.Value)
		}
	}
	datWriterAssertReport(t, report, code, 4, 0, raw)
	datWriterAssertOnlyEntries(t, dir, "geosite.dat")
}

func TestWriteGeoIPDATRoundTripsCanonicalPrefixesAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.dat")
	const code = "provider"
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.9/24"),
		netip.MustParsePrefix("2001:db8::1/32"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}

	report, err := writeGeoIPDAT(path, code, prefixes)
	if err != nil {
		t.Fatalf("writeGeoIPDAT() error = %v", err)
	}
	raw := datWriterReadFile(t, path)
	var list geodata.GeoIPList
	if err := proto.Unmarshal(raw, &list); err != nil {
		t.Fatalf("proto.Unmarshal(GeoIPList) error = %v", err)
	}
	if len(list.Entry) != 1 {
		t.Fatalf("decoded GeoIPList entries = %d, want 1", len(list.Entry))
	}

	decoded, err := geodata.UnmarshalGeoIp(logrus.New(), path, code)
	if err != nil {
		t.Fatalf("UnmarshalGeoIp() error = %v", err)
	}
	if decoded.CountryCode != code {
		t.Fatalf("decoded country code = %q, want %q", decoded.CountryCode, code)
	}
	want := []string{"192.0.2.0/24", "2001:db8::/32"}
	got := datWriterCanonicalPrefixes(t, decoded.Cidr)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded canonical prefixes = %#v, want %#v", got, want)
	}
	datWriterAssertReport(t, report, code, 2, 1, raw)
	datWriterAssertOnlyEntries(t, dir, "geoip.dat")
}

func TestDATWriterRejectsEmptyInputAndPreservesExistingOutputs(t *testing.T) {
	geoSiteOld := datWriterMarshal(t, &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		CountryCode: "provider",
		Domain:      []*geodata.Domain{{Type: geodata.Domain_Full, Value: "old.example.com"}},
	}}})
	geoIPOld := datWriterMarshal(t, &geodata.GeoIPList{Entry: []*geodata.GeoIP{{
		CountryCode: "provider",
		Cidr:        []*geodata.CIDR{{Ip: netip.MustParseAddr("192.0.2.0").AsSlice(), Prefix: 24}},
	}}})
	tests := []struct {
		name string
		old  []byte
		call func(string) (DATWriteReport, error)
	}{
		{
			name: "geosite",
			old:  geoSiteOld,
			call: func(path string) (DATWriteReport, error) {
				return writeGeoSiteDAT(path, "provider", nil)
			},
		},
		{
			name: "geoip",
			old:  geoIPOld,
			call: func(path string) (DATWriteReport, error) {
				return writeGeoIPDAT(path, "provider", nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.name+".dat")
			if err := os.WriteFile(path, tt.old, 0o640); err != nil {
				t.Fatalf("WriteFile(%q) error = %v", path, err)
			}
			if _, err := tt.call(path); err == nil {
				t.Fatal("empty DAT write error = nil")
			}
			datWriterAssertUnchanged(t, path, tt.old)
			datWriterAssertOnlyEntries(t, dir, filepath.Base(path))
		})
	}
}

func TestDATWriterRejectsInvalidDomainAndPrefixWithoutReplacing(t *testing.T) {
	geoSiteOld := datWriterMarshal(t, &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		CountryCode: "provider",
		Domain:      []*geodata.Domain{{Type: geodata.Domain_Full, Value: "old.example.com"}},
	}}})
	geoIPOld := datWriterMarshal(t, &geodata.GeoIPList{Entry: []*geodata.GeoIP{{
		CountryCode: "provider",
		Cidr:        []*geodata.CIDR{{Ip: netip.MustParseAddr("2001:db8::").AsSlice(), Prefix: 32}},
	}}})

	for _, kind := range []DomainKind{DomainFull, DomainSuffix, DomainKeyword, DomainRegex} {
		t.Run("empty-"+string(kind), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "empty-"+string(kind)+".dat")
			if err := os.WriteFile(path, geoSiteOld, 0o640); err != nil {
				t.Fatalf("WriteFile(%q) error = %v", path, err)
			}
			if _, err := writeGeoSiteDAT(path, "provider", []DomainRule{{Kind: kind, Value: ""}}); err == nil {
				t.Fatal("empty domain write error = nil")
			}
			datWriterAssertUnchanged(t, path, geoSiteOld)
			datWriterAssertOnlyEntries(t, dir, filepath.Base(path))
		})
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "invalid-prefix.dat")
	if err := os.WriteFile(path, geoIPOld, 0o640); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	var invalid netip.Prefix
	if invalid.IsValid() {
		t.Fatal("zero netip.Prefix unexpectedly valid")
	}
	if _, err := writeGeoIPDAT(path, "provider", []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		invalid,
	}); err == nil {
		t.Fatal("invalid prefix write error = nil")
	}
	datWriterAssertUnchanged(t, path, geoIPOld)
	datWriterAssertOnlyEntries(t, dir, filepath.Base(path))
}

func TestDATWriterExpandsExternalRulesThroughNormalizedRouting(t *testing.T) {
	externalDir := t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", "")
	const code = "provider"
	geoSitePath := filepath.Join(externalDir, "geosite.dat")
	geoIPPath := filepath.Join(externalDir, "geoip.dat")
	geoSiteRules := []DomainRule{
		{Kind: DomainFull, Value: "full.example.com"},
		{Kind: DomainSuffix, Value: "suffix.example.com"},
		{Kind: DomainKeyword, Value: "keyword-marker"},
		{Kind: DomainRegex, Value: `^regex[0-9]+\\.example$`},
	}
	geoIPPrefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.9/24"),
		netip.MustParsePrefix("2001:db8::1/32"),
	}
	if _, err := writeGeoSiteDAT(geoSitePath, code, geoSiteRules); err != nil {
		t.Fatalf("writeGeoSiteDAT() error = %v", err)
	}
	if _, err := writeGeoIPDAT(geoIPPath, code, geoIPPrefixes); err != nil {
		t.Fatalf("writeGeoIPDAT() error = %v", err)
	}

	sections, err := config_parser.Parse(`
global {}
routing {
    domain(ext:'geosite.dat:provider') -> proxy
    ip(ext:'geoip.dat:provider') -> direct
    fallback: direct
}
`)
	if err != nil {
		t.Fatalf("config_parser.Parse() error = %v", err)
	}
	var parsed config.Routing
	if err := config.SectionParser(reflect.ValueOf(&parsed), datWriterSection(t, sections, "routing")); err != nil {
		t.Fatalf("config.SectionParser() error = %v", err)
	}
	if len(parsed.Rules) != 2 {
		t.Fatalf("parsed routing rules = %d, want 2", len(parsed.Rules))
	}

	normalized, err := routing.ApplyRulesOptimizers(
		parsed.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{
			Logger:         logrus.New(),
			LocationFinder: assets.NewLocationFinder([]string{externalDir}),
		},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		t.Fatalf("routing.ApplyRulesOptimizers() error = %v", err)
	}

	domainParams := datWriterFindFunction(t, normalized, consts.Function_Domain, "proxy").Params
	wantDomains := map[string]string{
		string(consts.RoutingDomainKey_Full):    "full.example.com",
		string(consts.RoutingDomainKey_Suffix):  "suffix.example.com",
		string(consts.RoutingDomainKey_Keyword): "keyword-marker",
		string(consts.RoutingDomainKey_Regex):   `^regex[0-9]+\\.example$`,
	}
	gotDomains := make(map[string]string, len(domainParams))
	for _, param := range domainParams {
		if param.Key == "ext" {
			t.Fatalf("normalized domain still contains ext parameter: %#v", param)
		}
		gotDomains[param.Key] = param.Val
	}
	if !reflect.DeepEqual(gotDomains, wantDomains) {
		t.Fatalf("normalized domain params = %#v, want %#v", gotDomains, wantDomains)
	}

	ipParams := datWriterFindFunction(t, normalized, consts.Function_Ip, "direct").Params
	gotPrefixes := make([]string, 0, len(ipParams))
	for _, param := range ipParams {
		if param.Key == "ext" {
			t.Fatalf("normalized IP still contains ext parameter: %#v", param)
		}
		gotPrefixes = append(gotPrefixes, param.Val)
	}
	sort.Strings(gotPrefixes)
	wantPrefixes := []string{"192.0.2.0/24", "2001:db8::/32"}
	sort.Strings(wantPrefixes)
	if !reflect.DeepEqual(gotPrefixes, wantPrefixes) {
		t.Fatalf("normalized IP params = %#v, want %#v", gotPrefixes, wantPrefixes)
	}
	datWriterAssertOnlyEntries(t, externalDir, "geosite.dat", "geoip.dat")
}

func TestDATWriterPublishesCompleteProtobufWithoutTemporaryArtifacts(t *testing.T) {
	dir := t.TempDir()

	geoSitePath := filepath.Join(dir, "geosite.dat")
	geoSiteReport, err := writeGeoSiteDAT(geoSitePath, "site", []DomainRule{{
		Kind:  DomainSuffix,
		Value: "example.com",
	}})
	if err != nil {
		t.Fatalf("writeGeoSiteDAT() error = %v", err)
	}
	geoSiteRaw := datWriterReadFile(t, geoSitePath)
	var geoSiteList geodata.GeoSiteList
	if err := proto.Unmarshal(geoSiteRaw, &geoSiteList); err != nil {
		t.Fatalf("published geosite is not a complete protobuf: %v", err)
	}
	if len(geoSiteList.Entry) != 1 || len(geoSiteList.Entry[0].Domain) != 1 {
		t.Fatalf("published geosite entries = %#v, want one domain", geoSiteList.Entry)
	}
	datWriterAssertReport(t, geoSiteReport, "site", 1, 0, geoSiteRaw)
	datWriterAssertOnlyEntries(t, dir, "geosite.dat")

	geoIPPath := filepath.Join(dir, "geoip.dat")
	geoIPReport, err := writeGeoIPDAT(geoIPPath, "ip", []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
	})
	if err != nil {
		t.Fatalf("writeGeoIPDAT() error = %v", err)
	}
	geoIPRaw := datWriterReadFile(t, geoIPPath)
	var geoIPList geodata.GeoIPList
	if err := proto.Unmarshal(geoIPRaw, &geoIPList); err != nil {
		t.Fatalf("published geoip is not a complete protobuf: %v", err)
	}
	if len(geoIPList.Entry) != 1 || len(geoIPList.Entry[0].Cidr) != 1 {
		t.Fatalf("published geoip entries = %#v, want one CIDR", geoIPList.Entry)
	}
	datWriterAssertReport(t, geoIPReport, "ip", 1, 0, geoIPRaw)
	datWriterAssertOnlyEntries(t, dir, "geosite.dat", "geoip.dat")
}
