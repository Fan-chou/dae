package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type runnerRoundTripFunc func(*http.Request) (*http.Response, error)

const (
	generationLockHelperEnv          = "DAE_RULE_SYNC_GENERATION_LOCK_HELPER"
	generationLockHelperPathEnv      = "DAE_RULE_SYNC_GENERATION_LOCK_PATH"
	generationPublishHelperEnv       = "DAE_RULE_SYNC_GENERATION_PUBLISH_HELPER"
	generationPublishManifestPathEnv = "DAE_RULE_SYNC_GENERATION_PUBLISH_MANIFEST"
	generationPublishGroupsPathEnv   = "DAE_RULE_SYNC_GENERATION_PUBLISH_GROUPS"
	generationPublishRootEnv         = "DAE_RULE_SYNC_GENERATION_PUBLISH_ROOT"
)

func (f runnerRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func runnerResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func readCurrentGeneration(t *testing.T, root string) (string, []byte, []byte) {
	t.Helper()
	current := filepath.Join(root, "current")
	target, err := os.Readlink(current)
	if err != nil {
		t.Fatalf("Readlink(current) error = %v", err)
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		t.Fatalf("EvalSymlinks(current) error = %v", err)
	}
	routes, err := os.ReadFile(filepath.Join(resolved, "routes.dae"))
	if err != nil {
		t.Fatalf("ReadFile(current routes) error = %v", err)
	}
	groups, err := os.ReadFile(filepath.Join(resolved, "groups.dae"))
	if err != nil {
		t.Fatalf("ReadFile(current groups) error = %v", err)
	}
	return target, routes, groups
}

func assertDAEConfigRoundTrip(t *testing.T, routes, groups []byte) {
	t.Helper()
	sections, err := config_parser.Parse("global {}\n" + string(groups) + "routing {\n" + string(routes) + "  fallback: direct\n}\n")
	if err != nil {
		t.Fatalf("config_parser.Parse() error = %v; routes=%q groups=%q", err, routes, groups)
	}
	if _, err := config.New(sections); err != nil {
		t.Fatalf("config.New() error = %v; routes=%q groups=%q", err, routes, groups)
	}
}

func assertDAEConfigRejects(t *testing.T, routes, groups []byte) {
	t.Helper()
	sections, parseErr := config_parser.Parse("global {}\n" + string(groups) + "routing {\n" + string(routes) + "  fallback: direct\n}\n")
	if parseErr != nil {
		return
	}
	if _, err := config.New(sections); err == nil {
		t.Fatalf("invalid candidate unexpectedly passed config.New(): routes=%q groups=%q", routes, groups)
	}
}

const (
	runnerLargeProviderRuleThreshold = 256
	runnerLargeProviderRuleCount     = runnerLargeProviderRuleThreshold + 1
)

type runnerGenerationManifestProvider struct {
	name     string
	behavior string
	data     string
	outbound string
}

func runnerWriteGenerationManifest(t *testing.T, path string, providers ...runnerGenerationManifestProvider) {
	t.Helper()
	var manifest strings.Builder
	manifest.WriteString("providers:\n")
	for _, provider := range providers {
		fmt.Fprintf(&manifest, "  - name: %s\n", provider.name)
		manifest.WriteString("    type: inline\n")
		fmt.Fprintf(&manifest, "    behavior: %s\n", provider.behavior)
		manifest.WriteString("    format: yaml\n")
		fmt.Fprintf(&manifest, "    data: %q\n", provider.data)
	}
	manifest.WriteString("routes:\n")
	for _, provider := range providers {
		fmt.Fprintf(&manifest, "  - provider: %s\n", provider.name)
		fmt.Fprintf(&manifest, "    outbound: %s\n", provider.outbound)
		fmt.Fprintf(&manifest, "    kind: %s\n", provider.behavior)
	}
	if err := os.WriteFile(path, []byte(manifest.String()), 0o600); err != nil {
		t.Fatalf("WriteFile(generation manifest) error = %v", err)
	}
}

func runnerWriteGenerationGroupsInput(t *testing.T, path, member string) {
	t.Helper()
	groups := fmt.Sprintf(`proxies:
  - name: %s
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [%s]
`, member, member)
	if err := os.WriteFile(path, []byte(groups), 0o600); err != nil {
		t.Fatalf("WriteFile(generation groups input) error = %v", err)
	}
}

func runnerLargeDomainValues(count int, version string) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = fmt.Sprintf("%s-%03d.example.com", version, i)
	}
	return values
}

func runnerLargeDomainProviderData(count int, version string) string {
	var body strings.Builder
	body.WriteString("payload:\n")
	for _, value := range runnerLargeDomainValues(count, version) {
		fmt.Fprintf(&body, "  - %s\n", value)
	}
	return body.String()
}

func runnerGeoSiteRules(values []string, kind DomainKind) []DomainRule {
	rules := make([]DomainRule, 0, len(values))
	for _, value := range values {
		rules = append(rules, DomainRule{Kind: kind, Value: value})
	}
	return rules
}

func runnerLargeGeoIPPrefixes(count int, version string) []netip.Prefix {
	network := "192.0.2"
	v6Network := "2001:db8::"
	if version == "new" {
		network = "198.51.100"
		v6Network = "2001:db8:1::"
	}
	prefixes := make([]netip.Prefix, count)
	for i := range prefixes {
		if i < 256 {
			prefixes[i] = netip.MustParsePrefix(fmt.Sprintf("%s.%d/32", network, i))
			continue
		}
		prefixes[i] = netip.MustParsePrefix(fmt.Sprintf("%s%d/128", v6Network, i-255))
	}
	return prefixes
}

func runnerLargeGeoIPProviderData(count int, version string) string {
	var body strings.Builder
	body.WriteString("payload:\n")
	for _, prefix := range runnerLargeGeoIPPrefixes(count, version) {
		fmt.Fprintf(&body, "  - %s\n", prefix)
	}
	return body.String()
}

func runnerReadCurrentGenerationDetails(t *testing.T, root string) (string, string, []byte, []byte, map[string]any) {
	t.Helper()
	target, routes, groups := readCurrentGeneration(t, root)
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, "current"))
	if err != nil {
		t.Fatalf("EvalSymlinks(current) error = %v", err)
	}
	metadataBody, err := os.ReadFile(filepath.Join(resolved, "metadata.json"))
	if err != nil {
		t.Fatalf("ReadFile(current metadata) error = %v", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		t.Fatalf("json.Unmarshal(current metadata) error = %v", err)
	}
	return target, resolved, routes, groups, metadata
}

func runnerParseGenerationRouting(t *testing.T, routes, groups []byte) config.Routing {
	t.Helper()
	sections, err := config_parser.Parse("global {}\n" + string(groups) + "routing {\n" + string(routes) + "  fallback: direct\n}\n")
	if err != nil {
		t.Fatalf("config_parser.Parse() error = %v; routes=%q groups=%q", err, routes, groups)
	}
	var parsed config.Routing
	var routingSection *config_parser.Section
	for _, section := range sections {
		if section.Name == "routing" {
			routingSection = section
			break
		}
	}
	if routingSection == nil {
		t.Fatal("routing section is missing")
	}
	if err := config.SectionParser(reflect.ValueOf(&parsed), routingSection); err != nil {
		t.Fatalf("config.SectionParser() error = %v", err)
	}
	if _, err := config.New(sections); err != nil {
		t.Fatalf("config.New() error = %v; routes=%q groups=%q", err, routes, groups)
	}
	return parsed
}

func runnerOptimizeGenerationRouting(t *testing.T, routes, groups []byte, resolvedCurrent string) []*config_parser.RoutingRule {
	t.Helper()
	parsed := runnerParseGenerationRouting(t, routes, groups)
	normalized, err := routing.ApplyRulesOptimizers(
		parsed.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{
			Logger:         logrus.New(),
			LocationFinder: assets.NewLocationFinder([]string{resolvedCurrent}),
		},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		t.Fatalf("routing.ApplyRulesOptimizers() error = %v", err)
	}
	return normalized
}

func runnerFindRoutingFunction(t *testing.T, rules []*config_parser.RoutingRule, name, outbound string) *config_parser.Function {
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
	t.Fatalf("routing function %q for outbound %q not found in normalized rules", name, outbound)
	return nil
}

func runnerAssertExternalRoute(t *testing.T, routes, groups []byte, functionName, relativePath, outbound string, expectedRouteCount int) {
	t.Helper()
	parsed := runnerParseGenerationRouting(t, routes, groups)
	if len(parsed.Rules) != expectedRouteCount {
		preview := string(routes)
		if len(preview) > 240 {
			preview = preview[:240] + "..."
		}
		t.Fatalf("parsed candidate routes = %d, want %d external routes; route preview=%q", len(parsed.Rules), expectedRouteCount, preview)
	}
	rule := parsed.Rules[0]
	if expectedRouteCount > 1 {
		rule = nil
		for _, candidate := range parsed.Rules {
			if candidate.Outbound.Name != outbound {
				continue
			}
			if rule != nil {
				t.Fatalf("multiple external routes found for outbound %q", outbound)
			}
			rule = candidate
		}
		if rule == nil {
			t.Fatalf("external route for outbound %q not found in %d parsed rules", outbound, len(parsed.Rules))
		}
	}
	if rule.Outbound.Name != outbound {
		t.Fatalf("external route outbound = %q, want %q", rule.Outbound.Name, outbound)
	}
	if len(rule.AndFunctions) != 1 || rule.AndFunctions[0].Name != functionName {
		t.Fatalf("external route functions = %#v, want %s(ext)", rule.AndFunctions, functionName)
	}
	function := rule.AndFunctions[0]
	if len(function.Params) != 1 || function.Params[0].Key != "ext" || function.Params[0].Val != relativePath {
		t.Fatalf("external route params = %#v, want ext=%q", function.Params, relativePath)
	}
	if strings.Contains(string(routes), "-000.example.com") || strings.Count(string(routes), functionName+"(") != 1 {
		t.Fatalf("candidate route still contains inline expansion: %q", routes)
	}
}

func runnerReadDATMetadata(t *testing.T, metadata map[string]any, provider string) map[string]any {
	t.Helper()
	dats, ok := metadata["dats"].(map[string]any)
	if !ok {
		t.Fatalf("generation metadata dats = %#v, want provider-keyed DAT bindings", metadata["dats"])
	}
	binding, ok := dats[provider].(map[string]any)
	if !ok {
		t.Fatalf("generation metadata dats[%q] = %#v, want DAT binding", provider, dats[provider])
	}
	return binding
}

func runnerAssertDATMetadataBinding(t *testing.T, resolvedCurrent string, metadata map[string]any, provider, relativePath string, generated, skipped int) []byte {
	t.Helper()
	binding := runnerReadDATMetadata(t, metadata, provider)
	if binding["path"] != relativePath {
		t.Fatalf("generation metadata dats[%q].path = %#v, want %q", provider, binding["path"], relativePath)
	}
	path := filepath.Join(resolvedCurrent, filepath.FromSlash(relativePath))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s DAT) error = %v", relativePath, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%s DAT mode = %s, want regular file", relativePath, info.Mode())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s DAT) error = %v", relativePath, err)
	}
	if binding["sha256"] != digest(raw) {
		t.Fatalf("generation metadata dats[%q].sha256 = %#v, want %q", provider, binding["sha256"], digest(raw))
	}
	if got, ok := binding["generated"].(float64); !ok || int(got) != generated {
		t.Fatalf("generation metadata dats[%q].generated = %#v, want %d", provider, binding["generated"], generated)
	}
	if got, ok := binding["skipped"].(float64); !ok || int(got) != skipped {
		t.Fatalf("generation metadata dats[%q].skipped = %#v, want %d", provider, binding["skipped"], skipped)
	}
	return raw
}

func runnerAssertNoStandaloneDAT(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", root, err)
	}
	var walk func(string) error
	walk = func(path string) error {
		children, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, child := range children {
			childPath := filepath.Join(path, child.Name())
			if child.IsDir() {
				if err := walk(childPath); err != nil {
					return err
				}
				continue
			}
			if strings.HasSuffix(child.Name(), ".dat") {
				return fmt.Errorf("standalone DAT %q", childPath)
			}
		}
		return nil
	}
	for _, entry := range entries {
		if entry.Name() == "generations" || entry.Name() == "current" || entry.Name() == "generation.lock" {
			continue
		}
		if entry.IsDir() {
			if err := walk(filepath.Join(root, entry.Name())); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if strings.HasSuffix(entry.Name(), ".dat") {
			t.Fatalf("standalone DAT %q", filepath.Join(root, entry.Name()))
		}
	}
}

func runnerAssertGeoSiteGeneration(t *testing.T, resolvedCurrent string, routes, groups []byte, provider, outbound string, values []string, expectedRouteCount int) []byte {
	t.Helper()
	relativePath := filepath.ToSlash(filepath.Join("generated", "geosite", provider+".dat"))
	runnerAssertExternalRoute(t, routes, groups, "domain", relativePath+":"+provider, outbound, expectedRouteCount)
	raw, err := os.ReadFile(filepath.Join(resolvedCurrent, filepath.FromSlash(relativePath)))
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", relativePath, err)
	}
	decoded, err := geodata.UnmarshalGeoSite(logrus.New(), filepath.Join(resolvedCurrent, filepath.FromSlash(relativePath)), provider)
	if err != nil {
		t.Fatalf("UnmarshalGeoSite() error = %v", err)
	}
	if len(decoded.Domain) != len(values) {
		t.Fatalf("decoded GeoSite domain count = %d, want %d", len(decoded.Domain), len(values))
	}
	wantValues := make(map[string]struct{}, len(values))
	for _, value := range values {
		wantValues[value] = struct{}{}
	}
	for _, domain := range decoded.Domain {
		if domain.Type != geodata.Domain_RootDomain {
			t.Fatalf("decoded GeoSite domain type = %v, want suffix/root domain", domain.Type)
		}
		if _, ok := wantValues[domain.Value]; !ok {
			t.Fatalf("decoded GeoSite domain value = %q, not in expected provider values", domain.Value)
		}
	}
	normalized := runnerOptimizeGenerationRouting(t, routes, groups, resolvedCurrent)
	function := runnerFindRoutingFunction(t, normalized, consts.Function_Domain, outbound)
	if len(function.Params) != len(values) {
		t.Fatalf("normalized domain params = %d, want %d", len(function.Params), len(values))
	}
	gotValues := make(map[string]struct{}, len(function.Params))
	for _, param := range function.Params {
		if param.Key == "ext" {
			t.Fatalf("normalized domain still contains ext parameter: %#v", param)
		}
		if param.Key != string(consts.RoutingDomainKey_Suffix) {
			t.Fatalf("normalized domain param key = %q, want suffix", param.Key)
		}
		gotValues[param.Val] = struct{}{}
	}
	if !reflect.DeepEqual(gotValues, wantValues) {
		t.Fatalf("normalized domain params = %#v, want values %#v", gotValues, wantValues)
	}
	return raw
}

func runnerAssertGeoIPGeneration(t *testing.T, resolvedCurrent string, routes, groups []byte, provider, outbound string, prefixes []netip.Prefix, expectedRouteCount int) []byte {
	t.Helper()
	relativePath := filepath.ToSlash(filepath.Join("generated", "geoip", provider+".dat"))
	runnerAssertExternalRoute(t, routes, groups, "dip", relativePath+":"+provider, outbound, expectedRouteCount)
	path := filepath.Join(resolvedCurrent, filepath.FromSlash(relativePath))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", relativePath, err)
	}
	decoded, err := geodata.UnmarshalGeoIp(logrus.New(), path, provider)
	if err != nil {
		t.Fatalf("UnmarshalGeoIp() error = %v", err)
	}
	if len(decoded.Cidr) != len(prefixes) {
		t.Fatalf("decoded GeoIP prefix count = %d, want %d", len(decoded.Cidr), len(prefixes))
	}
	wantPrefixes := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		wantPrefixes[prefix.Masked().String()] = struct{}{}
	}
	for _, cidr := range decoded.Cidr {
		addr, ok := netip.AddrFromSlice(cidr.Ip)
		if !ok {
			t.Fatalf("AddrFromSlice(%v) failed", cidr.Ip)
		}
		prefix := netip.PrefixFrom(addr, int(cidr.Prefix)).Masked().String()
		if _, ok := wantPrefixes[prefix]; !ok {
			t.Fatalf("decoded GeoIP prefix = %q, not in expected provider prefixes", prefix)
		}
	}
	normalized := runnerOptimizeGenerationRouting(t, routes, groups, resolvedCurrent)
	function := runnerFindRoutingFunction(t, normalized, consts.Function_Ip, outbound)
	if len(function.Params) != len(prefixes) {
		t.Fatalf("normalized IP params = %d, want %d", len(function.Params), len(prefixes))
	}
	gotPrefixes := make(map[string]struct{}, len(function.Params))
	for _, param := range function.Params {
		if param.Key != "" {
			t.Fatalf("normalized IP param key = %q, want empty", param.Key)
		}
		gotPrefixes[param.Val] = struct{}{}
	}
	if !reflect.DeepEqual(gotPrefixes, wantPrefixes) {
		t.Fatalf("normalized IP params = %#v, want prefixes %#v", gotPrefixes, wantPrefixes)
	}
	return raw
}

func TestRunSyncGenerationUsesGeoSiteDATForLargeProvider(t *testing.T) {
	const (
		provider = "large-domain"
		outbound = "proxy"
	)
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	values := runnerLargeDomainValues(runnerLargeProviderRuleCount, "v1")
	runnerWriteGenerationManifest(t, manifestPath, runnerGenerationManifestProvider{
		name:     provider,
		behavior: "domain",
		data:     runnerLargeDomainProviderData(runnerLargeProviderRuleCount, "v1"),
		outbound: outbound,
	})
	runnerWriteGenerationGroupsInput(t, groupsPath, "hk-1")

	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}

	_, resolvedCurrent, routes, groups, metadata := runnerReadCurrentGenerationDetails(t, generationDir)
	runnerAssertGeoSiteGeneration(t, resolvedCurrent, routes, groups, provider, outbound, values, 1)
	runnerAssertDATMetadataBinding(t, resolvedCurrent, metadata, provider, "generated/geosite/"+provider+".dat", runnerLargeProviderRuleCount, 0)
	runnerAssertNoStandaloneDAT(t, generationDir)
}

func TestRunSyncGenerationUsesGeoIPDATForLargeProvider(t *testing.T) {
	const (
		provider = "large-ip"
		outbound = "direct"
	)
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	prefixes := runnerLargeGeoIPPrefixes(runnerLargeProviderRuleCount, "old")
	runnerWriteGenerationManifest(t, manifestPath, runnerGenerationManifestProvider{
		name:     provider,
		behavior: "ipcidr",
		data:     runnerLargeGeoIPProviderData(runnerLargeProviderRuleCount, "old"),
		outbound: outbound,
	})
	runnerWriteGenerationGroupsInput(t, groupsPath, "hk-1")

	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}

	_, resolvedCurrent, routes, groups, metadata := runnerReadCurrentGenerationDetails(t, generationDir)
	runnerAssertGeoIPGeneration(t, resolvedCurrent, routes, groups, provider, outbound, prefixes, 1)
	runnerAssertDATMetadataBinding(t, resolvedCurrent, metadata, provider, "generated/geoip/"+provider+".dat", runnerLargeProviderRuleCount, 0)
	runnerAssertNoStandaloneDAT(t, generationDir)
}

func TestRunSyncGenerationPublishesDATRoutesGroupsTogether(t *testing.T) {
	const (
		domainProvider = "large-domain"
		ipProvider     = "large-ip"
	)
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	writeManifest := func(domainVersion, ipVersion, domainOutbound, ipOutbound string) {
		t.Helper()
		runnerWriteGenerationManifest(t, manifestPath,
			runnerGenerationManifestProvider{
				name:     domainProvider,
				behavior: "domain",
				data:     runnerLargeDomainProviderData(runnerLargeProviderRuleCount, domainVersion),
				outbound: domainOutbound,
			},
			runnerGenerationManifestProvider{
				name:     ipProvider,
				behavior: "ipcidr",
				data:     runnerLargeGeoIPProviderData(runnerLargeProviderRuleCount, ipVersion),
				outbound: ipOutbound,
			},
		)
	}
	options := SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}

	writeManifest("old", "old", "proxy", "direct")
	runnerWriteGenerationGroupsInput(t, groupsPath, "hk-old")
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	oldTarget, oldDir, oldRoutes, oldGroups, oldMetadata := runnerReadCurrentGenerationDetails(t, generationDir)
	oldDomains := runnerLargeDomainValues(runnerLargeProviderRuleCount, "old")
	oldPrefixes := runnerLargeGeoIPPrefixes(runnerLargeProviderRuleCount, "old")
	oldDomainDAT := runnerAssertGeoSiteGeneration(t, oldDir, oldRoutes, oldGroups, domainProvider, "proxy", oldDomains, 2)
	oldIPDAT := runnerAssertGeoIPGeneration(t, oldDir, oldRoutes, oldGroups, ipProvider, "direct", oldPrefixes, 2)
	runnerAssertDATMetadataBinding(t, oldDir, oldMetadata, domainProvider, "generated/geosite/"+domainProvider+".dat", runnerLargeProviderRuleCount, 0)
	runnerAssertDATMetadataBinding(t, oldDir, oldMetadata, ipProvider, "generated/geoip/"+ipProvider+".dat", runnerLargeProviderRuleCount, 0)
	if !strings.Contains(string(oldGroups), "filter: name('hk-old')") {
		t.Fatalf("initial generation groups = %q, want hk-old", oldGroups)
	}
	runnerAssertNoStandaloneDAT(t, generationDir)

	writeManifest("new", "new", "proxy-v2", "direct-v2")
	runnerWriteGenerationGroupsInput(t, groupsPath, "hk-new")
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("second RunSync() error = %v", err)
	}
	newTarget, newDir, newRoutes, newGroups, newMetadata := runnerReadCurrentGenerationDetails(t, generationDir)
	if newTarget == oldTarget || newDir == oldDir {
		t.Fatalf("generation did not advance: old target/dir=%q/%q new=%q/%q", oldTarget, oldDir, newTarget, newDir)
	}
	newDomains := runnerLargeDomainValues(runnerLargeProviderRuleCount, "new")
	newPrefixes := runnerLargeGeoIPPrefixes(runnerLargeProviderRuleCount, "new")
	newDomainDAT := runnerAssertGeoSiteGeneration(t, newDir, newRoutes, newGroups, domainProvider, "proxy-v2", newDomains, 2)
	newIPDAT := runnerAssertGeoIPGeneration(t, newDir, newRoutes, newGroups, ipProvider, "direct-v2", newPrefixes, 2)
	runnerAssertDATMetadataBinding(t, newDir, newMetadata, domainProvider, "generated/geosite/"+domainProvider+".dat", runnerLargeProviderRuleCount, 0)
	runnerAssertDATMetadataBinding(t, newDir, newMetadata, ipProvider, "generated/geoip/"+ipProvider+".dat", runnerLargeProviderRuleCount, 0)
	if bytes.Equal(oldDomainDAT, newDomainDAT) || bytes.Equal(oldIPDAT, newIPDAT) {
		t.Fatal("second generation DAT content did not change with provider content")
	}
	if !strings.Contains(string(newGroups), "filter: name('hk-new')") {
		t.Fatalf("new generation groups = %q, want hk-new", newGroups)
	}
	if string(oldRoutes) == string(newRoutes) || string(oldGroups) == string(newGroups) {
		t.Fatalf("second generation routes/groups did not advance: old=%q/%q new=%q/%q", oldRoutes, oldGroups, newRoutes, newGroups)
	}
	if _, err := os.Stat(filepath.Join(oldDir, "generated", "geosite", domainProvider+".dat")); err != nil {
		t.Fatalf("old generation GeoSite DAT disappeared: %v", err)
	}
	if _, err := os.Stat(filepath.Join(oldDir, "generated", "geoip", ipProvider+".dat")); err != nil {
		t.Fatalf("old generation GeoIP DAT disappeared: %v", err)
	}
	if newMetadata["previous_generation"] != filepath.Base(oldTarget) {
		t.Fatalf("new generation previous_generation = %#v, want %q", newMetadata["previous_generation"], filepath.Base(oldTarget))
	}
	runnerAssertNoStandaloneDAT(t, generationDir)
}

func TestRunSyncGenerationValidatesClassicalProviderWithDomainAndIPDATs(t *testing.T) {
	const (
		provider       = "classical-large"
		domainOutbound = "proxy"
		ipOutbound     = "direct"
	)
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	domainValues := runnerLargeDomainValues(runnerLargeProviderRuleCount, "v1")
	prefixes := runnerLargeGeoIPPrefixes(runnerLargeProviderRuleCount, "old")
	var providerData strings.Builder
	providerData.WriteString("payload:\n")
	for _, value := range domainValues {
		fmt.Fprintf(&providerData, "  - %s\n", value)
	}
	for _, prefix := range prefixes {
		fmt.Fprintf(&providerData, "  - %s\n", prefix)
	}

	var manifest strings.Builder
	manifest.WriteString("providers:\n")
	fmt.Fprintf(&manifest, "  - name: %s\n", provider)
	manifest.WriteString("    type: inline\n")
	manifest.WriteString("    behavior: classical\n")
	manifest.WriteString("    format: yaml\n")
	fmt.Fprintf(&manifest, "    data: %q\n", providerData.String())
	manifest.WriteString("routes:\n")
	fmt.Fprintf(&manifest, "  - provider: %s\n    outbound: %s\n    kind: domain\n", provider, domainOutbound)
	fmt.Fprintf(&manifest, "  - provider: %s\n    outbound: %s\n    kind: ipcidr\n", provider, ipOutbound)
	if err := os.WriteFile(manifestPath, []byte(manifest.String()), 0o600); err != nil {
		t.Fatalf("WriteFile(classical generation manifest) error = %v", err)
	}
	runnerWriteGenerationGroupsInput(t, groupsPath, "hk-classical")

	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}); err != nil {
		t.Fatalf("RunSync() error = %v; legal primary DAT binding Additional was rejected as nested Additional", err)
	}

	target, resolvedCurrent, routes, groups, metadata := runnerReadCurrentGenerationDetails(t, generationDir)
	if strings.Count(string(routes), "domain(ext:") != 1 || strings.Count(string(routes), "dip(ext:") != 1 {
		t.Fatalf("current routes = %q, want one domain ext route and one dip ext route", routes)
	}
	runnerAssertGeoSiteGeneration(t, resolvedCurrent, routes, groups, provider, domainOutbound, domainValues, 2)
	runnerAssertGeoIPGeneration(t, resolvedCurrent, routes, groups, provider, ipOutbound, prefixes, 2)

	binding := runnerReadDATMetadata(t, metadata, provider)
	if binding["path"] != "generated/geosite/"+provider+".dat" || binding["kind"] != "domain" {
		t.Fatalf("metadata dats[%q] primary binding = %#v, want geosite domain DAT", provider, binding)
	}
	additional, ok := binding["additional"].([]any)
	if !ok || len(additional) != 1 {
		t.Fatalf("metadata dats[%q].additional = %#v, want one legal additional binding", provider, binding["additional"])
	}
	additionalBinding, ok := additional[0].(map[string]any)
	if !ok || additionalBinding["path"] != "generated/geoip/"+provider+".dat" || additionalBinding["kind"] != "ipcidr" {
		t.Fatalf("metadata dats[%q].additional[0] = %#v, want geoip ipcidr DAT", provider, additional[0])
	}
	if got, ok := binding["generated"].(float64); !ok || int(got) != runnerLargeProviderRuleCount {
		t.Fatalf("metadata dats[%q].generated = %#v, want %d", provider, binding["generated"], runnerLargeProviderRuleCount)
	}
	if got, ok := additionalBinding["generated"].(float64); !ok || int(got) != runnerLargeProviderRuleCount {
		t.Fatalf("metadata dats[%q].additional[0].generated = %#v, want %d", provider, additionalBinding["generated"], runnerLargeProviderRuleCount)
	}

	if err := validateStoredGeneration(resolvedCurrent, filepath.Base(target)); err != nil {
		t.Fatalf("validateStoredGeneration() error = %v; legal primary DAT binding Additional must validate", err)
	}
}

const runnerGenerationValidationProvider = "large-domain-validation"

func runnerPublishLargeDomainValidationGeneration(t *testing.T) (string, string, []byte, []byte, generationMetadata, []ProviderSnapshot) {
	t.Helper()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	values := runnerLargeDomainValues(runnerLargeProviderRuleCount, "v1")
	runnerWriteGenerationManifest(t, manifestPath, runnerGenerationManifestProvider{
		name:     runnerGenerationValidationProvider,
		behavior: "domain",
		data:     runnerLargeDomainProviderData(runnerLargeProviderRuleCount, "v1"),
		outbound: "proxy",
	})
	runnerWriteGenerationGroupsInput(t, groupsPath, "hk-validation")
	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}

	target, currentDir, routes, groups, _ := runnerReadCurrentGenerationDetails(t, generationDir)
	generationID := filepath.Base(target)
	metadata, err := readGenerationMetadata(currentDir, generationID)
	if err != nil {
		t.Fatalf("read generation metadata error = %v", err)
	}
	binding, ok := metadata.DATs[runnerGenerationValidationProvider]
	if !ok {
		t.Fatalf("generation metadata DAT binding for %q is missing", runnerGenerationValidationProvider)
	}
	raw := runnerAssertGeoSiteGeneration(t, currentDir, routes, groups, runnerGenerationValidationProvider, "proxy", values, 1)
	if digest(raw) != binding.SHA256 {
		t.Fatalf("generation metadata DAT sha256 = %q, want %q", binding.SHA256, digest(raw))
	}
	if binding.Generated != runnerLargeProviderRuleCount || binding.Skipped != 0 {
		t.Fatalf("generation metadata DAT counts = generated:%d skipped:%d, want generated:%d skipped:0", binding.Generated, binding.Skipped, runnerLargeProviderRuleCount)
	}
	snapshots, err := readGenerationProviderSnapshots(currentDir)
	if err != nil {
		t.Fatalf("read generation provider snapshots error = %v", err)
	}
	selected := make([]ProviderSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		selected = append(selected, snapshot)
	}
	return generationDir, currentDir, routes, groups, metadata, selected
}

func writeRunnerGenerationMetadata(t *testing.T, currentDir string, metadata generationMetadata) {
	t.Helper()
	body, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal(generation metadata) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(currentDir, "metadata.json"), body, 0o600); err != nil {
		t.Fatalf("WriteFile(generation metadata) error = %v", err)
	}
}

func TestValidateStoredGenerationRejectsDATWithValidChecksumButInvalidProtobuf(t *testing.T) {
	_, currentDir, _, _, metadata, _ := runnerPublishLargeDomainValidationGeneration(t)
	binding := metadata.DATs[runnerGenerationValidationProvider]
	datPath := filepath.Join(currentDir, filepath.FromSlash(binding.Path))
	invalidDAT := []byte{0x80}
	if err := os.WriteFile(datPath, invalidDAT, 0o600); err != nil {
		t.Fatalf("WriteFile(invalid DAT) error = %v", err)
	}
	binding.SHA256 = digest(invalidDAT)
	metadata.DATs[runnerGenerationValidationProvider] = binding
	writeRunnerGenerationMetadata(t, currentDir, metadata)

	if err := validateStoredGeneration(currentDir, metadata.Generation); err == nil {
		t.Fatal("validateStoredGeneration() error = nil for invalid protobuf with matching DAT checksum")
	}
}

func TestValidateStoredGenerationRejectsExtRouteWithoutDATBinding(t *testing.T) {
	_, currentDir, _, _, metadata, _ := runnerPublishLargeDomainValidationGeneration(t)
	metadata.DATs = nil
	writeRunnerGenerationMetadata(t, currentDir, metadata)

	if err := validateStoredGeneration(currentDir, metadata.Generation); err == nil {
		t.Fatal("validateStoredGeneration() error = nil for ext route without DAT metadata binding")
	}
}

func TestValidateStoredGenerationRejectsTamperedDATGeneratedCount(t *testing.T) {
	_, currentDir, _, _, metadata, _ := runnerPublishLargeDomainValidationGeneration(t)
	binding := metadata.DATs[runnerGenerationValidationProvider]
	originalDAT, err := os.ReadFile(filepath.Join(currentDir, filepath.FromSlash(binding.Path)))
	if err != nil {
		t.Fatalf("ReadFile(original DAT) error = %v", err)
	}
	originalSHA := binding.SHA256
	binding.Generated = 1
	metadata.DATs[runnerGenerationValidationProvider] = binding
	writeRunnerGenerationMetadata(t, currentDir, metadata)

	if err := validateStoredGeneration(currentDir, metadata.Generation); err == nil {
		t.Fatal("validateStoredGeneration() error = nil for tampered DAT generated count")
	}
	updatedDAT, err := os.ReadFile(filepath.Join(currentDir, filepath.FromSlash(binding.Path)))
	if err != nil {
		t.Fatalf("ReadFile(updated DAT) error = %v", err)
	}
	if !bytes.Equal(updatedDAT, originalDAT) || binding.SHA256 != originalSHA {
		t.Fatalf("DAT content or checksum changed while tampering generated count: contentChanged=%t sha=%q want %q", !bytes.Equal(updatedDAT, originalDAT), binding.SHA256, originalSHA)
	}
}

func TestGenerationMatchesCurrentRejectsDamagedCurrentDAT(t *testing.T) {
	generationDir, currentDir, routes, groups, metadata, snapshots := runnerPublishLargeDomainValidationGeneration(t)
	binding := metadata.DATs[runnerGenerationValidationProvider]
	if err := os.WriteFile(filepath.Join(currentDir, filepath.FromSlash(binding.Path)), []byte{0x80}, 0o600); err != nil {
		t.Fatalf("WriteFile(damaged current DAT) error = %v", err)
	}
	state := generationRootState{
		root:        generationDir,
		generations: filepath.Join(generationDir, "generations"),
		previousID:  metadata.Generation,
	}
	matched, err := generationMatchesCurrent(state, routes, groups, snapshots)
	if matched {
		t.Fatalf("generationMatchesCurrent() = true for damaged current DAT (error = %v)", err)
	}
}

func TestGenerationDATValidationDoesNotUseExternalSameNamedGeoSite(t *testing.T) {
	t.Run("candidate-publication", func(t *testing.T) {
		const provider = "candidate-external-asset"
		dir := t.TempDir()
		externalDir := filepath.Join(dir, "external")
		candidateProbeDir := filepath.Join(dir, "candidate-probe")
		relativePath := filepath.Join("generated", "geosite", provider+".dat")
		externalPath := filepath.Join(externalDir, relativePath)
		candidateProbePath := filepath.Join(candidateProbeDir, relativePath)
		externalValues := []string{"external-only.example.com"}
		candidateValues := runnerLargeDomainValues(runnerLargeProviderRuleCount, "candidate")
		for _, path := range []string{externalPath, candidateProbePath} {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(path), err)
			}
		}
		if _, err := writeGeoSiteDAT(externalPath, provider, runnerGeoSiteRules(externalValues, DomainSuffix)); err != nil {
			t.Fatalf("writeGeoSiteDAT(external) error = %v", err)
		}
		if _, err := writeGeoSiteDAT(candidateProbePath, provider, runnerGeoSiteRules(candidateValues, DomainSuffix)); err != nil {
			t.Fatalf("writeGeoSiteDAT(candidate probe) error = %v", err)
		}

		t.Setenv("DAE_LOCATION_ASSET", externalDir)
		finder := assets.NewLocationFinder([]string{candidateProbeDir})
		found, err := finder.GetLocationAsset(logrus.New(), filepath.ToSlash(relativePath))
		if err != nil {
			t.Fatalf("GetLocationAsset(%q) error = %v", relativePath, err)
		}
		if found != externalPath {
			t.Fatalf("same-named GeoSite asset path = %q, want external asset %q to prove environment priority", found, externalPath)
		}

		manifestPath := filepath.Join(dir, "providers.yaml")
		groupsPath := filepath.Join(dir, "mihomo.yaml")
		generationDir := filepath.Join(dir, "generation")
		runnerWriteGenerationManifest(t, manifestPath, runnerGenerationManifestProvider{
			name:     provider,
			behavior: "domain",
			data:     runnerLargeDomainProviderData(runnerLargeProviderRuleCount, "candidate"),
			outbound: "proxy",
		})
		runnerWriteGenerationGroupsInput(t, groupsPath, "hk-candidate")
		if _, err := RunSync(context.Background(), SyncOptions{
			ManifestPath:    manifestPath,
			CacheDir:        filepath.Join(dir, "cache"),
			GroupsInputPath: groupsPath,
			GenerationDir:   generationDir,
		}); err != nil {
			t.Fatalf("RunSync() error = %v; candidate validation must use its own generated GeoSite DAT, not the same-named external asset", err)
		}
		t.Setenv("DAE_LOCATION_ASSET", "")

		_, currentDir, routes, groups, _ := runnerReadCurrentGenerationDetails(t, generationDir)
		candidateDAT := runnerAssertGeoSiteGeneration(t, currentDir, routes, groups, provider, "proxy", candidateValues, 1)
		externalDAT, err := os.ReadFile(externalPath)
		if err != nil {
			t.Fatalf("ReadFile(external GeoSite DAT) error = %v", err)
		}
		if bytes.Equal(candidateDAT, externalDAT) {
			t.Fatal("published candidate GeoSite DAT unexpectedly equals external same-named DAT")
		}
	})

	t.Run("stored-current", func(t *testing.T) {
		t.Setenv("DAE_LOCATION_ASSET", "")
		_, currentDir, _, _, metadata, _ := runnerPublishLargeDomainValidationGeneration(t)
		binding := metadata.DATs[runnerGenerationValidationProvider]
		datPath := filepath.Join(currentDir, filepath.FromSlash(binding.Path))
		originalDAT, err := os.ReadFile(datPath)
		if err != nil {
			t.Fatalf("ReadFile(original GeoSite DAT) error = %v", err)
		}

		externalDir := t.TempDir()
		externalPath := filepath.Join(externalDir, filepath.FromSlash(binding.Path))
		if err := os.MkdirAll(filepath.Dir(externalPath), 0o750); err != nil {
			t.Fatalf("MkdirAll(external GeoSite DAT) error = %v", err)
		}
		snapshotValues := runnerLargeDomainValues(runnerLargeProviderRuleCount, "v1")
		if _, err := writeGeoSiteDAT(externalPath, runnerGenerationValidationProvider, runnerGeoSiteRules(snapshotValues, DomainSuffix)); err != nil {
			t.Fatalf("writeGeoSiteDAT(external snapshot) error = %v", err)
		}
		t.Setenv("DAE_LOCATION_ASSET", externalDir)
		finder := assets.NewLocationFinder([]string{currentDir})
		found, err := finder.GetLocationAsset(logrus.New(), filepath.ToSlash(binding.Path))
		if err != nil {
			t.Fatalf("GetLocationAsset(%q) error = %v", binding.Path, err)
		}
		if found != externalPath {
			t.Fatalf("same-named stored GeoSite asset path = %q, want external asset %q to prove environment priority", found, externalPath)
		}

		if _, err := writeGeoSiteDAT(datPath, runnerGenerationValidationProvider, runnerGeoSiteRules([]string{"tampered-only.example.com"}, DomainSuffix)); err != nil {
			t.Fatalf("writeGeoSiteDAT(tampered candidate) error = %v", err)
		}
		tamperedDAT, err := os.ReadFile(datPath)
		if err != nil {
			t.Fatalf("ReadFile(tampered GeoSite DAT) error = %v", err)
		}
		if bytes.Equal(tamperedDAT, originalDAT) {
			t.Fatal("tampered stored GeoSite DAT did not change")
		}
		binding.SHA256 = digest(tamperedDAT)
		metadata.DATs[runnerGenerationValidationProvider] = binding
		writeRunnerGenerationMetadata(t, currentDir, metadata)

		if err := validateStoredGeneration(currentDir, metadata.Generation); err == nil {
			t.Fatal("validateStoredGeneration() error = nil for a legal same-code GeoSite DAT with changed contents")
		}
	})
}

func TestDirectRunSyncKeepsSmallProviderInlineAndDoesNotPublishDAT(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	routesPath := filepath.Join(dir, "routes.dae")
	runnerWriteGenerationManifest(t, manifestPath, runnerGenerationManifestProvider{
		name:     "small-domain",
		behavior: "domain",
		data:     "payload: [small.example.com]\n",
		outbound: "proxy",
	})

	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath: manifestPath,
		CacheDir:     filepath.Join(dir, "cache"),
		RoutesOutput: routesPath,
	}); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	routes, err := os.ReadFile(routesPath)
	if err != nil {
		t.Fatalf("ReadFile(routes) error = %v", err)
	}
	wantRoutes := "domain(suffix: 'small.example.com') -> proxy\n"
	if string(routes) != wantRoutes {
		t.Fatalf("direct routes = %q, want exact inline output %q", routes, wantRoutes)
	}
	if strings.Contains(string(routes), "ext:") {
		t.Fatalf("direct small-provider routes unexpectedly use DAT/ext: %q", routes)
	}
	if _, err := os.Stat(filepath.Join(dir, "generated")); !os.IsNotExist(err) {
		t.Fatalf("direct mode generated sibling stat error = %v, want absent", err)
	}
	runnerAssertNoStandaloneDAT(t, dir)
}

func TestRunSyncRedactsQueryFromInvalidProviderURLPreflightError(t *testing.T) {
	const rawURL = "https://bad%zz.example/rules?token=secret-token"
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := fmt.Sprintf(`providers:
  - name: p
    type: http
    url: %s
    behavior: domain
    format: yaml
routes: []
`, rawURL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	_, err := RunSync(context.Background(), SyncOptions{ManifestPath: manifestPath})
	if err == nil {
		t.Fatal("RunSync() error = nil for malformed provider URL")
	}
	errText := err.Error()
	if strings.Contains(errText, "secret-token") {
		t.Fatalf("RunSync() leaked provider URL token: %v", err)
	}
	if strings.Contains(errText, "?token=secret-token") || strings.Contains(errText, rawURL) {
		t.Fatalf("RunSync() retained provider URL query: %v", err)
	}
	for _, diagnostic := range []string{`provider "p"`, "invalid url"} {
		if !strings.Contains(errText, diagnostic) {
			t.Fatalf("RunSync() error = %v, want diagnostic %q", err, diagnostic)
		}
	}
}

func TestRunSyncPublishesRoutesGroupsAndMetadataAsOneGeneration(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsInput := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")

	writeManifest := func(providerBody string) {
		t.Helper()
		manifest := fmt.Sprintf(`providers:
  - name: p
    type: inline
    behavior: domain
    format: yaml
    data: %q
routes:
  - provider: p
    outbound: proxy
    kind: domain
`, providerBody)
		if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
			t.Fatalf("WriteFile(manifest) error = %v", err)
		}
	}
	writeGroups := func(member string) {
		t.Helper()
		mihomo := fmt.Sprintf(`proxies:
  - name: %s
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [%s]
`, member, member)
		if err := os.WriteFile(groupsInput, []byte(mihomo), 0o600); err != nil {
			t.Fatalf("WriteFile(groups input) error = %v", err)
		}
	}

	readGeneration := func() (string, string, []byte, []byte, map[string]any) {
		t.Helper()
		currentPath := filepath.Join(generationDir, "current")
		info, err := os.Lstat(currentPath)
		if err != nil {
			t.Fatalf("Lstat(current) error = %v", err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("current mode = %s, want symlink", info.Mode())
		}
		target, err := os.Readlink(currentPath)
		if err != nil {
			t.Fatalf("Readlink(current) error = %v", err)
		}
		if target == "" || filepath.IsAbs(target) || filepath.Clean(target) != target || target != filepath.Join("generations", filepath.Base(target)) {
			t.Fatalf("current target = %q, want canonical relative generations/<id> target", target)
		}
		resolvedCurrent, err := filepath.EvalSymlinks(currentPath)
		if err != nil {
			t.Fatalf("EvalSymlinks(current) error = %v", err)
		}
		resolvedParent, err := filepath.EvalSymlinks(filepath.Join(generationDir, "generations"))
		if err != nil {
			t.Fatalf("EvalSymlinks(generations) error = %v", err)
		}
		relative, err := filepath.Rel(resolvedParent, resolvedCurrent)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.Dir(relative) != "." {
			t.Fatalf("resolved current = %q, want direct child of generated/generations", resolvedCurrent)
		}
		if info, err := os.Stat(resolvedCurrent); err != nil || !info.IsDir() {
			t.Fatalf("resolved generation = %q, stat error = %v, info = %#v", resolvedCurrent, err, info)
		}
		routes, err := os.ReadFile(filepath.Join(resolvedCurrent, "routes.dae"))
		if err != nil {
			t.Fatalf("ReadFile(generation routes) error = %v", err)
		}
		groups, err := os.ReadFile(filepath.Join(resolvedCurrent, "groups.dae"))
		if err != nil {
			t.Fatalf("ReadFile(generation groups) error = %v", err)
		}
		metadataBody, err := os.ReadFile(filepath.Join(resolvedCurrent, "metadata.json"))
		if err != nil {
			t.Fatalf("ReadFile(generation metadata) error = %v", err)
		}
		var metadata map[string]any
		if err := json.Unmarshal(metadataBody, &metadata); err != nil {
			t.Fatalf("json.Unmarshal(generation metadata) error = %v", err)
		}
		generation, ok := metadata["generation"].(string)
		if !ok || generation == "" {
			t.Fatalf("metadata generation = %#v, want non-empty identifier", metadata["generation"])
		}
		routeHash, ok := metadata["routes_sha256"].(string)
		if !ok || routeHash == "" {
			t.Fatalf("metadata routes_sha256 = %#v, want non-empty hash", metadata["routes_sha256"])
		}
		groupHash, ok := metadata["groups_sha256"].(string)
		if !ok || groupHash == "" {
			t.Fatalf("metadata groups_sha256 = %#v, want non-empty hash", metadata["groups_sha256"])
		}
		routeDigest := sha256.Sum256(routes)
		groupDigest := sha256.Sum256(groups)
		if routeHash != fmt.Sprintf("%x", routeDigest) || groupHash != fmt.Sprintf("%x", groupDigest) {
			t.Fatalf("metadata hashes = %#v, want routes=%x groups=%x", metadata, routeDigest, groupDigest)
		}
		return target, resolvedCurrent, routes, groups, metadata
	}

	writeManifest("payload: [example.com]")
	writeGroups("hk-1")
	options := SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: groupsInput,
		GenerationDir:   generationDir,
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	oldTarget, oldGenerationDir, oldRoutes, oldGroups, oldMetadata := readGeneration()
	if !strings.Contains(string(oldRoutes), "domain(suffix: 'example.com') -> proxy") {
		t.Fatalf("initial generation routes = %q", oldRoutes)
	}
	if !strings.Contains(string(oldGroups), "filter: name('hk-1')") {
		t.Fatalf("initial generation groups = %q", oldGroups)
	}

	writeManifest("payload: [new.example.com]")
	writeGroups("hk-2")
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("second RunSync() error = %v", err)
	}
	newTarget, newGenerationDir, newRoutes, newGroups, newMetadata := readGeneration()
	if newTarget == oldTarget || newGenerationDir == oldGenerationDir {
		t.Fatalf("generation did not advance: old target/dir=%q/%q new=%q/%q", oldTarget, oldGenerationDir, newTarget, newGenerationDir)
	}
	if !strings.Contains(string(newRoutes), "domain(suffix: 'new.example.com') -> proxy") {
		t.Fatalf("new generation routes = %q", newRoutes)
	}
	if !strings.Contains(string(newGroups), "filter: name('hk-2')") {
		t.Fatalf("new generation groups = %q", newGroups)
	}
	if _, err := os.Stat(filepath.Join(oldGenerationDir, "routes.dae")); err != nil {
		t.Fatalf("old generation routes disappeared: %v", err)
	}
	if _, err := os.Stat(filepath.Join(oldGenerationDir, "groups.dae")); err != nil {
		t.Fatalf("old generation groups disappeared: %v", err)
	}
	if _, err := os.Stat(filepath.Join(oldGenerationDir, "metadata.json")); err != nil {
		t.Fatalf("old generation metadata disappeared: %v", err)
	}
	if string(oldRoutes) == string(newRoutes) || string(oldGroups) == string(newGroups) || oldMetadata["generation"] == newMetadata["generation"] {
		t.Fatalf("generation contents or metadata did not change: old=%#v/%q/%q new=%#v/%q/%q", oldMetadata, oldRoutes, oldGroups, newMetadata, newRoutes, newGroups)
	}
}

func TestRunSyncDoesNotMaskEmptyOrAllSkippedReferencedProvider(t *testing.T) {
	tests := []struct {
		name     string
		badBody  string
		badCheck string
	}{
		{name: "empty", badBody: "payload: []\n", badCheck: "empty"},
		{name: "all-skipped", badBody: "PROCESS-NAME,ignored\n", badCheck: "all-skipped"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			manifestPath := filepath.Join(dir, "providers.yaml")
			p1URL := "https://provider-one.test/rules"
			p2URL := "https://provider-two.test/rules"
			manifest := fmt.Sprintf(`providers:
  - name: p1
    type: http
    url: %s
    behavior: domain
    format: yaml
  - name: p2
    type: http
    url: %s
    behavior: classical
    format: text
routes:
  - provider: p1
    outbound: proxy
    kind: domain
  - provider: p2
    outbound: proxy
    kind: domain
`, p1URL, p2URL)
			if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
				t.Fatalf("WriteFile(manifest) error = %v", err)
			}

			calls := make(map[string]int)
			client := &http.Client{Transport: runnerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls[req.URL.String()]++
				switch req.URL.String() {
				case p1URL:
					if calls[p1URL] == 1 {
						return runnerResponse(req, "payload:\n  - p1-old.example\n"), nil
					}
					return runnerResponse(req, "payload:\n  - p1-new.example\n"), nil
				case p2URL:
					if calls[p2URL] == 1 {
						return runnerResponse(req, "DOMAIN-SUFFIX,p2-old.example\n"), nil
					}
					return runnerResponse(req, tc.badBody), nil
				default:
					return nil, fmt.Errorf("unexpected provider URL %q", req.URL.String())
				}
			})}
			outputPath := filepath.Join(dir, "routes.dae")
			options := SyncOptions{
				ManifestPath: manifestPath,
				CacheDir:     filepath.Join(dir, "cache"),
				RoutesOutput: outputPath,
				Client:       client,
				AllowPrivate: true,
			}
			if _, err := RunSync(context.Background(), options); err != nil {
				t.Fatalf("initial RunSync() error = %v", err)
			}
			oldRoutes, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("ReadFile(initial routes) error = %v", err)
			}
			wantOld := "domain(suffix: 'p1-old.example') -> proxy\ndomain(suffix: 'p2-old.example') -> proxy\n"
			if string(oldRoutes) != wantOld {
				t.Fatalf("initial routes = %q, want %q", oldRoutes, wantOld)
			}

			if _, err := RunSync(context.Background(), options); err == nil {
				t.Fatalf("RunSync() error = nil for %s provider update", tc.badCheck)
			}
			currentRoutes, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("ReadFile(routes after failed update) error = %v", err)
			}
			if string(currentRoutes) != string(oldRoutes) {
				t.Fatalf("routes after %s provider update = %q, want last-good output %q", tc.badCheck, currentRoutes, oldRoutes)
			}
		})
	}
}

func TestPublishGenerationRejectsCandidatesFailingDAEConfigValidation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated")
	validRoutes := []byte("domain(suffix: 'example.com') -> proxy\n")
	validGroups := []byte("group {\n    proxy {\n        filter: name('hk-1')\n        policy: fixed(0)\n    }\n}\n")
	if err := publishGeneration(root, validRoutes, validGroups); err != nil {
		t.Fatalf("initial publishGeneration() error = %v", err)
	}
	assertDAEConfigRoundTrip(t, validRoutes, validGroups)
	oldTarget, oldRoutes, oldGroups := readCurrentGeneration(t, root)

	invalidCandidates := []struct {
		name   string
		routes []byte
		groups []byte
	}{
		{
			name:   "invalid routes",
			routes: []byte("domain(suffix: 'example.com') => proxy\n"),
			groups: validGroups,
		},
		{
			name:   "invalid groups",
			routes: validRoutes,
			groups: []byte("group {\n    proxy {\n        filter: name('hk-1')\n        policy: fixed(0)\n    \n}\n"),
		},
	}
	for _, candidate := range invalidCandidates {
		t.Run(candidate.name, func(t *testing.T) {
			assertDAEConfigRejects(t, candidate.routes, candidate.groups)
			if err := publishGeneration(root, candidate.routes, candidate.groups); err == nil {
				t.Fatal("publishGeneration() error = nil for invalid DAE candidate")
			}
			newTarget, newRoutes, newGroups := readCurrentGeneration(t, root)
			if newTarget != oldTarget || string(newRoutes) != string(oldRoutes) || string(newGroups) != string(oldGroups) {
				t.Fatalf("current changed after invalid candidate: target=%q routes=%q groups=%q; want target=%q routes=%q groups=%q", newTarget, newRoutes, newGroups, oldTarget, oldRoutes, oldGroups)
			}
		})
	}
}

func TestRunSyncRejectsGenerationRootWithExternalGenerationsSymlink(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "generated")
	external := filepath.Join(dir, "external-generations")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("MkdirAll(root) error = %v", err)
	}
	if err := os.MkdirAll(external, 0o750); err != nil {
		t.Fatalf("MkdirAll(external) error = %v", err)
	}
	if err := os.Symlink(external, filepath.Join(root, "generations")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := `providers:
  - name: p
    type: inline
    behavior: domain
    format: yaml
    data: "payload: [example.com]"
routes:
  - provider: p
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	groups := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1]
`
	if err := os.WriteFile(groupsPath, []byte(groups), 0o600); err != nil {
		t.Fatalf("WriteFile(groups) error = %v", err)
	}

	_, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   root,
	})
	if err == nil {
		t.Fatal("RunSync() error = nil when generations is a symlink outside generation root")
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !os.IsNotExist(err) {
		t.Fatalf("current = %v, want no current symlink", err)
	}
	entries, err := os.ReadDir(external)
	if err != nil {
		t.Fatalf("ReadDir(external) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("external generations entries = %#v, want none", entries)
	}
}

// The stable retention contract is two directories: current plus one immediately
// previous generation, which preserves one rollback point without unbounded growth.
func TestRunSyncRetainsLatestTwoGenerations(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationRoot := filepath.Join(dir, "generated")
	groups := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1]
`
	if err := os.WriteFile(groupsPath, []byte(groups), 0o600); err != nil {
		t.Fatalf("WriteFile(groups) error = %v", err)
	}
	for i, domain := range []string{"one.example", "two.example", "three.example"} {
		manifest := fmt.Sprintf(`providers:
  - name: p
    type: inline
    behavior: domain
    format: yaml
    data: "payload: [%s]"
routes:
  - provider: p
    outbound: proxy
    kind: domain
`, domain)
		if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
			t.Fatalf("WriteFile(manifest %d) error = %v", i, err)
		}
		if _, err := RunSync(context.Background(), SyncOptions{
			ManifestPath:    manifestPath,
			GroupsInputPath: groupsPath,
			GenerationDir:   generationRoot,
		}); err != nil {
			t.Fatalf("RunSync(%d) error = %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(generationRoot, "generations"))
	if err != nil {
		t.Fatalf("ReadDir(generations) error = %v", err)
	}
	directories := 0
	for _, entry := range entries {
		if entry.IsDir() {
			directories++
		}
	}
	if directories != 2 {
		t.Fatalf("generation directory count = %d, want current plus one previous generation", directories)
	}
}

func TestRunSyncDoesNotUseProviderCacheFromRunWithFailedGroupsPublish(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	providerURL := "https://provider.test/rules"
	manifest := fmt.Sprintf(`providers:
  - name: p
    type: http
    url: %s
    behavior: domain
    format: yaml
routes:
  - provider: p
    outbound: proxy
    kind: domain
`, providerURL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	validGroups := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1]
`
	if err := os.WriteFile(groupsPath, []byte(validGroups), 0o600); err != nil {
		t.Fatalf("WriteFile(valid groups) error = %v", err)
	}

	call := 0
	client := &http.Client{Transport: runnerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		call++
		switch call {
		case 1:
			return runnerResponse(req, "payload:\n  - old.example\n"), nil
		case 2:
			return runnerResponse(req, "payload:\n  - new.example\n"), nil
		default:
			return nil, fmt.Errorf("provider unavailable after failed groups publish")
		}
	})}
	options := SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		RoutesOutput:    filepath.Join(dir, "routes.dae"),
		GroupsInputPath: groupsPath,
		GroupsOutput:    filepath.Join(dir, "groups.dae"),
		Client:          client,
		AllowPrivate:    true,
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	oldRoutes, err := os.ReadFile(options.RoutesOutput)
	if err != nil {
		t.Fatalf("ReadFile(initial routes) error = %v", err)
	}

	if err := os.WriteFile(groupsPath, []byte(`proxies: []
proxy-groups:
  - name: Proxy
    type: select
    proxies: [missing]
`), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid groups) error = %v", err)
	}
	if _, err := RunSync(context.Background(), options); err == nil {
		t.Fatal("RunSync() error = nil when groups conversion fails")
	}
	failedRoutes, err := os.ReadFile(options.RoutesOutput)
	if err != nil {
		t.Fatalf("ReadFile(routes after failed groups publish) error = %v", err)
	}
	if string(failedRoutes) != string(oldRoutes) {
		t.Fatalf("routes changed after failed groups publish: %q, want %q", failedRoutes, oldRoutes)
	}

	if err := os.WriteFile(groupsPath, []byte(validGroups), 0o600); err != nil {
		t.Fatalf("restore valid groups error = %v", err)
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("RunSync() after provider failure error = %v", err)
	}
	recoveredRoutes, err := os.ReadFile(options.RoutesOutput)
	if err != nil {
		t.Fatalf("ReadFile(routes after recovery) error = %v", err)
	}
	if string(recoveredRoutes) != string(oldRoutes) {
		t.Fatalf("routes after recovery used an unapplied provider snapshot: %q, want %q", recoveredRoutes, oldRoutes)
	}
}

func TestRunSyncFetchesProviderAndWritesRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
	}))
	defer server.Close()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := fmt.Sprintf("providers:\n  - name: example\n    type: http\n    url: %s\n    behavior: domain\n    format: yaml\nroutes:\n  - provider: example\n    outbound: proxy\n    kind: domain\n", server.URL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	outputPath := filepath.Join(dir, "generated", "routes.dae")

	report, err := RunSync(context.Background(), SyncOptions{
		ManifestPath: manifestPath,
		CacheDir:     filepath.Join(dir, "cache"),
		RoutesOutput: outputPath,
		Client:       http.DefaultClient,
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(body) != "domain(suffix: 'example.com') -> proxy\n" {
		t.Fatalf("routes = %q", body)
	}
	if report.Providers[0].Updated != true || report.Routes.Generated != 1 {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunSyncWritesFlatGroupsAndReportsUnsupportedMembers(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	if err := os.WriteFile(manifestPath, []byte("providers: []\nroutes: []\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	mihomoPath := filepath.Join(dir, "mihomo.yaml")
	mihomo := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1, DIRECT]
`
	if err := os.WriteFile(mihomoPath, []byte(mihomo), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	groupsPath := filepath.Join(dir, "generated", "groups.dae")

	report, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: mihomoPath,
		GroupsOutput:    groupsPath,
	})
	if err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	body, err := os.ReadFile(groupsPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(body), "filter: name('hk-1')") {
		t.Fatalf("groups = %q", body)
	}
	if len(report.Groups.Unsupported) != 1 {
		t.Fatalf("groups report = %#v", report.Groups)
	}
}

func TestRunSyncKeepsLastGoodCacheWhenNewProviderBodyCannotBeParsed(t *testing.T) {
	valid := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if valid {
			_, _ = fmt.Fprint(w, "payload:\n  - good.example\n")
			return
		}
		_, _ = fmt.Fprint(w, "payload: [this is not valid yaml")
	}))
	defer server.Close()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := fmt.Sprintf("providers:\n  - name: p\n    type: http\n    url: %s\n    behavior: domain\n    format: yaml\nroutes:\n  - provider: p\n    outbound: proxy\n    kind: domain\n", server.URL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	outputPath := filepath.Join(dir, "routes.dae")
	options := SyncOptions{ManifestPath: manifestPath, CacheDir: filepath.Join(dir, "cache"), RoutesOutput: outputPath, Client: http.DefaultClient, AllowPrivate: true}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	valid = false
	report, err := RunSync(context.Background(), options)
	if err != nil {
		t.Fatalf("stale-cache RunSync() error = %v", err)
	}
	if report.Providers[0].Warning == "" || !report.Providers[0].UsedCache {
		t.Fatalf("report = %#v, want stale-cache warning", report)
	}
	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(body) != "domain(suffix: 'good.example') -> proxy\n" {
		t.Fatalf("routes after bad update = %q", body)
	}
}

func TestRunSyncGenerationIgnoresStandaloneProviderCacheBlockerAndPublishesCompleteState(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	cacheDir := filepath.Join(dir, "cache")
	generationDir := filepath.Join(dir, "generated")
	p1URL := "https://provider-one.test/rules"
	p2URL := "https://provider-two.test/rules"
	manifest := fmt.Sprintf(`providers:
  - name: p1
    type: http
    url: %s
    behavior: domain
    format: yaml
  - name: p2
    type: http
    url: %s
    behavior: domain
    format: yaml
routes:
  - provider: p1
    outbound: proxy
    kind: domain
  - provider: p2
    outbound: direct
    kind: domain
`, p1URL, p2URL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	groups := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1]
`
	if err := os.WriteFile(groupsPath, []byte(groups), 0o600); err != nil {
		t.Fatalf("WriteFile(groups) error = %v", err)
	}
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(cache) error = %v", err)
	}
	const cacheBlockerBody = "cache path must remain a file"
	cacheBlocker := filepath.Join(cacheDir, "p2")
	if err := os.WriteFile(cacheBlocker, []byte(cacheBlockerBody), 0o600); err != nil {
		t.Fatalf("WriteFile(p2 cache blocker) error = %v", err)
	}

	calls := make(map[string]int)
	client := &http.Client{Transport: runnerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls[req.URL.String()]++
		bodies := map[string][]string{
			p1URL: {"payload: [p1-old.example]\n", "payload: [p1-new.example]\n"},
			p2URL: {"payload: [p2-old.example]\n", "payload: [p2-new.example]\n"},
		}
		bodySet, ok := bodies[req.URL.String()]
		if !ok {
			return nil, fmt.Errorf("unexpected provider URL %q", req.URL.String())
		}
		call := calls[req.URL.String()]
		if call > len(bodySet) {
			call = len(bodySet)
		}
		return runnerResponse(req, bodySet[call-1]), nil
	})}
	options := SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        cacheDir,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
		Client:          client,
		AllowPrivate:    true,
	}
	type providerExpectation struct {
		name      string
		body      string
		sourceURL string
	}
	readGeneration := func(wantRoutes string, providers []providerExpectation) (string, string, []byte, []byte, map[string]any) {
		t.Helper()
		target, routes, groups := readCurrentGeneration(t, generationDir)
		currentPath := filepath.Join(generationDir, "current")
		currentInfo, err := os.Lstat(currentPath)
		if err != nil {
			t.Fatalf("Lstat(current) error = %v", err)
		}
		if currentInfo.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("current mode = %s, want symlink", currentInfo.Mode())
		}
		if target == "" || filepath.IsAbs(target) || filepath.Clean(target) != target || target != filepath.Join("generations", filepath.Base(target)) {
			t.Fatalf("current target = %q, want canonical relative generations/<id> target", target)
		}
		resolvedCurrent, err := filepath.EvalSymlinks(currentPath)
		if err != nil {
			t.Fatalf("EvalSymlinks(current) error = %v", err)
		}
		if filepath.Base(resolvedCurrent) != filepath.Base(target) {
			t.Fatalf("resolved current = %q, want target %q", resolvedCurrent, target)
		}
		if string(routes) != wantRoutes {
			t.Fatalf("generation routes = %q, want exact routes from provider snapshots %q", routes, wantRoutes)
		}

		generationMetadataBody, err := os.ReadFile(filepath.Join(resolvedCurrent, "metadata.json"))
		if err != nil {
			t.Fatalf("ReadFile(generation metadata) error = %v", err)
		}
		var generationMetadata map[string]any
		if err := json.Unmarshal(generationMetadataBody, &generationMetadata); err != nil {
			t.Fatalf("json.Unmarshal(generation metadata) error = %v", err)
		}
		if generationMetadata["generation"] != filepath.Base(target) {
			t.Fatalf("generation metadata generation = %#v, want current target %q", generationMetadata["generation"], filepath.Base(target))
		}
		if generationMetadata["routes_sha256"] != digest(routes) {
			t.Fatalf("generation metadata routes_sha256 = %#v, want %q", generationMetadata["routes_sha256"], digest(routes))
		}
		if generationMetadata["groups_sha256"] != digest(groups) {
			t.Fatalf("generation metadata groups_sha256 = %#v, want %q", generationMetadata["groups_sha256"], digest(groups))
		}
		generationProviders, ok := generationMetadata["providers"].(map[string]any)
		if !ok || len(generationProviders) != len(providers) {
			t.Fatalf("generation metadata providers = %#v, want %d provider bindings", generationMetadata["providers"], len(providers))
		}
		for _, provider := range providers {
			providerDir := filepath.Join(resolvedCurrent, "providers", provider.name)
			body, err := os.ReadFile(filepath.Join(providerDir, "body"))
			if err != nil {
				t.Fatalf("ReadFile(%s generation body) error = %v", provider.name, err)
			}
			if string(body) != provider.body {
				t.Fatalf("%s generation body = %q, want exact fetched body %q", provider.name, body, provider.body)
			}
			providerMetadataBody, err := os.ReadFile(filepath.Join(providerDir, "metadata.json"))
			if err != nil {
				t.Fatalf("ReadFile(%s generation metadata) error = %v", provider.name, err)
			}
			var providerMetadata map[string]any
			if err := json.Unmarshal(providerMetadataBody, &providerMetadata); err != nil {
				t.Fatalf("json.Unmarshal(%s generation metadata) error = %v", provider.name, err)
			}
			if providerMetadata["sha256"] != digest(body) {
				t.Fatalf("%s provider metadata sha256 = %#v, want %q", provider.name, providerMetadata["sha256"], digest(body))
			}
			wantSourceKey := digest([]byte(provider.sourceURL))
			if providerMetadata["source_key"] != wantSourceKey {
				t.Fatalf("%s provider metadata source_key = %#v, want %q", provider.name, providerMetadata["source_key"], wantSourceKey)
			}
			binding, ok := generationProviders[provider.name].(map[string]any)
			if !ok {
				t.Fatalf("generation metadata providers[%q] = %#v, want provider binding", provider.name, generationProviders[provider.name])
			}
			if binding["sha256"] != providerMetadata["sha256"] || binding["source_key"] != providerMetadata["source_key"] || binding["metadata_sha256"] != digest(providerMetadataBody) {
				t.Fatalf("generation metadata providers[%q] = %#v, want binding for provider metadata", provider.name, binding)
			}
		}
		return target, resolvedCurrent, routes, groups, generationMetadata
	}
	assertNoStandaloneProviderCurrent := func() {
		t.Helper()
		for _, name := range []string{"p1", "p2"} {
			currentPath := filepath.Join(cacheDir, name, "current")
			if _, err := os.Lstat(currentPath); err == nil {
				t.Fatalf("standalone provider current %q was created in generation mode", currentPath)
			} else if !os.IsNotExist(err) && !errors.Is(err, unix.ENOTDIR) {
				t.Fatalf("Lstat(%s provider current) error = %v, want absent", name, err)
			}
		}
		body, err := os.ReadFile(cacheBlocker)
		if err != nil {
			t.Fatalf("ReadFile(p2 cache blocker) error = %v", err)
		}
		if string(body) != cacheBlockerBody {
			t.Fatalf("p2 cache blocker changed to %q, want %q", body, cacheBlockerBody)
		}
		info, err := os.Stat(cacheBlocker)
		if err != nil {
			t.Fatalf("Stat(p2 cache blocker) error = %v", err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("p2 cache blocker mode = %s, want regular file", info.Mode())
		}
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	oldProviders := []providerExpectation{
		{name: "p1", body: "payload: [p1-old.example]\n", sourceURL: p1URL},
		{name: "p2", body: "payload: [p2-old.example]\n", sourceURL: p2URL},
	}
	oldTarget, oldGenerationDir, oldRoutes, oldGroups, oldMetadata := readGeneration(
		"domain(suffix: 'p1-old.example') -> proxy\ndomain(suffix: 'p2-old.example') -> direct\n",
		oldProviders,
	)
	assertNoStandaloneProviderCurrent()

	newProviders := []providerExpectation{
		{name: "p1", body: "payload: [p1-new.example]\n", sourceURL: p1URL},
		{name: "p2", body: "payload: [p2-new.example]\n", sourceURL: p2URL},
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("second RunSync() error = %v; generation mode must ignore standalone cache blocker", err)
	}
	newTarget, newGenerationDir, newRoutes, newGroups, newMetadata := readGeneration(
		"domain(suffix: 'p1-new.example') -> proxy\ndomain(suffix: 'p2-new.example') -> direct\n",
		newProviders,
	)
	assertNoStandaloneProviderCurrent()
	if newTarget == oldTarget || newGenerationDir == oldGenerationDir {
		t.Fatalf("generation did not advance with standalone cache blocker: old target/dir=%q/%q new=%q/%q", oldTarget, oldGenerationDir, newTarget, newGenerationDir)
	}
	if newMetadata["previous_generation"] != filepath.Base(oldTarget) {
		t.Fatalf("new generation previous_generation = %#v, want %q", newMetadata["previous_generation"], filepath.Base(oldTarget))
	}
	if string(oldRoutes) == string(newRoutes) || string(oldGroups) != string(newGroups) || oldMetadata["generation"] == newMetadata["generation"] {
		t.Fatalf("generation contents or metadata did not advance coherently: old=%#v/%q/%q new=%#v/%q/%q", oldMetadata, oldRoutes, oldGroups, newMetadata, newRoutes, newGroups)
	}
	if _, err := os.Stat(filepath.Join(oldGenerationDir, "routes.dae")); err != nil {
		t.Fatalf("previous generation routes disappeared: %v", err)
	}
	if _, err := os.Stat(filepath.Join(oldGenerationDir, "groups.dae")); err != nil {
		t.Fatalf("previous generation groups disappeared: %v", err)
	}
	for _, provider := range oldProviders {
		body, err := os.ReadFile(filepath.Join(oldGenerationDir, "providers", provider.name, "body"))
		if err != nil {
			t.Fatalf("ReadFile(previous %s body) error = %v", provider.name, err)
		}
		if string(body) != provider.body {
			t.Fatalf("previous %s body changed: got %q, want %q", provider.name, body, provider.body)
		}
	}
	for url, count := range calls {
		if count != 2 {
			t.Fatalf("provider %s request count = %d, want two deterministic generation fetches", url, count)
		}
	}
}

func TestGenerationFallsBackPerProviderForEmptyOrAllSkippedUpdate(t *testing.T) {
	tests := []struct {
		name       string
		p2Behavior string
		p2Format   string
		p2OldBody  string
		p2BadBody  string
	}{
		{
			name:       "empty",
			p2Behavior: "domain",
			p2Format:   "yaml",
			p2OldBody:  "payload: [p2-old.example]\n",
			p2BadBody:  "payload: []\n",
		},
		{
			name:       "all-skipped",
			p2Behavior: "classical",
			p2Format:   "text",
			p2OldBody:  "DOMAIN-SUFFIX,p2-old.example\n",
			p2BadBody:  "PROCESS-NAME,ignored\nIP-ASN,64512\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			manifestPath := filepath.Join(dir, "providers.yaml")
			groupsPath := filepath.Join(dir, "mihomo.yaml")
			generationDir := filepath.Join(dir, "generated")
			p1URL := "https://provider-one.test/rules"
			p2URL := "https://provider-two.test/rules"
			manifest := fmt.Sprintf(`providers:
  - name: p1
    type: http
    url: %s
    behavior: domain
    format: yaml
  - name: p2
    type: http
    url: %s
    behavior: %s
    format: %s
routes:
  - provider: p1
    outbound: proxy
    kind: domain
  - provider: p2
    outbound: direct
    kind: domain
`, p1URL, p2URL, tc.p2Behavior, tc.p2Format)
			if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
				t.Fatalf("WriteFile(manifest) error = %v", err)
			}
			writeGenerationGroupsInput(t, groupsPath)

			calls := make(map[string]int)
			client := &http.Client{Transport: runnerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls[req.URL.String()]++
				switch req.URL.String() {
				case p1URL:
					if calls[p1URL] == 1 {
						return runnerResponse(req, "payload: [p1-old.example]\n"), nil
					}
					return runnerResponse(req, "payload: [p1-new.example]\n"), nil
				case p2URL:
					if calls[p2URL] == 1 {
						return runnerResponse(req, tc.p2OldBody), nil
					}
					return runnerResponse(req, tc.p2BadBody), nil
				default:
					return nil, fmt.Errorf("unexpected provider URL %q", req.URL.String())
				}
			})}
			options := SyncOptions{
				ManifestPath:    manifestPath,
				CacheDir:        filepath.Join(dir, "cache"),
				GroupsInputPath: groupsPath,
				GenerationDir:   generationDir,
				Client:          client,
				AllowPrivate:    true,
			}

			if _, err := RunSync(context.Background(), options); err != nil {
				t.Fatalf("initial RunSync() error = %v", err)
			}
			oldTarget, _, _ := readCurrentGeneration(t, generationDir)

			report, err := RunSync(context.Background(), options)
			if err != nil {
				t.Fatalf("second RunSync() error = %v; generation mode should pin p2's last-good snapshot", err)
			}
			newTarget, routes, _ := readCurrentGeneration(t, generationDir)
			if newTarget == oldTarget {
				t.Fatalf("current generation target = %q, want a new generation after p1 update", newTarget)
			}
			wantRoutes := "domain(suffix: 'p1-new.example') -> proxy\ndomain(suffix: 'p2-old.example') -> direct\n"
			if string(routes) != wantRoutes {
				t.Fatalf("current generation routes = %q, want %q", routes, wantRoutes)
			}

			resolvedCurrent, err := filepath.EvalSymlinks(filepath.Join(generationDir, "current"))
			if err != nil {
				t.Fatalf("EvalSymlinks(current) error = %v", err)
			}
			p2Body, err := os.ReadFile(filepath.Join(resolvedCurrent, "providers", "p2", "body"))
			if err != nil {
				t.Fatalf("ReadFile(current p2 body) error = %v", err)
			}
			if string(p2Body) != tc.p2OldBody {
				t.Fatalf("current p2 generation body = %q, want pinned last-good body %q", p2Body, tc.p2OldBody)
			}

			var p2Report ProviderSyncReport
			foundP2 := false
			for _, providerReport := range report.Providers {
				if providerReport.Name == "p2" {
					p2Report = providerReport
					foundP2 = true
					break
				}
			}
			if !foundP2 {
				t.Fatalf("provider report = %#v, want p2 report", report.Providers)
			}
			if !p2Report.UsedCache || p2Report.Updated {
				t.Fatalf("p2 report = %#v, want UsedCache=true and Updated=false after semantic fallback", p2Report)
			}
			if strings.TrimSpace(p2Report.Warning) == "" {
				t.Fatalf("p2 report = %#v, want a semantic fallback warning", p2Report)
			}
		})
	}
}

func TestRunSyncRetainsOnlyCurrentAndOneOldHTTPProviderCacheVersion(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	cacheDir := filepath.Join(dir, "cache")
	outputPath := filepath.Join(dir, "routes.dae")
	providerURL := "https://provider.test/rules"
	manifest := fmt.Sprintf(`providers:
  - name: p
    type: http
    url: %s
    behavior: domain
    format: yaml
routes:
  - provider: p
    outbound: proxy
    kind: domain
`, providerURL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	var call int
	client := &http.Client{Transport: runnerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		call++
		return runnerResponse(req, fmt.Sprintf("payload: [version-%d.example]", call)), nil
	})}
	options := SyncOptions{
		ManifestPath: manifestPath,
		CacheDir:     cacheDir,
		RoutesOutput: outputPath,
		Client:       client,
		AllowPrivate: true,
	}
	for i := 0; i < 3; i++ {
		if _, err := RunSync(context.Background(), options); err != nil {
			t.Fatalf("RunSync(%d) error = %v", i, err)
		}
	}

	versionsRoot := filepath.Join(cacheDir, "p", "versions")
	entries, err := os.ReadDir(versionsRoot)
	if err != nil {
		t.Fatalf("ReadDir(cache versions) error = %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("temporary cache version remains: %s", entry.Name())
		}
		if !entry.IsDir() {
			t.Fatalf("cache version %q is not a directory", entry.Name())
		}
		for _, name := range []string{"body", "metadata.json"} {
			if _, err := os.Stat(filepath.Join(versionsRoot, entry.Name(), name)); err != nil {
				t.Fatalf("cache version %q missing %s: %v", entry.Name(), name, err)
			}
		}
	}
	if len(entries) != 2 {
		t.Fatalf("effective cache version count = %d, want current plus one old version", len(entries))
	}
	currentTarget, err := os.Readlink(filepath.Join(cacheDir, "p", "current"))
	if err != nil {
		t.Fatalf("Readlink(cache current) error = %v", err)
	}
	if filepath.Dir(currentTarget) != "versions" {
		t.Fatalf("cache current target = %q, want versions/<id>", currentTarget)
	}
}

func TestRunSyncDoesNotRetainInvalidGenerationResidue(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	invalidID := "generation-residual-invalid"
	invalidDir := filepath.Join(generationDir, "generations", invalidID)
	if err := os.MkdirAll(invalidDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(invalid generation) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(invalidDir, "metadata.json"), []byte(`{"generation":"`+invalidID+`","routes_sha256":"invalid","groups_sha256":"invalid"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid metadata) error = %v", err)
	}
	manifest := `providers:
  - name: p
    type: inline
    behavior: domain
    format: yaml
    data: "payload: [example.com]"
routes:
  - provider: p
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	groups := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1]
`
	if err := os.WriteFile(groupsPath, []byte(groups), 0o600); err != nil {
		t.Fatalf("WriteFile(groups) error = %v", err)
	}
	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	if _, err := os.Lstat(invalidDir); !os.IsNotExist(err) {
		t.Fatalf("invalid generation residue = %v, want cleaned", err)
	}

	entries, err := os.ReadDir(filepath.Join(generationDir, "generations"))
	if err != nil {
		t.Fatalf("ReadDir(generations) error = %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			t.Fatalf("retained generation %q is not a directory", entry.Name())
		}
		generationPath := filepath.Join(generationDir, "generations", entry.Name())
		routes, err := os.ReadFile(filepath.Join(generationPath, "routes.dae"))
		if err != nil {
			t.Fatalf("ReadFile(%s routes) error = %v", entry.Name(), err)
		}
		groupsBody, err := os.ReadFile(filepath.Join(generationPath, "groups.dae"))
		if err != nil {
			t.Fatalf("ReadFile(%s groups) error = %v", entry.Name(), err)
		}
		metadataBody, err := os.ReadFile(filepath.Join(generationPath, "metadata.json"))
		if err != nil {
			t.Fatalf("ReadFile(%s metadata) error = %v", entry.Name(), err)
		}
		var metadata generationMetadata
		if err := json.Unmarshal(metadataBody, &metadata); err != nil {
			t.Fatalf("Unmarshal(%s metadata) error = %v", entry.Name(), err)
		}
		if metadata.Generation != entry.Name() || metadata.RoutesSHA256 != digest(routes) || metadata.GroupsSHA256 != digest(groupsBody) {
			t.Fatalf("retained generation %q has invalid metadata: %#v", entry.Name(), metadata)
		}
	}
}

func TestRunSyncRejectsFileProviderSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("payload:\n  - outside.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	link := filepath.Join(dir, "rules.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := `providers:
  - name: p
    type: file
    path: rules.yaml
    behavior: domain
    format: yaml
routes:
  - provider: p
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := RunSync(context.Background(), SyncOptions{ManifestPath: manifestPath, RoutesOutput: filepath.Join(dir, "routes.dae")}); err == nil {
		t.Fatal("RunSync() error = nil for symlink escape")
	}
}

func TestRunSyncDoesNotOverwriteRoutesWithEmptyProviderResult(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := `providers:
  - name: empty
    type: inline
    behavior: domain
    format: yaml
    data: "payload: []"
routes:
  - provider: empty
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	outputPath := filepath.Join(dir, "routes.dae")
	if err := os.WriteFile(outputPath, []byte("domain(suffix: 'old.example') -> proxy\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := RunSync(context.Background(), SyncOptions{ManifestPath: manifestPath, RoutesOutput: outputPath})
	if err == nil {
		t.Fatal("RunSync() error = nil for empty route result")
	}
	body, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if string(body) != "domain(suffix: 'old.example') -> proxy\n" {
		t.Fatalf("routes after empty result = %q", body)
	}
}

func TestRunSyncDoesNotOverwriteGroupsWithEmptyConversion(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := `providers:
  - name: p
    type: inline
    behavior: domain
    format: yaml
    data: "payload: [example.com]"
routes:
  - provider: p
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	groupsInput := filepath.Join(dir, "mihomo.yaml")
	if err := os.WriteFile(groupsInput, []byte("proxies: []\nproxy-groups:\n  - name: nested\n    type: select\n    proxies: [DIRECT]\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	groupsOutput := filepath.Join(dir, "groups.dae")
	old := "group {\n    old {\n    }\n}\n"
	if err := os.WriteFile(groupsOutput, []byte(old), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	routesOutput := filepath.Join(dir, "routes.dae")
	oldRoutes := "domain(suffix: 'old.example') -> old\n"
	if err := os.WriteFile(routesOutput, []byte(oldRoutes), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := RunSync(context.Background(), SyncOptions{ManifestPath: manifestPath, RoutesOutput: routesOutput, GroupsInputPath: groupsInput, GroupsOutput: groupsOutput})
	if err == nil {
		t.Fatal("RunSync() error = nil for empty group conversion")
	}
	body, readErr := os.ReadFile(groupsOutput)
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if string(body) != old {
		t.Fatalf("groups after empty conversion = %q", body)
	}
	routeBody, readErr := os.ReadFile(routesOutput)
	if readErr != nil {
		t.Fatalf("ReadFile(routes) error = %v", readErr)
	}
	if string(routeBody) != oldRoutes {
		t.Fatalf("routes after failed group conversion = %q", routeBody)
	}
}

func TestRunSyncDoesNotPublishGroupsWhenRoutesWriteFails(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := `providers:
  - name: p
    type: inline
    behavior: domain
    format: yaml
    data: "payload: [example.com]"
routes:
  - provider: p
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	groupsInput := filepath.Join(dir, "mihomo.yaml")
	mihomo := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1]
`
	if err := os.WriteFile(groupsInput, []byte(mihomo), 0o600); err != nil {
		t.Fatalf("WriteFile(groups input) error = %v", err)
	}
	routesOutput := filepath.Join(dir, "generated", "routes.dae")
	groupsOutput := filepath.Join(dir, "generated", "groups.dae")
	options := SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		RoutesOutput:    routesOutput,
		GroupsInputPath: groupsInput,
		GroupsOutput:    groupsOutput,
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	oldGroups, err := os.ReadFile(groupsOutput)
	if err != nil {
		t.Fatalf("ReadFile(initial groups) error = %v", err)
	}
	if !strings.Contains(string(oldGroups), "filter: name('hk-1')") {
		t.Fatalf("initial groups = %q, want hk-1 group member", oldGroups)
	}
	secondMihomo := strings.ReplaceAll(mihomo, "hk-1", "hk-2")
	if err := os.WriteFile(groupsInput, []byte(secondMihomo), 0o600); err != nil {
		t.Fatalf("WriteFile(second groups input) error = %v", err)
	}
	if err := os.Remove(routesOutput); err != nil {
		t.Fatalf("Remove(routes output) error = %v", err)
	}
	if err := os.Mkdir(routesOutput, 0o750); err != nil {
		t.Fatalf("Mkdir(routes output directory) error = %v", err)
	}

	if _, err := RunSync(context.Background(), options); err == nil {
		t.Fatal("second RunSync() error = nil when routes output is a directory")
	}
	newGroups, err := os.ReadFile(groupsOutput)
	if err != nil {
		t.Fatalf("ReadFile(groups after routes failure) error = %v", err)
	}
	if string(newGroups) != string(oldGroups) {
		t.Fatalf("groups changed after routes write failure: old=%q new=%q", oldGroups, newGroups)
	}
}

func TestRunSyncDoesNotPublishRoutesWhenGroupsOutputPreflightFails(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	manifest := `providers:
  - name: p
    type: inline
    behavior: domain
    format: yaml
    data: "payload: [example.com]"
routes:
  - provider: p
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	groupsInput := filepath.Join(dir, "mihomo.yaml")
	validGroups := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1]
`
	if err := os.WriteFile(groupsInput, []byte(validGroups), 0o600); err != nil {
		t.Fatalf("WriteFile(groups input) error = %v", err)
	}
	routesOutput := filepath.Join(dir, "routes.dae")
	groupsOutput := filepath.Join(dir, "groups.dae")
	options := SyncOptions{
		ManifestPath:    manifestPath,
		RoutesOutput:    routesOutput,
		GroupsInputPath: groupsInput,
		GroupsOutput:    groupsOutput,
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	oldRoutes, err := os.ReadFile(routesOutput)
	if err != nil {
		t.Fatalf("ReadFile(initial routes) error = %v", err)
	}
	if err := os.Remove(groupsOutput); err != nil {
		t.Fatalf("Remove(groups output) error = %v", err)
	}
	if err := os.Mkdir(groupsOutput, 0o750); err != nil {
		t.Fatalf("Mkdir(groups output) error = %v", err)
	}

	if _, err := RunSync(context.Background(), options); err == nil {
		t.Fatal("RunSync() error = nil when groups output target is a directory")
	}
	newRoutes, err := os.ReadFile(routesOutput)
	if err != nil {
		t.Fatalf("ReadFile(routes after groups failure) error = %v", err)
	}
	if string(newRoutes) != string(oldRoutes) {
		t.Fatalf("routes changed after groups output failure: old=%q new=%q", oldRoutes, newRoutes)
	}
	if info, statErr := os.Stat(groupsOutput); statErr != nil || !info.IsDir() {
		t.Fatalf("groups target after preflight failure = %#v/%v, want the pre-existing directory", info, statErr)
	}
}

func TestAtomicWriteReplacesFileWithoutTemporarySibling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "output.dae")
	if err := writeAtomic(path, []byte("first")); err != nil {
		t.Fatalf("first writeAtomic() error = %v", err)
	}
	if err := writeAtomic(path, []byte("second")); err != nil {
		t.Fatalf("second writeAtomic() error = %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(body) != "second" {
		t.Fatalf("body = %q", body)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temporary sibling remains: %s", entry.Name())
		}
	}
}

func TestGenerationEmbedsProviderSnapshotsAndBindsMetadata(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	localProviderPath := filepath.Join(dir, "local.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	const remoteURL = "https://provider.test/remote.yaml"
	remoteBody := []byte("payload: [remote.example.com]\n")
	localBody := []byte("payload: [local.example.com]\n")
	if err := os.WriteFile(localProviderPath, localBody, 0o600); err != nil {
		t.Fatalf("WriteFile(local provider) error = %v", err)
	}
	manifest := fmt.Sprintf(`providers:
  - name: remote
    type: http
    url: %s
    behavior: domain
    format: yaml
  - name: local
    type: file
    path: %s
    behavior: domain
    format: yaml
routes:
  - provider: remote
    outbound: proxy
    kind: domain
  - provider: local
    outbound: proxy
    kind: domain
`, remoteURL, filepath.Base(localProviderPath))
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writeGenerationGroupsInput(t, groupsPath)

	client := &http.Client{Transport: runnerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != remoteURL {
			return nil, fmt.Errorf("unexpected provider URL %q", req.URL.String())
		}
		return runnerResponse(req, string(remoteBody)), nil
	})}
	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
		Client:          client,
		AllowPrivate:    true,
	}); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}

	target, routes, groups := readCurrentGeneration(t, generationDir)
	resolvedCurrent, err := filepath.EvalSymlinks(filepath.Join(generationDir, "current"))
	if err != nil {
		t.Fatalf("EvalSymlinks(current) error = %v", err)
	}
	if target == "" || resolvedCurrent == "" {
		t.Fatal("generation/current did not resolve to a generation")
	}
	wantRoutes := "domain(suffix: 'remote.example.com') -> proxy\ndomain(suffix: 'local.example.com') -> proxy\n"
	if string(routes) != wantRoutes {
		t.Fatalf("routes = %q, want routes generated from both generation provider snapshots %q", routes, wantRoutes)
	}
	if len(groups) == 0 {
		t.Fatal("groups output is empty")
	}

	providerMetadata := make(map[string]map[string]any, 2)
	providers := []struct {
		name string
		body []byte
	}{
		{name: "remote", body: remoteBody},
		{name: "local", body: localBody},
	}
	for _, provider := range providers {
		name, wantBody := provider.name, provider.body
		providerDir := filepath.Join(resolvedCurrent, "providers", name)
		body, err := os.ReadFile(filepath.Join(providerDir, "body"))
		if err != nil {
			t.Fatalf("ReadFile(%s body) error = %v", name, err)
		}
		if string(body) != string(wantBody) {
			t.Fatalf("%s snapshot body = %q, want %q", name, body, wantBody)
		}
		metadataBody, err := os.ReadFile(filepath.Join(providerDir, "metadata.json"))
		if err != nil {
			t.Fatalf("ReadFile(%s metadata) error = %v", name, err)
		}
		var metadata map[string]any
		if err := json.Unmarshal(metadataBody, &metadata); err != nil {
			t.Fatalf("json.Unmarshal(%s metadata) error = %v", name, err)
		}
		sha256Value, ok := metadata["sha256"].(string)
		if !ok || sha256Value != digest(body) {
			t.Fatalf("%s metadata sha256 = %#v, want %q", name, metadata["sha256"], digest(body))
		}
		sourceKey, ok := metadata["source_key"].(string)
		if !ok || strings.TrimSpace(sourceKey) == "" {
			t.Fatalf("%s metadata source_key = %#v, want a non-empty source binding", name, metadata["source_key"])
		}
		providerMetadata[name] = metadata
	}

	generationMetadataBody, err := os.ReadFile(filepath.Join(resolvedCurrent, "metadata.json"))
	if err != nil {
		t.Fatalf("ReadFile(generation metadata) error = %v", err)
	}
	var generationMetadata map[string]any
	if err := json.Unmarshal(generationMetadataBody, &generationMetadata); err != nil {
		t.Fatalf("json.Unmarshal(generation metadata) error = %v", err)
	}
	if generationMetadata["routes_sha256"] != digest(routes) {
		t.Fatalf("generation metadata routes_sha256 = %#v, want %q", generationMetadata["routes_sha256"], digest(routes))
	}
	if generationMetadata["groups_sha256"] != digest(groups) {
		t.Fatalf("generation metadata groups_sha256 = %#v, want %q", generationMetadata["groups_sha256"], digest(groups))
	}
	generationProviders, ok := generationMetadata["providers"].(map[string]any)
	if !ok {
		t.Fatalf("generation metadata providers = %#v, want object keyed by provider name", generationMetadata["providers"])
	}
	for name, metadata := range providerMetadata {
		binding, ok := generationProviders[name].(map[string]any)
		if !ok {
			t.Fatalf("generation metadata providers[%q] = %#v, want provider binding", name, generationProviders[name])
		}
		for _, field := range []string{"sha256", "source_key"} {
			if binding[field] != metadata[field] {
				t.Fatalf("generation metadata providers[%q][%q] = %#v, want provider metadata value %#v", name, field, binding[field], metadata[field])
			}
		}
	}
}

func TestGenerationModeDoesNotPublishSeparateProviderCacheCurrent(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	cacheDir := filepath.Join(dir, "cache")
	const providerURL = "https://provider.test/rules"
	manifest := fmt.Sprintf(`providers:
  - name: remote
    type: http
    url: %s
    behavior: domain
    format: yaml
routes:
  - provider: remote
    outbound: proxy
    kind: domain
`, providerURL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writeGenerationGroupsInput(t, groupsPath)
	client := &http.Client{Transport: runnerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return runnerResponse(req, "payload: [generation.example.com]\n"), nil
	})}

	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        cacheDir,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
		Client:          client,
		AllowPrivate:    true,
	}); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	target, routes, _ := readCurrentGeneration(t, generationDir)
	if target == "" || !strings.Contains(string(routes), "generation.example.com") {
		t.Fatalf("generation current target/routes = %q/%q, want authoritative published generation", target, routes)
	}
	providerCurrent := filepath.Join(cacheDir, "remote", "current")
	if _, err := os.Lstat(providerCurrent); !os.IsNotExist(err) {
		t.Fatalf("provider cache current = %v, want no separate cache/current publication", err)
	}
}

func TestRunSyncStrictModeRejectsUnsupportedProviderRule(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	validManifest := `providers:
  - name: mixed
    type: inline
    behavior: classical
    format: text
    data: "DOMAIN-SUFFIX,good.example"
routes:
  - provider: mixed
    outbound: proxy
    kind: domain
`
	strictManifest := `providers:
  - name: mixed
    type: inline
    behavior: classical
    format: text
    data: |
      DOMAIN-SUFFIX,good.example
      PROCESS-NAME,ignored
      IP-ASN,64512
routes:
  - provider: mixed
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(validManifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writeGenerationGroupsInput(t, groupsPath)

	options := SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	oldTarget, oldRoutes, oldGroups := readCurrentGeneration(t, generationDir)
	if err := os.WriteFile(manifestPath, []byte(strictManifest), 0o600); err != nil {
		t.Fatalf("WriteFile(strict manifest) error = %v", err)
	}

	options.Strict = true
	_, err := RunSync(context.Background(), options)
	if err == nil {
		t.Fatal("RunSync() error = nil for strict unsupported provider rule")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unsupported") {
		t.Fatalf("RunSync() error = %v, want unsupported-rule diagnostic", err)
	}
	newTarget, newRoutes, newGroups := readCurrentGeneration(t, generationDir)
	if newTarget != oldTarget || string(newRoutes) != string(oldRoutes) || string(newGroups) != string(oldGroups) {
		t.Fatalf("generation changed after strict rejection: target=%q routes=%q groups=%q; want target=%q routes=%q groups=%q", newTarget, newRoutes, newGroups, oldTarget, oldRoutes, oldGroups)
	}
	entries, err := os.ReadDir(filepath.Join(generationDir, "generations"))
	if err != nil {
		t.Fatalf("ReadDir(generations after strict rejection) error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("generation entries after strict rejection = %#v, want only the prior publication", entries)
	}
}

func TestRunSyncStrictHTTPGenerationFallsBackToPreviousProviderSnapshot(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	calls := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		call := calls[r.URL.Path]
		switch r.URL.Path {
		case "/p1":
			if call == 1 {
				_, _ = fmt.Fprint(w, "payload: [p1-old.example]\n")
				return
			}
			_, _ = fmt.Fprint(w, "payload: [p1-new.example]\n")
		case "/p2":
			if call == 1 {
				_, _ = fmt.Fprint(w, "payload: [p2-old.example]\n")
				return
			}
			_, _ = fmt.Fprint(w, "payload:\n  - p2-new.example\n  - PROCESS-NAME,ignored\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	manifest := fmt.Sprintf(`providers:
  - name: p1
    type: http
    url: %s/p1
    behavior: domain
    format: yaml
  - name: p2
    type: http
    url: %s/p2
    behavior: domain
    format: yaml
routes:
  - provider: p1
    outbound: proxy
    kind: domain
  - provider: p2
    outbound: direct
    kind: domain
`, server.URL, server.URL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writeGenerationGroupsInput(t, groupsPath)
	options := SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
		Client:          server.Client(),
		Strict:          true,
		AllowPrivate:    true,
	}

	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial strict HTTP RunSync() error = %v", err)
	}
	oldTarget, oldRoutes, oldGroups := readCurrentGeneration(t, generationDir)
	if string(oldRoutes) != "domain(suffix: 'p1-old.example') -> proxy\ndomain(suffix: 'p2-old.example') -> direct\n" {
		t.Fatalf("initial strict HTTP routes = %q", oldRoutes)
	}

	report, err := RunSync(context.Background(), options)
	if err != nil {
		t.Fatalf("strict HTTP fallback RunSync() error = %v", err)
	}
	newTarget, newRoutes, newGroups := readCurrentGeneration(t, generationDir)
	if newTarget == oldTarget {
		t.Fatalf("current generation target = %q, want p1 update to publish a new generation", newTarget)
	}
	wantRoutes := "domain(suffix: 'p1-new.example') -> proxy\ndomain(suffix: 'p2-old.example') -> direct\n"
	if string(newRoutes) != wantRoutes {
		t.Fatalf("strict HTTP current routes = %q, want p2's complete old snapshot and p1's new rules %q", newRoutes, wantRoutes)
	}
	if string(newGroups) != string(oldGroups) {
		t.Fatalf("groups changed during strict HTTP provider fallback: got %q, want %q", newGroups, oldGroups)
	}
	currentDir := filepath.Join(generationDir, newTarget)
	p2Body, err := os.ReadFile(filepath.Join(currentDir, "providers", "p2", "body"))
	if err != nil {
		t.Fatalf("ReadFile(current p2 body) error = %v", err)
	}
	if string(p2Body) != "payload: [p2-old.example]\n" {
		t.Fatalf("current p2 body = %q, want old generation snapshot", p2Body)
	}
	var p1Report, p2Report ProviderSyncReport
	for _, providerReport := range report.Providers {
		switch providerReport.Name {
		case "p1":
			p1Report = providerReport
		case "p2":
			p2Report = providerReport
		}
	}
	if !p1Report.Updated || p1Report.UsedCache {
		t.Fatalf("p1 report = %#v, want a fresh update", p1Report)
	}
	if !p2Report.UsedCache || p2Report.Updated || p2Report.Warning == "" {
		t.Fatalf("p2 report = %#v, want strict semantic fallback warning", p2Report)
	}
	metadata, err := readGenerationMetadata(filepath.Join(generationDir, newTarget), filepath.Base(newTarget))
	if err != nil {
		t.Fatalf("read current strict HTTP generation metadata error = %v", err)
	}
	if metadata.PreviousGeneration != filepath.Base(oldTarget) {
		t.Fatalf("strict HTTP current previous_generation = %q, want %q", metadata.PreviousGeneration, filepath.Base(oldTarget))
	}
}

func TestRunSyncDoesNotReinterpretGenerationSnapshotWhenProviderSpecChanges(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			_, _ = fmt.Fprint(w, "[old.example]\n")
			return
		}
		http.Error(w, "network unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	writeManifest := func(behavior, format string) {
		t.Helper()
		manifest := fmt.Sprintf(`providers:
  - name: p
    type: http
    url: %s
    behavior: %s
    format: %s
routes:
  - provider: p
    outbound: proxy
    kind: domain
`, server.URL, behavior, format)
		if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
			t.Fatalf("WriteFile(manifest) error = %v", err)
		}
	}
	writeGenerationGroupsInput(t, groupsPath)
	writeManifest("domain", "yaml")
	options := SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
		Client:          server.Client(),
		AllowPrivate:    true,
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial domain/yaml RunSync() error = %v", err)
	}
	oldTarget, oldRoutes, oldGroups := readCurrentGeneration(t, generationDir)
	if string(oldRoutes) != "domain(suffix: 'old.example') -> proxy\n" {
		t.Fatalf("initial domain/yaml routes = %q", oldRoutes)
	}

	writeManifest("classical", "text")
	if _, err := RunSync(context.Background(), options); err == nil {
		t.Fatal("changed classical/text RunSync() error = nil; old snapshot was reinterpreted under the new provider spec")
	}
	newTarget, newRoutes, newGroups := readCurrentGeneration(t, generationDir)
	if newTarget != oldTarget || string(newRoutes) != string(oldRoutes) || string(newGroups) != string(oldGroups) {
		t.Fatalf("current generation changed after behavior/format mismatch: target=%q routes=%q groups=%q; want target=%q routes=%q groups=%q", newTarget, newRoutes, newGroups, oldTarget, oldRoutes, oldGroups)
	}
}

func TestGenerationBindsDefaultFormatAsYAML(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			_, _ = fmt.Fprint(w, "payload: [default-format.example]\n")
			return
		}
		http.Error(w, "remote unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	writeManifest := func(explicitFormat bool) {
		t.Helper()
		formatLine := ""
		if explicitFormat {
			formatLine = "    format: yaml\n"
		}
		manifest := fmt.Sprintf(`providers:
  - name: p
    type: http
    url: %s
    behavior: domain
%sroutes:
  - provider: p
    outbound: proxy
    kind: domain
`, server.URL, formatLine)
		if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
			t.Fatalf("WriteFile(manifest) error = %v", err)
		}
	}
	writeGenerationGroupsInput(t, groupsPath)
	writeManifest(false)
	options := SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
		Client:          server.Client(),
		AllowPrivate:    true,
	}
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial default-format RunSync() error = %v", err)
	}
	oldTarget, oldRoutes, oldGroups := readCurrentGeneration(t, generationDir)
	if string(oldRoutes) != "domain(suffix: 'default-format.example') -> proxy\n" {
		t.Fatalf("initial default-format routes = %q", oldRoutes)
	}

	resolvedCurrent, err := filepath.EvalSymlinks(filepath.Join(generationDir, "current"))
	if err != nil {
		t.Fatalf("EvalSymlinks(current) error = %v", err)
	}
	providerMetadataBody, err := os.ReadFile(filepath.Join(resolvedCurrent, "providers", "p", "metadata.json"))
	if err != nil {
		t.Fatalf("ReadFile(provider metadata) error = %v", err)
	}
	var providerMetadata map[string]any
	if err := json.Unmarshal(providerMetadataBody, &providerMetadata); err != nil {
		t.Fatalf("json.Unmarshal(provider metadata) error = %v", err)
	}
	if providerMetadata["format"] != "yaml" {
		t.Errorf("provider metadata format = %#v, want yaml", providerMetadata["format"])
	}
	generationMetadataBody, err := os.ReadFile(filepath.Join(resolvedCurrent, "metadata.json"))
	if err != nil {
		t.Fatalf("ReadFile(generation metadata) error = %v", err)
	}
	var generationMetadata map[string]any
	if err := json.Unmarshal(generationMetadataBody, &generationMetadata); err != nil {
		t.Fatalf("json.Unmarshal(generation metadata) error = %v", err)
	}
	generationProviders, ok := generationMetadata["providers"].(map[string]any)
	if !ok {
		t.Fatalf("generation metadata providers = %#v, want provider binding", generationMetadata["providers"])
	}
	binding, ok := generationProviders["p"].(map[string]any)
	if !ok {
		t.Fatalf("generation metadata providers[\"p\"] = %#v, want provider binding", generationProviders["p"])
	}
	if binding["format"] != "yaml" {
		t.Errorf("generation provider binding format = %#v, want yaml", binding["format"])
	}

	writeManifest(true)
	report, err := RunSync(context.Background(), options)
	if err != nil {
		t.Errorf("explicit-yaml fallback RunSync() error = %v, want successful use of the equivalent old snapshot", err)
	} else {
		var providerReport ProviderSyncReport
		for _, candidate := range report.Providers {
			if candidate.Name == "p" {
				providerReport = candidate
				break
			}
		}
		if !providerReport.UsedCache || providerReport.Updated || strings.TrimSpace(providerReport.Warning) == "" {
			t.Errorf("explicit-yaml fallback provider report = %#v, want UsedCache=true, Updated=false, and warning", providerReport)
		}
	}
	newTarget, newRoutes, newGroups := readCurrentGeneration(t, generationDir)
	if newTarget != oldTarget {
		t.Errorf("current generation target after equivalent fallback = %q, want unchanged %q", newTarget, oldTarget)
	}
	if string(newRoutes) != string(oldRoutes) || string(newGroups) != string(oldGroups) {
		t.Errorf("current generation contents changed after equivalent fallback: routes=%q groups=%q; want routes=%q groups=%q", newRoutes, newGroups, oldRoutes, oldGroups)
	}
	if requests != 2 {
		t.Errorf("HTTP requests = %d, want initial fetch plus one failed revalidation", requests)
	}
}

func TestGenerationNormalizesDefaultFormatForNonHTTPProviders(t *testing.T) {
	const providerBody = "payload: [non-http-default-format.example]\n"
	providerTypes := []struct {
		name     string
		typeName string
	}{
		{name: "inline", typeName: "inline"},
		{name: "file", typeName: "file"},
	}

	for _, providerType := range providerTypes {
		t.Run(providerType.name, func(t *testing.T) {
			dir := t.TempDir()
			manifestPath := filepath.Join(dir, "providers.yaml")
			groupsPath := filepath.Join(dir, "mihomo.yaml")
			generationDir := filepath.Join(dir, "generated")

			providerSource := ""
			switch providerType.typeName {
			case "inline":
				providerSource = "    data: |\n      " + strings.TrimSuffix(providerBody, "\n") + "\n"
			case "file":
				providerPath := filepath.Join(dir, "rules.yaml")
				if err := os.WriteFile(providerPath, []byte(providerBody), 0o600); err != nil {
					t.Fatalf("WriteFile(provider) error = %v", err)
				}
				providerSource = "    path: rules.yaml\n"
			default:
				t.Fatalf("unsupported test provider type %q", providerType.typeName)
			}

			manifest := fmt.Sprintf(`providers:
  - name: p
    type: %s
%s    behavior: domain
routes:
  - provider: p
    outbound: proxy
    kind: domain
`, providerType.typeName, providerSource)
			if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
				t.Fatalf("WriteFile(manifest) error = %v", err)
			}
			writeGenerationGroupsInput(t, groupsPath)

			if _, err := RunSync(context.Background(), SyncOptions{
				ManifestPath:    manifestPath,
				GroupsInputPath: groupsPath,
				GenerationDir:   generationDir,
			}); err != nil {
				t.Fatalf("RunSync() error = %v", err)
			}

			resolvedCurrent, err := filepath.EvalSymlinks(filepath.Join(generationDir, "current"))
			if err != nil {
				t.Fatalf("EvalSymlinks(current) error = %v", err)
			}
			providerMetadataBody, err := os.ReadFile(filepath.Join(resolvedCurrent, "providers", "p", "metadata.json"))
			if err != nil {
				t.Fatalf("ReadFile(provider metadata) error = %v", err)
			}
			var providerMetadata map[string]any
			if err := json.Unmarshal(providerMetadataBody, &providerMetadata); err != nil {
				t.Fatalf("json.Unmarshal(provider metadata) error = %v", err)
			}
			if providerMetadata["format"] != "yaml" {
				t.Errorf("provider metadata format = %#v, want yaml", providerMetadata["format"])
			}

			generationMetadataBody, err := os.ReadFile(filepath.Join(resolvedCurrent, "metadata.json"))
			if err != nil {
				t.Fatalf("ReadFile(generation metadata) error = %v", err)
			}
			var generationMetadata map[string]any
			if err := json.Unmarshal(generationMetadataBody, &generationMetadata); err != nil {
				t.Fatalf("json.Unmarshal(generation metadata) error = %v", err)
			}
			generationProviders, ok := generationMetadata["providers"].(map[string]any)
			if !ok {
				t.Fatalf("generation metadata providers = %#v, want provider binding", generationMetadata["providers"])
			}
			binding, ok := generationProviders["p"].(map[string]any)
			if !ok {
				t.Fatalf("generation metadata providers[\"p\"] = %#v, want provider binding", generationProviders["p"])
			}
			if binding["format"] != "yaml" {
				t.Errorf("generation provider binding format = %#v, want yaml", binding["format"])
			}
		})
	}
}

func TestGenerationLockHelperProcess(t *testing.T) {
	if os.Getenv(generationLockHelperEnv) != "1" {
		return
	}
	lockPath := os.Getenv(generationLockHelperPathEnv)
	if lockPath == "" {
		t.Fatal("generation lock helper path is empty")
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("OpenFile(generation lock helper) error = %v", err)
	}
	defer lockFile.Close()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			_, _ = fmt.Fprintln(os.Stdout, "UNSUPPORTED")
			return
		}
		t.Fatalf("Flock(generation lock helper) error = %v", err)
	}
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	if _, err := fmt.Fprintln(os.Stdout, "READY"); err != nil {
		t.Fatalf("write generation lock helper readiness error = %v", err)
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatalf("wait for generation lock helper release error = %v", err)
	}
}

func TestGenerationPublishHelperProcess(t *testing.T) {
	if os.Getenv(generationPublishHelperEnv) != "1" {
		return
	}
	manifestPath := os.Getenv(generationPublishManifestPathEnv)
	groupsPath := os.Getenv(generationPublishGroupsPathEnv)
	generationDir := os.Getenv(generationPublishRootEnv)
	if manifestPath == "" || groupsPath == "" || generationDir == "" {
		t.Fatalf("generation publish helper paths are incomplete: manifest=%q groups=%q root=%q", manifestPath, groupsPath, generationDir)
	}
	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
		AllowPrivate:    true,
	}); err != nil {
		t.Fatalf("subprocess RunSync() error = %v", err)
	}
}

func TestGenerationPublicationPredecessorChainAcrossSubprocesses(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch requests {
		case 1:
			_, _ = fmt.Fprint(w, "payload: [first-subprocess.example]\n")
		case 2:
			_, _ = fmt.Fprint(w, "payload: [second-subprocess.example]\n")
		default:
			http.Error(w, "unexpected extra request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	manifest := fmt.Sprintf(`providers:
  - name: p
    type: http
    url: %s
    behavior: domain
    format: yaml
routes:
  - provider: p
    outbound: proxy
    kind: domain
`, server.URL)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writeGenerationGroupsInput(t, groupsPath)

	runPublishHelper := func(label string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestGenerationPublishHelperProcess$")
		cmd.Env = append(os.Environ(),
			generationPublishHelperEnv+"=1",
			generationPublishManifestPathEnv+"="+manifestPath,
			generationPublishGroupsPathEnv+"="+groupsPath,
			generationPublishRootEnv+"="+generationDir,
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s generation publish subprocess error = %v; output = %q", label, err, output)
		}
	}

	runPublishHelper("first")
	firstTarget, firstRoutes, firstGroups := readCurrentGeneration(t, generationDir)
	firstID := filepath.Base(firstTarget)
	firstDir := filepath.Join(generationDir, firstTarget)
	firstMetadata, err := readGenerationMetadata(firstDir, firstID)
	if err != nil {
		t.Fatalf("read first subprocess generation metadata error = %v", err)
	}
	if firstMetadata.PreviousGeneration != "" {
		t.Fatalf("first subprocess generation previous_generation = %q, want empty", firstMetadata.PreviousGeneration)
	}
	if string(firstRoutes) != "domain(suffix: 'first-subprocess.example') -> proxy\n" {
		t.Fatalf("first subprocess routes = %q", firstRoutes)
	}
	if err := validateStoredGeneration(firstDir, firstID); err != nil {
		t.Fatalf("first subprocess generation validation error = %v", err)
	}

	runPublishHelper("second")
	secondTarget, secondRoutes, secondGroups := readCurrentGeneration(t, generationDir)
	secondID := filepath.Base(secondTarget)
	secondDir := filepath.Join(generationDir, secondTarget)
	if secondTarget == firstTarget || secondID == firstID {
		t.Fatalf("second subprocess current target = %q, want a distinct generation from %q", secondTarget, firstTarget)
	}
	secondMetadata, err := readGenerationMetadata(secondDir, secondID)
	if err != nil {
		t.Fatalf("read second subprocess generation metadata error = %v", err)
	}
	if secondMetadata.PreviousGeneration != firstID {
		t.Fatalf("second subprocess previous_generation = %q, want first generation %q", secondMetadata.PreviousGeneration, firstID)
	}
	if string(secondRoutes) != "domain(suffix: 'second-subprocess.example') -> proxy\n" {
		t.Fatalf("second subprocess routes = %q", secondRoutes)
	}
	if string(secondGroups) != string(firstGroups) {
		t.Fatalf("second subprocess groups = %q, want first groups %q", secondGroups, firstGroups)
	}
	if err := validateStoredGeneration(firstDir, firstID); err != nil {
		t.Fatalf("retained first subprocess generation validation error = %v", err)
	}
	if err := validateStoredGeneration(secondDir, secondID); err != nil {
		t.Fatalf("second subprocess generation validation error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("HTTP requests across subprocesses = %d, want one per successful publication", requests)
	}
}

func TestGenerationLockWaitHonorsContextCancellationWithHelperProcess(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	manifest := `providers:
  - name: inline
    type: inline
    data: "payload: [locked-by-helper.example.com]"
    behavior: domain
    format: yaml
routes:
  - provider: inline
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writeGenerationGroupsInput(t, groupsPath)
	if err := os.MkdirAll(generationDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(generation root) error = %v", err)
	}
	lockPath := filepath.Join(generationDir, "generation.lock")

	cmd := exec.Command(os.Args[0], "-test.run=^TestGenerationLockHelperProcess$")
	cmd.Env = append(os.Environ(),
		generationLockHelperEnv+"=1",
		generationLockHelperPathEnv+"="+lockPath,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error = %v", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error = %v", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start generation lock helper: %v", err)
	}

	waited := false
	finishHelper := func() {
		if waited {
			return
		}
		_ = stdin.Close()
		waitErr := cmd.Wait()
		waited = true
		if waitErr != nil {
			t.Errorf("generation lock helper exited with %v; stderr=%q", waitErr, stderr.String())
		}
	}
	defer finishHelper()

	type helperReadyResult struct {
		line string
		err  error
	}
	ready := make(chan helperReadyResult, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		ready <- helperReadyResult{line: line, err: err}
	}()
	select {
	case result := <-ready:
		if result.err != nil {
			t.Fatalf("read generation lock helper readiness: %v; output=%q stderr=%q", result.err, result.line, stderr.String())
		}
		if strings.TrimSpace(result.line) == "UNSUPPORTED" {
			t.Skip("subprocess flock is unsupported")
		}
		if strings.TrimSpace(result.line) != "READY" {
			t.Fatalf("generation lock helper readiness = %q, want READY", result.line)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		waited = true
		t.Fatalf("timed out waiting for generation lock helper readiness; stderr=%q", stderr.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = RunSync(ctx, SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	})
	if err == nil {
		t.Fatal("RunSync() error = nil while subprocess holds generation lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunSync() error = %v, want context cancellation/deadline while waiting for subprocess generation lock", err)
	}
	if _, err := os.Lstat(filepath.Join(generationDir, "current")); !os.IsNotExist(err) {
		t.Fatalf("generation current after subprocess lock cancellation = %v, want no publication", err)
	}
	entries, err := os.ReadDir(filepath.Join(generationDir, "generations"))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatalf("ReadDir(generations after subprocess lock cancellation) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("generation entries after subprocess lock cancellation = %#v, want no candidate publication", entries)
	}
	finishHelper()
}

func TestGenerationLockWaitHonorsContextCancellation(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	manifest := `providers:
  - name: inline
    type: inline
    data: "payload: [locked.example.com]"
    behavior: domain
    format: yaml
routes:
  - provider: inline
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writeGenerationGroupsInput(t, groupsPath)
	if err := os.MkdirAll(generationDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(generation root) error = %v", err)
	}
	lockPath := filepath.Join(generationDir, "generation.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("OpenFile(generation lock) error = %v", err)
	}
	defer func() {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		_ = lockFile.Close()
	}()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("Flock(generation lock) error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = RunSync(ctx, SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	})
	if err == nil {
		t.Fatal("RunSync() error = nil while another process holds generation lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunSync() error = %v, want context cancellation/deadline while waiting for generation lock", err)
	}
	if _, err := os.Lstat(filepath.Join(generationDir, "current")); !os.IsNotExist(err) {
		t.Fatalf("generation current after canceled lock wait = %v, want no publication", err)
	}
	generationsPath := filepath.Join(generationDir, "generations")
	entries, err := os.ReadDir(generationsPath)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatalf("ReadDir(generations after canceled lock wait) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("generation entries after canceled lock wait = %#v, want no candidate publication", entries)
	}
}

func TestRunSyncRejectsMixedGenerationAndDirectOutputOptions(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	routesOutput := filepath.Join(dir, "direct", "routes.dae")
	manifest := `providers:
  - name: inline
    type: inline
    data: "payload: [mixed.example.com]"
    behavior: domain
    format: yaml
routes:
  - provider: inline
    outbound: proxy
    kind: domain
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writeGenerationGroupsInput(t, groupsPath)
	_, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		RoutesOutput:    routesOutput,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	})
	if err == nil {
		t.Fatal("RunSync() error = nil for mixed generation and direct output options")
	}
	errText := strings.ToLower(err.Error())
	if !strings.Contains(errText, "generation") || !strings.Contains(errText, "output") || (!strings.Contains(errText, "route") && !strings.Contains(errText, "direct")) {
		t.Fatalf("RunSync() validation error = %v, want clear generation/direct-output conflict", err)
	}
	if _, err := os.Lstat(filepath.Join(generationDir, "current")); !os.IsNotExist(err) {
		t.Fatalf("generation current after mixed-option rejection = %v, want no publication", err)
	}
	if _, err := os.Stat(routesOutput); !os.IsNotExist(err) {
		t.Fatalf("direct routes output after mixed-option rejection = %v, want no publication", err)
	}
}

func TestGenerationRetentionPreservesRecordedPredecessor(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	writeGenerationGroupsInput(t, groupsPath)
	writeManifest := func(domain string) {
		t.Helper()
		manifest := fmt.Sprintf(`providers:
  - name: inline
    type: inline
    data: "payload: [%s]"
    behavior: domain
    format: yaml
routes:
  - provider: inline
    outbound: proxy
    kind: domain
`, domain)
		if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
			t.Fatalf("WriteFile(manifest) error = %v", err)
		}
	}
	options := SyncOptions{
		ManifestPath:    manifestPath,
		CacheDir:        filepath.Join(dir, "cache"),
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}
	writeManifest("recorded.example.com")
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("initial RunSync() error = %v", err)
	}
	previousTarget, _, _ := readCurrentGeneration(t, generationDir)
	previousDir := filepath.Join(generationDir, previousTarget)
	previousID := filepath.Base(previousTarget)
	if previousID == "." || previousID == string(filepath.Separator) {
		t.Fatalf("previous target = %q, want generation target", previousTarget)
	}

	newerMTimeID := "generation-valid-but-newer-mtime"
	newerMTimeDir := filepath.Join(generationDir, "generations", newerMTimeID)
	copyGenerationTree(t, previousDir, newerMTimeDir)
	metadataPath := filepath.Join(newerMTimeDir, "metadata.json")
	metadataBody, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("ReadFile(newer mtime metadata) error = %v", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		t.Fatalf("json.Unmarshal(newer mtime metadata) error = %v", err)
	}
	metadata["generation"] = newerMTimeID
	metadataBody, err = json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal(newer mtime metadata) error = %v", err)
	}
	if err := os.WriteFile(metadataPath, metadataBody, 0o600); err != nil {
		t.Fatalf("WriteFile(newer mtime metadata) error = %v", err)
	}
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(newerMTimeDir, future, future); err != nil {
		t.Fatalf("Chtimes(newer mtime generation) error = %v", err)
	}

	writeManifest("published.example.com")
	if _, err := RunSync(context.Background(), options); err != nil {
		t.Fatalf("new RunSync() error = %v", err)
	}
	currentTarget, _, _ := readCurrentGeneration(t, generationDir)
	if currentTarget == previousTarget {
		t.Fatalf("current target = %q, want a new generation", currentTarget)
	}
	if _, err := os.Stat(previousDir); err != nil {
		t.Fatalf("recorded predecessor %q was removed: %v", previousID, err)
	}
	if _, err := os.Stat(newerMTimeDir); !os.IsNotExist(err) {
		t.Fatalf("unrecorded generation with newer mtime = %v, want it removed", err)
	}

	entries, err := os.ReadDir(filepath.Join(generationDir, "generations"))
	if err != nil {
		t.Fatalf("ReadDir(generations) error = %v", err)
	}
	directories := 0
	for _, entry := range entries {
		if entry.IsDir() {
			directories++
		}
	}
	if directories != 2 {
		t.Fatalf("generation directory count = %d, want current plus recorded predecessor", directories)
	}
}

func writeGenerationGroupsInput(t *testing.T, path string) {
	t.Helper()
	groups := `proxies:
  - name: hk-1
    type: anytls
proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk-1]
`
	if err := os.WriteFile(path, []byte(groups), 0o600); err != nil {
		t.Fatalf("WriteFile(generation groups input) error = %v", err)
	}
}

func copyGenerationTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(destination, 0o750); err != nil {
		t.Fatalf("MkdirAll(generation copy) error = %v", err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatalf("ReadDir(generation source) error = %v", err)
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		destinationPath := filepath.Join(destination, entry.Name())
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("Info(%s) error = %v", sourcePath, err)
		}
		if info.IsDir() {
			copyGenerationTree(t, sourcePath, destinationPath)
			continue
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("generation source entry %q has unsupported mode %s", sourcePath, info.Mode())
		}
		body, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", sourcePath, err)
		}
		if err := os.WriteFile(destinationPath, body, info.Mode().Perm()); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", destinationPath, err)
		}
	}
}
