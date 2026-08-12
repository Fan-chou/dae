package ruleprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type countingRoundTripper struct {
	calls int
}

func (t *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, fmt.Errorf("unexpected provider request")
}

func TestLoadAndExpandRejectsUnhardenedProductionRuntimeBeforeIO(t *testing.T) {
	transport := &countingRoundTripper{}
	conf := &config.Config{
		RuleProvider: []config.RuleProvider{{
			Name:     "remote",
			Type:     "http",
			URL:      "https://example.invalid/rules.yaml",
			Behavior: "domain",
		}},
	}

	err := LoadAndExpand(context.Background(), conf, t.TempDir(), &http.Client{Transport: transport})
	if !errors.Is(err, ErrProductionRuntimeDisabled) {
		t.Fatalf("LoadAndExpand() error = %v, want %v", err, ErrProductionRuntimeDisabled)
	}
	if transport.calls != 0 {
		t.Fatalf("provider requests = %d, want 0", transport.calls)
	}
}

func TestLoadAndExpandAllowsEmptyProviderConfiguration(t *testing.T) {
	for name, conf := range map[string]*config.Config{
		"nil":   nil,
		"empty": {},
		"slice": {RuleProvider: []config.RuleProvider{}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := LoadAndExpand(context.Background(), conf, "", nil); err != nil {
				t.Fatalf("LoadAndExpand() error = %v, want nil", err)
			}
		})
	}
}

func TestExpandRulesetPreservesAndFunctionsAndOutbound(t *testing.T) {
	sections, err := config_parser.Parse(`
routing {
  ruleset(openai) && l4proto(udp) -> proxy
  fallback: proxy
}
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var routing config.Routing
	if err := config.SectionParser(reflect.ValueOf(&routing), sections[0]); err != nil {
		t.Fatalf("SectionParser() error = %v", err)
	}
	got, err := ExpandRoutingRules(routing.Rules, Registry{
		"openai": {Functions: []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "openai.com"}}}}},
	})
	if err != nil {
		t.Fatalf("ExpandRoutingRules() error = %v", err)
	}
	if len(got) != 1 || len(got[0].AndFunctions) != 2 || got[0].Outbound.Name != "proxy" {
		t.Fatalf("expanded rules = %#v", got)
	}
	if got[0].AndFunctions[0].Name != "domain" || got[0].AndFunctions[1].Name != "l4proto" {
		t.Fatalf("expanded functions = %#v", got[0].AndFunctions)
	}
}

func TestExpandRulesetRejectsUnknownAndNegatedProvider(t *testing.T) {
	unknown := &config_parser.RoutingRule{AndFunctions: []*config_parser.Function{{Name: "ruleset", Params: []*config_parser.Param{{Val: "missing"}}}}, Outbound: config_parser.Function{Name: "proxy"}}
	if _, err := ExpandRoutingRules([]*config_parser.RoutingRule{unknown}, Registry{}); err == nil {
		t.Fatal("unknown provider error = nil")
	}
	negated := &config_parser.RoutingRule{AndFunctions: []*config_parser.Function{{Name: "ruleset", Not: true, Params: []*config_parser.Param{{Val: "p"}}}}, Outbound: config_parser.Function{Name: "proxy"}}
	if _, err := ExpandRoutingRules([]*config_parser.RoutingRule{negated}, Registry{"p": {Functions: []*config_parser.Function{{Name: "domain"}}}}); err == nil {
		t.Fatal("negated provider error = nil")
	}
}

func TestLoadFileProviderAndExpandIPRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "telegram.yaml")
	if err := os.WriteFile(path, []byte("payload:\n  - 192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	registry, err := LoadWithOptions(context.Background(), []config.RuleProvider{{Name: "telegram", Type: "file", Path: "telegram.yaml", Behavior: "ipcidr", Format: "yaml", MaxSize: 1024}}, dir, http.DefaultClient, LoadOptions{AllowPrivate: true})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(registry["telegram"].Functions) != 1 || registry["telegram"].Functions[0].Name != "dip" {
		t.Fatalf("registry = %#v", registry)
	}
	want := netip.MustParsePrefix("192.0.2.0/24").String()
	if got := registry["telegram"].Functions[0].Params[0].Val; got != want {
		t.Fatalf("prefix = %q, want %q", got, want)
	}
}

func TestLoadHTTPProviderWritesCacheAndUsesItAfterFailure(t *testing.T) {
	available := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{Name: "p", Type: "http", URL: server.URL, Path: "persist/p.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024}
	first, err := LoadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, LoadOptions{AllowPrivate: true})
	if err != nil {
		t.Fatalf("first Load() error = %v", err)
	}
	available = false
	second, err := LoadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, LoadOptions{AllowPrivate: true})
	if err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	if len(first["p"].Functions) != 1 || len(second["p"].Functions) != 1 {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
}
