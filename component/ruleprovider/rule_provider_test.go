package ruleprovider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

type countingRoundTripper struct {
	calls int
}

func (t *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, fmt.Errorf("unexpected provider request")
}

func testCacheDescriptor(t *testing.T, provider config.RuleProvider, baseDir string) cacheDescriptor {
	t.Helper()
	resolvedBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) error = %v", baseDir, err)
	}
	descriptor, err := newCacheDescriptor(provider, resolvedBase)
	if err != nil {
		t.Fatalf("newCacheDescriptor() error = %v", err)
	}
	return descriptor
}

func newPublicHTTPTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot inspect interfaces for public HTTP fixture: %v", err)
	}
	var lastErr error
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || blockedIP(ip) {
				continue
			}
			network := "tcp"
			if ip.To4() == nil {
				network = "tcp6"
			}
			listener, err := net.Listen(network, net.JoinHostPort(ip.String(), "0"))
			if err != nil {
				lastErr = err
				continue
			}
			server := httptest.NewUnstartedServer(handler)
			server.Listener = listener
			server.Start()
			t.Cleanup(server.Close)
			return server
		}
	}
	if lastErr == nil {
		t.Skip("no non-blocked global-unicast interface address for public HTTP fixture")
	}
	t.Skipf("cannot bind public HTTP fixture: %v", lastErr)
	return nil
}

func newPublicRawHTTPRedirectServer(t *testing.T, location string) (string, <-chan error) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot inspect interfaces for public raw HTTP fixture: %v", err)
	}
	var lastErr error
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || blockedIP(ip) {
				continue
			}
			network := "tcp"
			if ip.To4() == nil {
				network = "tcp6"
			}
			listener, err := net.Listen(network, net.JoinHostPort(ip.String(), "0"))
			if err != nil {
				lastErr = err
				continue
			}
			served := make(chan error, 1)
			t.Cleanup(func() { _ = listener.Close() })
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					served <- err
					return
				}
				defer conn.Close()
				_, err = io.WriteString(conn, "HTTP/1.1 302 Found\r\nLocation: "+location+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				served <- err
			}()
			return "http://" + listener.Addr().String(), served
		}
	}
	if lastErr == nil {
		t.Skip("no non-blocked global-unicast interface address for public raw HTTP fixture")
	}
	t.Skipf("cannot bind public raw HTTP fixture: %v", lastErr)
	return "", nil
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

func TestLoadAndExpandRejectsUnknownProviderWithEmptyProviderList(t *testing.T) {
	conf := &config.Config{
		Routing: config.Routing{Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name:   "ruleset",
				Params: []*config_parser.Param{{Val: "missing"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}}},
	}

	err := LoadAndExpand(context.Background(), conf, "", nil)
	if err == nil {
		t.Fatal("LoadAndExpand() error = nil for unknown provider with empty provider list")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "missing") && !strings.Contains(strings.ToLower(err.Error()), "unknown") {
		t.Fatalf("LoadAndExpand() error = %v, want unknown/missing provider error", err)
	}
}

func TestLoadAndExpandRejectsNegatedRulesetWithEmptyProviderList(t *testing.T) {
	conf := &config.Config{
		Routing: config.Routing{Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name:   "ruleset",
				Not:    true,
				Params: []*config_parser.Param{{Val: "missing"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}}},
	}

	err := LoadAndExpand(context.Background(), conf, "", nil)
	if err == nil {
		t.Fatal("LoadAndExpand() error = nil for negated ruleset with empty provider list")
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "negated") && !strings.Contains(message, "unsupported") && !strings.Contains(message, "missing") {
		t.Fatalf("LoadAndExpand() error = %v, want negated/unsupported provider error", err)
	}
}

func TestLoadAndExpandAcceptsValidatedFileProvider(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte("payload:\n  - example.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	sections, err := config_parser.Parse(`
routing {
  ruleset(local) -> proxy
  fallback: direct
}
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var routing config.Routing
	if err := config.SectionParser(reflect.ValueOf(&routing), sections[0]); err != nil {
		t.Fatalf("SectionParser() error = %v", err)
	}
	conf := &config.Config{
		RuleProvider: []config.RuleProvider{{Name: "local", Type: "file", Path: "rules.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024}},
		Routing:      routing,
	}

	if err := LoadAndExpand(context.Background(), conf, dir, nil); err != nil {
		t.Fatalf("LoadAndExpand() error = %v", err)
	}
	if len(conf.Routing.Rules) != 1 || conf.Routing.Rules[0].AndFunctions[0].Name != "domain" {
		t.Fatalf("routing rules = %#v", conf.Routing.Rules)
	}
}

func TestLoadRedactsCredentialsFromMalformedProviderURL(t *testing.T) {
	rawURL := "http://stage1-user:stage1-secret%zz@example.com/rules"
	_, err := Load(context.Background(), []config.RuleProvider{{
		Name: "credentialed", Type: "http", URL: rawURL,
		Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}}, t.TempDir(), nil)
	if err == nil {
		t.Fatal("Load() error = nil for malformed credentialed provider URL")
	}
	for _, forbidden := range []string{rawURL, "stage1-user", "stage1-secret", "%zz"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("Load() error %q leaks %q", err, forbidden)
		}
	}
}

func TestLoadRejectsEmptyProvider(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "empty.txt"), nil, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := Load(context.Background(), []config.RuleProvider{{Name: "empty", Type: "file", Path: "empty.txt", Behavior: "domain", Format: "text", MaxSize: 1024}}, dir, nil)
	if err == nil {
		t.Fatal("Load() error = nil for empty provider")
	}
}

func TestLoadRejectsAllUnsupportedProvider(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"ip-cidr in domain provider":   "IP-CIDR,192.0.2.0/24\n",
		"unsupported mihomo rule type": "PROCESS-NAME,curl\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".txt")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			_, err := Load(context.Background(), []config.RuleProvider{{
				Name: "unsupported", Type: "file", Path: filepath.Base(path),
				Behavior: "domain", Format: "text", MaxSize: 1024,
			}}, dir, nil)
			if err == nil {
				t.Fatal("Load() error = nil for provider with no supported rules")
			}
		})
	}
}

func TestParseBodyRejectsYAMLComplexityAndUnsupportedRules(t *testing.T) {
	provider := config.RuleProvider{Name: "p", Behavior: "domain", Format: "yaml", MaxSize: 4 << 20}
	if _, err := parseBody([]byte("payload: &rules\n  - example.com\ncopy: *rules\n"), provider); err == nil {
		t.Fatal("parseBody() error = nil for YAML alias")
	}
	if _, err := parseBody([]byte("- &a\n  - *a\n"), provider); err == nil {
		t.Fatal("parseBody() error = nil for recursive YAML alias")
	}
	deep := ""
	for i := 0; i < 66; i++ {
		deep += "- "
	}
	deep += "example.com\n"
	if _, err := parseBody([]byte(deep), provider); err == nil {
		t.Fatal("parseBody() error = nil for deeply nested YAML")
	}
	if _, err := parseBody([]byte("IP-CIDR,192.0.2.0/24\n"), provider); err == nil {
		t.Fatal("parseBody() error = nil for mixed unsupported rule")
	}

	tooLong := "DOMAIN," + strings.Repeat("a", 16<<10)
	if _, err := parseBody([]byte(tooLong), config.RuleProvider{Name: "p", Behavior: "domain", Format: "text", MaxSize: 1 << 20}); err == nil {
		t.Fatal("parseBody() error = nil for oversized rule")
	}

	items := make([]string, maxProviderYAMLNodes)
	for i := range items {
		items[i] = fmt.Sprintf("example-%d.com", i)
	}
	if _, err := parseBody([]byte("payload:\n  - "+strings.Join(items, "\n  - ")), provider); err == nil {
		t.Fatal("parseBody() error = nil for excessive YAML node count")
	}

	textItems := make([]string, maxProviderRules+1)
	for i := range textItems {
		textItems[i] = fmt.Sprintf("example-%d.com", i)
	}
	if _, err := parseBody([]byte(strings.Join(textItems, "\n")), config.RuleProvider{
		Name: "p", Behavior: "domain", Format: "text", MaxSize: 4 << 20,
	}); err == nil {
		t.Fatal("parseBody() error = nil for excessive provider rule count")
	}
}

func TestParseTextRejectsOversizedLineBeforeMaterializingString(t *testing.T) {
	const oversizedLineSize = 32 << 20
	body := []byte(strings.Repeat("x", oversizedLineSize))
	provider := config.RuleProvider{
		Name: "p", Behavior: "domain", Format: "text", MaxSize: int64(len(body) + 1),
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := parseBody(body, provider)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("parseBody() error = nil for oversized text rule")
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= oversizedLineSize {
		t.Fatalf("parseBody() allocated %d bytes before rejecting oversized text line; want less than line size %d", allocated, oversizedLineSize)
	}
}

func TestParseTextRejectsExcessiveRuleCountBeforeMaterializingAllRules(t *testing.T) {
	const paddingSize = 480
	padding := strings.Repeat("a", paddingSize)
	var source strings.Builder
	source.Grow((maxProviderRules + 1) * (paddingSize + 24))
	for i := 0; i <= maxProviderRules; i++ {
		fmt.Fprintf(&source, "example-%d-%s.example\n", i, padding)
	}
	body := []byte(source.String())
	provider := config.RuleProvider{
		Name: "p", Behavior: "domain", Format: "text", MaxSize: int64(len(body) + 1),
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := parseBody(body, provider)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("parseBody() error = nil for excessive text rule count")
	}
	const maxRejectedInputAllocation = 16 << 20
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= maxRejectedInputAllocation {
		t.Fatalf("parseBody() allocated %d bytes while rejecting excessive text rule count; want less than %d", allocated, maxRejectedInputAllocation)
	}
}

func TestParseYAMLRejectsNodeLimitBeforeMaterializingLargeTrailingScalar(t *testing.T) {
	const trailingScalarSize = 32 << 20

	var source strings.Builder
	source.WriteString("payload:\n")
	for i := 0; i < maxProviderYAMLNodes; i++ {
		fmt.Fprintf(&source, "  - item-%d.example\n", i)
	}
	source.WriteString("tail: ")
	source.WriteString(strings.Repeat("x", trailingScalarSize))
	source.WriteByte('\n')
	body := []byte(source.String())
	provider := config.RuleProvider{
		Name: "p", Behavior: "domain", Format: "yaml", MaxSize: int64(len(body) + 1),
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := parseBody(body, provider)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("parseBody() error = nil for excessive YAML node count")
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= trailingScalarSize {
		t.Fatalf("parseBody() allocated %d bytes before rejecting YAML node limit; want less than trailing scalar size %d", allocated, trailingScalarSize)
	}
}

func TestParseYAMLRejectsMultilineScalarsBeforeMaterializingOversizedRule(t *testing.T) {
	const (
		physicalLineSize = maxProviderRuleLength / 2
		lineCount        = 256
	)

	buildBody := func(kind string) ([]byte, int) {
		chunk := strings.Repeat("a", physicalLineSize)
		var source strings.Builder
		source.Grow(lineCount * (physicalLineSize + 8))
		source.WriteString("payload:\n")
		switch kind {
		case "quoted":
			source.WriteString("  - \"")
			for index := 0; index < lineCount; index++ {
				source.WriteString(chunk)
				if index == lineCount-1 {
					source.WriteByte('"')
				}
				source.WriteByte('\n')
				if index != lineCount-1 {
					source.WriteString("    ")
				}
			}
		case "plain":
			source.WriteString("  - ")
			for index := 0; index < lineCount; index++ {
				source.WriteString(chunk)
				source.WriteByte('\n')
				if index != lineCount-1 {
					source.WriteString("    ")
				}
			}
		case "folded":
			source.WriteString("  - >\n")
			for index := 0; index < lineCount; index++ {
				source.WriteString("    ")
				source.WriteString(chunk)
				source.WriteByte('\n')
			}
		default:
			panic("unknown YAML multiline scalar kind")
		}
		return []byte(source.String()), lineCount * physicalLineSize
	}

	for _, kind := range []string{"quoted", "plain", "folded"} {
		t.Run(kind, func(t *testing.T) {
			body, logicalScalarSize := buildBody(kind)
			if len(body) >= maxSize {
				t.Fatalf("fixture body size = %d, want less than maxSize %d", len(body), maxSize)
			}
			for lineNumber, line := range strings.Split(string(body), "\n") {
				if len(line) > maxProviderRuleLength {
					t.Fatalf("fixture physical line %d has length %d, want <= %d", lineNumber, len(line), maxProviderRuleLength)
				}
			}

			provider := config.RuleProvider{
				Name: "p", Behavior: "domain", Format: "yaml", MaxSize: maxSize,
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := parseBody(body, provider)
			runtime.ReadMemStats(&after)
			if err == nil {
				t.Fatal("parseBody() error = nil for oversized multiline YAML scalar")
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= uint64(logicalScalarSize) {
				t.Fatalf("parseBody() allocated %d bytes while rejecting %s scalar of %d bytes; want rejection before materialization", allocated, kind, logicalScalarSize)
			}
		})
	}
}

func TestParseYAMLRejectsFlowMultilineScalarsBeforeMaterializingOversizedRule(t *testing.T) {
	const (
		physicalLineSize = maxProviderRuleLength / 2
		lineCount        = 256
	)

	buildBody := func(kind string) []byte {
		chunk := strings.Repeat("a", physicalLineSize)
		var source strings.Builder
		source.Grow(lineCount * (physicalLineSize + 8))
		source.WriteString("payload: [\n")
		switch kind {
		case "quoted":
			source.WriteString("  \"")
			for index := 0; index < lineCount; index++ {
				source.WriteString(chunk)
				if index == lineCount-1 {
					source.WriteByte('"')
				}
				source.WriteByte('\n')
				if index != lineCount-1 {
					source.WriteString("    ")
				}
			}
		case "plain":
			source.WriteString("  ")
			for index := 0; index < lineCount; index++ {
				source.WriteString(chunk)
				source.WriteByte('\n')
				if index != lineCount-1 {
					source.WriteString("    ")
				}
			}
		default:
			panic("unknown YAML flow multiline scalar kind")
		}
		source.WriteString("]\n")
		return []byte(source.String())
	}

	for _, kind := range []string{"quoted", "plain"} {
		t.Run(kind, func(t *testing.T) {
			body := buildBody(kind)
			if len(body) >= maxSize {
				t.Fatalf("fixture body size = %d, want less than maxSize %d", len(body), maxSize)
			}
			for lineNumber, line := range strings.Split(string(body), "\n") {
				if len(line) > maxProviderRuleLength {
					t.Fatalf("fixture physical line %d has length %d, want <= %d", lineNumber, len(line), maxProviderRuleLength)
				}
			}

			var decoded struct {
				Payload []string `yaml:"payload"`
			}
			if err := yaml.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("yaml.Unmarshal() fixture error = %v", err)
			}
			if len(decoded.Payload) != 1 || len(decoded.Payload[0]) <= maxProviderRuleLength {
				t.Fatalf("decoded flow payload = %d items/%d bytes, want one scalar > %d bytes", len(decoded.Payload), func() int {
					if len(decoded.Payload) == 0 {
						return 0
					}
					return len(decoded.Payload[0])
				}(), maxProviderRuleLength)
			}

			provider := config.RuleProvider{
				Name: "p", Behavior: "domain", Format: "yaml", MaxSize: maxSize,
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := parseBody(body, provider)
			runtime.ReadMemStats(&after)
			if err == nil {
				t.Fatal("parseBody() error = nil for oversized flow multiline YAML scalar")
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= uint64(len(decoded.Payload[0])) {
				t.Fatalf("parseBody() allocated %d bytes while rejecting %s flow scalar of %d bytes; want rejection before materialization", allocated, kind, len(decoded.Payload[0]))
			}
		})
	}
}

func TestPreflightRejectsMultilineFlowDepthBeforeMaterializing(t *testing.T) {
	const nestedCollections = maxProviderYAMLDepth + 4

	var source strings.Builder
	source.WriteString("payload: [\n")
	closing := make([]byte, nestedCollections)
	for index := 0; index < nestedCollections; index++ {
		if index%2 == 0 {
			source.WriteString("[\n")
			closing[index] = ']'
			continue
		}
		source.WriteString("{value:\n")
		closing[index] = '}'
	}
	source.WriteString("deep.example\n")
	for index := nestedCollections - 1; index >= 0; index-- {
		source.WriteByte(closing[index])
		source.WriteByte('\n')
	}
	source.WriteString("]\n")
	body := []byte(source.String())

	var decoded any
	if err := yaml.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("yaml.Unmarshal() fixture error = %v\nfixture:\n%s", err, body)
	}
	if err := preflightProviderYAML(body); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("preflightProviderYAML() error = %v, want a nesting rejection for %d multiline flow levels", err, nestedCollections+1)
	}

	provider := config.RuleProvider{
		Name: "p", Behavior: "domain", Format: "yaml", MaxSize: int64(len(body) + 1),
	}
	if _, err := parseBody(body, provider); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("parseBody() error = %v, want a preflight nesting rejection", err)
	}
}

func TestLoadRejectsProviderPathSymlinkAndDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("example.com\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	socketPath := filepath.Join(dir, "rules.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	for name, path := range map[string]string{
		"symlink":     "link.txt",
		"directory":   ".",
		"non-regular": "rules.sock",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(context.Background(), []config.RuleProvider{{Name: "p", Type: "file", Path: path, Behavior: "domain", Format: "text", MaxSize: 1024}}, dir, nil)
			if err == nil {
				t.Fatalf("Load() error = nil for %s", name)
			}
		})
	}
}

func TestBlockedIPRejectsSpecialInternalRanges(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.1", "100.64.0.1", "192.0.0.1", "192.0.2.1",
		"198.18.0.1", "198.51.100.1", "203.0.113.1",
		"100.100.100.200", "168.63.129.16", "169.254.169.254", "192.88.99.1",
		"2001:db8::1", "240.0.0.1", "255.255.255.255",
	} {
		if !blockedIP(net.ParseIP(raw)) {
			t.Fatalf("blockedIP(%s) = false", raw)
		}
	}
}

func TestBlockedIPRejectsReservedIPv6Ranges(t *testing.T) {
	for _, raw := range []string{
		"2001:0::1",          // Teredo special-purpose range.
		"2001:2::1",          // Benchmarking range.
		"2001:10::1",         // ORCHIDv2 range.
		"2001:20::1",         // ORCHIDv2 range.
		"fec0::1",            // IPv6 site-local range.
		"64:ff9b::a00:1",     // NAT64 well-known prefix embedding 10.0.0.1.
		"64:ff9b::a9fe:a9fe", // NAT64 well-known prefix embedding 169.254.169.254.
		"64:ff9b:1::a00:1",   // NAT64 local-use translation of 10.0.0.1.
		"2002:7f00:1::1",     // 6to4 address embedding 127.0.0.1.
		"100:0:0:1::1",       // IPv6 special-purpose range.
		"5f00::1",            // IPv6 special-purpose range.
		"3fff::1",            // Documentation range.
		"100::1",             // Discard-only range.
	} {
		if !blockedIP(net.ParseIP(raw)) {
			t.Fatalf("blockedIP(%s) = false for reserved IPv6 range", raw)
		}
	}
}

func TestProviderSecurityRejectsBlockedRedirectTargets(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/rules.yaml",
		"http://192.0.2.1/rules.yaml",
		"http://100.64.0.1/rules.yaml",
		"http://169.254.169.254/latest/meta-data",
		"http://[64:ff9b::a00:1]/rules.yaml",
		"http://[64:ff9b::a9fe:a9fe]/rules.yaml",
		"http://[64:ff9b:1::a00:1]/rules.yaml",
		"http://192.88.99.1/rules.yaml",
		"http://[2002:7f00:1::1]/rules.yaml",
		"http://[100:0:0:1::1]/rules.yaml",
		"http://[5f00::1]/rules.yaml",
		"http://metadata.google.internal/rules.yaml",
	} {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("url.Parse() error = %v", err)
			}
			if err := validatePublicURL(parsed); err == nil {
				t.Fatalf("validatePublicURL(%q) error = nil", raw)
			}
		})
	}
}

func TestFetchHTTPRejectsRedirectToBlockedEndpoint(t *testing.T) {
	server := newPublicHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/blocked", http.StatusFound)
	}))

	_, err := fetchHTTP(context.Background(), server.URL, 1024, http.DefaultClient, false, cacheSnapshot{})
	if err == nil {
		t.Fatal("fetchHTTP() error = nil for redirect to blocked endpoint")
	}
	if !strings.Contains(err.Error(), "not allowed") && !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("fetchHTTP() error = %v, want blocked redirect rejection", err)
	}
}

func TestFetchHTTPRedactsRedirectUserinfo(t *testing.T) {
	const rawLocation = "http://stage1-user:stage1-secret@127.0.0.1:1/redirected"
	server := newPublicHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, rawLocation, http.StatusFound)
	}))

	_, err := fetchHTTP(context.Background(), server.URL, 1024, http.DefaultClient, false, cacheSnapshot{})
	if err == nil {
		t.Fatal("fetchHTTP() error = nil for redirect with userinfo to blocked endpoint")
	}
	for _, secret := range []string{"stage1-user", "stage1-secret", rawLocation} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("fetchHTTP() error = %q, must not contain redirect credential/URL %q", err, secret)
		}
	}
}

func TestFetchHTTPRedactsMalformedRedirectLocationUserinfo(t *testing.T) {
	const rawLocation = "http://stage1-user:stage1-secret@example.com/a\tb"
	endpoint, served := newPublicRawHTTPRedirectServer(t, rawLocation)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := fetchHTTP(ctx, endpoint, 1024, http.DefaultClient, false, cacheSnapshot{})
	select {
	case serveErr := <-served:
		if serveErr != nil {
			t.Fatalf("raw redirect response write error = %v", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("raw redirect listener did not serve the request")
	}
	if err == nil {
		t.Fatal("fetchHTTP() error = nil for malformed redirect Location")
	}
	for _, forbidden := range []string{"stage1-user", "stage1-secret", "example.com/a", rawLocation} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("fetchHTTP() error = %q, must not contain malformed redirect detail %q", err, forbidden)
		}
	}
}

func TestSafeDialRejectsHostnameResolvingToBlockedIP(t *testing.T) {
	dialCalled := false
	dial := safeDialContext(func(context.Context, string, string) (net.Conn, error) {
		dialCalled = true
		return nil, fmt.Errorf("unexpected dial")
	})
	_, err := dial(context.Background(), "tcp", "localhost:80")
	if err == nil {
		t.Fatal("safeDialContext() error = nil for hostname resolving to localhost")
	}
	if !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("safeDialContext() error = %v, want blocked-address rejection", err)
	}
	if dialCalled {
		t.Fatal("safeDialContext() called the original dialer for a blocked hostname")
	}
}

func TestSafeTransportDisablesProxyAndDialBypassHooks(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	dialCalled := false
	original := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialCalled = true
			return nil, fmt.Errorf("custom dial should not be called")
		},
	}
	got, err := safeTransport(original)
	if err != nil {
		t.Fatalf("safeTransport() error = %v", err)
	}
	transport := got.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("safeTransport() retained proxy configuration")
	}
	if transport.DialContext == nil {
		t.Fatal("safeTransport() did not install a guarded dialer")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:9"); err == nil {
		t.Fatal("guarded dial error = nil for loopback")
	}
	if dialCalled {
		t.Fatal("safeTransport() called the caller-provided dialer")
	}
}

func TestSafeTransportAllowsOnlyHTTP1Protocols(t *testing.T) {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	original := &http.Transport{
		Protocols:         protocols,
		ForceAttemptHTTP2: true,
	}

	got, err := safeTransport(original)
	if err != nil {
		t.Fatalf("safeTransport() error = %v", err)
	}
	transport, ok := got.(*http.Transport)
	if !ok {
		t.Fatalf("safeTransport() returned %T, want *http.Transport", got)
	}
	if transport.Protocols == nil {
		t.Fatal("safeTransport() left Protocols nil; want explicit HTTP/1-only policy")
	}
	if !transport.Protocols.HTTP1() || transport.Protocols.HTTP2() || transport.Protocols.UnencryptedHTTP2() {
		t.Fatalf("safeTransport() Protocols = %s, want HTTP1 only", *transport.Protocols)
	}
}

func TestFetchHTTPRejectsResponseHeadersWhenCustomTransportLimitIsNegative(t *testing.T) {
	server := newPublicHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("x", (1<<20)+4096))
		_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
	}))

	client := &http.Client{Transport: &http.Transport{MaxResponseHeaderBytes: -1}}
	_, err := fetchHTTP(context.Background(), server.URL, 4<<20, client, false, cacheSnapshot{})
	if err == nil {
		t.Fatal("fetchHTTP() error = nil for response headers larger than the 1 MiB production limit")
	}
}

func TestLoadRejectsBlockedProviderBeforeTransportIO(t *testing.T) {
	transport := &countingRoundTripper{}
	_, err := Load(context.Background(), []config.RuleProvider{{
		Name: "blocked", Type: "http", URL: "http://127.0.0.1:9/rules.yaml",
		Behavior: "domain", Format: "text", MaxSize: 1024,
	}}, t.TempDir(), &http.Client{Transport: transport})
	if err == nil {
		t.Fatal("Load() error = nil for blocked provider URL")
	}
	if transport.calls != 0 {
		t.Fatalf("provider requests = %d, want 0", transport.calls)
	}
}

func TestExpandRoutingRulesRejectsOversizedCartesianProductWithoutPublishing(t *testing.T) {
	dir := t.TempDir()
	writeRules := func(name string, count int) {
		t.Helper()
		var body strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&body, "example-%d.com\n", i)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(body.String()), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}
	writeRules("a", 400)
	writeRules("b", 400)
	sections, err := config_parser.Parse(`
routing {
  ruleset(a) && ruleset(b) -> proxy
  fallback: direct
}
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var routing config.Routing
	if err := config.SectionParser(reflect.ValueOf(&routing), sections[0]); err != nil {
		t.Fatalf("SectionParser() error = %v", err)
	}
	conf := &config.Config{
		RuleProvider: []config.RuleProvider{
			{Name: "a", Type: "file", Path: "a.txt", Behavior: "domain", Format: "text", MaxSize: 1 << 20},
			{Name: "b", Type: "file", Path: "b.txt", Behavior: "domain", Format: "text", MaxSize: 1 << 20},
		},
		Routing: routing,
	}
	if err := LoadAndExpand(context.Background(), conf, dir, nil); err == nil {
		t.Fatalf("LoadAndExpand() error = %v, want expansion limit error", err)
	}
	if len(conf.Routing.Rules) != 1 || conf.Routing.Rules[0].AndFunctions[0].Name != "ruleset" {
		t.Fatalf("routing rules mutated after failed expansion: %#v", conf.Routing.Rules)
	}
	for _, name := range []string{"a", "b"} {
		if _, err := os.Stat(filepath.Join(dir, "persist.d", "rule-providers", name, "current")); !os.IsNotExist(err) {
			t.Fatalf("cache current for %s = %v, want absent", name, err)
		}
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
	registry, err := loadWithOptions(context.Background(), []config.RuleProvider{{Name: "telegram", Type: "file", Path: "telegram.yaml", Behavior: "ipcidr", Format: "yaml", MaxSize: 1024}}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
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

func TestLoadFileProviderUsesPersistedLastGoodAfterFileDisappears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte("payload:\n  - first.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	spec := config.RuleProvider{
		Name: "local", Type: "file", Path: "rules.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	first, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, nil, loadOptions{})
	if err != nil {
		t.Fatalf("initial file provider load error = %v", err)
	}
	if len(first["local"].Functions) != 1 || first["local"].Functions[0].Params[0].Val != "first.example" {
		t.Fatalf("initial registry = %#v", first)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove(provider file) error = %v", err)
	}

	second, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, nil, loadOptions{})
	if err != nil {
		t.Fatalf("file provider load after source disappearance error = %v, want last-good snapshot", err)
	}
	if len(second["local"].Functions) != 1 || second["local"].Functions[0].Params[0].Val != "first.example" {
		t.Fatalf("last-good registry = %#v", second)
	}
}

func TestLoadFileProviderBadUpdateDoesNotReplaceLastGoodSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte("payload:\n  - first.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	spec := config.RuleProvider{
		Name: "local", Type: "file", Path: "rules.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, nil, loadOptions{}); err != nil {
		t.Fatalf("initial file provider load error = %v", err)
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read initial file-provider snapshot error = %v", err)
	}
	if err := os.WriteFile(path, []byte("payload: []\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(bad provider update) error = %v", err)
	}

	got, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, nil, loadOptions{})
	if err != nil {
		t.Fatalf("bad file update load error = %v, want last-good snapshot", err)
	}
	if len(got["local"].Functions) != 1 || got["local"].Functions[0].Params[0].Val != "first.example" {
		t.Fatalf("registry after bad update = %#v", got)
	}
	current, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read snapshot after bad update error = %v", err)
	}
	if string(current.body) != string(initial.body) || current.metadata != initial.metadata {
		t.Fatalf("last-good snapshot changed after bad file update: initial=%#v current=%#v", initial, current)
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
	first, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("first Load() error = %v", err)
	}
	available = false
	second, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	if len(first["p"].Functions) != 1 || len(second["p"].Functions) != 1 {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
}

func TestLoadRejectsInsecureCachePermissions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, descriptor cacheDescriptor, state currentState)
	}{
		{
			name: "body-world-writable",
			mutate: func(t *testing.T, descriptor cacheDescriptor, state currentState) {
				t.Helper()
				if err := os.Chmod(filepath.Join(state.resolved, "body"), 0o666); err != nil {
					t.Fatalf("Chmod(body) error = %v", err)
				}
			},
		},
		{
			name: "metadata-group-writable",
			mutate: func(t *testing.T, descriptor cacheDescriptor, state currentState) {
				t.Helper()
				if err := os.Chmod(filepath.Join(state.resolved, "metadata.json"), 0o660); err != nil {
					t.Fatalf("Chmod(metadata) error = %v", err)
				}
			},
		},
		{
			name: "provider-root-world-writable",
			mutate: func(t *testing.T, descriptor cacheDescriptor, state currentState) {
				t.Helper()
				if err := os.Chmod(descriptor.root, 0o777); err != nil {
					t.Fatalf("Chmod(cache root) error = %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, "payload:\n  - first.example\n")
			}))
			dir := t.TempDir()
			spec := config.RuleProvider{
				Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
			}
			if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
				server.Close()
				t.Fatalf("initial Load() error = %v", err)
			}
			descriptor := testCacheDescriptor(t, spec, dir)
			state, err := readCurrentState(descriptor.root)
			if err != nil {
				server.Close()
				t.Fatalf("readCurrentState() error = %v", err)
			}
			if !state.exists {
				server.Close()
				t.Fatal("initial cache has no current snapshot")
			}
			tc.mutate(t, descriptor, state)
			server.Close()

			if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err == nil {
				t.Fatalf("Load() accepted %s persistent cache after network failure", tc.name)
			}
		})
	}
}

func TestCacheFIFOLoadIsBounded(t *testing.T) {
	for _, kind := range []string{"body", "metadata", "journal"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, "payload:\n  - first.example\n")
			}))
			dir := t.TempDir()
			spec := config.RuleProvider{
				Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
			}
			if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
				server.Close()
				t.Fatalf("initial Load() error = %v", err)
			}
			server.Close()

			descriptor := testCacheDescriptor(t, spec, dir)
			fifoPath := filepath.Join(descriptor.root, "current")
			if kind == "journal" {
				fifoPath = filepath.Join(filepath.Dir(descriptor.root), "transaction.journal")
				current, err := readCurrentState(descriptor.root)
				if err != nil {
					t.Fatalf("readCurrentState() for journal fixture error = %v", err)
				}
				if !current.exists || current.target == "" {
					t.Fatalf("journal fixture current = %#v, want published current", current)
				}
				journal := cacheTransaction{
					SchemaVersion: cacheTransactionVersion,
					State:         "publishing",
					Generation:    "fifo-fixture",
					Providers: map[string]cacheTransactionEntry{
						"p": {OldCurrent: current.target, NewCurrent: current.target},
					},
				}
				if err := writeCacheTransaction(fifoPath, journal); err != nil {
					t.Fatalf("write valid transaction journal fixture error = %v", err)
				}
			} else {
				state, err := readCurrentState(descriptor.root)
				if err != nil {
					t.Fatalf("readCurrentState() error = %v", err)
				}
				name := "body"
				if kind == "metadata" {
					name = "metadata.json"
				}
				fifoPath = filepath.Join(state.resolved, name)
			}
			if err := os.Remove(fifoPath); err != nil {
				t.Fatalf("Remove(%q) error = %v", fifoPath, err)
			}
			if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
				t.Fatalf("Mkfifo(%q) error = %v", fifoPath, err)
			}

			cmd := exec.Command(os.Args[0], "-test.run", "^TestCacheFIFOLoadChild$", "-test.v")
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			cmd.Env = append(os.Environ(),
				"DAE_RULE_PROVIDER_FIFO_CHILD=1",
				"DAE_RULE_PROVIDER_FIFO_BASE="+dir,
				"DAE_RULE_PROVIDER_FIFO_URL="+spec.URL,
				"DAE_RULE_PROVIDER_FIFO_KIND="+kind,
			)
			if err := cmd.Start(); err != nil {
				t.Fatalf("start FIFO child error = %v", err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("FIFO child exited with error = %v, output = %s", err, output.String())
				}
			case <-timer.C:
				killErr := cmd.Process.Kill()
				waitErr := <-done
				t.Fatalf("FIFO child blocked reading %s; killed child: kill=%v wait=%v", kind, killErr, waitErr)
			}
		})
	}
}

func TestCacheFIFOLoadChild(t *testing.T) {
	if os.Getenv("DAE_RULE_PROVIDER_FIFO_CHILD") != "1" {
		return
	}
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: os.Getenv("DAE_RULE_PROVIDER_FIFO_URL"),
		Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	_, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, os.Getenv("DAE_RULE_PROVIDER_FIFO_BASE"), http.DefaultClient, loadOptions{allowPrivate: true})
	if err == nil {
		t.Fatal("Load() error = nil for FIFO cache fixture")
	}
}

func TestMultiProviderLoadDoesNotReturnMixedRegistryGeneration(t *testing.T) {
	var generationMu sync.Mutex
	generation := "one"
	aStarted := make(chan struct{})
	releaseA := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseA) }) }
	defer release()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			close(aStarted)
			<-releaseA
			generationMu.Lock()
			current := generation
			generationMu.Unlock()
			w.Header().Set(providerGenerationHeader, current)
			_, _ = fmt.Fprintf(w, "payload:\n  - generation-%s.example\n", current)
		case "/b":
			generationMu.Lock()
			current := generation
			generationMu.Unlock()
			w.Header().Set(providerGenerationHeader, current)
			_, _ = fmt.Fprintf(w, "payload:\n  - generation-%s.example\n", current)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	providers := []config.RuleProvider{
		{Name: "a", Type: "http", URL: server.URL + "/a", Behavior: "domain", Format: "yaml", MaxSize: 1024},
		{Name: "b", Type: "http", URL: server.URL + "/b", Behavior: "domain", Format: "yaml", MaxSize: 1024},
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var registry Registry
	var loadErr error
	done := make(chan struct{})
	go func() {
		registry, loadErr = loadWithOptions(ctx, providers, dir, http.DefaultClient, loadOptions{allowPrivate: true})
		close(done)
	}()

	select {
	case <-aStarted:
	case <-done:
		t.Fatalf("Load() completed before provider a fixture was released: err=%v", loadErr)
	case <-ctx.Done():
		t.Fatalf("Load() did not reach provider a fixture: %v", ctx.Err())
	}
	generationMu.Lock()
	generation = "two"
	generationMu.Unlock()
	release()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("Load() did not complete after provider a fixture release: %v", ctx.Err())
	}
	if loadErr != nil {
		message := strings.ToLower(loadErr.Error())
		if !strings.Contains(message, "generation") ||
			(!strings.Contains(message, "mismatch") && !strings.Contains(message, "drift") && !strings.Contains(message, "batch")) {
			t.Fatalf("Load() error = %v, want explicit generation mismatch rejection", loadErr)
		}
		for _, provider := range providers {
			descriptor := testCacheDescriptor(t, provider, dir)
			if _, err := os.Lstat(filepath.Join(descriptor.root, "current")); err == nil {
				t.Fatalf("generation mismatch left partial current for provider %q", provider.Name)
			} else if !os.IsNotExist(err) {
				t.Fatalf("stat current for provider %q after generation mismatch: %v", provider.Name, err)
			}
		}
		return
	}
	aRules := registry["a"].Functions
	bRules := registry["b"].Functions
	if len(aRules) != 1 || len(bRules) != 1 {
		t.Fatalf("registry rules = %#v, want one rule per provider", registry)
	}
	if aRules[0].Params[0].Val != bRules[0].Params[0].Val {
		t.Fatalf("Load() returned mixed provider generations: a=%q b=%q", aRules[0].Params[0].Val, bRules[0].Params[0].Val)
	}
}

func TestMultiProviderLoadRejectsReverseFetchFenceMixedGeneration(t *testing.T) {
	var sourceMu sync.Mutex
	source := "one"
	bReturned := make(chan struct{})
	aStarted := make(chan struct{})
	releaseA := make(chan struct{})
	var bReturnedOnce sync.Once
	var aStartedOnce sync.Once

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/b":
			sourceMu.Lock()
			current := source
			sourceMu.Unlock()
			w.Header().Set("X-Dae-Rule-Provider-Generation", current)
			_, _ = fmt.Fprintf(w, "payload:\n  - b-%s.example\n", current)
			bReturnedOnce.Do(func() { close(bReturned) })
		case "/a":
			aStartedOnce.Do(func() { close(aStarted) })
			<-releaseA
			sourceMu.Lock()
			current := source
			sourceMu.Unlock()
			w.Header().Set("X-Dae-Rule-Provider-Generation", current)
			_, _ = fmt.Fprintf(w, "payload:\n  - a-%s.example\n", current)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	providers := []config.RuleProvider{
		{Name: "a", Type: "http", URL: server.URL + "/a", Behavior: "domain", Format: "yaml", MaxSize: 1024},
		{Name: "b", Type: "http", URL: server.URL + "/b", Behavior: "domain", Format: "yaml", MaxSize: 1024},
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var registry Registry
	var loadErr error
	done := make(chan struct{})
	go func() {
		registry, loadErr = loadWithOptions(ctx, providers, dir, http.DefaultClient, loadOptions{allowPrivate: true})
		close(done)
	}()

	select {
	case <-bReturned:
	case <-done:
		t.Fatalf("Load() completed before reverse fetch fence was established: err=%v", loadErr)
	case <-ctx.Done():
		t.Fatalf("/b did not return generation-one before timeout: %v", ctx.Err())
	}
	select {
	case <-aStarted:
	case <-done:
		t.Fatalf("Load() completed before /a was blocked: err=%v", loadErr)
	case <-ctx.Done():
		t.Fatalf("/a did not reach blocking fence: %v", ctx.Err())
	}

	sourceMu.Lock()
	source = "two"
	sourceMu.Unlock()
	close(releaseA)

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("Load() did not complete after reverse fetch fence release: %v", ctx.Err())
	}
	if loadErr != nil {
		message := strings.ToLower(loadErr.Error())
		if !strings.Contains(message, "generation") ||
			(!strings.Contains(message, "drift") &&
				!strings.Contains(message, "mismatch") &&
				!strings.Contains(message, "inconsistent") &&
				!strings.Contains(message, "batch")) {
			t.Fatalf("Load() error = %v, want explicit batch generation drift rejection", loadErr)
		}
		for _, provider := range providers {
			descriptor := testCacheDescriptor(t, provider, dir)
			if _, err := os.Lstat(filepath.Join(descriptor.root, "current")); err == nil {
				t.Fatalf("Load() generation-drift rejection left partial current for provider %q", provider.Name)
			} else if !os.IsNotExist(err) {
				t.Fatalf("stat current for provider %q after generation-drift rejection: %v", provider.Name, err)
			}
		}
		return
	}
	aRules := registry["a"].Functions
	bRules := registry["b"].Functions
	if len(aRules) != 1 || len(bRules) != 1 {
		t.Fatalf("registry rules = %#v, want one rule per provider", registry)
	}
	aValue := aRules[0].Params[0].Val
	bValue := bRules[0].Params[0].Val
	aGeneration := strings.TrimSuffix(strings.TrimPrefix(aValue, "a-"), ".example")
	bGeneration := strings.TrimSuffix(strings.TrimPrefix(bValue, "b-"), ".example")
	if aGeneration == "" || aGeneration == aValue || bGeneration == "" || bGeneration == bValue {
		t.Fatalf("Load() returned malformed generation-tagged rules: a=%q b=%q", aValue, bValue)
	}
	if aGeneration != bGeneration {
		t.Fatalf("Load() returned reverse-fence mixed generations: a=%q b=%q", aValue, bValue)
	}
}

func TestPublishPreparedRejectsOlderCandidateThanCurrent(t *testing.T) {
	const (
		firstGeneration  = "one"
		secondGeneration = "two"
		firstBody        = "payload:\n  - first.example\n"
		oldBody          = "payload:\n  - old-prepared.example\n"
		secondBody       = "payload:\n  - second.example\n"
	)
	var requestMu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requestCount++
		currentRequest := requestCount
		requestMu.Unlock()
		w.Header().Set(providerGenerationHeader, firstGeneration)
		switch currentRequest {
		case 1:
			_, _ = fmt.Fprint(w, firstBody)
		case 2:
			_, _ = fmt.Fprint(w, oldBody)
		case 3:
			w.Header().Set(providerGenerationHeader, secondGeneration)
			_, _ = fmt.Fprint(w, secondBody)
		default:
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("initial current-generation load error = %v", err)
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read current-generation snapshot error = %v", err)
	}
	if initial.metadata.Generation != firstGeneration || string(initial.body) != firstBody {
		t.Fatalf("initial snapshot = %#v, want generation %q and first body", initial, firstGeneration)
	}
	initialCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read initial current state error = %v", err)
	}
	if !initialCurrent.exists {
		t.Fatal("initial current state does not exist")
	}

	prepared, err := prepareProvider(context.Background(), spec, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("prepare old candidate error = %v", err)
	}
	if prepared.candidate == nil {
		t.Fatal("prepareProvider() candidate = nil, want an old prepared candidate")
	}
	if !prepared.candidate.expectedCurrentKnown || prepared.candidate.expectedCurrent.target != initialCurrent.target {
		t.Fatalf("prepared candidate current identity = %#v, want initial current", prepared.candidate)
	}

	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("publish newer current-generation load error = %v", err)
	}
	newer, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read newer snapshot error = %v", err)
	}
	newerCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read newer current state error = %v", err)
	}
	if newer.metadata.Generation != secondGeneration || string(newer.body) != secondBody || !newerCurrent.exists {
		t.Fatalf("newer snapshot/current = %#v/%#v, want generation %q and second body", newer, newerCurrent, secondGeneration)
	}

	publishErr := publishPrepared([]preparedProvider{prepared})

	after, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read snapshot after older candidate publish error = %v", err)
	}
	afterCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read current state after older candidate publish error = %v", err)
	}
	if publishErr != nil {
		t.Logf("publishPrepared() rejected old candidate as allowed: %v", publishErr)
	}
	if afterCurrent.target != newerCurrent.target || after.metadata.Generation != secondGeneration || !bytes.Equal(after.body, newer.body) {
		t.Fatalf("older candidate regressed newer current: publishErr=%v newer=%#v/%#v after=%#v/%#v", publishErr, newerCurrent, newer, afterCurrent, after)
	}
	transactionPath, err := cacheTransactionPath(dir)
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal after older candidate publish = %v, want absent", err)
	}
}

func TestPublishPreparedRejectsRemoteOldGenerationReplayAfterNewerCurrent(t *testing.T) {
	const (
		generationOne = "one"
		generationTwo = "two"
		bodyOne       = "payload:\n  - remote-one.example\n"
		bodyTwo       = "payload:\n  - remote-two.example\n"
	)
	var requestMu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requestCount++
		currentRequest := requestCount
		requestMu.Unlock()
		switch currentRequest {
		case 1:
			w.Header().Set(providerGenerationHeader, generationOne)
			_, _ = fmt.Fprint(w, bodyOne)
		case 2:
			w.Header().Set(providerGenerationHeader, generationTwo)
			_, _ = fmt.Fprint(w, bodyTwo)
		case 3:
			// This response arrives after generation two has been accepted, but
			// carries the opaque remote generation-one token again.
			w.Header().Set(providerGenerationHeader, generationOne)
			_, _ = fmt.Fprint(w, bodyOne)
		default:
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("generation-one load error = %v", err)
	}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("generation-two load error = %v", err)
	}

	descriptor := testCacheDescriptor(t, spec, dir)
	newer, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read generation-two snapshot error = %v", err)
	}
	newerCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read generation-two current state error = %v", err)
	}
	if newer.metadata.Generation != generationTwo || string(newer.body) != bodyTwo || !newerCurrent.exists {
		t.Fatalf("generation-two snapshot/current = %#v/%#v, want generation two", newer, newerCurrent)
	}

	late, err := prepareProvider(context.Background(), spec, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("prepare remote old-generation replay error = %v", err)
	}
	if late.candidate == nil {
		t.Fatal("late remote old-generation candidate = nil, want fresh replay candidate")
	}
	if late.generation != generationOne || string(late.candidate.body) != bodyOne {
		t.Fatalf("late candidate = generation %q body %q, want generation-one replay", late.generation, late.candidate.body)
	}
	if !late.candidate.expectedCurrentKnown || late.candidate.expectedCurrent.target != newerCurrent.target {
		t.Fatalf("late candidate expected current = %#v, want generation-two current identity", late.candidate.expectedCurrent)
	}

	publishErr := publishPrepared([]preparedProvider{late})
	after, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read snapshot after remote old-generation replay error = %v", err)
	}
	afterCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read current state after remote old-generation replay error = %v", err)
	}
	if publishErr != nil {
		t.Logf("remote old-generation replay rejected as allowed: %v", publishErr)
	}
	transactionPath, err := cacheTransactionPath(dir)
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	journalErr := error(nil)
	if _, journalErr = os.Lstat(transactionPath); !os.IsNotExist(journalErr) {
		t.Fatalf("remote old-generation replay left transaction journal: publishErr=%v journalErr=%v current=%#v snapshot=%#v", publishErr, journalErr, afterCurrent, after)
	}
	if after.metadata.Generation != generationTwo || !bytes.Equal(after.body, newer.body) || afterCurrent.target != newerCurrent.target {
		t.Fatalf("remote old-generation replay regressed current: publishErr=%v newerTarget=%q newerGeneration=%q newerBody=%q afterTarget=%q afterGeneration=%q afterBody=%q journalErr=%v", publishErr, newerCurrent.target, newer.metadata.Generation, newer.body, afterCurrent.target, after.metadata.Generation, after.body, journalErr)
	}
}

func TestMultiProviderLoadRejectsNoCandidateProviderSwitch(t *testing.T) {
	const generation = "one"
	var requestMu sync.Mutex
	aRequests, bRequests := 0, 0
	aStarted := make(chan struct{})
	releaseA := make(chan struct{})
	var aStartedOnce sync.Once
	var releaseAOnce sync.Once
	release := func() {
		releaseAOnce.Do(func() { close(releaseA) })
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(providerGenerationHeader, generation)
		switch r.URL.Path {
		case "/a":
			requestMu.Lock()
			aRequests++
			currentRequest := aRequests
			requestMu.Unlock()
			switch currentRequest {
			case 1:
				_, _ = fmt.Fprint(w, "payload:\n  - a-initial.example\n")
			case 2:
				aStartedOnce.Do(func() { close(aStarted) })
				<-releaseA
				_, _ = fmt.Fprint(w, "payload:\n  - a-prepared.example\n")
			default:
				http.Error(w, "unexpected /a request", http.StatusInternalServerError)
			}
		case "/b":
			requestMu.Lock()
			bRequests++
			currentRequest := bRequests
			requestMu.Unlock()
			switch currentRequest {
			case 1:
				w.Header().Set("ETag", `"b-one"`)
				w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
				_, _ = fmt.Fprint(w, "payload:\n  - b-initial.example\n")
			case 2:
				w.Header().Set("ETag", `"b-one"`)
				w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
				w.WriteHeader(http.StatusNotModified)
			case 3:
				w.Header().Set(providerGenerationHeader, "two")
				_, _ = fmt.Fprint(w, "payload:\n  - b-switched.example\n")
			default:
				http.Error(w, "unexpected /b request", http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	providers := []config.RuleProvider{
		{Name: "a", Type: "http", URL: server.URL + "/a", Behavior: "domain", Format: "yaml", MaxSize: 1024},
		{Name: "b", Type: "http", URL: server.URL + "/b", Behavior: "domain", Format: "yaml", MaxSize: 1024},
	}
	dir := t.TempDir()
	if _, err := loadWithOptions(context.Background(), providers, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("initial A/B load error = %v", err)
	}
	descriptorA := testCacheDescriptor(t, providers[0], dir)
	descriptorB := testCacheDescriptor(t, providers[1], dir)
	initialA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("read initial A snapshot error = %v", err)
	}
	initialB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("read initial B snapshot error = %v", err)
	}
	if initialB.metadata.Generation != generation || string(initialB.body) != "payload:\n  - b-initial.example\n" {
		t.Fatalf("initial B snapshot = %#v, want generation %q and initial body", initialB, generation)
	}
	initialAState, err := readCurrentState(descriptorA.root)
	if err != nil {
		t.Fatalf("read initial A current state error = %v", err)
	}
	if !initialAState.exists {
		t.Fatal("initial A current state does not exist")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var registry Registry
	var loadErr error
	done := make(chan struct{})
	failAfterStart := func(format string, args ...any) {
		cancel()
		release()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatalf(format, args...)
	}
	go func() {
		registry, loadErr = loadWithOptions(ctx, providers, dir, http.DefaultClient, loadOptions{allowPrivate: true})
		close(done)
	}()

	select {
	case <-aStarted:
	case <-done:
		failAfterStart("second A/B load completed before A preparation barrier: err=%v", loadErr)
	case <-ctx.Done():
		failAfterStart("A preparation barrier was not reached: %v", ctx.Err())
	}

	if _, err := loadWithOptions(ctx, []config.RuleProvider{providers[1]}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		failAfterStart("independent B switch load error = %v", err)
	}
	switchedB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		failAfterStart("read switched B snapshot error = %v", err)
	}
	if string(switchedB.body) != "payload:\n  - b-switched.example\n" {
		failAfterStart("switched B snapshot = %q", switchedB.body)
	}
	switchedBState, err := readCurrentState(descriptorB.root)
	if err != nil {
		failAfterStart("read switched B current state error = %v", err)
	}
	if !switchedBState.exists {
		failAfterStart("switched B current state does not exist")
	}
	release()

	select {
	case <-done:
	case <-ctx.Done():
		failAfterStart("second A/B load did not complete: %v", ctx.Err())
	}

	afterA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("read final A snapshot error = %v", err)
	}
	afterB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("read final B snapshot error = %v", err)
	}
	afterAState, err := readCurrentState(descriptorA.root)
	if err != nil {
		t.Fatalf("read final A current state error = %v", err)
	}
	afterBState, err := readCurrentState(descriptorB.root)
	if err != nil {
		t.Fatalf("read final B current state error = %v", err)
	}
	transactionPath, err := cacheTransactionPath(dir)
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal after no-candidate switch = %v, want absent", err)
	}

	if loadErr != nil {
		t.Logf("second A/B load rejected no-candidate switch as allowed: %v", loadErr)
		if registry != nil {
			t.Fatalf("rejected batch returned non-nil mixed registry: %#v", registry)
		}
		if afterAState.target != initialAState.target || !bytes.Equal(afterA.body, initialA.body) {
			t.Fatalf("rejected batch changed A current: snapshot=%#v state=%#v", afterA, afterAState)
		}
		if !bytes.Equal(afterB.body, switchedB.body) || afterBState.target != switchedBState.target {
			t.Fatalf("rejected batch lost independent B switch: snapshot=%#v state=%#v", afterB, afterBState)
		}
		return
	}

	if len(registry["a"].Functions) != 1 || len(registry["b"].Functions) != 1 {
		t.Fatalf("accepted registry = %#v, want one rule per provider", registry)
	}
	aValue := registry["a"].Functions[0].Params[0].Val
	bValue := registry["b"].Functions[0].Params[0].Val
	if aValue != "a-prepared.example" || bValue != "b-switched.example" {
		t.Fatalf("accepted registry = a:%q b:%q, want current A/B bodies", aValue, bValue)
	}
	if !bytes.Equal(afterA.body, []byte("payload:\n  - a-prepared.example\n")) || !bytes.Equal(afterB.body, switchedB.body) {
		t.Fatalf("accepted cache snapshots are not the same generation of the returned registry: A=%q B=%q", afterA.body, afterB.body)
	}
}

func TestLoadRejects304GenerationDriftAgainstCachedSnapshot(t *testing.T) {
	const (
		body       = "payload:\n  - cached.example\n"
		etag       = `"cached-v1"`
		generation = "one"
	)
	var requestMu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requestCount++
		currentRequest := requestCount
		requestMu.Unlock()
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		if currentRequest == 1 {
			w.Header().Set(providerGenerationHeader, generation)
			_, _ = fmt.Fprint(w, body)
			return
		}
		if currentRequest == 2 {
			w.Header().Set(providerGenerationHeader, "two")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("initial cached load error = %v", err)
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read initial cached snapshot error = %v", err)
	}

	registry, loadErr := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if loadErr == nil {
		t.Fatalf("304 generation drift Load() error = nil, registry=%#v", registry)
	}
	if registry != nil {
		t.Fatalf("304 generation drift returned non-nil registry with error: %v, registry=%#v", loadErr, registry)
	}
	after, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read snapshot after 304 generation drift error = %v", err)
	}
	if after.metadata.Generation != generation || !bytes.Equal(after.body, initial.body) {
		t.Fatalf("304 generation drift changed cached snapshot: loadErr=%v initial=%#v after=%#v", loadErr, initial, after)
	}
	transactionPath, err := cacheTransactionPath(dir)
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal after 304 generation drift = %v, want absent", err)
	}
}

func TestMultiProviderLoadRejectsUnversionedStableMixedBodies(t *testing.T) {
	const (
		oldABody = "payload:\n  - a-old.example\n"
		oldBBody = "payload:\n  - b-old.example\n"
		newBBody = "payload:\n  - b-new.example\n"
	)
	var requestMu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requests[r.URL.Path]++
		requestNumber := requests[r.URL.Path]
		requestMu.Unlock()

		switch r.URL.Path {
		case "/a":
			_, _ = fmt.Fprint(w, oldABody)
		case "/b":
			if requestNumber <= 2 {
				_, _ = fmt.Fprint(w, oldBBody)
				return
			}
			_, _ = fmt.Fprint(w, newBBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	providers := []config.RuleProvider{
		{Name: "a", Type: "http", URL: server.URL + "/a", Behavior: "domain", Format: "yaml", MaxSize: 1024},
		{Name: "b", Type: "http", URL: server.URL + "/b", Behavior: "domain", Format: "yaml", MaxSize: 1024},
	}
	dir := t.TempDir()
	options := loadOptions{allowPrivate: true}

	initialRegistry, err := loadWithOptions(context.Background(), providers, dir, http.DefaultClient, options)
	if err != nil {
		t.Fatalf("initial unversioned A/B load error = %v", err)
	}
	if initialRegistry["a"].Functions[0].Params[0].Val != "a-old.example" || initialRegistry["b"].Functions[0].Params[0].Val != "b-old.example" {
		t.Fatalf("initial registry = %#v, want A-old/B-old", initialRegistry)
	}

	descriptorA := testCacheDescriptor(t, providers[0], dir)
	descriptorB := testCacheDescriptor(t, providers[1], dir)
	initialA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("read initial A snapshot error = %v", err)
	}
	initialB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("read initial B snapshot error = %v", err)
	}
	initialAState, err := readCurrentState(descriptorA.root)
	if err != nil {
		t.Fatalf("read initial A current state error = %v", err)
	}
	initialBState, err := readCurrentState(descriptorB.root)
	if err != nil {
		t.Fatalf("read initial B current state error = %v", err)
	}
	if initialA.metadata.Generation != "" || initialB.metadata.Generation != "" {
		t.Fatalf("initial snapshots unexpectedly have generation tokens: A=%#v B=%#v", initialA.metadata, initialB.metadata)
	}

	registry, loadErr := loadWithOptions(context.Background(), providers, dir, http.DefaultClient, options)
	if loadErr == nil {
		aValue, bValue := "<missing>", "<missing>"
		if rules, ok := registry["a"]; ok && len(rules.Functions) > 0 && len(rules.Functions[0].Params) > 0 {
			aValue = rules.Functions[0].Params[0].Val
		}
		if rules, ok := registry["b"]; ok && len(rules.Functions) > 0 && len(rules.Functions[0].Params) > 0 {
			bValue = rules.Functions[0].Params[0].Val
		}
		t.Fatalf("unversioned stable mixed batch was accepted: a=%q b=%q registry=%#v", aValue, bValue, registry)
	}
	if registry != nil {
		t.Fatalf("unversioned stable mixed batch returned registry with error: err=%v registry=%#v", loadErr, registry)
	}
	message := strings.ToLower(loadErr.Error())
	if !strings.Contains(message, "batch") ||
		(!strings.Contains(message, "consisten") && !strings.Contains(message, "fence") && !strings.Contains(message, "freshness") && !strings.Contains(message, "generation")) {
		t.Fatalf("unversioned stable mixed batch error = %v, want explicit batch consistency/fence error", loadErr)
	}

	afterA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("read final A snapshot error = %v", err)
	}
	afterB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("read final B snapshot error = %v", err)
	}
	afterAState, err := readCurrentState(descriptorA.root)
	if err != nil {
		t.Fatalf("read final A current state error = %v", err)
	}
	afterBState, err := readCurrentState(descriptorB.root)
	if err != nil {
		t.Fatalf("read final B current state error = %v", err)
	}
	if !reflect.DeepEqual(afterA, initialA) || !reflect.DeepEqual(afterAState, initialAState) {
		t.Fatalf("rejected unversioned mixed batch changed A current/cache: initial=%#v/%#v after=%#v/%#v", initialAState, initialA, afterAState, afterA)
	}
	if !reflect.DeepEqual(afterB, initialB) || !reflect.DeepEqual(afterBState, initialBState) {
		t.Fatalf("rejected unversioned mixed batch changed B current/cache: initial=%#v/%#v after=%#v/%#v", initialBState, initialB, afterBState, afterB)
	}
}

func TestMultiProviderLoadRejectsUnversionedMixedLastGoodFallback(t *testing.T) {
	const (
		aOldBody = "payload:\n  - a-old.example\n"
		aNewBody = "payload:\n  - a-new.example\n"
		bOldBody = "payload:\n  - b-old.example\n"
	)
	var requestMu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requests[r.URL.Path]++
		requestNumber := requests[r.URL.Path]
		requestMu.Unlock()

		switch r.URL.Path {
		case "/a":
			switch requestNumber {
			case 1:
				_, _ = fmt.Fprint(w, aOldBody)
			case 2:
				_, _ = fmt.Fprint(w, aNewBody)
			default:
				http.Error(w, "A unavailable", http.StatusServiceUnavailable)
			}
		case "/b":
			if requestNumber == 1 {
				_, _ = fmt.Fprint(w, bOldBody)
				return
			}
			http.Error(w, "B unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	providerA := config.RuleProvider{
		Name: "a", Type: "http", URL: server.URL + "/a", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	providerB := config.RuleProvider{
		Name: "b", Type: "http", URL: server.URL + "/b", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	dir := t.TempDir()
	options := loadOptions{allowPrivate: true}

	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{providerA}, dir, http.DefaultClient, options); err != nil {
		t.Fatalf("initial A-old load error = %v", err)
	}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{providerB}, dir, http.DefaultClient, options); err != nil {
		t.Fatalf("initial B-old load error = %v", err)
	}
	newRegistry, err := loadWithOptions(context.Background(), []config.RuleProvider{providerA}, dir, http.DefaultClient, options)
	if err != nil {
		t.Fatalf("independent A-new load error = %v", err)
	}
	if newRegistry[providerA.Name].Functions[0].Params[0].Val != "a-new.example" {
		t.Fatalf("independent A-new registry = %#v, want A-new", newRegistry)
	}

	providers := []config.RuleProvider{providerA, providerB}
	descriptorA := testCacheDescriptor(t, providerA, dir)
	descriptorB := testCacheDescriptor(t, providerB, dir)
	initialA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("read A-new snapshot error = %v", err)
	}
	initialB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("read B-old snapshot error = %v", err)
	}
	initialAState, err := readCurrentState(descriptorA.root)
	if err != nil {
		t.Fatalf("read A-new current state error = %v", err)
	}
	initialBState, err := readCurrentState(descriptorB.root)
	if err != nil {
		t.Fatalf("read B-old current state error = %v", err)
	}
	if string(initialA.body) != aNewBody || string(initialB.body) != bOldBody || initialA.metadata.Generation != "" || initialB.metadata.Generation != "" {
		t.Fatalf("last-good setup snapshots = A:%#v B:%#v, want unversioned A-new/B-old", initialA, initialB)
	}

	registry, loadErr := loadWithOptions(context.Background(), providers, dir, http.DefaultClient, options)
	if loadErr == nil {
		aValue, bValue := "<missing>", "<missing>"
		if rules, ok := registry["a"]; ok && len(rules.Functions) > 0 && len(rules.Functions[0].Params) > 0 {
			aValue = rules.Functions[0].Params[0].Val
		}
		if rules, ok := registry["b"]; ok && len(rules.Functions) > 0 && len(rules.Functions[0].Params) > 0 {
			bValue = rules.Functions[0].Params[0].Val
		}
		t.Fatalf("unversioned mixed last-good batch was accepted: a=%q b=%q registry=%#v", aValue, bValue, registry)
	}
	if registry != nil {
		t.Fatalf("unversioned mixed last-good batch returned registry with error: err=%v registry=%#v", loadErr, registry)
	}
	message := strings.ToLower(loadErr.Error())
	if !strings.Contains(message, "batch") ||
		(!strings.Contains(message, "consisten") && !strings.Contains(message, "fence") && !strings.Contains(message, "freshness") && !strings.Contains(message, "generation")) {
		t.Fatalf("unversioned mixed last-good batch error = %v, want explicit batch consistency/fence error", loadErr)
	}

	afterA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("read final A snapshot error = %v", err)
	}
	afterB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("read final B snapshot error = %v", err)
	}
	afterAState, err := readCurrentState(descriptorA.root)
	if err != nil {
		t.Fatalf("read final A current state error = %v", err)
	}
	afterBState, err := readCurrentState(descriptorB.root)
	if err != nil {
		t.Fatalf("read final B current state error = %v", err)
	}
	if !reflect.DeepEqual(afterA, initialA) || !reflect.DeepEqual(afterAState, initialAState) {
		t.Fatalf("rejected unversioned mixed last-good batch changed A current/cache: initial=%#v/%#v after=%#v/%#v", initialAState, initialA, afterAState, afterA)
	}
	if !reflect.DeepEqual(afterB, initialB) || !reflect.DeepEqual(afterBState, initialBState) {
		t.Fatalf("rejected unversioned mixed last-good batch changed B current/cache: initial=%#v/%#v after=%#v/%#v", initialBState, initialB, afterBState, afterB)
	}
}

func TestLoadRejects304GenerationWhenCachedSnapshotHasNoToken(t *testing.T) {
	const (
		body = "payload:\n  - cached-without-token.example\n"
		etag = `"cached-no-token-v1"`
	)
	var requestMu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requestCount++
		currentRequest := requestCount
		requestMu.Unlock()
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		switch currentRequest {
		case 1:
			// Establish a valid cached snapshot without a generation token.
			_, _ = fmt.Fprint(w, body)
		case 2:
			w.Header().Set(providerGenerationHeader, "G1")
			w.WriteHeader(http.StatusNotModified)
		default:
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	firstRegistry, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("initial no-token cached Load() error = %v", err)
	}
	if firstRegistry == nil {
		t.Fatal("initial no-token cached Load() registry = nil")
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read initial no-token cached snapshot error = %v", err)
	}
	if initial.metadata.Generation != "" || initial.metadata.GenerationHistory != (generationHistory{}) {
		t.Fatalf("initial snapshot unexpectedly has generation state: %#v", initial.metadata)
	}
	initialCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read initial no-token current state error = %v", err)
	}
	if !initialCurrent.exists {
		t.Fatal("initial no-token current state does not exist")
	}

	registry, loadErr := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if loadErr == nil {
		t.Fatalf("304 generation with token on no-token cache Load() error = nil, registry=%#v", registry)
	}
	if registry != nil {
		t.Fatalf("304 generation with token on no-token cache returned non-nil registry with error: %v, registry=%#v", loadErr, registry)
	}
	after, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read snapshot after no-token 304 generation error = %v", err)
	}
	afterCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read current state after no-token 304 generation error = %v", err)
	}
	if afterCurrent.target != initialCurrent.target || !bytes.Equal(after.body, initial.body) || after.metadata != initial.metadata {
		t.Fatalf("no-token 304 generation changed cached state: loadErr=%v initialCurrent=%#v afterCurrent=%#v initial=%#v after=%#v", loadErr, initialCurrent, afterCurrent, initial, after)
	}
	if after.metadata.Generation != "" || after.metadata.GenerationHistory != (generationHistory{}) {
		t.Fatalf("no-token 304 generation changed generation history: initial=%#v after=%#v", initial.metadata, after.metadata)
	}
	transactionPath, err := cacheTransactionPath(dir)
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal after no-token 304 generation = %v, want absent", err)
	}
}

func TestLoadRejectsFreshBodyChangeWithinSameGeneration(t *testing.T) {
	const (
		generation = "G1"
		bodyA1     = "payload:\n  - a1.example\n"
		bodyA2     = "payload:\n  - a2.example\n"
	)
	var requestMu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requestCount++
		currentRequest := requestCount
		requestMu.Unlock()
		w.Header().Set(providerGenerationHeader, generation)
		switch currentRequest {
		case 1:
			_, _ = fmt.Fprint(w, bodyA1)
		case 2:
			_, _ = fmt.Fprint(w, bodyA2)
		default:
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	firstRegistry, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("initial G1 Load() error = %v", err)
	}
	if firstRegistry == nil {
		t.Fatal("initial G1 Load() registry = nil")
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read initial G1 snapshot error = %v", err)
	}
	initialCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read initial G1 current state error = %v", err)
	}
	if initial.metadata.Generation != generation || string(initial.body) != bodyA1 || !initialCurrent.exists {
		t.Fatalf("initial G1 state = current:%#v snapshot:%#v", initialCurrent, initial)
	}

	secondRegistry, secondErr := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if secondErr != nil {
		t.Logf("same-generation body change rejected as allowed: %v", secondErr)
	}
	if secondErr == nil && secondRegistry != nil {
		t.Fatalf("same-generation body change returned accepted registry: %#v", secondRegistry)
	}
	if secondErr != nil && secondRegistry != nil {
		t.Fatalf("same-generation body change returned registry with error: err=%v registry=%#v", secondErr, secondRegistry)
	}

	after, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read snapshot after same-generation body change error = %v", err)
	}
	afterCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read current state after same-generation body change error = %v", err)
	}
	if afterCurrent.target != initialCurrent.target || !bytes.Equal(after.body, initial.body) || after.metadata != initial.metadata {
		t.Fatalf("same-generation body change mutated last-good snapshot: err=%v initialTarget=%q afterTarget=%q initialBody=%q afterBody=%q initialMetadata=%#v afterMetadata=%#v", secondErr, initialCurrent.target, afterCurrent.target, initial.body, after.body, initial.metadata, after.metadata)
	}
	transactionPath, err := cacheTransactionPath(dir)
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal after same-generation body change = %v, want absent", err)
	}
}

func TestLoadRejectsFreshBodyWhenGenerationHeaderDisappears(t *testing.T) {
	const (
		generation = "G1"
		bodyA1     = "payload:\n  - a1.example\n"
		bodyA2     = "payload:\n  - a2.example\n"
	)
	var requestMu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMu.Lock()
		requestCount++
		currentRequest := requestCount
		requestMu.Unlock()
		switch currentRequest {
		case 1:
			w.Header().Set(providerGenerationHeader, generation)
			_, _ = fmt.Fprint(w, bodyA1)
		case 2:
			// Deliberately omit the generation header on a fresh 200 response.
			_, _ = fmt.Fprint(w, bodyA2)
		default:
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	firstRegistry, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("initial G1 Load() error = %v", err)
	}
	if firstRegistry == nil {
		t.Fatal("initial G1 Load() registry = nil")
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read initial G1 snapshot error = %v", err)
	}
	initialCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read initial G1 current state error = %v", err)
	}
	if initial.metadata.Generation != generation || string(initial.body) != bodyA1 || !initialCurrent.exists {
		t.Fatalf("initial G1 state = current:%#v snapshot:%#v", initialCurrent, initial)
	}

	secondRegistry, secondErr := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	after, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read snapshot after missing generation header error = %v", err)
	}
	afterCurrent, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("read current state after missing generation header error = %v", err)
	}
	if afterCurrent.target != initialCurrent.target || !bytes.Equal(after.body, initial.body) || after.metadata != initial.metadata {
		t.Fatalf("missing generation header mutated last-good snapshot: err=%v initialTarget=%q afterTarget=%q initialBody=%q afterBody=%q initialGeneration=%q afterGeneration=%q initialHistory=%#v afterHistory=%#v", secondErr, initialCurrent.target, afterCurrent.target, initial.body, after.body, initial.metadata.Generation, after.metadata.Generation, initial.metadata.GenerationHistory, after.metadata.GenerationHistory)
	}
	transactionPath, err := cacheTransactionPath(dir)
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal after missing generation header = %v, want absent", err)
	}
	if secondErr == nil && secondRegistry != nil {
		t.Fatalf("fresh response without generation header was accepted: registry=%#v currentTarget=%q generation=%q history=%#v", secondRegistry, afterCurrent.target, after.metadata.Generation, after.metadata.GenerationHistory)
	}
	if secondErr != nil && secondRegistry != nil {
		t.Fatalf("fresh response without generation header returned registry with error: err=%v registry=%#v", secondErr, secondRegistry)
	}
}

func TestLoadDoesNotOverwriteJournalCreatedDuringHTTPPrepare(t *testing.T) {
	const (
		body         = "payload:\n  - stable.example\n"
		etag         = `"stable-v1"`
		lastModified = "Wed, 21 Oct 2015 07:28:00 GMT"
		generation   = "stable"
	)
	secondBodySent := make(chan struct{})
	releaseSecondResponse := make(chan struct{})
	var secondBodyOnce sync.Once
	var releaseOnce sync.Once
	var requestMu sync.Mutex
	requestCount := 0
	var requestErrMu sync.Mutex
	var requestErr error
	recordRequestError := func(err error) {
		requestErrMu.Lock()
		defer requestErrMu.Unlock()
		if requestErr == nil {
			requestErr = err
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", lastModified)
		w.Header().Set(providerGenerationHeader, generation)

		requestMu.Lock()
		requestCount++
		currentRequest := requestCount
		requestMu.Unlock()
		if currentRequest == 2 {
			if got := r.Header.Get("If-None-Match"); got != etag {
				recordRequestError(fmt.Errorf("second request If-None-Match = %q, want %q", got, etag))
			}
			if got := r.Header.Get("If-Modified-Since"); got != lastModified {
				recordRequestError(fmt.Errorf("second request If-Modified-Since = %q, want %q", got, lastModified))
			}
		}
		_, _ = fmt.Fprint(w, body)
		if currentRequest != 2 {
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			recordRequestError(errors.New("second HTTP response does not support flushing"))
		} else {
			flusher.Flush()
		}
		secondBodyOnce.Do(func() { close(secondBodySent) })
		<-releaseSecondResponse
	}))
	defer server.Close()
	defer releaseOnce.Do(func() { close(releaseSecondResponse) })

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	first, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	if len(first[spec.Name].Functions) != 1 || first[spec.Name].Functions[0].Params[0].Val != "stable.example" {
		t.Fatalf("initial registry = %#v", first)
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("read initial cache snapshot error = %v", err)
	}
	if string(initial.body) != body || initial.metadata.ETag != etag || initial.metadata.LastModified != lastModified || initial.metadata.Generation != generation {
		t.Fatalf("initial cache snapshot = %#v, want stable body and headers", initial)
	}
	transactionPath, err := cacheTransactionPath(dir)
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal preflight state = %v, want absent", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var registry Registry
	var loadErr error
	done := make(chan struct{})
	go func() {
		registry, loadErr = loadWithOptions(ctx, []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
		close(done)
	}()

	select {
	case <-secondBodySent:
	case <-done:
		t.Fatalf("second Load() completed before same-body HTTP barrier: err=%v", loadErr)
	case <-ctx.Done():
		t.Fatalf("second same-body HTTP response was not flushed: %v", ctx.Err())
	}

	marker := []byte("TOCTOU-journal-marker-" + t.Name())
	if err := os.WriteFile(transactionPath, marker, 0o600); err != nil {
		t.Fatalf("WriteFile(transaction marker) error = %v", err)
	}
	releaseOnce.Do(func() { close(releaseSecondResponse) })

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("second Load() did not complete after HTTP release: %v", ctx.Err())
	}
	requestErrMu.Lock()
	secondRequestErr := requestErr
	requestErrMu.Unlock()
	if secondRequestErr != nil {
		t.Fatalf("second HTTP response did not reuse cached request headers: %v", secondRequestErr)
	}
	if loadErr == nil {
		t.Fatalf("Load() silently accepted/published over an existing journal marker: registry=%#v", registry)
	}
	message := strings.ToLower(loadErr.Error())
	if !strings.Contains(message, "journal") && !strings.Contains(message, "transaction") {
		t.Fatalf("Load() error = %v, want transaction journal rejection", loadErr)
	}

	gotMarker, err := os.ReadFile(transactionPath)
	if err != nil {
		t.Fatalf("ReadFile(transaction marker) error = %v; journal may have been removed or overwritten", err)
	}
	if !bytes.Equal(gotMarker, marker) {
		t.Fatalf("transaction journal marker = %q, want preserved marker %q", gotMarker, marker)
	}
	if len(registry) != 0 {
		t.Fatalf("Load() returned registry with journal rejection: %#v", registry)
	}

	current, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("readCurrentState() after journal rejection error = %v", err)
	}
	if !current.exists {
		t.Fatalf("cache current disappeared despite journal rejection: %#v", current)
	}
	after, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() after journal rejection error = %v", err)
	}
	if !bytes.Equal(after.body, initial.body) || !reflect.DeepEqual(after.metadata, initial.metadata) {
		t.Fatalf("cache snapshot changed despite journal rejection: initial=%#v after=%#v", initial, after)
	}
	entries, err := os.ReadDir(filepath.Join(descriptor.root, "versions"))
	if err != nil {
		t.Fatalf("ReadDir(cache versions) error = %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".candidate-") {
			t.Fatalf("candidate directory remained after journal rejection: %q", entry.Name())
		}
	}
}

func TestCacheVersionsAreBoundedAfterRepeatedFreshUpdates(t *testing.T) {
	const updates = 6
	request := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request++
		_, _ = fmt.Fprintf(w, "payload:\n  - generation-%d.example\n", request)
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	for i := 0; i < updates; i++ {
		if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
			t.Fatalf("loadWithOptions() update %d error = %v", i, err)
		}
	}

	descriptor := testCacheDescriptor(t, spec, dir)
	entries, err := os.ReadDir(filepath.Join(descriptor.root, "versions"))
	if err != nil {
		t.Fatalf("ReadDir(versions) error = %v", err)
	}
	versionCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			versionCount++
		}
	}
	const maxRetainedVersions = 3 // current plus bounded rollback history
	if versionCount > maxRetainedVersions {
		t.Fatalf("cache retained %d published versions after %d fresh updates, want <= %d", versionCount, updates, maxRetainedVersions)
	}

	current, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("readCurrentState() error = %v", err)
	}
	if !current.exists {
		t.Fatal("cache current is missing after the final fresh update")
	}

	snapshot, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() error = %v", err)
	}
	expectedBody := []byte(fmt.Sprintf("payload:\n  - generation-%d.example\n", updates))
	if !bytes.Equal(snapshot.body, expectedBody) {
		t.Fatalf("current cache body = %q, want final fresh body %q", snapshot.body, expectedBody)
	}
}

func TestMultiProviderLoadRejectsFreshAndLastGoodGenerationMix(t *testing.T) {
	aGeneration := "one"
	aServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(providerGenerationHeader, aGeneration)
		_, _ = fmt.Fprintf(w, "payload:\n  - a-%s.example\n", aGeneration)
	}))
	bServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(providerGenerationHeader, "one")
		_, _ = fmt.Fprint(w, "payload:\n  - b-one.example\n")
	}))

	dir := t.TempDir()
	providers := []config.RuleProvider{
		{Name: "a", Type: "http", URL: aServer.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024},
		{Name: "b", Type: "http", URL: bServer.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024},
	}
	if _, err := loadWithOptions(context.Background(), providers, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		aServer.Close()
		bServer.Close()
		t.Fatalf("initial A1/B1 Load() error = %v", err)
	}
	descriptorA := testCacheDescriptor(t, providers[0], dir)
	descriptorB := testCacheDescriptor(t, providers[1], dir)
	initialA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		aServer.Close()
		bServer.Close()
		t.Fatalf("read initial A1 cache error = %v", err)
	}
	initialB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		aServer.Close()
		bServer.Close()
		t.Fatalf("read initial B1 cache error = %v", err)
	}
	if initialA.metadata.Generation != "one" || initialB.metadata.Generation != "one" {
		aServer.Close()
		bServer.Close()
		t.Fatalf("initial cache generations = A:%q B:%q, want one/one", initialA.metadata.Generation, initialB.metadata.Generation)
	}

	aGeneration = "two"
	bServer.Close()
	second, err := loadWithOptions(context.Background(), providers, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		message := strings.ToLower(err.Error())
		if !strings.Contains(message, "generation") || !strings.Contains(message, "mismatch") {
			aServer.Close()
			t.Fatalf("fresh/last-good Load() error = %v, want generation mismatch rejection", err)
		}
	} else {
		aRules := second["a"].Functions
		bRules := second["b"].Functions
		if len(aRules) != 1 || len(bRules) != 1 {
			aServer.Close()
			t.Fatalf("fresh/last-good fallback registry = %#v, want one rule per provider", second)
		}
		aValue := aRules[0].Params[0].Val
		bValue := bRules[0].Params[0].Val
		if strings.HasPrefix(aValue, "a-two.") && strings.HasPrefix(bValue, "b-one.") {
			aServer.Close()
			t.Fatalf("Load() returned fresh/last-good mixed registry: a=%q b=%q", aValue, bValue)
		}
		aGenerationValue := strings.TrimSuffix(strings.TrimPrefix(aValue, "a-"), ".example")
		bGenerationValue := strings.TrimSuffix(strings.TrimPrefix(bValue, "b-"), ".example")
		if aGenerationValue == "" || aGenerationValue != bGenerationValue {
			aServer.Close()
			t.Fatalf("Load() returned non-uniform fallback generations: a=%q b=%q", aValue, bValue)
		}
	}
	aServer.Close()

	currentA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("read A cache after fresh/last-good batch error = %v", err)
	}
	currentB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("read B cache after fresh/last-good batch error = %v", err)
	}
	if string(currentA.body) != string(initialA.body) || currentA.metadata != initialA.metadata {
		t.Fatalf("A cache changed after rejected/fallback batch: initial=%#v current=%#v", initialA, currentA)
	}
	if string(currentB.body) != string(initialB.body) || currentB.metadata != initialB.metadata {
		t.Fatalf("B cache changed after rejected/fallback batch: initial=%#v current=%#v", initialB, currentB)
	}
}

func TestRestartRecoversInterruptedMultiProviderPublishWithoutMixedGeneration(t *testing.T) {
	generation := "one"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "payload:\n  - generation-%s.example\n", generation)
	}))

	dir := t.TempDir()
	providers := []config.RuleProvider{
		{Name: "a", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024},
		{Name: "b", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024},
	}
	if _, err := loadWithOptions(context.Background(), providers, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		server.Close()
		t.Fatalf("initial multi-provider load error = %v", err)
	}
	descriptorA := testCacheDescriptor(t, providers[0], dir)
	descriptorB := testCacheDescriptor(t, providers[1], dir)
	oldA, err := readCurrentState(descriptorA.root)
	if err != nil {
		server.Close()
		t.Fatalf("readCurrentState(a) error = %v", err)
	}
	oldB, err := readCurrentState(descriptorB.root)
	if err != nil {
		server.Close()
		t.Fatalf("readCurrentState(b) error = %v", err)
	}

	// Model a process dying after provider a switched but before provider b did.
	generation = "two"
	if _, err := loadWithOptions(context.Background(), providers[:1], dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		server.Close()
		t.Fatalf("partial publish setup error = %v", err)
	}
	newA, err := readCurrentState(descriptorA.root)
	if err != nil {
		server.Close()
		t.Fatalf("readCurrentState(a) after partial publish error = %v", err)
	}
	if newA.target == oldA.target || oldB.target == "" {
		server.Close()
		t.Fatalf("partial publish fixture did not create one switched provider: oldA=%#v newA=%#v oldB=%#v", oldA, newA, oldB)
	}

	// The aggregate journal is the persisted recovery contract for a restart.
	type journalEntry struct {
		OldCurrent string `json:"old_current"`
		NewCurrent string `json:"new_current"`
	}
	journal := struct {
		SchemaVersion int                     `json:"schema_version"`
		State         string                  `json:"state"`
		Generation    string                  `json:"generation"`
		Providers     map[string]journalEntry `json:"providers"`
	}{
		SchemaVersion: 1,
		State:         "publishing",
		Generation:    "two",
		Providers: map[string]journalEntry{
			"a": {OldCurrent: oldA.target, NewCurrent: newA.target},
			"b": {OldCurrent: oldB.target},
		},
	}
	journalBody, err := json.Marshal(journal)
	if err != nil {
		server.Close()
		t.Fatalf("json.Marshal(journal) error = %v", err)
	}
	journalPath := filepath.Join(filepath.Dir(descriptorA.root), "transaction.journal")
	if err := os.WriteFile(journalPath, journalBody, 0o600); err != nil {
		server.Close()
		t.Fatalf("WriteFile(transaction.journal) error = %v", err)
	}
	server.Close()

	if _, err := loadWithOptions(context.Background(), providers, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("restart load with network failure error = %v", err)
	}
	afterA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("readCacheSnapshot(a) after restart error = %v", err)
	}
	afterB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("readCacheSnapshot(b) after restart error = %v", err)
	}
	wantBody := "payload:\n  - generation-one.example\n"
	if string(afterA.body) != wantBody || string(afterB.body) != wantBody {
		t.Fatalf("restart left mixed provider generations: a=%q b=%q", afterA.body, afterB.body)
	}
}

func TestConcurrentPublishAndRecoveryKeepsTransactionRootConsistent(t *testing.T) {
	dir := t.TempDir()
	providers := []config.RuleProvider{
		{Name: "a", Type: "file", Path: "a.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024},
		{Name: "b", Type: "file", Path: "b.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024},
	}
	writeProvider := func(path, generation string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, path), []byte(fmt.Sprintf("payload:\n  - generation-%s.example\n", generation)), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	writeProvider("a.yaml", "one")
	writeProvider("b.yaml", "one")
	if _, err := loadWithOptions(context.Background(), providers, dir, nil, loadOptions{}); err != nil {
		t.Fatalf("initial multi-provider file load error = %v", err)
	}
	descriptorA := testCacheDescriptor(t, providers[0], dir)
	descriptorB := testCacheDescriptor(t, providers[1], dir)
	oldA, err := readCurrentState(descriptorA.root)
	if err != nil {
		t.Fatalf("readCurrentState(a) error = %v", err)
	}
	oldB, err := readCurrentState(descriptorB.root)
	if err != nil {
		t.Fatalf("readCurrentState(b) error = %v", err)
	}

	writeProvider("a.yaml", "two")
	if _, err := loadWithOptions(context.Background(), providers[:1], dir, nil, loadOptions{}); err != nil {
		t.Fatalf("partial publish setup error = %v", err)
	}
	newA, err := readCurrentState(descriptorA.root)
	if err != nil {
		t.Fatalf("readCurrentState(a) after partial publish error = %v", err)
	}
	if newA.target == oldA.target || oldB.target == "" {
		t.Fatalf("partial publish fixture did not create one switched provider: oldA=%#v newA=%#v oldB=%#v", oldA, newA, oldB)
	}
	writeProvider("b.yaml", "two")

	journalPath := filepath.Join(filepath.Dir(descriptorA.root), "transaction.journal")
	journal := cacheTransaction{
		SchemaVersion: cacheTransactionVersion,
		State:         "publishing",
		Generation:    "fixture-generation",
		Providers: map[string]cacheTransactionEntry{
			"a": {OldCurrent: oldA.target, NewCurrent: newA.target},
			"b": {OldCurrent: oldB.target, NewCurrent: oldB.target},
		},
	}
	journalBody, err := json.Marshal(journal)
	if err != nil {
		t.Fatalf("json.Marshal(journal) error = %v", err)
	}
	if err := os.WriteFile(journalPath, journalBody, 0o600); err != nil {
		t.Fatalf("WriteFile(transaction.journal) error = %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 8)
	var waitGroup sync.WaitGroup
	for i := 0; i < 4; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			results <- recoverPendingPublish(dir)
		}()
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := loadWithOptions(context.Background(), providers, dir, nil, loadOptions{})
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent publish/recovery error = %v", err)
		}
	}

	if _, err := os.Lstat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal stat error = %v, want journal consumed", err)
	}
	afterA, err := readCacheSnapshot(descriptorA)
	if err != nil {
		t.Fatalf("readCacheSnapshot(a) after concurrent recovery error = %v", err)
	}
	afterB, err := readCacheSnapshot(descriptorB)
	if err != nil {
		t.Fatalf("readCacheSnapshot(b) after concurrent recovery error = %v", err)
	}
	wantBody := "payload:\n  - generation-two.example\n"
	if string(afterA.body) != wantBody || string(afterB.body) != wantBody {
		t.Fatalf("concurrent publish/recovery left mixed current generations: a=%q b=%q", afterA.body, afterB.body)
	}
}

func TestCrossProcessRecoveryHonorsTransactionFlock(t *testing.T) {
	dir := t.TempDir()
	provider := config.RuleProvider{
		Name: "p", Type: "file", Path: "rules.yaml", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	if err := os.WriteFile(filepath.Join(dir, provider.Path), []byte("payload:\n  - first.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(provider) error = %v", err)
	}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{provider}, dir, nil, loadOptions{}); err != nil {
		t.Fatalf("initial file provider load error = %v", err)
	}
	descriptor := testCacheDescriptor(t, provider, dir)
	current, err := readCurrentState(descriptor.root)
	if err != nil {
		t.Fatalf("readCurrentState() error = %v", err)
	}
	if !current.exists || current.target == "" {
		t.Fatalf("current state = %#v, want published snapshot", current)
	}
	transactionPath := filepath.Join(filepath.Dir(descriptor.root), "transaction.journal")
	journal := cacheTransaction{
		SchemaVersion: cacheTransactionVersion,
		State:         "publishing",
		Generation:    "cross-process-fixture",
		Providers: map[string]cacheTransactionEntry{
			"p": {OldCurrent: current.target, NewCurrent: current.target},
		},
	}
	if err := writeCacheTransaction(transactionPath, journal); err != nil {
		t.Fatalf("write transaction journal fixture error = %v", err)
	}

	startHelper := func(mode string, withInput bool) (*exec.Cmd, io.WriteCloser, *bufio.Reader, <-chan error, error) {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestCrossProcessRecoveryHelper$")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		var input io.WriteCloser
		if withInput {
			input, err = cmd.StdinPipe()
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}
		cmd.Env = append(os.Environ(),
			"DAE_RULE_PROVIDER_CROSS_PROCESS_MODE="+mode,
			"DAE_RULE_PROVIDER_CROSS_PROCESS_BASE="+dir,
		)
		if err := cmd.Start(); err != nil {
			return nil, nil, nil, nil, err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		return cmd, input, bufio.NewReader(stdout), done, nil
	}

	holder, holderInput, holderOutput, holderDone, err := startHelper("hold", true)
	if err != nil {
		t.Fatalf("start transaction-lock helper error = %v", err)
	}
	holderDoneConsumed := false
	t.Cleanup(func() {
		if holderDoneConsumed {
			return
		}
		_ = holderInput.Close()
		_ = holder.Process.Kill()
		select {
		case <-holderDone:
		case <-time.After(2 * time.Second):
			t.Errorf("transaction-lock helper did not exit during cleanup")
		}
	})
	ready := make(chan string, 1)
	go func() {
		line, readErr := holderOutput.ReadString('\n')
		if readErr != nil {
			ready <- fmt.Sprintf("read error: %v", readErr)
			return
		}
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatalf("transaction-lock helper readiness = %q, want ready", line)
		}
	case err := <-holderDone:
		holderDoneConsumed = true
		t.Fatalf("transaction-lock helper exited before readiness: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for transaction-lock helper readiness")
	}

	recovery, _, recoveryOutput, recoveryDone, err := startHelper("recover", false)
	if err != nil {
		t.Fatalf("start recovery helper error = %v", err)
	}
	recoveryDoneConsumed := false
	t.Cleanup(func() {
		if recoveryDoneConsumed {
			return
		}
		_ = recovery.Process.Kill()
		select {
		case <-recoveryDone:
		case <-time.After(2 * time.Second):
			t.Errorf("recovery helper did not exit during cleanup")
		}
	})
	started := make(chan string, 1)
	go func() {
		line, readErr := recoveryOutput.ReadString('\n')
		if readErr != nil {
			started <- fmt.Sprintf("read error: %v", readErr)
			return
		}
		started <- line
	}()
	select {
	case line := <-started:
		if line != "started\n" {
			t.Fatalf("recovery helper start marker = %q, want started", line)
		}
	case err := <-recoveryDone:
		recoveryDoneConsumed = true
		t.Fatalf("recovery helper exited before attempting recovery: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for recovery helper start marker")
	}
	select {
	case err := <-recoveryDone:
		recoveryDoneConsumed = true
		t.Fatalf("recovery helper completed while another process held transaction flock: %v", err)
	case <-time.After(1 * time.Second):
	}

	if _, err := holderInput.Write([]byte{'x'}); err != nil {
		t.Fatalf("release transaction-lock helper error = %v", err)
	}
	if err := holderInput.Close(); err != nil {
		t.Fatalf("close transaction-lock helper stdin error = %v", err)
	}
	select {
	case err := <-holderDone:
		holderDoneConsumed = true
		if err != nil {
			t.Fatalf("transaction-lock helper exit error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for transaction-lock helper release")
	}
	select {
	case err := <-recoveryDone:
		recoveryDoneConsumed = true
		if err != nil {
			t.Fatalf("recovery helper exit error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for recovery helper after flock release")
	}
	if _, err := os.Lstat(transactionPath); !os.IsNotExist(err) {
		t.Fatalf("transaction journal stat error = %v, want journal consumed", err)
	}
	if _, err := readCacheSnapshot(descriptor); err != nil {
		t.Fatalf("readCacheSnapshot() after cross-process recovery error = %v", err)
	}
}

func TestCrossProcessRecoveryHelper(t *testing.T) {
	mode := os.Getenv("DAE_RULE_PROVIDER_CROSS_PROCESS_MODE")
	if mode == "" {
		return
	}
	transactionPath, err := cacheTransactionPath(os.Getenv("DAE_RULE_PROVIDER_CROSS_PROCESS_BASE"))
	if err != nil {
		t.Fatalf("cacheTransactionPath() error = %v", err)
	}
	transactionRoot := filepath.Dir(transactionPath)
	switch mode {
	case "hold":
		lock, err := acquireTransactionLock(transactionRoot)
		if err != nil {
			t.Fatalf("acquireTransactionLock() error = %v", err)
		}
		defer lock.Close()
		_, _ = fmt.Fprintln(os.Stdout, "ready")
		var signal [1]byte
		_, _ = os.Stdin.Read(signal[:])
	case "recover":
		_, _ = fmt.Fprintln(os.Stdout, "started")
		if err := recoverPendingPublish(os.Getenv("DAE_RULE_PROVIDER_CROSS_PROCESS_BASE")); err != nil {
			t.Fatalf("recoverPendingPublish() error = %v", err)
		}
		_, _ = fmt.Fprintln(os.Stdout, "done")
	default:
		t.Fatalf("unknown cross-process helper mode %q", mode)
	}
}

func TestLoadHTTPProviderRetainsLastGoodAfterInvalidUpdateAndNetworkFailure(t *testing.T) {
	mode := "good"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "good":
			_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
		case "invalid":
			_, _ = fmt.Fprint(w, "payload: []\n")
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	var err error
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() error = %v", err)
	}

	mode = "invalid"
	result, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("invalid HTTP update Load() error = %v", err)
	}
	if len(result["p"].Functions) != 1 {
		t.Fatalf("invalid HTTP update result = %#v", result)
	}
	afterInvalid, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() after invalid HTTP update error = %v", err)
	}
	if string(afterInvalid.body) != string(initial.body) || afterInvalid.metadata != initial.metadata {
		t.Fatalf("cache changed after invalid HTTP update: initial=%#v current=%#v", initial, afterInvalid)
	}

	conf := &config.Config{
		RuleProvider: []config.RuleProvider{spec},
		Routing: config.Routing{Rules: []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name:   "domain",
				Params: []*config_parser.Param{{Key: "suffix", Val: "example.com"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}}},
	}
	lastGoodRules := []*config_parser.RoutingRule{cloneRule(conf.Routing.Rules[0])}
	if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("invalid HTTP update LoadAndExpand() error = %v", err)
	}
	if !reflect.DeepEqual(conf.Routing.Rules, lastGoodRules) {
		t.Fatalf("conf changed after invalid HTTP update: before=%#v after=%#v", lastGoodRules, conf.Routing.Rules)
	}

	server.Close()
	if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("network failure LoadAndExpand() error = %v", err)
	}
	current, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() after failures error = %v", err)
	}
	if string(current.body) != string(initial.body) || current.metadata != initial.metadata {
		t.Fatalf("cache changed after network failure: initial=%#v current=%#v", initial, current)
	}
	if !reflect.DeepEqual(conf.Routing.Rules, lastGoodRules) {
		t.Fatalf("conf changed after network failure: before=%#v after=%#v", lastGoodRules, conf.Routing.Rules)
	}
}

func TestPrepareProviderUsesValidatedCacheAfterSecurityFetchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	descriptor := testCacheDescriptor(t, spec, dir)
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() error = %v", err)
	}
	resolvedBase, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	prepared, err := prepareProvider(context.Background(), spec, resolvedBase, http.DefaultClient, loadOptions{})
	if err != nil {
		t.Fatalf("prepareProvider() error = %v", err)
	}
	if len(prepared.rules.Functions) != 1 || prepared.rules.Functions[0].Name != "domain" {
		t.Fatalf("prepared rules = %#v", prepared.rules)
	}
	if prepared.candidate != nil {
		t.Fatalf("prepared cache candidate = %#v, want nil on security fallback", prepared.candidate)
	}
	current, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() after security fallback error = %v", err)
	}
	if string(current.body) != string(initial.body) || current.metadata != initial.metadata {
		t.Fatalf("cache changed after security fallback: initial=%#v current=%#v", initial, current)
	}
}

func TestReadCacheRejectsMetadataIsolationAndCorruption(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
	}))
	defer server.Close()

	cases := map[string]func(*cacheMetadata){
		"schema":      func(metadata *cacheMetadata) { metadata.SchemaVersion++ },
		"provider":    func(metadata *cacheMetadata) { metadata.ProviderName = "other" },
		"source-type": func(metadata *cacheMetadata) { metadata.SourceType = "file" },
		"source":      func(metadata *cacheMetadata) { metadata.Source = "https://other.example/rules.yaml" },
		"source-key":  func(metadata *cacheMetadata) { metadata.SourceKey = "tampered" },
		"behavior":    func(metadata *cacheMetadata) { metadata.Behavior = "ipcidr" },
		"format":      func(metadata *cacheMetadata) { metadata.Format = "text" },
		"max-size":    func(metadata *cacheMetadata) { metadata.MaxSize++ },
	}
	for name, mutate := range cases {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			spec := config.RuleProvider{Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024}
			if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
				t.Fatalf("initial Load() error = %v", err)
			}
			descriptor := testCacheDescriptor(t, spec, dir)
			state, err := readCurrentState(descriptor.root)
			if err != nil {
				t.Fatalf("readCurrentState() error = %v", err)
			}
			metadataPath := filepath.Join(state.resolved, "metadata.json")
			metadataBody, err := os.ReadFile(metadataPath)
			if err != nil {
				t.Fatalf("ReadFile(metadata) error = %v", err)
			}
			var metadata cacheMetadata
			if err := json.Unmarshal(metadataBody, &metadata); err != nil {
				t.Fatalf("json.Unmarshal(metadata) error = %v", err)
			}
			mutate(&metadata)
			metadataBody, err = json.Marshal(metadata)
			if err != nil {
				t.Fatalf("json.Marshal(metadata) error = %v", err)
			}
			if err := os.WriteFile(metadataPath, metadataBody, 0o600); err != nil {
				t.Fatalf("WriteFile(metadata) error = %v", err)
			}
			if _, err := readCacheSnapshot(descriptor); err == nil {
				t.Fatal("readCacheSnapshot() error = nil for isolated metadata")
			}
		})
	}

	t.Run("checksum", func(t *testing.T) {
		dir := t.TempDir()
		spec := config.RuleProvider{Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024}
		if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
			t.Fatalf("initial Load() error = %v", err)
		}
		descriptor := testCacheDescriptor(t, spec, dir)
		var err error
		state, err := readCurrentState(descriptor.root)
		if err != nil {
			t.Fatalf("readCurrentState() error = %v", err)
		}
		bodyPath := filepath.Join(state.resolved, "body")
		body, err := os.ReadFile(bodyPath)
		if err != nil {
			t.Fatalf("ReadFile(body) error = %v", err)
		}
		body[0] ^= 1
		if err := os.WriteFile(bodyPath, body, 0o600); err != nil {
			t.Fatalf("WriteFile(body) error = %v", err)
		}
		if _, err := readCacheSnapshot(descriptor); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("readCacheSnapshot() error = %v, want checksum error", err)
		}
	})

	t.Run("corrupt-metadata", func(t *testing.T) {
		dir := t.TempDir()
		spec := config.RuleProvider{Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024}
		if _, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
			t.Fatalf("initial Load() error = %v", err)
		}
		descriptor := testCacheDescriptor(t, spec, dir)
		var err error
		state, err := readCurrentState(descriptor.root)
		if err != nil {
			t.Fatalf("readCurrentState() error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(state.resolved, "metadata.json"), []byte("{"), 0o600); err != nil {
			t.Fatalf("WriteFile(metadata) error = %v", err)
		}
		if _, err := readCacheSnapshot(descriptor); err == nil {
			t.Fatal("readCacheSnapshot() error = nil for corrupt metadata")
		}
	})
}

func TestLoadDoesNotUseCacheWhenHTTPSourceChanges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
	}))
	dir := t.TempDir()
	first := config.RuleProvider{Name: "p", Type: "http", URL: server.URL + "/first", Behavior: "domain", Format: "yaml", MaxSize: 1024}
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{first}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err != nil {
		server.Close()
		t.Fatalf("initial Load() error = %v", err)
	}
	descriptor := testCacheDescriptor(t, first, dir)
	var err error
	initial, err := readCacheSnapshot(descriptor)
	if err != nil {
		server.Close()
		t.Fatalf("readCacheSnapshot() error = %v", err)
	}
	server.Close()

	changed := first
	changed.URL = server.URL + "/changed"
	if _, err := loadWithOptions(context.Background(), []config.RuleProvider{changed}, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err == nil {
		t.Fatal("Load() error = nil for changed source with unavailable network")
	}
	current, err := readCacheSnapshot(descriptor)
	if err != nil {
		t.Fatalf("readCacheSnapshot() after source change error = %v", err)
	}
	if string(current.body) != string(initial.body) || current.metadata != initial.metadata {
		t.Fatalf("cache changed after source mismatch: initial=%#v current=%#v", initial, current)
	}
}

func TestReadCurrentStateRejectsNonCanonicalTarget(t *testing.T) {
	for _, target := range []string{
		"versions/./version-1",
		"versions/nested/../version-1",
		"versions/../versions/version-1",
	} {
		t.Run(target, func(t *testing.T) {
			baseDir := t.TempDir()
			root := filepath.Join(baseDir, "persist.d", "rule-providers", "p")
			versionDir := filepath.Join(root, "versions", "version-1")
			if err := os.MkdirAll(versionDir, 0o700); err != nil {
				t.Fatalf("MkdirAll(version) error = %v", err)
			}
			if strings.Contains(target, "nested") {
				if err := os.Mkdir(filepath.Join(root, "versions", "nested"), 0o700); err != nil {
					t.Fatalf("Mkdir(nested) error = %v", err)
				}
			}
			if err := os.Symlink(target, filepath.Join(root, "current")); err != nil {
				t.Fatalf("Symlink(current) error = %v", err)
			}

			state, err := readCurrentState(root)
			if err == nil {
				t.Fatalf("readCurrentState(%q) = %#v, want rejection of non-canonical target", target, state)
			}
		})
	}
}

func TestLoadAcceptsFreshValidProviderSourceChange(t *testing.T) {
	const (
		oldBody = "payload:\n  - old.example\n"
		newBody = "payload:\n  - new.example\n"
	)
	var sourceMu sync.Mutex
	newAvailable := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/old":
			w.Header().Set(providerGenerationHeader, "G1")
			_, _ = fmt.Fprint(w, oldBody)
		case "/new":
			sourceMu.Lock()
			available := newAvailable
			sourceMu.Unlock()
			if !available {
				http.Error(w, "new source unavailable", http.StatusBadGateway)
				return
			}
			w.Header().Set(providerGenerationHeader, "G2")
			_, _ = fmt.Fprint(w, newBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	spec := config.RuleProvider{
		Name: "p", Type: "http", URL: server.URL + "/old", Behavior: "domain", Format: "yaml", MaxSize: 1024,
	}
	oldRegistry, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("initial old-source Load() error = %v", err)
	}
	if rules, ok := oldRegistry[spec.Name]; !ok || len(rules.Functions) != 1 || rules.Functions[0].Params[0].Val != "old.example" {
		t.Fatalf("initial old-source registry = %#v", oldRegistry)
	}
	oldDescriptor := testCacheDescriptor(t, spec, dir)
	oldSnapshot, err := readCacheSnapshot(oldDescriptor)
	if err != nil {
		t.Fatalf("read old-source snapshot error = %v", err)
	}
	if string(oldSnapshot.body) != oldBody || oldSnapshot.metadata.Source != oldDescriptor.source || oldSnapshot.metadata.SourceKey != oldDescriptor.sourceKey || oldSnapshot.metadata.Generation != "G1" {
		t.Fatalf("old-source snapshot = %#v, want body/source/source-key/generation for old source", oldSnapshot)
	}

	spec.URL = server.URL + "/new"
	newRegistry, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("fresh valid source-change Load() error = %v", err)
	}
	if rules, ok := newRegistry[spec.Name]; !ok || len(rules.Functions) != 1 || rules.Functions[0].Params[0].Val != "new.example" {
		t.Fatalf("new-source registry = %#v, want new.example", newRegistry)
	}
	newDescriptor := testCacheDescriptor(t, spec, dir)
	newSnapshot, err := readCacheSnapshot(newDescriptor)
	if err != nil {
		t.Fatalf("read new-source snapshot error = %v", err)
	}
	if string(newSnapshot.body) != newBody || newSnapshot.metadata.Source != newDescriptor.source || newSnapshot.metadata.SourceKey != newDescriptor.sourceKey || newSnapshot.metadata.Generation != "G2" {
		t.Fatalf("new-source snapshot = %#v, want body/source/source-key/generation for new source", newSnapshot)
	}
	if newSnapshot.metadata.Source == oldSnapshot.metadata.Source || newSnapshot.metadata.SourceKey == oldSnapshot.metadata.SourceKey {
		t.Fatalf("source rotation did not change cache identity: old=%#v new=%#v", oldSnapshot.metadata, newSnapshot.metadata)
	}

	sourceMu.Lock()
	newAvailable = false
	sourceMu.Unlock()
	lastGoodRegistry, err := loadWithOptions(context.Background(), []config.RuleProvider{spec}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("new-source network-failure Load() error = %v, want new-source last-good fallback", err)
	}
	if rules, ok := lastGoodRegistry[spec.Name]; !ok || len(rules.Functions) != 1 || rules.Functions[0].Params[0].Val != "new.example" {
		t.Fatalf("registry after new-source network failure = %#v, want new.example", lastGoodRegistry)
	}
	lastGoodSnapshot, err := readCacheSnapshot(newDescriptor)
	if err != nil {
		t.Fatalf("read snapshot after new-source network failure error = %v", err)
	}
	if string(lastGoodSnapshot.body) != newBody || lastGoodSnapshot.metadata != newSnapshot.metadata {
		t.Fatalf("new-source last-good snapshot changed after network failure: initial=%#v current=%#v", newSnapshot, lastGoodSnapshot)
	}
}

func TestLoadAcceptsFreshValidProviderSemanticChange(t *testing.T) {
	const body = "payload:\n  - example.com\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()
	dir := t.TempDir()
	first := config.RuleProvider{Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024}
	initial, err := loadWithOptions(context.Background(), []config.RuleProvider{first}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	if rules, ok := initial[first.Name]; !ok || len(rules.Functions) != 1 || rules.Functions[0].Name != "domain" || len(rules.Functions[0].Params) != 1 || rules.Functions[0].Params[0].Key != "suffix" || rules.Functions[0].Params[0].Val != "example.com" {
		t.Fatalf("initial registry = %#v, want one domain suffix rule", initial)
	}
	initialDescriptor := testCacheDescriptor(t, first, dir)
	initialSnapshot, err := readCacheSnapshot(initialDescriptor)
	if err != nil {
		t.Fatalf("read initial snapshot error = %v", err)
	}
	if initialSnapshot.metadata.Behavior != "domain" || string(initialSnapshot.body) != body {
		t.Fatalf("initial snapshot = %#v, want domain behavior and body %q", initialSnapshot, body)
	}

	second := first
	second.Behavior = "classical"
	registry, err := loadWithOptions(context.Background(), []config.RuleProvider{second}, dir, http.DefaultClient, loadOptions{allowPrivate: true})
	if err != nil {
		t.Fatalf("fresh valid semantic-change Load() error = %v", err)
	}
	if rules, ok := registry[second.Name]; !ok || len(rules.Functions) != 1 || rules.Functions[0].Name != "domain" || len(rules.Functions[0].Params) != 1 || rules.Functions[0].Params[0].Key != "suffix" || rules.Functions[0].Params[0].Val != "example.com" {
		t.Fatalf("semantic-change registry = %#v, want one domain suffix rule", registry)
	}
	secondDescriptor := testCacheDescriptor(t, second, dir)
	current, err := readCurrentState(secondDescriptor.root)
	if err != nil {
		t.Fatalf("read current state after semantic change error = %v", err)
	}
	if !current.exists {
		t.Fatal("current state after semantic change does not exist")
	}
	updated, err := readCacheSnapshot(secondDescriptor)
	if err != nil {
		t.Fatalf("read snapshot after semantic change error = %v", err)
	}
	if string(updated.body) != body || updated.metadata.Behavior != "classical" || updated.metadata.Source != secondDescriptor.source || updated.metadata.SourceKey != secondDescriptor.sourceKey {
		t.Fatalf("updated snapshot = %#v, want classical behavior with unchanged source identity", updated)
	}
}

func TestLoadAndExpandDoesNotPublishHTTPCacheWhenExpansionExceedsLimit(t *testing.T) {
	makeBody := func(prefix string) string {
		var body strings.Builder
		for i := 0; i < 400; i++ {
			fmt.Fprintf(&body, "%s-%d.example\n", prefix, i)
		}
		return body.String()
	}
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, makeBody("a")) }))
	defer serverA.Close()
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, makeBody("b")) }))
	defer serverB.Close()
	sections, err := config_parser.Parse(`
routing {
  ruleset(a) && ruleset(b) -> proxy
  fallback: direct
}
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var routing config.Routing
	if err := config.SectionParser(reflect.ValueOf(&routing), sections[0]); err != nil {
		t.Fatalf("SectionParser() error = %v", err)
	}
	dir := t.TempDir()
	conf := &config.Config{
		RuleProvider: []config.RuleProvider{
			{Name: "a", Type: "http", URL: serverA.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20},
			{Name: "b", Type: "http", URL: serverB.URL, Behavior: "domain", Format: "text", MaxSize: 1 << 20},
		},
		Routing: routing,
	}
	if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err == nil {
		t.Fatal("loadAndExpandWithOptions() error = nil for oversized Cartesian product")
	}
	if len(conf.Routing.Rules) != 1 || conf.Routing.Rules[0].AndFunctions[0].Name != "ruleset" {
		t.Fatalf("routing rules mutated after failed expansion: %#v", conf.Routing.Rules)
	}
	for _, name := range []string{"a", "b"} {
		if _, err := os.Stat(filepath.Join(dir, "persist.d", "rule-providers", name, "current")); !os.IsNotExist(err) {
			t.Fatalf("cache current for %s = %v, want absent", name, err)
		}
	}
}

func TestLoadAndExpandDoesNotMutateConfigWhenCachePublishFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "payload:\n  - example.com\n")
	}))
	defer server.Close()
	sections, err := config_parser.Parse(`
routing {
  ruleset(p) -> proxy
  fallback: direct
}
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var routing config.Routing
	if err := config.SectionParser(reflect.ValueOf(&routing), sections[0]); err != nil {
		t.Fatalf("SectionParser() error = %v", err)
	}
	dir := t.TempDir()
	cacheRoot := filepath.Join(dir, "persist.d", "rule-providers")
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheRoot, "p"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	conf := &config.Config{
		RuleProvider: []config.RuleProvider{{Name: "p", Type: "http", URL: server.URL, Behavior: "domain", Format: "yaml", MaxSize: 1024}},
		Routing:      routing,
	}
	if err := loadAndExpandWithOptions(context.Background(), conf, dir, http.DefaultClient, loadOptions{allowPrivate: true}); err == nil {
		t.Fatal("loadAndExpandWithOptions() error = nil for cache publish failure")
	}
	if len(conf.Routing.Rules) != 1 || conf.Routing.Rules[0].AndFunctions[0].Name != "ruleset" {
		t.Fatalf("routing rules mutated after cache publish failure: %#v", conf.Routing.Rules)
	}
}

func TestExpandRulesetRejectsOversizedProviderBeforeAllocation(t *testing.T) {
	replacement := &config_parser.Function{Name: "domain"}
	functions := make([]*config_parser.Function, maxExpandedRoutingRules+1)
	for index := range functions {
		functions[index] = replacement
	}
	original := &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{Name: "ruleset", Params: []*config_parser.Param{{Val: "large"}}}},
		Outbound:     config_parser.Function{Name: "proxy"},
	}
	if _, err := ExpandRoutingRules([]*config_parser.RoutingRule{original}, Registry{"large": {Functions: functions}}); err == nil {
		t.Fatal("ExpandRoutingRules() error = nil for oversized provider")
	}
	if original.AndFunctions[0].Name != "ruleset" {
		t.Fatalf("original routing rule mutated: %#v", original)
	}
}
