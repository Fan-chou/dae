package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMihomoConfigReadsNodeConversionFields(t *testing.T) {
	config, err := ParseMihomoConfig([]byte(`proxies:
  - name: anytls-node
    type: anytls
    server: anytls.example
    port: 443
    password: anytls-secret
    sni: edge.example
    servername: edge.example
    client-fingerprint: chrome
    tls: true
    skip-cert-verify: true
    udp: true
  - name: ss-node
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-256-gcm
    password: ss-secret
    plugin: shadow-tls
    plugin-opts:
      password: plugin-secret
      version: 3
  - name: socks-node
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: user
    password: socks-secret
  - name: hy2-node
    type: hysteria2
    server: 2407:cdc0:d002::1961
    port: 58526
    password: hy2-secret
    sni: edge.example
    up: "50 Mbps"
    down: "800 Mbps"
    obfs: salamander
    obfs-password: obfs-secret
`))
	if err != nil {
		t.Fatalf("ParseMihomoConfig() error = %v", err)
	}
	if len(config.Proxies) != 4 {
		t.Fatalf("proxies = %#v, want four proxies", config.Proxies)
	}
	anytls := config.Proxies[0]
	if anytls.Server != "anytls.example" || anytls.Port != 443 || anytls.Password != "anytls-secret" || anytls.SNI != "edge.example" || anytls.ServerName != "edge.example" || anytls.ClientFingerprint != "chrome" || anytls.TLS == nil || !*anytls.TLS || anytls.SkipCertVerify == nil || !*anytls.SkipCertVerify || anytls.UDP == nil || !*anytls.UDP {
		t.Fatalf("anytls fields = %#v", anytls)
	}
	if config.Proxies[1].Plugin != "shadow-tls" || config.Proxies[1].PluginOpts["password"] != "plugin-secret" || config.Proxies[1].PluginOpts["version"] != 3 {
		t.Fatalf("ss plugin fields = %#v", config.Proxies[1])
	}
	if config.Proxies[2].Username != "user" || config.Proxies[2].Password != "socks-secret" {
		t.Fatalf("socks5 auth fields = %#v", config.Proxies[2])
	}
	hy2 := config.Proxies[3]
	if hy2.Type != "hysteria2" || hy2.Server != "2407:cdc0:d002::1961" || hy2.Port != 58526 || hy2.Password != "hy2-secret" || hy2.SNI != "edge.example" || hy2.Up != "50 Mbps" || hy2.Down != "800 Mbps" || hy2.Obfs != "salamander" || hy2.ObfsPassword != "obfs-secret" {
		t.Fatalf("hysteria2 fields = %#v", hy2)
	}
}

func TestGenerateMihomoNodesSupportsAnyTLSShadowsocksAndSocks5(t *testing.T) {
	const encodedPassword = "p@ss:/?#"
	config := MihomoConfig{Proxies: []MihomoProxy{
		{
			Name:           "普通/节点",
			Type:           "anytls",
			Server:         "anytls.example",
			Port:           443,
			Password:       encodedPassword,
			ServerName:     "edge.example",
			SkipCertVerify: boolPtr(true),
			UDP:            boolPtr(true),
		},
		{
			Name:     "ss-node",
			Type:     "ss",
			Server:   "ss.example",
			Port:     8388,
			Cipher:   "aes-256-gcm",
			Password: "ss-secret",
		},
		{
			Name:     "socks-node",
			Type:     "socks5",
			Server:   "127.0.0.1",
			Port:     1080,
			Username: "user@example",
			Password: "socks-secret",
		},
	}}

	nodes, report, err := GenerateMihomoNodes(config)
	if err != nil {
		t.Fatalf("GenerateMihomoNodes() error = %v", err)
	}
	if report.Converted != len(config.Proxies) {
		t.Fatalf("converted = %d, want %d", report.Converted, len(config.Proxies))
	}
	if got := report.NameMap["普通/节点"]; got != safeMihomoNodeName("普通/节点") || got == "普通/节点" {
		t.Fatalf("Unicode node mapping = %q", got)
	}
	for _, name := range []string{"ss-node", "socks-node"} {
		if report.NameMap[name] != name {
			t.Fatalf("ASCII node mapping for %q = %q, want unchanged", name, report.NameMap[name])
		}
	}
	for _, protocol := range []string{"anytls://", "ss://", "socks5://"} {
		if !strings.Contains(nodes, protocol) {
			t.Fatalf("nodes output = %q, want %q link", nodes, protocol)
		}
	}
	if strings.Contains(nodes, encodedPassword) {
		t.Fatalf("nodes output contains an unencoded password: %q", nodes)
	}
	reportBody, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal(report) error = %v", err)
	}
	if strings.Contains(string(reportBody), encodedPassword) || strings.Contains(string(reportBody), "ss-secret") || strings.Contains(string(reportBody), "socks-secret") {
		t.Fatalf("conversion report contains credentials: %s", reportBody)
	}
}

func TestGenerateMihomoNodesSupportsDaeBackedSSPlugins(t *testing.T) {
	config := MihomoConfig{Proxies: []MihomoProxy{
		{
			Name:     "obfs",
			Type:     "ss",
			Server:   "127.0.0.1",
			Port:     8388,
			Cipher:   "aes-256-gcm",
			Password: "obfs-secret",
			Plugin:   "obfs",
			UDP:      boolPtr(false),
			PluginOpts: map[string]any{
				"mode": "http",
				"host": "cdn.example",
				"path": "/proxy",
			},
		},
		{
			Name:     "shadow",
			Type:     "ss",
			Server:   "127.0.0.1",
			Port:     8388,
			Cipher:   "aes-256-gcm",
			Password: "shadow-secret",
			Plugin:   "shadow-tls",
			PluginOpts: map[string]any{
				"password": "shadow-plugin-secret",
				"version":  3,
				"host":     "shadow.example",
			},
		},
		{
			Name:     "v2ray",
			Type:     "ss",
			Server:   "127.0.0.1",
			Port:     8388,
			Cipher:   "aes-256-gcm",
			Password: "v2ray-secret",
			Plugin:   "v2ray-plugin",
			PluginOpts: map[string]any{
				"mode": "websocket",
				"host": "ws.example",
				"tls":  true,
			},
		},
	}}

	if nodes, _, err := GenerateMihomoNodes(config); err != nil {
		t.Fatalf("GenerateMihomoNodes() error = %v", err)
	} else if !strings.Contains(nodes, "simple-obfs") || !strings.Contains(nodes, "shadow-tls") || !strings.Contains(nodes, "v2ray-plugin") {
		t.Fatalf("nodes output = %q, want all supported plugin links", nodes)
	}
}

func TestMihomoNodeNameMappingIsStableAndFailClosed(t *testing.T) {
	longName := strings.Repeat("a", maxMihomoNodeNameLength+1)
	for _, name := range []string{"普通/节点", "name with spaces", "name'with\"quotes", longName} {
		mapped := safeMihomoNodeName(name)
		if mapped != safeMihomoNodeName(name) || !mihomoNodeIdentifierPattern.MatchString(mapped) {
			t.Fatalf("name %q maps nondeterministically or illegally to %q", name, mapped)
		}
		if len(name) > maxMihomoNodeNameLength && mapped == name {
			t.Fatalf("long name was not hashed: %q", mapped)
		}
	}

	valid := MihomoProxy{Name: "node", Type: "socks5", Server: "127.0.0.1", Port: 1080}
	for name, config := range map[string]MihomoConfig{
		"duplicate name":         {Proxies: []MihomoProxy{valid, valid}},
		"reserved direct name":   {Proxies: []MihomoProxy{{Name: "DIRECT", Type: "socks5", Server: "127.0.0.1", Port: 1080}}},
		"unknown protocol":       {Proxies: []MihomoProxy{{Name: "node", Type: "vmess", Server: "127.0.0.1", Port: 443}}},
		"missing password":       {Proxies: []MihomoProxy{{Name: "node", Type: "anytls", Server: "127.0.0.1", Port: 443}}},
		"unsupported anytls udp": {Proxies: []MihomoProxy{{Name: "node", Type: "anytls", Server: "127.0.0.1", Port: 443, Password: "secret", UDP: boolPtr(false)}}},
		"unsupported plugin":     {Proxies: []MihomoProxy{{Name: "node", Type: "ss", Server: "127.0.0.1", Port: 8388, Cipher: "aes-256-gcm", Password: "secret", Plugin: "not-supported"}}},
		"unsupported option":     {Proxies: []MihomoProxy{{Name: "node", Type: "ss", Server: "127.0.0.1", Port: 8388, Cipher: "aes-256-gcm", Password: "secret", Plugin: "simple-obfs", PluginOpts: map[string]any{"obfs": "http", "exec": "unexpected"}}}},
		"ss plugin udp":          {Proxies: []MihomoProxy{{Name: "node", Type: "ss", Server: "127.0.0.1", Port: 8388, Cipher: "aes-256-gcm", Password: "secret", UDP: boolPtr(true), Plugin: "obfs", PluginOpts: map[string]any{"mode": "http"}}}},
		"hy2 missing password":   {Proxies: []MihomoProxy{{Name: "node", Type: "hysteria2", Server: "127.0.0.1", Port: 443}}},
		"hy2 hop-interval":       {Proxies: []MihomoProxy{{Name: "node", Type: "hysteria2", Server: "127.0.0.1", Port: 443, Password: "secret", Ports: "443-8443", HopInterval: 10}}},
		"hy2 alpn":               {Proxies: []MihomoProxy{{Name: "node", Type: "hysteria2", Server: "127.0.0.1", Port: 443, Password: "secret", ALPN: []string{"h3"}}}},
		"hy2 ca-str":             {Proxies: []MihomoProxy{{Name: "node", Type: "hysteria2", Server: "127.0.0.1", Port: 443, Password: "secret", CAString: "-----BEGIN CERTIFICATE-----"}}},
		"hy2 cwnd":               {Proxies: []MihomoProxy{{Name: "node", Type: "hysteria2", Server: "127.0.0.1", Port: 443, Password: "secret", CWND: 10}}},
		"hy2 udp-mtu":            {Proxies: []MihomoProxy{{Name: "node", Type: "hysteria2", Server: "127.0.0.1", Port: 443, Password: "secret", UdpMTU: 1200}}},
		"hy2 client fingerprint": {Proxies: []MihomoProxy{{Name: "node", Type: "hysteria2", Server: "127.0.0.1", Port: 443, Password: "secret", Fingerprint: "chrome"}}},
		"hy2 salamander no pass": {Proxies: []MihomoProxy{{Name: "node", Type: "hysteria2", Server: "127.0.0.1", Port: 443, Password: "secret", Obfs: "salamander"}}},
	} {
		if _, _, err := GenerateMihomoNodes(config); err == nil {
			t.Errorf("%s: GenerateMihomoNodes() error = nil", name)
		}
	}
}

func TestMihomoLinkURIEncodesCredentials(t *testing.T) {
	proxy := MihomoProxy{
		Name:     "ss",
		Type:     "ss",
		Server:   "127.0.0.1",
		Port:     8388,
		Cipher:   "aes-256-gcm",
		Password: "p@ss:/?#",
	}
	link, err := mihomoShadowsocksLink(proxy)
	if err != nil {
		t.Fatalf("mihomoShadowsocksLink() error = %v", err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	password, ok := parsed.User.Password()
	if !ok || password != proxy.Password {
		t.Fatalf("decoded password = %q, want %q", password, proxy.Password)
	}
	if strings.Contains(link, proxy.Password) {
		t.Fatalf("link contains an unescaped credential: %q", link)
	}
}

func TestGenerateMihomoNodesSupportsHysteria2(t *testing.T) {
	config := MihomoConfig{Proxies: []MihomoProxy{
		{
			Name:     "🇸🇬 NNC.SG | Hysteria",
			Type:     "hysteria2",
			Server:   "2407:cdc0:d002::1961",
			Port:     58526,
			Password: "p@ss:/?#",
			SNI:      "sg.example",
		},
		{
			Name:         "us-hy2",
			Type:         "hy2",
			Server:       "127.0.0.1",
			Port:         443,
			Password:     "hy2-secret",
			Up:           "50 Mbps",
			Down:         "800 Mbps",
			Obfs:         "salamander",
			ObfsPassword: "obfs-secret",
		},
	}}

	nodes, report, err := GenerateMihomoNodes(config)
	if err != nil {
		t.Fatalf("GenerateMihomoNodes() error = %v", err)
	}
	if report.Converted != 2 || report.Types[report.NameMap["🇸🇬 NNC.SG | Hysteria"]] != "hysteria2" || report.Types["us-hy2"] != "hysteria2" {
		t.Fatalf("report = %#v", report)
	}
	if !strings.Contains(nodes, "hysteria2://") || !strings.Contains(nodes, "[2407:cdc0:d002::1961]:58526") || !strings.Contains(nodes, "sni=sg.example") {
		t.Fatalf("nodes output = %q, want hysteria2 IPv6 link", nodes)
	}
	if !strings.Contains(nodes, "upmbps=50") || !strings.Contains(nodes, "downmbps=800") || !strings.Contains(nodes, "obfs=salamander") {
		t.Fatalf("nodes output = %q, want bandwidth and obfs query", nodes)
	}
	if strings.Contains(nodes, "p@ss:/?#") {
		t.Fatalf("nodes output contains an unencoded credential: %q", nodes)
	}
	reportBody, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal(report) error = %v", err)
	}
	if strings.Contains(string(reportBody), "hy2-secret") || strings.Contains(string(reportBody), "obfs-secret") || strings.Contains(string(reportBody), "p@ss") {
		t.Fatalf("conversion report contains credentials: %s", reportBody)
	}
}

func TestParseMihomoBandwidthAcceptsMihomoUnits(t *testing.T) {
	cases := []struct {
		in      string
		wantBps uint64
	}{
		{in: "", wantBps: 0},
		{in: "50", wantBps: 50 * 1_000_000 / 8},
		{in: "50 Mbps", wantBps: 50 * 1_000_000 / 8},
		{in: "1 Gbps", wantBps: 1_000 * 1_000_000 / 8},
		{in: "100 Kbps", wantBps: 100_000 / 8},
		{in: "1.5 Mbps", wantBps: 1_500_000 / 8},
		{in: "8 Bps", wantBps: 8},
	}
	for _, tc := range cases {
		got, err := parseMihomoBandwidth("node", "up", tc.in)
		if err != nil {
			t.Fatalf("parseMihomoBandwidth(%q) error = %v", tc.in, err)
		}
		if got != tc.wantBps {
			t.Fatalf("parseMihomoBandwidth(%q) = %d, want %d", tc.in, got, tc.wantBps)
		}
	}
	for _, invalid := range []string{"50 MB", "not-a-rate", "0", "0 Mbps"} {
		if _, err := parseMihomoBandwidth("node", "up", invalid); err == nil {
			t.Fatalf("parseMihomoBandwidth(%q) error = nil", invalid)
		}
	}
}

func TestMihomoHysteria2PreservesPasswordSpaces(t *testing.T) {
	const secret = " secret "
	link, err := mihomoHysteria2Link(MihomoProxy{
		Name:     "node",
		Type:     "hysteria2",
		Server:   "127.0.0.1",
		Port:     443,
		Password: secret,
	})
	if err != nil {
		t.Fatalf("mihomoHysteria2Link() error = %v", err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if parsed.User.Username() != secret {
		t.Fatalf("username = %q, want %q", parsed.User.Username(), secret)
	}
}

func TestGenerateMihomoNodesMapsHysteria2FieldsKdaeSupports(t *testing.T) {
	const pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	caPath := writeTempCAPEM(t)
	config := MihomoConfig{Proxies: []MihomoProxy{
		{
			Name:        "hop",
			Type:        "hysteria2",
			Server:      "2407:cdc0:d002::1961",
			Port:        443,
			Password:    "hop-secret",
			Ports:       "443-8443",
			Fingerprint: "01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef",
			CA:          caPath,
			Up:          "1 Gbps",
		},
		{
			Name:     "decimal-bw",
			Type:     "hysteria2",
			Server:   "127.0.0.1",
			Port:     443,
			Password: "bw-secret",
			Up:       "1.5 Mbps",
			Down:     "800 Mbps",
		},
	}}

	nodes, report, err := GenerateMihomoNodes(config)
	if err != nil {
		t.Fatalf("GenerateMihomoNodes() error = %v", err)
	}
	if report.Converted != 2 {
		t.Fatalf("report = %#v, want two converted nodes", report)
	}
	if !strings.Contains(nodes, "[2407:cdc0:d002::1961]:443-8443") {
		t.Fatalf("nodes output = %q, want port hopping in host", nodes)
	}
	if !strings.Contains(nodes, "pinSHA256="+pin) {
		t.Fatalf("nodes output = %q, want certificate pin", nodes)
	}
	if !strings.Contains(nodes, "ca=") {
		t.Fatalf("nodes output = %q, want ca path", nodes)
	}
	if !strings.Contains(nodes, "upmbps=1000") {
		t.Fatalf("nodes output = %q, want 1 Gbps as 1000 Mbps", nodes)
	}
	if !strings.Contains(nodes, "maxTx=187500") || !strings.Contains(nodes, "maxRx=100000000") {
		t.Fatalf("nodes output = %q, want decimal Mbps as maxTx/maxRx", nodes)
	}
}

func TestRunSyncGenerationPublishesMihomoNodesWithMappedGroupMembers(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
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
	groups := `proxies:
  - name: "普通/节点"
    type: anytls
    server: anytls.example
    port: 443
    password: metadata-secret
  - name: ss-node
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-256-gcm
    password: ss-secret
  - name: socks-node
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: user
    password: socks-secret
proxy-groups:
  - name: "主组"
    type: select
    proxies: ["普通/节点", ss-node, socks-node, DIRECT, REJECT]
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	if err := os.WriteFile(groupsPath, []byte(groups), 0o600); err != nil {
		t.Fatalf("WriteFile(groups) error = %v", err)
	}

	report, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	})
	if err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	if report.Nodes.Converted != 3 {
		t.Fatalf("node report = %#v, want three converted nodes", report.Nodes)
	}
	currentDir, err := filepath.EvalSymlinks(filepath.Join(generationDir, "current"))
	if err != nil {
		t.Fatalf("EvalSymlinks(current) error = %v", err)
	}
	nodes, err := os.ReadFile(filepath.Join(currentDir, "nodes.dae"))
	if err != nil {
		t.Fatalf("ReadFile(nodes.dae) error = %v", err)
	}
	groupsOutput, err := os.ReadFile(filepath.Join(currentDir, "groups.dae"))
	if err != nil {
		t.Fatalf("ReadFile(groups.dae) error = %v", err)
	}
	metadata, err := os.ReadFile(filepath.Join(currentDir, "metadata.json"))
	if err != nil {
		t.Fatalf("ReadFile(metadata.json) error = %v", err)
	}
	if !strings.Contains(string(nodes), report.Nodes.NameMap["普通/节点"]+":") || !strings.Contains(string(nodes), "ss-node:") || !strings.Contains(string(nodes), "socks-node:") {
		t.Fatalf("nodes.dae = %q, want all generated node names", nodes)
	}
	if !strings.Contains(string(groupsOutput), "filter: name('"+report.Nodes.NameMap["普通/节点"]+"')") || !strings.Contains(string(groupsOutput), "selection_members:") || strings.Contains(string(groupsOutput), "普通/节点") {
		t.Fatalf("groups.dae = %q, want mapped node member without raw Unicode name", groupsOutput)
	}
	if strings.Contains(string(metadata), "metadata-secret") || strings.Contains(string(metadata), "ss-secret") || strings.Contains(string(metadata), "socks-secret") {
		t.Fatalf("metadata.json contains credentials: %s", metadata)
	}
	if err := validateStoredGeneration(currentDir, filepath.Base(currentDir)); err != nil {
		t.Fatalf("validateStoredGeneration() error = %v", err)
	}
}

func TestRunSyncGenerationPublishesNodesRoutesGroupsAndDATTogether(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsPath := filepath.Join(dir, "mihomo.yaml")
	generationDir := filepath.Join(dir, "generated")
	runnerWriteGenerationManifest(t, manifestPath, runnerGenerationManifestProvider{
		name:     "large-domain",
		behavior: "domain",
		data:     runnerLargeDomainProviderData(runnerLargeProviderRuleCount, "generation"),
		outbound: "proxy",
	})
	runnerWriteGenerationGroupsInput(t, groupsPath, "hk-1")

	if _, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsPath,
		GenerationDir:   generationDir,
	}); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	currentDir, err := filepath.EvalSymlinks(filepath.Join(generationDir, "current"))
	if err != nil {
		t.Fatalf("EvalSymlinks(current) error = %v", err)
	}
	for _, name := range []string{"nodes.dae", "groups.dae", "routes.dae", "metadata.json", "generated/geosite/large-domain.dat"} {
		if _, err := os.Stat(filepath.Join(currentDir, name)); err != nil {
			t.Fatalf("generation file %q is missing: %v", name, err)
		}
	}
	metadataBody, err := os.ReadFile(filepath.Join(currentDir, "metadata.json"))
	if err != nil {
		t.Fatalf("ReadFile(metadata.json) error = %v", err)
	}
	var metadata generationMetadata
	if err := json.Unmarshal(metadataBody, &metadata); err != nil {
		t.Fatalf("json.Unmarshal(metadata) error = %v", err)
	}
	nodes, err := os.ReadFile(filepath.Join(currentDir, "nodes.dae"))
	if err != nil {
		t.Fatalf("ReadFile(nodes.dae) error = %v", err)
	}
	if metadata.NodesSHA256 != digest(nodes) || metadata.Mihomo == nil || metadata.DATs["large-domain"].Path == "" {
		t.Fatalf("metadata = %#v, want node and DAT bindings for one generation", metadata)
	}
	if err := validateStoredGeneration(currentDir, filepath.Base(currentDir)); err != nil {
		t.Fatalf("validateStoredGeneration() error = %v", err)
	}
}

func TestRunSyncDirectNodeAndGroupOutputsUseMappedNames(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "providers.yaml")
	groupsInputPath := filepath.Join(dir, "mihomo.yaml")
	nodesOutputPath := filepath.Join(dir, "nodes.dae")
	groupsOutputPath := filepath.Join(dir, "groups.dae")
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
	groups := `proxies:
  - name: "普通节点"
    type: anytls
    server: anytls.example
    port: 443
    password: direct-secret
proxy-groups:
  - name: main
    type: select
    proxies: ["普通节点", DIRECT]
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	if err := os.WriteFile(groupsInputPath, []byte(groups), 0o600); err != nil {
		t.Fatalf("WriteFile(groups) error = %v", err)
	}

	report, err := RunSync(context.Background(), SyncOptions{
		ManifestPath:    manifestPath,
		GroupsInputPath: groupsInputPath,
		GroupsOutput:    groupsOutputPath,
		NodesOutput:     nodesOutputPath,
	})
	if err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	nodes, err := os.ReadFile(nodesOutputPath)
	if err != nil {
		t.Fatalf("ReadFile(nodes) error = %v", err)
	}
	groupsOutput, err := os.ReadFile(groupsOutputPath)
	if err != nil {
		t.Fatalf("ReadFile(groups) error = %v", err)
	}
	safeName := report.Nodes.NameMap["普通节点"]
	if report.Nodes.Converted != 1 || !strings.Contains(string(nodes), safeName+":") {
		t.Fatalf("report/nodes = %#v / %q", report.Nodes, nodes)
	}
	if !strings.Contains(string(groupsOutput), "filter: name('"+safeName+"')") || strings.Contains(string(groupsOutput), "普通节点") {
		t.Fatalf("groups output = %q, want mapped node member", groupsOutput)
	}
	if reportJSON, err := report.JSON(); err != nil {
		t.Fatalf("SyncReport.JSON() error = %v", err)
	} else if strings.Contains(string(reportJSON), "direct-secret") {
		t.Fatalf("sync report contains credential: %s", reportJSON)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func writeTempCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
