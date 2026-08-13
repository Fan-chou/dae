package main

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
`))
	if err != nil {
		t.Fatalf("ParseMihomoConfig() error = %v", err)
	}
	if len(config.Proxies) != 3 {
		t.Fatalf("proxies = %#v, want three proxies", config.Proxies)
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
	if !strings.Contains(string(groupsOutput), "filter: name('"+report.Nodes.NameMap["普通/节点"]+"')") || strings.Contains(string(groupsOutput), "普通/节点") {
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
