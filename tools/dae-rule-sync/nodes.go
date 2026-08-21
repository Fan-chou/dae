package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxMihomoNodeNameLength = 64
	sha256FingerprintBytes  = 32
)

var (
	mihomoNodeIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	// Mihomo StringToBps, plus a decimal coefficient. Unit prefix is
	// case-insensitive; b vs B still distinguishes bits from bytes.
	mihomoRateRegexp = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([kKmMgGtT]?)([Bb])ps$`)
)

type NodeConversionReport struct {
	Converted int
	NameMap   map[string]string
	Types     map[string]string
}

// GenerateMihomoNodes converts every declared Mihomo proxy into a dae node.
// Unused proxies are intentionally converted as well: a declaration that is
// invalid must not be silently hidden merely because a group does not refer to
// it today.
func GenerateMihomoNodes(config MihomoConfig) (string, NodeConversionReport, error) {
	return GenerateMihomoNodesWithResolveDNS(config, nil)
}

func GenerateMihomoNodesWithResolveDNS(config MihomoConfig, overlay map[string]string) (string, NodeConversionReport, error) {
	report := NodeConversionReport{
		NameMap: make(map[string]string, len(config.Proxies)),
		Types:   make(map[string]string, len(config.Proxies)),
	}
	seenNames := make(map[string]struct{}, len(config.Proxies))
	seenSafeNames := make(map[string]string, len(config.Proxies))
	for _, proxy := range config.Proxies {
		if proxy.Name == "" || strings.TrimSpace(proxy.Name) == "" {
			return "", NodeConversionReport{}, fmt.Errorf("proxy has empty name")
		}
		if proxy.Name == "DIRECT" || proxy.Name == "REJECT" {
			return "", NodeConversionReport{}, fmt.Errorf("proxy %q uses a reserved Mihomo member name", proxy.Name)
		}
		if !utf8.ValidString(proxy.Name) {
			return "", NodeConversionReport{}, fmt.Errorf("proxy name is not valid UTF-8")
		}
		if _, exists := seenNames[proxy.Name]; exists {
			return "", NodeConversionReport{}, fmt.Errorf("duplicate proxy %q", proxy.Name)
		}
		seenNames[proxy.Name] = struct{}{}

		safeName := safeMihomoNodeName(proxy.Name)
		if safeName == "direct" || safeName == "block" {
			return "", NodeConversionReport{}, fmt.Errorf("mihomo proxy %q maps to reserved dae outbound %q", proxy.Name, safeName)
		}
		if previous, exists := seenSafeNames[safeName]; exists && previous != proxy.Name {
			return "", NodeConversionReport{}, fmt.Errorf("proxies %q and %q map to the same dae node name %q", previous, proxy.Name, safeName)
		}
		seenSafeNames[safeName] = proxy.Name
		report.NameMap[proxy.Name] = safeName
	}

	var output strings.Builder
	output.WriteString("node {\n")
	for _, proxy := range config.Proxies {
		safeName := report.NameMap[proxy.Name]
		link, protocol, err := mihomoProxyLink(proxy)
		if err != nil {
			return "", NodeConversionReport{}, err
		}
		link, err = applyResolveDNSOverlay(link, proxy.Name, overlay)
		if err != nil {
			return "", NodeConversionReport{}, fmt.Errorf("mihomo proxy %q: %w", proxy.Name, err)
		}
		if err := validateDaeLiteral(link); err != nil {
			return "", NodeConversionReport{}, fmt.Errorf("mihomo proxy %q generated an invalid dae link", proxy.Name)
		}
		if err := validateMihomoLinkWithDae(link); err != nil {
			// The outbound parser can include the complete link in its error.
			// Do not wrap or expose that error: links contain credentials.
			return "", NodeConversionReport{}, fmt.Errorf("mihomo proxy %q generated %s link cannot be parsed by dae", proxy.Name, protocol)
		}
		fmt.Fprintf(&output, "    %s: %s\n", safeName, daeQuote(link))
		report.Types[safeName] = protocol
		report.Converted++
	}
	output.WriteString("}\n")
	return output.String(), report, nil
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func validateGenerationMihomoMetadata(metadata *generationMihomoMetadata) error {
	if metadata == nil || metadata.InputSHA256 == "" || len(metadata.InputSHA256) != 64 {
		return fmt.Errorf("generation Mihomo metadata is incomplete")
	}
	if _, err := hex.DecodeString(metadata.InputSHA256); err != nil {
		return fmt.Errorf("generation Mihomo input checksum is invalid")
	}
	if metadata.NodeNameMap == nil || metadata.GroupNameMap == nil || metadata.NodeTypes == nil {
		return fmt.Errorf("generation Mihomo name metadata is incomplete")
	}
	if len(metadata.NodeNameMap) != len(metadata.NodeTypes) {
		return fmt.Errorf("generation Mihomo node metadata is inconsistent")
	}
	seenSafeNames := make(map[string]string, len(metadata.NodeNameMap))
	for original, safeName := range metadata.NodeNameMap {
		if original == "" || original == "DIRECT" || original == "REJECT" || safeName == "" || safeMihomoNodeName(original) != safeName {
			return fmt.Errorf("generation Mihomo node name mapping is invalid")
		}
		if previous, exists := seenSafeNames[safeName]; exists && previous != original {
			return fmt.Errorf("generation Mihomo node name mapping collides")
		}
		seenSafeNames[safeName] = original
		protocol := strings.ToLower(metadata.NodeTypes[safeName])
		if !mihomoSupportedNodeProtocol(protocol) {
			return fmt.Errorf("generation Mihomo node protocol is unsupported")
		}
	}
	for safeName := range metadata.NodeTypes {
		if _, exists := seenSafeNames[safeName]; !exists {
			return fmt.Errorf("generation Mihomo node type has no name mapping")
		}
	}
	seenSafeNames = make(map[string]string, len(metadata.GroupNameMap))
	for original, safeName := range metadata.GroupNameMap {
		if original == "" || safeName == "" || safeDaeIdentifier(original) != safeName {
			return fmt.Errorf("generation Mihomo group name mapping is invalid")
		}
		if isReservedMihomoGroupName(original) {
			return fmt.Errorf("generation Mihomo group name %q is reserved", original)
		}
		if previous, exists := seenSafeNames[safeName]; exists && previous != original {
			return fmt.Errorf("generation Mihomo group name mapping collides")
		}
		seenSafeNames[safeName] = original
	}
	if err := validateMihomoOutputNames(metadata.NodeNameMap, metadata.GroupNameMap); err != nil {
		return err
	}
	return nil
}

func mihomoProxyLink(proxy MihomoProxy) (string, string, error) {
	protocol := strings.ToLower(strings.TrimSpace(proxy.Type))
	if protocol == "" {
		return "", "", fmt.Errorf("mihomo proxy %q has empty type", proxy.Name)
	}
	if err := validateMihomoProxyFields(proxy); err != nil {
		return "", protocol, err
	}
	switch protocol {
	case "anytls":
		link, err := mihomoAnyTLSLink(proxy)
		return link, protocol, err
	case "ss":
		link, err := mihomoShadowsocksLink(proxy)
		return link, protocol, err
	case "socks5":
		link, err := mihomoSocks5Link(proxy)
		return link, protocol, err
	case "hysteria2", "hy2":
		link, err := mihomoHysteria2Link(proxy)
		return link, "hysteria2", err
	default:
		return "", protocol, fmt.Errorf("mihomo proxy %q uses unsupported type %q", proxy.Name, protocol)
	}
}

func mihomoSupportedNodeProtocol(protocol string) bool {
	switch protocol {
	case "anytls", "ss", "socks5", "hysteria2":
		return true
	default:
		return false
	}
}

func validateMihomoProxyFields(proxy MihomoProxy) error {
	if err := validateMihomoEndpoint(proxy); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "username", value: proxy.Username},
		{name: "password", value: proxy.Password},
		{name: "auth", value: proxy.Auth},
		{name: "cipher", value: proxy.Cipher},
		{name: "sni", value: proxy.SNI},
		{name: "servername", value: proxy.ServerName},
		{name: "client-fingerprint", value: proxy.ClientFingerprint},
		{name: "plugin", value: proxy.Plugin},
		{name: "up", value: proxy.Up},
		{name: "down", value: proxy.Down},
		{name: "obfs", value: proxy.Obfs},
		{name: "obfs-password", value: proxy.ObfsPassword},
		{name: "ports", value: proxy.Ports},
		{name: "fingerprint", value: proxy.Fingerprint},
		{name: "ca", value: proxy.CA},
		{name: "ca-str", value: proxy.CAString},
	} {
		if strings.ContainsAny(field.value, "\x00\r\n") {
			return fmt.Errorf("mihomo proxy %q has a control character in %s", proxy.Name, field.name)
		}
	}
	for _, value := range proxy.ALPN {
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("mihomo proxy %q has a control character in alpn", proxy.Name)
		}
	}
	if proxy.SNI != "" && proxy.ServerName != "" && proxy.SNI != proxy.ServerName {
		return fmt.Errorf("mihomo proxy %q has conflicting sni and servername", proxy.Name)
	}
	for _, key := range sortedMihomoPluginOptionKeys(proxy.PluginOpts) {
		value := proxy.PluginOpts[key]
		if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\x00\r\n") {
			return fmt.Errorf("mihomo proxy %q has an invalid plugin option name", proxy.Name)
		}
		if value == nil {
			return fmt.Errorf("mihomo proxy %q has an empty plugin option", proxy.Name)
		}
	}
	return nil
}

func validateMihomoEndpoint(proxy MihomoProxy) error {
	if proxy.Server == "" || strings.TrimSpace(proxy.Server) != proxy.Server || strings.ContainsAny(proxy.Server, "\x00\r\n\t /?#@") {
		return fmt.Errorf("mihomo proxy %q has an invalid server", proxy.Name)
	}
	if proxy.Port == 0 && strings.TrimSpace(proxy.Ports) != "" {
		return nil
	}
	if proxy.Port < 1 || proxy.Port > 65535 {
		return fmt.Errorf("mihomo proxy %q has an invalid port", proxy.Name)
	}
	return nil
}

func mihomoAnyTLSLink(proxy MihomoProxy) (string, error) {
	if proxy.Password == "" {
		return "", fmt.Errorf("mihomo proxy %q anytls password is required", proxy.Name)
	}
	if proxy.Username != "" || proxy.Cipher != "" || proxy.Plugin != "" || len(proxy.PluginOpts) != 0 || mihomoProxyHasHysteria2Fields(proxy) {
		return "", fmt.Errorf("mihomo proxy %q anytls has unsupported fields", proxy.Name)
	}
	if proxy.TLS != nil && !*proxy.TLS {
		return "", fmt.Errorf("mihomo proxy %q anytls tls=false is unsupported", proxy.Name)
	}
	if proxy.UDP != nil && !*proxy.UDP {
		return "", fmt.Errorf("mihomo proxy %q anytls udp=false is unsupported by dae", proxy.Name)
	}
	query := url.Values{}
	if sni := mihomoProxySNI(proxy); sni != "" {
		query.Set("sni", sni)
	}
	if proxy.SkipCertVerify != nil && *proxy.SkipCertVerify {
		query.Set("insecure", "1")
	}
	return buildMihomoLink("anytls", url.User(proxy.Password), proxy.Server, proxy.Port, query)
}

func mihomoShadowsocksLink(proxy MihomoProxy) (string, error) {
	if proxy.Cipher == "" || proxy.Password == "" {
		return "", fmt.Errorf("mihomo proxy %q ss cipher and password are required", proxy.Name)
	}
	if proxy.Username != "" || proxy.SNI != "" || proxy.ServerName != "" || proxy.ClientFingerprint != "" || mihomoProxyHasHysteria2Fields(proxy) {
		return "", fmt.Errorf("mihomo proxy %q ss has unsupported fields", proxy.Name)
	}
	if proxy.TLS != nil && *proxy.TLS {
		return "", fmt.Errorf("mihomo proxy %q ss tls=true is unsupported", proxy.Name)
	}
	if proxy.SkipCertVerify != nil && *proxy.SkipCertVerify {
		return "", fmt.Errorf("mihomo proxy %q ss skip-cert-verify is unsupported", proxy.Name)
	}
	plugin, err := mihomoSSPlugin(proxy)
	if err != nil {
		return "", err
	}
	if plugin == "" {
		if proxy.UDP != nil && !*proxy.UDP {
			return "", fmt.Errorf("mihomo proxy %q ss udp=false is unsupported", proxy.Name)
		}
	} else if proxy.UDP != nil && *proxy.UDP {
		return "", fmt.Errorf("mihomo proxy %q ss udp=true is unsupported with an ss plugin", proxy.Name)
	}
	query := url.Values{}
	if plugin != "" {
		query.Set("plugin", plugin)
	}
	return buildMihomoLink("ss", url.UserPassword(proxy.Cipher, proxy.Password), proxy.Server, proxy.Port, query)
}

func mihomoSocks5Link(proxy MihomoProxy) (string, error) {
	if proxy.Cipher != "" || proxy.SNI != "" || proxy.ServerName != "" || proxy.ClientFingerprint != "" || proxy.Plugin != "" || len(proxy.PluginOpts) != 0 || mihomoProxyHasHysteria2Fields(proxy) {
		return "", fmt.Errorf("mihomo proxy %q socks5 has unsupported fields", proxy.Name)
	}
	if proxy.TLS != nil && *proxy.TLS {
		return "", fmt.Errorf("mihomo proxy %q socks5 tls=true is unsupported", proxy.Name)
	}
	if proxy.SkipCertVerify != nil && *proxy.SkipCertVerify {
		return "", fmt.Errorf("mihomo proxy %q socks5 skip-cert-verify is unsupported", proxy.Name)
	}
	if proxy.UDP != nil && !*proxy.UDP {
		return "", fmt.Errorf("mihomo proxy %q socks5 udp=false is unsupported", proxy.Name)
	}

	var user *url.Userinfo
	switch {
	case proxy.Username == "" && proxy.Password == "":
	case proxy.Password == "":
		user = url.User(proxy.Username)
	default:
		user = url.UserPassword(proxy.Username, proxy.Password)
	}
	return buildMihomoLink("socks5", user, proxy.Server, proxy.Port, nil)
}

func mihomoHysteria2Link(proxy MihomoProxy) (string, error) {
	auth, err := mihomoHysteria2Auth(proxy)
	if err != nil {
		return "", err
	}
	if proxy.Username != "" || proxy.Cipher != "" || proxy.ClientFingerprint != "" || proxy.Plugin != "" || len(proxy.PluginOpts) != 0 {
		return "", fmt.Errorf("mihomo proxy %q hysteria2 has unsupported fields", proxy.Name)
	}
	if proxy.CAString != "" || proxy.CWND != 0 || proxy.UdpMTU != 0 || len(proxy.ALPN) != 0 || proxy.HopInterval != 0 {
		return "", fmt.Errorf("mihomo proxy %q hysteria2 has fields unsupported by kdae", proxy.Name)
	}
	if proxy.TLS != nil && !*proxy.TLS {
		return "", fmt.Errorf("mihomo proxy %q hysteria2 tls=false is unsupported", proxy.Name)
	}
	if proxy.UDP != nil && !*proxy.UDP {
		return "", fmt.Errorf("mihomo proxy %q hysteria2 udp=false is unsupported by dae", proxy.Name)
	}

	host, err := mihomoHysteria2Host(proxy)
	if err != nil {
		return "", err
	}

	query := url.Values{}
	if sni := mihomoProxySNI(proxy); sni != "" {
		query.Set("sni", sni)
	}
	if proxy.SkipCertVerify != nil && *proxy.SkipCertVerify {
		query.Set("insecure", "1")
	}
	if pin, err := mihomoHysteria2PinSHA256(proxy); err != nil {
		return "", err
	} else if pin != "" {
		query.Set("pinSHA256", pin)
	}
	if ca := strings.TrimSpace(proxy.CA); ca != "" {
		query.Set("ca", ca)
	}

	up, err := parseMihomoBandwidth(proxy.Name, "up", proxy.Up)
	if err != nil {
		return "", err
	}
	down, err := parseMihomoBandwidth(proxy.Name, "down", proxy.Down)
	if err != nil {
		return "", err
	}
	setHysteria2BandwidthQuery(query, up, down)

	obfs := strings.ToLower(strings.TrimSpace(proxy.Obfs))
	switch obfs {
	case "":
		if strings.TrimSpace(proxy.ObfsPassword) != "" {
			return "", fmt.Errorf("mihomo proxy %q hysteria2 obfs-password requires obfs", proxy.Name)
		}
	case "salamander":
		if strings.TrimSpace(proxy.ObfsPassword) == "" {
			return "", fmt.Errorf("mihomo proxy %q hysteria2 obfs=salamander requires obfs-password", proxy.Name)
		}
		query.Set("obfs", "salamander")
		query.Set("obfs-password", proxy.ObfsPassword)
	default:
		return "", fmt.Errorf("mihomo proxy %q hysteria2 has unsupported obfs", proxy.Name)
	}

	return buildMihomoLinkWithHost("hysteria2", url.User(auth), host, query)
}

// mihomoHysteria2Auth keeps the credential bytes unchanged. TrimSpace is only
// used to decide whether password/auth is present or empty.
func mihomoHysteria2Auth(proxy MihomoProxy) (string, error) {
	passwordSet := strings.TrimSpace(proxy.Password) != ""
	authSet := strings.TrimSpace(proxy.Auth) != ""
	switch {
	case passwordSet && authSet:
		if proxy.Password != proxy.Auth {
			return "", fmt.Errorf("mihomo proxy %q hysteria2 has conflicting password and auth", proxy.Name)
		}
		return proxy.Password, nil
	case passwordSet:
		return proxy.Password, nil
	case authSet:
		return proxy.Auth, nil
	default:
		return "", fmt.Errorf("mihomo proxy %q hysteria2 password is required", proxy.Name)
	}
}

func mihomoHysteria2Host(proxy MihomoProxy) (string, error) {
	ports := strings.TrimSpace(proxy.Ports)
	if ports == "" {
		return net.JoinHostPort(proxy.Server, strconv.Itoa(proxy.Port)), nil
	}
	normalized, err := normalizeMihomoHysteria2Ports(ports)
	if err != nil {
		return "", fmt.Errorf("mihomo proxy %q has an invalid hysteria2 ports", proxy.Name)
	}
	return net.JoinHostPort(proxy.Server, normalized), nil
}

func normalizeMihomoHysteria2Ports(ports string) (string, error) {
	if ports == "all" || ports == "*" {
		return "", fmt.Errorf("wildcard ports")
	}
	var parts []string
	for _, part := range strings.Split(ports, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", fmt.Errorf("empty port")
		}
		if startText, endText, ok := strings.Cut(part, "-"); ok {
			startText = strings.TrimSpace(startText)
			endText = strings.TrimSpace(endText)
			if startText == "" || endText == "" || strings.Contains(endText, "-") {
				return "", fmt.Errorf("invalid port range")
			}
			start, err := strconv.ParseUint(startText, 10, 16)
			if err != nil || start == 0 {
				return "", fmt.Errorf("invalid port range")
			}
			end, err := strconv.ParseUint(endText, 10, 16)
			if err != nil || end == 0 {
				return "", fmt.Errorf("invalid port range")
			}
			parts = append(parts, startText+"-"+endText)
			continue
		}
		port, err := strconv.ParseUint(part, 10, 16)
		if err != nil || port == 0 {
			return "", fmt.Errorf("invalid port")
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("empty ports")
	}
	return strings.Join(parts, ","), nil
}

func mihomoHysteria2PinSHA256(proxy MihomoProxy) (string, error) {
	fingerprint := strings.TrimSpace(proxy.Fingerprint)
	if fingerprint == "" {
		return "", nil
	}
	switch strings.ToLower(fingerprint) {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return "", fmt.Errorf("mihomo proxy %q hysteria2 fingerprint is a client impersonation name; kdae has no mapping", proxy.Name)
	}
	normalized := strings.ToLower(fingerprint)
	normalized = strings.ReplaceAll(normalized, ":", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	raw, err := hex.DecodeString(normalized)
	if err != nil || len(raw) != sha256FingerprintBytes {
		return "", fmt.Errorf("mihomo proxy %q has an invalid hysteria2 fingerprint", proxy.Name)
	}
	return hex.EncodeToString(raw), nil
}

func mihomoProxyHasHysteria2Fields(proxy MihomoProxy) bool {
	return proxy.Auth != "" || proxy.Up != "" || proxy.Down != "" || proxy.Obfs != "" || proxy.ObfsPassword != "" ||
		proxy.Ports != "" || proxy.HopInterval != 0 || proxy.Fingerprint != "" || len(proxy.ALPN) != 0 ||
		proxy.CA != "" || proxy.CAString != "" || proxy.CWND != 0 || proxy.UdpMTU != 0
}

func parseMihomoBandwidth(name, field, value string) (uint64, error) {
	s := strings.TrimSpace(value)
	if s == "" {
		return 0, nil
	}
	if v, err := strconv.Atoi(s); err == nil {
		if v <= 0 {
			return 0, fmt.Errorf("mihomo proxy %q has an invalid hysteria2 %s", name, field)
		}
		return uint64(v) * 1_000_000 / 8, nil
	}
	m := mihomoRateRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("mihomo proxy %q has an invalid hysteria2 %s", name, field)
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil || n <= 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, fmt.Errorf("mihomo proxy %q has an invalid hysteria2 %s", name, field)
	}
	mul := 1.0
	switch strings.ToUpper(m[2]) {
	case "T":
		mul *= 1000
		fallthrough
	case "G":
		mul *= 1000
		fallthrough
	case "M":
		mul *= 1000
		fallthrough
	case "K":
		mul *= 1000
	}
	amount := n * mul
	if m[3] == "b" {
		amount /= 8
	}
	if amount <= 0 || amount > float64(math.MaxUint64) {
		return 0, fmt.Errorf("mihomo proxy %q has an invalid hysteria2 %s", name, field)
	}
	rounded := math.Round(amount)
	if math.Abs(amount-rounded) > 1e-6 {
		return 0, fmt.Errorf("mihomo proxy %q hysteria2 %s is not an integer byte rate", name, field)
	}
	bps := uint64(rounded)
	if bps == 0 {
		return 0, fmt.Errorf("mihomo proxy %q has an invalid hysteria2 %s", name, field)
	}
	return bps, nil
}

func setHysteria2BandwidthQuery(query url.Values, upBps, downBps uint64) {
	upMbps, upOK := bpsToIntegerMbps(upBps)
	downMbps, downOK := bpsToIntegerMbps(downBps)
	if upOK && downOK {
		if upBps > 0 {
			query.Set("upmbps", strconv.FormatUint(upMbps, 10))
		}
		if downBps > 0 {
			query.Set("downmbps", strconv.FormatUint(downMbps, 10))
		}
		return
	}
	// Non-integer Mbps uses dae's raw maxTx/maxRx (bytes/s). The URI parser
	// requires both query keys together; a missing side is encoded as 0.
	query.Set("maxTx", strconv.FormatUint(upBps, 10))
	query.Set("maxRx", strconv.FormatUint(downBps, 10))
}

func bpsToIntegerMbps(bps uint64) (uint64, bool) {
	if bps == 0 {
		return 0, true
	}
	if bps > math.MaxUint64/8 {
		return 0, false
	}
	bits := bps * 8
	if bits%1_000_000 != 0 {
		return 0, false
	}
	return bits / 1_000_000, true
}

func mihomoProxySNI(proxy MihomoProxy) string {
	if proxy.SNI != "" {
		return proxy.SNI
	}
	return proxy.ServerName
}

func buildMihomoLink(scheme string, user *url.Userinfo, server string, port int, query url.Values) (string, error) {
	return buildMihomoLinkWithHost(scheme, user, net.JoinHostPort(server, strconv.Itoa(port)), query)
}

func buildMihomoLinkWithHost(scheme string, user *url.Userinfo, host string, query url.Values) (string, error) {
	u := url.URL{
		Scheme: scheme,
		User:   user,
		Host:   host,
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	link := u.String()
	if err := validateDaeLiteral(link); err != nil {
		return "", fmt.Errorf("generated %s link contains an invalid literal", scheme)
	}
	return link, nil
}

func mihomoSSPlugin(proxy MihomoProxy) (string, error) {
	pluginName := strings.ToLower(strings.TrimSpace(proxy.Plugin))
	if pluginName == "" {
		if len(proxy.PluginOpts) != 0 {
			return "", fmt.Errorf("mihomo proxy %q has plugin options without a plugin", proxy.Name)
		}
		return "", nil
	}
	if strings.Contains(pluginName, ";") {
		return "", fmt.Errorf("mihomo proxy %q has an invalid ss plugin", proxy.Name)
	}

	options, err := mihomoPluginOptionValues(proxy)
	if err != nil {
		return "", err
	}
	switch pluginName {
	case "obfs", "obfs-local", "simple-obfs", "simpleobfs":
		return mihomoSimpleObfsPlugin(proxy, options)
	case "shadowtls", "shadow-tls", "sstls":
		return mihomoShadowTLSPlugin(proxy, options)
	case "v2ray-plugin":
		return mihomoV2RayPlugin(proxy, options)
	default:
		return "", fmt.Errorf("mihomo proxy %q uses unsupported ss plugin", proxy.Name)
	}
}

func mihomoPluginOptionValues(proxy MihomoProxy) (map[string]string, error) {
	options := make(map[string]string, len(proxy.PluginOpts))
	for _, rawKey := range sortedMihomoPluginOptionKeys(proxy.PluginOpts) {
		rawValue := proxy.PluginOpts[rawKey]
		value, err := mihomoPluginOptionString(rawValue)
		if err != nil {
			return nil, fmt.Errorf("mihomo proxy %q has an invalid plugin option", proxy.Name)
		}
		if strings.ContainsAny(value, "\x00\r\n;") {
			return nil, fmt.Errorf("mihomo proxy %q has an invalid plugin option value", proxy.Name)
		}
		key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(rawKey), "_", "-"))
		if previous, exists := options[key]; exists && previous != value {
			return nil, fmt.Errorf("mihomo proxy %q has conflicting plugin options", proxy.Name)
		}
		options[key] = value
	}
	return options, nil
}

func sortedMihomoPluginOptionKeys(options map[string]any) []string {
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func mihomoPluginOptionString(value any) (string, error) {
	switch value := value.(type) {
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case int:
		return strconv.Itoa(value), nil
	case int8:
		return strconv.FormatInt(int64(value), 10), nil
	case int16:
		return strconv.FormatInt(int64(value), 10), nil
	case int32:
		return strconv.FormatInt(int64(value), 10), nil
	case int64:
		return strconv.FormatInt(value, 10), nil
	case uint:
		return strconv.FormatUint(uint64(value), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(value), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(value), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(value), 10), nil
	case uint64:
		return strconv.FormatUint(value, 10), nil
	case float32:
		f := float64(value)
		if math.Trunc(f) != f {
			return "", fmt.Errorf("non-integral option")
		}
		return strconv.FormatFloat(f, 'f', -1, 32), nil
	case float64:
		if math.Trunc(value) != value {
			return "", fmt.Errorf("non-integral option")
		}
		return strconv.FormatFloat(value, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unsupported option type")
	}
}

func mihomoSimpleObfsPlugin(proxy MihomoProxy, options map[string]string) (string, error) {
	canonical := map[string]string{}
	for key, value := range options {
		switch key {
		case "mode", "obfs":
			if err := setMihomoPluginOption(canonical, "obfs", value); err != nil {
				return "", fmt.Errorf("mihomo proxy %q has conflicting simple-obfs options", proxy.Name)
			}
		case "host", "obfs-host":
			if err := setMihomoPluginOption(canonical, "host", value); err != nil {
				return "", fmt.Errorf("mihomo proxy %q has conflicting simple-obfs options", proxy.Name)
			}
		case "path", "uri", "obfs-path", "obfs-uri":
			if err := setMihomoPluginOption(canonical, "uri", value); err != nil {
				return "", fmt.Errorf("mihomo proxy %q has conflicting simple-obfs options", proxy.Name)
			}
		default:
			return "", fmt.Errorf("mihomo proxy %q uses unsupported simple-obfs option", proxy.Name)
		}
	}
	obfs := strings.ToLower(canonical["obfs"])
	if obfs != "http" && obfs != "tls" {
		return "", fmt.Errorf("mihomo proxy %q has unsupported simple-obfs mode", proxy.Name)
	}
	parts := []string{"simple-obfs", "obfs=" + obfs}
	if value := canonical["host"]; value != "" {
		parts = append(parts, "obfs-host="+value)
	}
	if value := canonical["uri"]; value != "" {
		if !strings.HasPrefix(value, "/") {
			value = "/" + value
		}
		parts = append(parts, "obfs-uri="+value)
	}
	return strings.Join(parts, ";"), nil
}

func mihomoShadowTLSPlugin(proxy MihomoProxy, options map[string]string) (string, error) {
	canonical := map[string]string{}
	for key, value := range options {
		canonicalKey := key
		switch key {
		case "passwd", "pwd":
			canonicalKey = "password"
		case "v":
			canonicalKey = "version"
		case "allow-insecure", "allowinsecure", "insecure", "skip-cert-verify", "skipverify":
			canonicalKey = "allowInsecure"
		case "password", "version", "host", "sni":
		default:
			return "", fmt.Errorf("mihomo proxy %q uses unsupported shadow-tls option", proxy.Name)
		}
		if canonicalKey == "allowInsecure" {
			var err error
			value, err = mihomoBooleanOption(value)
			if err != nil {
				return "", fmt.Errorf("mihomo proxy %q has an invalid shadow-tls option", proxy.Name)
			}
		}
		if err := setMihomoPluginOption(canonical, canonicalKey, value); err != nil {
			return "", fmt.Errorf("mihomo proxy %q has conflicting shadow-tls options", proxy.Name)
		}
	}
	parts := []string{"shadow-tls"}
	for _, key := range []string{"password", "version", "host", "sni", "allowInsecure"} {
		if value := canonical[key]; value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, ";"), nil
}

func mihomoV2RayPlugin(proxy MihomoProxy, options map[string]string) (string, error) {
	canonical := map[string]string{}
	for key, value := range options {
		switch key {
		case "mode", "obfs":
			if value != "" && strings.ToLower(value) != "websocket" && strings.ToLower(value) != "ws" {
				return "", fmt.Errorf("mihomo proxy %q has unsupported v2ray-plugin mode", proxy.Name)
			}
		case "host", "obfs-host":
			if err := setMihomoPluginOption(canonical, "host", value); err != nil {
				return "", fmt.Errorf("mihomo proxy %q has conflicting v2ray-plugin options", proxy.Name)
			}
		case "tls":
			if strings.EqualFold(value, "true") || strings.EqualFold(value, "tls") || value == "1" {
				if err := setMihomoPluginOption(canonical, "tls", "true"); err != nil {
					return "", fmt.Errorf("mihomo proxy %q has conflicting v2ray-plugin options", proxy.Name)
				}
			} else if !strings.EqualFold(value, "false") && value != "0" {
				return "", fmt.Errorf("mihomo proxy %q has an invalid v2ray-plugin tls option", proxy.Name)
			}
		default:
			return "", fmt.Errorf("mihomo proxy %q uses unsupported v2ray-plugin option", proxy.Name)
		}
	}
	parts := []string{"v2ray-plugin"}
	if canonical["tls"] == "true" {
		parts = append(parts, "tls")
	}
	if value := canonical["host"]; value != "" {
		parts = append(parts, "host="+value)
	}
	return strings.Join(parts, ";"), nil
}

func setMihomoPluginOption(options map[string]string, key, value string) error {
	if previous, exists := options[key]; exists && previous != value {
		return fmt.Errorf("conflicting option")
	}
	options[key] = value
	return nil
}

func mihomoBooleanOption(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return "true", nil
	case "false", "0", "no", "off":
		return "false", nil
	default:
		return "", fmt.Errorf("not a boolean")
	}
}
