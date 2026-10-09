/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"encoding/hex"
	"errors"
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

// Node is one Mihomo proxy lowered to a dae node.
type Node struct {
	// Name is the original Mihomo proxy name; Safe is the dae node tag.
	Name     string
	Safe     string
	Protocol string
	// Link is a dae node link. It contains credentials and must never be
	// logged.
	Link string
}

// LinkValidator reports whether dae can actually parse a generated link. It
// must not include the link in its error. Nil skips the check.
type LinkValidator func(link string) error

// proxyFields are the Mihomo proxy keys that influence the lowering. Unknown
// keys are ignored, as Mihomo itself would for options it does not know.
type proxyFields struct {
	Server            string         `yaml:"server"`
	Port              int            `yaml:"port"`
	Username          string         `yaml:"username"`
	Password          string         `yaml:"password"`
	Auth              string         `yaml:"auth"`
	Cipher            string         `yaml:"cipher"`
	SNI               string         `yaml:"sni"`
	ServerName        string         `yaml:"servername"`
	ClientFingerprint string         `yaml:"client-fingerprint"`
	TLS               *bool          `yaml:"tls"`
	SkipCertVerify    *bool          `yaml:"skip-cert-verify"`
	UDP               *bool          `yaml:"udp"`
	Plugin            string         `yaml:"plugin"`
	PluginOpts        map[string]any `yaml:"plugin-opts"`
	Up                string         `yaml:"up"`
	Down              string         `yaml:"down"`
	Obfs              string         `yaml:"obfs"`
	ObfsPassword      string         `yaml:"obfs-password"`
	Ports             string         `yaml:"ports"`
	HopInterval       int            `yaml:"hop-interval"`
	Fingerprint       string         `yaml:"fingerprint"`
	ALPN              []string       `yaml:"alpn"`
	CA                string         `yaml:"ca"`
	CAString          string         `yaml:"ca-str"`
	CWND              int            `yaml:"cwnd"`
	UdpMTU            int            `yaml:"udp-mtu"`
}

func (f proxyFields) hasHysteria2Fields() bool {
	return f.Auth != "" || f.Up != "" || f.Down != "" || f.Obfs != "" || f.ObfsPassword != "" ||
		f.Ports != "" || f.HopInterval != 0 || f.Fingerprint != "" || len(f.ALPN) != 0 ||
		f.CA != "" || f.CAString != "" || f.CWND != 0 || f.UdpMTU != 0
}

func (f proxyFields) sni() string {
	if f.SNI != "" {
		return f.SNI
	}
	return f.ServerName
}

// ConvertProxies lowers every declared proxy, used or not: an invalid
// declaration must not be hidden just because no group references it today.
// Any proxy that cannot be lowered with identical semantics fails the whole
// conversion. Errors never contain credentials.
//
// Node.Name keeps the original Mihomo name for display; Node.Safe is the
// internal dae tag. Safe names are stable: they only change when two proxies
// would otherwise share one (see assignSafeNames).
func ConvertProxies(entries []Entry, validate LinkValidator) ([]Node, error) {
	names := make([]string, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for i, entry := range entries {
		name := entry.Name
		switch {
		case strings.TrimSpace(name) == "":
			return nil, errors.New("proxy has empty name")
		case name == "DIRECT" || name == "REJECT":
			return nil, fmt.Errorf("proxy %q uses a reserved Mihomo member name", name)
		case !utf8.ValidString(name):
			return nil, errors.New("proxy name is not valid UTF-8")
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("duplicate proxy %q", name)
		}
		seen[name] = struct{}{}
		names[i] = name
	}
	safe, err := assignSafeNames(names, SafeNodeName, nodeIdentifier, maxNodeNameLength, nil)
	if err != nil {
		return nil, err
	}

	nodes := make([]Node, 0, len(entries))
	for i, entry := range entries {
		link, protocol, err := proxyLink(entry)
		if err != nil {
			return nil, err
		}
		if strings.ContainsAny(link, "\x00\r\n") || (strings.Contains(link, "'") && strings.Contains(link, `"`)) {
			return nil, fmt.Errorf("proxy %q generated an invalid dae link", entry.Name)
		}
		if validate != nil {
			if err := validate(link); err != nil {
				// The parser's error may quote the whole link.
				return nil, fmt.Errorf("proxy %q generated %s link cannot be parsed by dae", entry.Name, protocol)
			}
		}
		nodes = append(nodes, Node{Name: entry.Name, Safe: safe[i], Protocol: protocol, Link: link})
	}
	return nodes, nil
}

func proxyLink(entry Entry) (link, protocol string, err error) {
	protocol = strings.ToLower(strings.TrimSpace(entry.Type))
	if protocol == "" {
		return "", "", fmt.Errorf("proxy %q has empty type", entry.Name)
	}
	if field, bad := firstUnsupportedField(entry.Node, proxyFieldSet); bad {
		return "", protocol, fmt.Errorf("proxy %q has unsupported field %q", entry.Name, field)
	}
	var f proxyFields
	if err := entry.Node.Decode(&f); err != nil {
		return "", protocol, fmt.Errorf("proxy %q has invalid fields", entry.Name)
	}
	if err := f.validate(entry.Name); err != nil {
		return "", protocol, err
	}
	switch protocol {
	case "anytls":
		link, err = anytlsLink(entry.Name, f)
	case "ss":
		link, err = shadowsocksLink(entry.Name, f)
	case "socks5":
		link, err = socks5Link(entry.Name, f)
	case "hysteria2", "hy2":
		protocol = "hysteria2"
		link, err = hysteria2Link(entry.Name, f)
	default:
		return "", protocol, fmt.Errorf("proxy %q uses unsupported type %q", entry.Name, protocol)
	}
	return link, protocol, err
}

func (f proxyFields) validate(name string) error {
	if f.Server == "" || strings.TrimSpace(f.Server) != f.Server || strings.ContainsAny(f.Server, "\x00\r\n\t /?#@") {
		return fmt.Errorf("proxy %q has an invalid server", name)
	}
	if !(f.Port == 0 && strings.TrimSpace(f.Ports) != "") && (f.Port < 1 || f.Port > 65535) {
		return fmt.Errorf("proxy %q has an invalid port", name)
	}
	for field, value := range map[string]string{
		"username": f.Username, "password": f.Password, "auth": f.Auth, "cipher": f.Cipher,
		"sni": f.SNI, "servername": f.ServerName, "client-fingerprint": f.ClientFingerprint,
		"plugin": f.Plugin, "up": f.Up, "down": f.Down, "obfs": f.Obfs, "obfs-password": f.ObfsPassword,
		"ports": f.Ports, "fingerprint": f.Fingerprint, "ca": f.CA, "ca-str": f.CAString,
	} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("proxy %q has a control character in %s", name, field)
		}
	}
	for _, value := range f.ALPN {
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("proxy %q has a control character in alpn", name)
		}
	}
	if f.SNI != "" && f.ServerName != "" && f.SNI != f.ServerName {
		return fmt.Errorf("proxy %q has conflicting sni and servername", name)
	}
	for key, value := range f.PluginOpts {
		if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\x00\r\n") {
			return fmt.Errorf("proxy %q has an invalid plugin option name", name)
		}
		if value == nil {
			return fmt.Errorf("proxy %q has an empty plugin option", name)
		}
	}
	return nil
}

func buildLink(scheme string, user *url.Userinfo, host string, query url.Values) string {
	u := url.URL{Scheme: scheme, User: user, Host: host}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

func hostPort(f proxyFields) string {
	return net.JoinHostPort(f.Server, strconv.Itoa(f.Port))
}

func anytlsLink(name string, f proxyFields) (string, error) {
	if f.Password == "" {
		return "", fmt.Errorf("proxy %q anytls password is required", name)
	}
	if f.Username != "" || f.Cipher != "" || f.Plugin != "" || len(f.PluginOpts) != 0 || f.hasHysteria2Fields() {
		return "", fmt.Errorf("proxy %q anytls has unsupported fields", name)
	}
	if f.TLS != nil && !*f.TLS {
		return "", fmt.Errorf("proxy %q anytls tls=false is unsupported", name)
	}
	if f.UDP != nil && !*f.UDP {
		return "", fmt.Errorf("proxy %q anytls udp=false is unsupported by dae", name)
	}
	query := url.Values{}
	if sni := f.sni(); sni != "" {
		query.Set("sni", sni)
	}
	if f.SkipCertVerify != nil && *f.SkipCertVerify {
		query.Set("insecure", "1")
	}
	return buildLink("anytls", url.User(f.Password), hostPort(f), query), nil
}

func socks5Link(name string, f proxyFields) (string, error) {
	if f.Cipher != "" || f.SNI != "" || f.ServerName != "" || f.ClientFingerprint != "" || f.Plugin != "" || len(f.PluginOpts) != 0 || f.hasHysteria2Fields() {
		return "", fmt.Errorf("proxy %q socks5 has unsupported fields", name)
	}
	if f.TLS != nil && *f.TLS {
		return "", fmt.Errorf("proxy %q socks5 tls=true is unsupported", name)
	}
	if f.SkipCertVerify != nil && *f.SkipCertVerify {
		return "", fmt.Errorf("proxy %q socks5 skip-cert-verify is unsupported", name)
	}
	if f.UDP != nil && !*f.UDP {
		return "", fmt.Errorf("proxy %q socks5 udp=false is unsupported", name)
	}
	var user *url.Userinfo
	switch {
	case f.Username == "" && f.Password == "":
	case f.Password == "":
		user = url.User(f.Username)
	default:
		user = url.UserPassword(f.Username, f.Password)
	}
	return buildLink("socks5", user, hostPort(f), nil), nil
}

func shadowsocksLink(name string, f proxyFields) (string, error) {
	if f.Cipher == "" || f.Password == "" {
		return "", fmt.Errorf("proxy %q ss cipher and password are required", name)
	}
	if f.Username != "" || f.SNI != "" || f.ServerName != "" || f.ClientFingerprint != "" || f.hasHysteria2Fields() {
		return "", fmt.Errorf("proxy %q ss has unsupported fields", name)
	}
	if f.TLS != nil && *f.TLS {
		return "", fmt.Errorf("proxy %q ss tls=true is unsupported", name)
	}
	if f.SkipCertVerify != nil && *f.SkipCertVerify {
		return "", fmt.Errorf("proxy %q ss skip-cert-verify is unsupported", name)
	}
	plugin, err := ssPlugin(name, f)
	if err != nil {
		return "", err
	}
	// Plugins carry TCP only: UDP must be explicitly off with one, and may
	// not be explicitly off without one.
	if plugin == "" {
		if f.UDP != nil && !*f.UDP {
			return "", fmt.Errorf("proxy %q ss udp=false is unsupported", name)
		}
	} else if f.UDP != nil && *f.UDP {
		return "", fmt.Errorf("proxy %q ss udp=true is unsupported with an ss plugin", name)
	}
	query := url.Values{}
	if plugin != "" {
		query.Set("plugin", plugin)
	}
	return buildLink("ss", url.UserPassword(f.Cipher, f.Password), hostPort(f), query), nil
}

// ---- ss plugins ----

func ssPlugin(name string, f proxyFields) (string, error) {
	plugin := strings.ToLower(strings.TrimSpace(f.Plugin))
	if plugin == "" {
		if len(f.PluginOpts) != 0 {
			return "", fmt.Errorf("proxy %q has plugin options without a plugin", name)
		}
		return "", nil
	}
	if strings.Contains(plugin, ";") {
		return "", fmt.Errorf("proxy %q has an invalid ss plugin", name)
	}
	options, err := pluginOptions(name, f.PluginOpts)
	if err != nil {
		return "", err
	}
	switch plugin {
	case "obfs", "obfs-local", "simple-obfs", "simpleobfs":
		return simpleObfs(name, options)
	case "shadowtls", "shadow-tls", "sstls":
		return shadowTLS(name, options)
	case "v2ray-plugin":
		return v2rayPlugin(name, options)
	}
	return "", fmt.Errorf("proxy %q uses unsupported ss plugin", name)
}

func pluginOptions(name string, raw map[string]any) (map[string]string, error) {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	options := make(map[string]string, len(raw))
	for _, rawKey := range keys {
		value, err := optionString(raw[rawKey])
		if err != nil {
			return nil, fmt.Errorf("proxy %q has an invalid plugin option", name)
		}
		if strings.ContainsAny(value, "\x00\r\n;") {
			return nil, fmt.Errorf("proxy %q has an invalid plugin option value", name)
		}
		key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(rawKey), "_", "-"))
		if prev, ok := options[key]; ok && prev != value {
			return nil, fmt.Errorf("proxy %q has conflicting plugin options", name)
		}
		options[key] = value
	}
	return options, nil
}

func optionString(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return v, nil
	case bool:
		return strconv.FormatBool(v), nil
	case int:
		return strconv.Itoa(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case uint64:
		return strconv.FormatUint(v, 10), nil
	case float64:
		if math.Trunc(v) != v || math.IsInf(v, 0) {
			return "", errors.New("non-integral option")
		}
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	}
	return "", errors.New("unsupported option type")
}

func setOnce(m map[string]string, key, value string) error {
	if prev, ok := m[key]; ok && prev != value {
		return errors.New("conflicting option")
	}
	m[key] = value
	return nil
}

func simpleObfs(name string, options map[string]string) (string, error) {
	canon := map[string]string{}
	for key, value := range options {
		var target string
		switch key {
		case "mode", "obfs":
			target = "obfs"
		case "host", "obfs-host":
			target = "host"
		case "path", "uri", "obfs-path", "obfs-uri":
			target = "uri"
		default:
			return "", fmt.Errorf("proxy %q uses unsupported simple-obfs option", name)
		}
		if err := setOnce(canon, target, value); err != nil {
			return "", fmt.Errorf("proxy %q has conflicting simple-obfs options", name)
		}
	}
	mode := strings.ToLower(canon["obfs"])
	if mode != "http" && mode != "tls" {
		return "", fmt.Errorf("proxy %q has unsupported simple-obfs mode", name)
	}
	parts := []string{"simple-obfs", "obfs=" + mode}
	if v := canon["host"]; v != "" {
		parts = append(parts, "obfs-host="+v)
	}
	if v := canon["uri"]; v != "" {
		if !strings.HasPrefix(v, "/") {
			v = "/" + v
		}
		parts = append(parts, "obfs-uri="+v)
	}
	return strings.Join(parts, ";"), nil
}

func shadowTLS(name string, options map[string]string) (string, error) {
	canon := map[string]string{}
	for key, value := range options {
		target := key
		switch key {
		case "passwd", "pwd":
			target = "password"
		case "v":
			target = "version"
		case "allow-insecure", "allowinsecure", "insecure", "skip-cert-verify", "skipverify":
			target = "allowInsecure"
		case "password", "version", "host", "sni":
		default:
			return "", fmt.Errorf("proxy %q uses unsupported shadow-tls option", name)
		}
		if target == "allowInsecure" {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "true", "1", "yes", "on":
				value = "true"
			case "false", "0", "no", "off":
				value = "false"
			default:
				return "", fmt.Errorf("proxy %q has an invalid shadow-tls option", name)
			}
		}
		if err := setOnce(canon, target, value); err != nil {
			return "", fmt.Errorf("proxy %q has conflicting shadow-tls options", name)
		}
	}
	parts := []string{"shadow-tls"}
	for _, key := range []string{"password", "version", "host", "sni", "allowInsecure"} {
		if v := canon[key]; v != "" {
			parts = append(parts, key+"="+v)
		}
	}
	return strings.Join(parts, ";"), nil
}

func v2rayPlugin(name string, options map[string]string) (string, error) {
	canon := map[string]string{}
	for key, value := range options {
		switch key {
		case "mode", "obfs":
			if lower := strings.ToLower(value); value != "" && lower != "websocket" && lower != "ws" {
				return "", fmt.Errorf("proxy %q has unsupported v2ray-plugin mode", name)
			}
		case "host", "obfs-host":
			if err := setOnce(canon, "host", value); err != nil {
				return "", fmt.Errorf("proxy %q has conflicting v2ray-plugin options", name)
			}
		case "tls":
			switch {
			case strings.EqualFold(value, "true") || strings.EqualFold(value, "tls") || value == "1":
				if err := setOnce(canon, "tls", "true"); err != nil {
					return "", fmt.Errorf("proxy %q has conflicting v2ray-plugin options", name)
				}
			case strings.EqualFold(value, "false") || value == "0":
			default:
				return "", fmt.Errorf("proxy %q has an invalid v2ray-plugin tls option", name)
			}
		default:
			return "", fmt.Errorf("proxy %q uses unsupported v2ray-plugin option", name)
		}
	}
	parts := []string{"v2ray-plugin"}
	if canon["tls"] == "true" {
		parts = append(parts, "tls")
	}
	if v := canon["host"]; v != "" {
		parts = append(parts, "host="+v)
	}
	return strings.Join(parts, ";"), nil
}

// ---- hysteria2 ----

var rateRE = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([kKmMgGtT]?)([Bb])ps$`)

func hysteria2Link(name string, f proxyFields) (string, error) {
	auth, err := hysteria2Auth(name, f)
	if err != nil {
		return "", err
	}
	if f.Username != "" || f.Cipher != "" || f.ClientFingerprint != "" || f.Plugin != "" || len(f.PluginOpts) != 0 {
		return "", fmt.Errorf("proxy %q hysteria2 has unsupported fields", name)
	}
	if f.CAString != "" || f.CWND != 0 || f.UdpMTU != 0 || len(f.ALPN) != 0 || f.HopInterval != 0 {
		return "", fmt.Errorf("proxy %q hysteria2 has fields unsupported by kdae", name)
	}
	if f.TLS != nil && !*f.TLS {
		return "", fmt.Errorf("proxy %q hysteria2 tls=false is unsupported", name)
	}
	if f.UDP != nil && !*f.UDP {
		return "", fmt.Errorf("proxy %q hysteria2 udp=false is unsupported by dae", name)
	}
	host := hostPort(f)
	if ports := strings.TrimSpace(f.Ports); ports != "" {
		normalized, err := normalizePorts(ports)
		if err != nil {
			return "", fmt.Errorf("proxy %q has an invalid hysteria2 ports", name)
		}
		host = net.JoinHostPort(f.Server, normalized)
	}

	query := url.Values{}
	if sni := f.sni(); sni != "" {
		query.Set("sni", sni)
	}
	if f.SkipCertVerify != nil && *f.SkipCertVerify {
		query.Set("insecure", "1")
	}
	pin, err := pinSHA256(name, f.Fingerprint)
	if err != nil {
		return "", err
	}
	if pin != "" {
		query.Set("pinSHA256", pin)
	}
	if ca := strings.TrimSpace(f.CA); ca != "" {
		query.Set("ca", ca)
	}
	up, err := bandwidth(name, "up", f.Up)
	if err != nil {
		return "", err
	}
	down, err := bandwidth(name, "down", f.Down)
	if err != nil {
		return "", err
	}
	setBandwidth(query, up, down)

	switch obfs := strings.ToLower(strings.TrimSpace(f.Obfs)); obfs {
	case "":
		if strings.TrimSpace(f.ObfsPassword) != "" {
			return "", fmt.Errorf("proxy %q hysteria2 obfs-password requires obfs", name)
		}
	case "salamander":
		if strings.TrimSpace(f.ObfsPassword) == "" {
			return "", fmt.Errorf("proxy %q hysteria2 obfs=salamander requires obfs-password", name)
		}
		query.Set("obfs", "salamander")
		query.Set("obfs-password", f.ObfsPassword)
	default:
		return "", fmt.Errorf("proxy %q hysteria2 has unsupported obfs", name)
	}
	return buildLink("hysteria2", url.User(auth), host, query), nil
}

// hysteria2Auth keeps credential bytes unchanged; trimming only decides
// whether a credential is present.
func hysteria2Auth(name string, f proxyFields) (string, error) {
	hasPassword := strings.TrimSpace(f.Password) != ""
	hasAuth := strings.TrimSpace(f.Auth) != ""
	switch {
	case hasPassword && hasAuth:
		if f.Password != f.Auth {
			return "", fmt.Errorf("proxy %q hysteria2 has conflicting password and auth", name)
		}
		return f.Password, nil
	case hasPassword:
		return f.Password, nil
	case hasAuth:
		return f.Auth, nil
	}
	return "", fmt.Errorf("proxy %q hysteria2 password is required", name)
}

func normalizePorts(ports string) (string, error) {
	if ports == "all" || ports == "*" {
		return "", errors.New("wildcard ports")
	}
	parse := func(s string) (string, error) {
		n, err := strconv.ParseUint(s, 10, 16)
		if err != nil || n == 0 {
			return "", errors.New("invalid port")
		}
		return s, nil
	}
	var parts []string
	for _, part := range strings.Split(ports, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", errors.New("empty port")
		}
		if from, to, isRange := strings.Cut(part, "-"); isRange {
			from, to = strings.TrimSpace(from), strings.TrimSpace(to)
			if from == "" || to == "" || strings.Contains(to, "-") {
				return "", errors.New("invalid port range")
			}
			if _, err := parse(from); err != nil {
				return "", err
			}
			if _, err := parse(to); err != nil {
				return "", err
			}
			parts = append(parts, from+"-"+to)
			continue
		}
		if _, err := parse(part); err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ","), nil
}

func pinSHA256(name, fingerprint string) (string, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return "", nil
	}
	switch strings.ToLower(fingerprint) {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return "", fmt.Errorf("proxy %q hysteria2 fingerprint is a client impersonation name; kdae has no mapping", name)
	}
	clean := strings.NewReplacer(":", "", "-", "").Replace(strings.ToLower(fingerprint))
	raw, err := hex.DecodeString(clean)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("proxy %q has an invalid hysteria2 fingerprint", name)
	}
	return hex.EncodeToString(raw), nil
}

// bandwidth returns bytes/second. A bare integer means Mbps (Mihomo
// convention); otherwise "<n><K|M|G|T>?<b|B>ps" where b is bits, B bytes.
func bandwidth(name, field, value string) (uint64, error) {
	s := strings.TrimSpace(value)
	if s == "" {
		return 0, nil
	}
	invalid := fmt.Errorf("proxy %q has an invalid hysteria2 %s", name, field)
	if v, err := strconv.Atoi(s); err == nil {
		if v <= 0 {
			return 0, invalid
		}
		return uint64(v) * 1_000_000 / 8, nil
	}
	m := rateRE.FindStringSubmatch(s)
	if m == nil {
		return 0, invalid
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil || n <= 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, invalid
	}
	scale := map[string]float64{"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[strings.ToUpper(m[2])]
	amount := n * scale
	if m[3] == "b" {
		amount /= 8
	}
	if amount <= 0 || amount > float64(math.MaxUint64) {
		return 0, invalid
	}
	rounded := math.Round(amount)
	if math.Abs(amount-rounded) > 1e-6 {
		return 0, fmt.Errorf("proxy %q hysteria2 %s is not an integer byte rate", name, field)
	}
	if rounded == 0 {
		return 0, invalid
	}
	return uint64(rounded), nil
}

func setBandwidth(query url.Values, upBps, downBps uint64) {
	upMbps, upOK := wholeMbps(upBps)
	downMbps, downOK := wholeMbps(downBps)
	if upOK && downOK {
		if upBps > 0 {
			query.Set("upmbps", strconv.FormatUint(upMbps, 10))
		}
		if downBps > 0 {
			query.Set("downmbps", strconv.FormatUint(downMbps, 10))
		}
		return
	}
	// Non-integer Mbps uses dae's raw maxTx/maxRx (bytes/s); the URI parser
	// wants both keys, a missing side is encoded as 0.
	query.Set("maxTx", strconv.FormatUint(upBps, 10))
	query.Set("maxRx", strconv.FormatUint(downBps, 10))
}

func wholeMbps(bps uint64) (uint64, bool) {
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
