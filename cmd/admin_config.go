/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/daeuniverse/dae/config"
)

const (
	adminSecretPlaceholder = "***"
	adminMaxConfigBytes    = 2 << 20
	adminConfigFileMode    = 0o600
)

var (
	// adminConfigWriteMu serializes admin configuration reads/edits,
	// backup/restore, reload queuing, and snapshot recovery across config.dae
	// and routing.dae.
	adminConfigWriteMu sync.Mutex

	errAdminReloadQueueFull = errors.New("reload queue is full or unavailable; configuration changes were rolled back")
)

var nodeURIScheme = regexp.MustCompile(`(?i)(hy2|hysteria2?|ssr?|vmess|vless|trojan|tuic|juicity|anytls|socks5?)://`)
var adminSecretAssign = regexp.MustCompile(`(?m)^([ \t]*admin_secret[ \t]*:[ \t]*)('[^']*'|"[^"]*"|[^\s#]+)`)

// inboundPasswordAssign matches an inbound section's password line. routing.dae
// is served whole, so an inbound section placed there must not leak it.
var inboundPasswordAssign = regexp.MustCompile(`(?m)^([ \t]*password[ \t]*:[ \t]*)('[^']*'|"[^"]*"|[^\s#]+)`)

func redactInboundPasswords(src string) string {
	return inboundPasswordAssign.ReplaceAllString(src, "${1}'"+adminSecretPlaceholder+"'")
}

// hasRedactedInboundPassword reports whether src still carries the placeholder
// that redactInboundPasswords wrote, i.e. a client echoed back a redacted read.
func hasRedactedInboundPassword(src string) bool {
	for _, m := range inboundPasswordAssign.FindAllStringSubmatch(src, -1) {
		if unquoteAdminScalar(m[2]) == adminSecretPlaceholder {
			return true
		}
	}
	return false
}

type adminConfigBody struct {
	Config  *string `json:"config"`
	Routing *string `json:"routing"`
}

type adminConfigResponse struct {
	Config  string `json:"config"`
	Routing string `json:"routing"`
}

type rawSection struct {
	Name  string
	Raw   string
	Start int
	End   int
}

func adminConfigPaths(configDir string) (configPath, routingPath string, err error) {
	if strings.TrimSpace(configDir) == "" {
		return "", "", fmt.Errorf("config directory is not set")
	}
	dir := filepath.Clean(configDir)
	return filepath.Join(dir, "config.dae"), filepath.Join(dir, "routing.dae"), nil
}

type adminFileStatKey struct {
	exists  bool
	modNano int64
	size    int64
}

func statAdminFileKey(path string) (adminFileStatKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return adminFileStatKey{exists: false}, nil
		}
		return adminFileStatKey{}, err
	}
	return adminFileStatKey{
		exists:  true,
		modNano: info.ModTime().UnixNano(),
		size:    info.Size(),
	}, nil
}

var adminConfigCache = struct {
	mu        sync.Mutex
	configDir string
	cfgStat   adminFileStatKey
	routeStat adminFileStatKey
	resp      adminConfigResponse
	etag      string
}{}

func invalidateAdminFileCaches() {
	adminConfigCache.mu.Lock()
	adminConfigCache.configDir = ""
	adminConfigCache.mu.Unlock()

	adminInboundsCache.mu.Lock()
	adminInboundsCache.configDir = ""
	adminInboundsCache.mu.Unlock()
}

func formatAdminETag(digest string) string {
	if len(digest) > 32 {
		digest = digest[:32]
	}
	return `"` + digest + `"`
}

func checkAdminIfMatch(header, currentETag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return true
	}
	if header == "*" {
		return currentETag != ""
	}
	cur := strings.Trim(strings.TrimPrefix(strings.TrimSpace(currentETag), "W/"), `"`)
	if cur == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		cand := strings.TrimSpace(part)
		cand = strings.TrimPrefix(cand, "W/")
		cand = strings.Trim(cand, `"`)
		if cand == cur {
			return true
		}
	}
	return false
}

func currentAdminConfigETag(configDir string) (string, error) {
	snap, err := readAdminConfigSnapshot(configDir)
	if err != nil {
		return "", err
	}
	return formatAdminETag(snap.digest), nil
}

func loadAdminConfigCached(configDir string) (adminConfigResponse, string, error) {
	configPath, routingPath, err := adminConfigPaths(configDir)
	if err != nil {
		return adminConfigResponse{}, "", err
	}
	cfgStat, err := statAdminFileKey(configPath)
	if err != nil {
		return adminConfigResponse{}, "", err
	}
	routeStat, err := statAdminFileKey(routingPath)
	if err != nil {
		return adminConfigResponse{}, "", err
	}

	adminConfigCache.mu.Lock()
	if adminConfigCache.configDir == configDir &&
		adminConfigCache.cfgStat == cfgStat &&
		adminConfigCache.routeStat == routeStat &&
		adminConfigCache.etag != "" {
		resp := adminConfigCache.resp
		etag := adminConfigCache.etag
		adminConfigCache.mu.Unlock()
		return resp, etag, nil
	}
	adminConfigCache.mu.Unlock()

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return adminConfigResponse{}, "", err
	}
	extracted, err := extractNamedSections(string(raw), "global", "routing")
	if err != nil {
		return adminConfigResponse{}, "", err
	}
	extracted = stripNodeURILines(rewriteAdminSecret(extracted, adminSecretPlaceholder))
	routingText := ""
	var routingBytes []byte
	routingExists := false
	if body, readErr := os.ReadFile(routingPath); readErr == nil {
		routingExists = true
		routingBytes = body
		routingText = stripNodeURILines(redactInboundPasswords(string(body)))
	} else if !os.IsNotExist(readErr) {
		return adminConfigResponse{}, "", readErr
	}
	resp := adminConfigResponse{Config: extracted, Routing: routingText}
	etag := formatAdminETag(adminSnapshotDigest(raw, routingExists, routingBytes))

	adminConfigCache.mu.Lock()
	adminConfigCache.configDir = configDir
	adminConfigCache.cfgStat = cfgStat
	adminConfigCache.routeStat = routeStat
	adminConfigCache.resp = resp
	adminConfigCache.etag = etag
	adminConfigCache.mu.Unlock()

	return resp, etag, nil
}

func loadAdminConfig(configDir string) (adminConfigResponse, error) {
	resp, _, err := loadAdminConfigCached(configDir)
	return resp, err
}

func validateLoadedAdminConfig(configDir string) error {
	configPath, _, err := adminConfigPaths(configDir)
	if err != nil {
		return err
	}
	conf, _, err := readConfig(configPath)
	if err != nil {
		return err
	}
	return config.ValidateAdminListen(conf.Global.AdminListen)
}

func applyAdminConfig(configDir string, incoming adminConfigBody, reload adminReloadFunc) (queued bool, err error) {
	adminConfigWriteMu.Lock()
	defer adminConfigWriteMu.Unlock()
	return applyAdminConfigLocked(configDir, incoming, reload)
}

func applyAdminConfigLocked(configDir string, incoming adminConfigBody, reload adminReloadFunc) (queued bool, err error) {
	configPath, routingPath, err := adminConfigPaths(configDir)
	if err != nil {
		return false, err
	}
	diskConfig, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}
	diskRouting := []byte{}
	routingExists := true
	if body, readErr := os.ReadFile(routingPath); readErr == nil {
		diskRouting = body
	} else if os.IsNotExist(readErr) {
		routingExists = false
	} else {
		return false, readErr
	}

	mergedConfig := string(diskConfig)
	if incoming.Config != nil && strings.TrimSpace(*incoming.Config) != "" {
		if err := rejectDisallowedAdminConfig(*incoming.Config, false); err != nil {
			return false, err
		}
		if err := incomingSectionsOnly(*incoming.Config, "global", "routing"); err != nil {
			return false, err
		}
		restored := overlayAdminSecret(*incoming.Config, string(diskConfig))
		mergedConfig, err = replaceNamedSections(string(diskConfig), restored, "global", "routing")
		if err != nil {
			return false, err
		}
	}
	mergedRouting := string(diskRouting)
	if incoming.Routing != nil {
		restored, err := restoreRoutingInboundPasswords(*incoming.Routing, string(diskRouting))
		if err != nil {
			return false, err
		}
		if err := rejectDisallowedAdminConfig(restored, true); err != nil {
			return false, err
		}
		mergedRouting = restored
	}

	configBak := configPath + ".admin-bak"
	routingBak := routingPath + ".admin-bak"
	if err := writeFileAtomic(configBak, diskConfig, adminConfigFileMode); err != nil {
		return false, err
	}
	if routingExists {
		if err := writeFileAtomic(routingBak, diskRouting, adminConfigFileMode); err != nil {
			_ = os.Remove(configBak)
			return false, err
		}
	}
	cleanupBak := func() {
		_ = os.Remove(configBak)
		_ = os.Remove(routingBak)
	}
	restore := func() {
		if renameErr := os.Rename(configBak, configPath); renameErr == nil {
			_ = os.Remove(configBak)
		}
		if routingExists {
			if renameErr := os.Rename(routingBak, routingPath); renameErr == nil {
				_ = os.Remove(routingBak)
			}
		} else {
			_ = os.Remove(routingPath)
			_ = os.Remove(routingBak)
		}
	}

	if err := writeFileAtomic(configPath, []byte(mergedConfig), adminConfigFileMode); err != nil {
		restore()
		return false, err
	}
	if incoming.Routing != nil || routingExists {
		if err := writeFileAtomic(routingPath, []byte(mergedRouting), adminConfigFileMode); err != nil {
			restore()
			return false, err
		}
	}
	if err := validateLoadedAdminConfig(configDir); err != nil {
		restore()
		return false, fmt.Errorf("%s", sanitizeAdminError(err))
	}
	if reload == nil || !reload() {
		restore()
		invalidateAdminFileCaches()
		return false, errAdminReloadQueueFull
	}
	cleanupBak()
	invalidateAdminFileCaches()
	return true, nil
}

type adminConfigSnapshot struct {
	digest        string
	configBytes   []byte
	routingExists bool
	routingBytes  []byte
}

func adminSnapshotDigest(configBytes []byte, routingExists bool, routingBytes []byte) string {
	h := sha256.New()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(configBytes)))
	h.Write(lenBuf[:])
	h.Write(configBytes)
	if routingExists {
		h.Write([]byte{1})
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(routingBytes)))
		h.Write(lenBuf[:])
		h.Write(routingBytes)
	} else {
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readAdminConfigSnapshot(configDir string) (adminConfigSnapshot, error) {
	configPath, routingPath, err := adminConfigPaths(configDir)
	if err != nil {
		return adminConfigSnapshot{}, err
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return adminConfigSnapshot{}, err
	}
	var routingBytes []byte
	routingExists := true
	if body, readErr := os.ReadFile(routingPath); readErr == nil {
		routingBytes = body
	} else if os.IsNotExist(readErr) {
		routingExists = false
	} else {
		return adminConfigSnapshot{}, readErr
	}
	return adminConfigSnapshot{
		digest:        adminSnapshotDigest(configBytes, routingExists, routingBytes),
		configBytes:   configBytes,
		routingExists: routingExists,
		routingBytes:  routingBytes,
	}, nil
}

func writeAdminLastGoodSnapshot(configDir string, snap adminConfigSnapshot) {
	configPath, routingPath, err := adminConfigPaths(configDir)
	if err != nil {
		return
	}
	_ = writeFileAtomic(configPath+".admin-last-good", snap.configBytes, adminConfigFileMode)
	if snap.routingExists {
		_ = writeFileAtomic(routingPath+".admin-last-good", snap.routingBytes, adminConfigFileMode)
	} else {
		_ = os.Remove(routingPath + ".admin-last-good")
	}
}

func restoreAdminConfigSnapshot(configDir string, snap adminConfigSnapshot) error {
	if snap.digest == "" {
		return fmt.Errorf("no last-good snapshot recorded")
	}
	configPath, routingPath, err := adminConfigPaths(configDir)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(configPath, snap.configBytes, adminConfigFileMode); err != nil {
		return err
	}
	if snap.routingExists {
		if err := writeFileAtomic(routingPath, snap.routingBytes, adminConfigFileMode); err != nil {
			return err
		}
	} else if err := os.Remove(routingPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func rejectDisallowedAdminConfig(src string, routingFile bool) error {
	if nodeURIScheme.MatchString(src) {
		return fmt.Errorf("node URIs are not allowed")
	}
	if strings.Contains(src, "nodes.dae") {
		return fmt.Errorf("nodes.dae cannot be edited here")
	}
	sections, err := scanTopLevelSections(src)
	if err != nil {
		return err
	}
	for _, sec := range sections {
		switch strings.ToLower(sec.Name) {
		case "node", "subscription", "group":
			return fmt.Errorf("%s cannot be edited here", sec.Name)
		case "global", "routing":
		default:
			if !routingFile {
				return fmt.Errorf("section %s cannot be edited here", sec.Name)
			}
		}
	}
	if routingFile && strings.Contains(src, "://") {
		return fmt.Errorf("URIs are not allowed in routing.dae")
	}
	if routingFile && hasRedactedInboundPassword(src) {
		return fmt.Errorf("an inbound password is redacted in this view; edit it in the file instead")
	}
	return nil
}

func incomingSectionsOnly(src string, names ...string) error {
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[strings.ToLower(name)] = true
	}
	sections, err := scanTopLevelSections(src)
	if err != nil {
		return err
	}
	if len(sections) == 0 {
		return fmt.Errorf("config must contain global or routing")
	}
	for _, sec := range sections {
		if !allowed[strings.ToLower(sec.Name)] {
			return fmt.Errorf("section %s cannot be edited here", sec.Name)
		}
	}
	return nil
}

func extractNamedSections(src string, names ...string) (string, error) {
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[strings.ToLower(name)] = true
	}
	sections, err := scanTopLevelSections(src)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, sec := range sections {
		if !wanted[strings.ToLower(sec.Name)] {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.TrimRight(sec.Raw, "\n"))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func replaceNamedSections(original, incoming string, names ...string) (string, error) {
	incomingSections, err := scanTopLevelSections(incoming)
	if err != nil {
		return "", err
	}
	byName := map[string]string{}
	for _, sec := range incomingSections {
		byName[strings.ToLower(sec.Name)] = sec.Raw
	}
	origSections, err := scanTopLevelSections(original)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	last := 0
	replaced := map[string]bool{}
	for _, sec := range origSections {
		b.WriteString(original[last:sec.Start])
		if raw, ok := byName[strings.ToLower(sec.Name)]; ok {
			b.WriteString(raw)
			replaced[strings.ToLower(sec.Name)] = true
		} else {
			b.WriteString(sec.Raw)
		}
		last = sec.End
	}
	b.WriteString(original[last:])
	for _, name := range names {
		raw, ok := byName[strings.ToLower(name)]
		if !ok || replaced[strings.ToLower(name)] {
			continue
		}
		out := b.String()
		if out != "" && !strings.HasSuffix(out, "\n") {
			b.WriteByte('\n')
		}
		b.WriteString(raw)
		if !strings.HasSuffix(raw, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

func rewriteAdminSecret(src, value string) string {
	quoted := "'" + strings.ReplaceAll(value, "'", "") + "'"
	if !adminSecretAssign.MatchString(src) {
		return src
	}
	return adminSecretAssign.ReplaceAllStringFunc(src, func(match string) string {
		parts := adminSecretAssign.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		return parts[1] + quoted
	})
}

func overlayAdminSecret(incoming, disk string) string {
	diskValue := adminSecretValue(disk)
	if diskValue == "" {
		return stripAdminSecretLine(incoming)
	}
	if adminSecretAssign.MatchString(incoming) {
		return rewriteAdminSecret(incoming, diskValue)
	}
	return incoming
}

func adminSecretValue(src string) string {
	match := adminSecretAssign.FindStringSubmatch(src)
	if len(match) < 3 {
		return ""
	}
	return unquoteAdminScalar(match[2])
}

func unquoteAdminScalar(raw string) string {
	if len(raw) >= 2 {
		if (raw[0] == '\'' && raw[len(raw)-1] == '\'') || (raw[0] == '"' && raw[len(raw)-1] == '"') {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}

func stripAdminSecretLine(src string) string {
	return regexp.MustCompile(`(?m)^[ \t]*admin_secret[ \t]*:[ \t]*.*\n?`).ReplaceAllString(src, "")
}

func stripNodeURILines(src string) string {
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if nodeURIScheme.MatchString(line) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func sanitizeAdminError(err error) string {
	if err == nil {
		return "unknown error"
	}
	msg := err.Error()
	if nodeURIScheme.MatchString(msg) || strings.Contains(msg, "://") {
		return "config validation failed"
	}
	return truncateUTF8Bytes(msg, 400)
}

func sanitizeAdminSourceMessage(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return truncateUTF8Bytes(sanitizeLogString(raw), 400)
}

func sanitizeAdminSourceError(err error) string {
	if err == nil {
		return "sources refresh failed"
	}
	msg := sanitizeAdminSourceMessage(err.Error())
	if msg == "" {
		return "sources refresh failed"
	}
	return msg
}

func writeFileAtomic(path string, body []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func scanTopLevelSections(src string) ([]rawSection, error) {
	var out []rawSection
	i := 0
	n := len(src)
	for i < n {
		i = skipIdle(src, i)
		if i >= n {
			break
		}
		if !isIdentStart(rune(src[i])) {
			return nil, fmt.Errorf("unexpected %q in config", src[i])
		}
		start := i
		i++
		for i < n && isIdentPart(rune(src[i])) {
			i++
		}
		name := src[start:i]
		i = skipIdle(src, i)
		if i >= n || src[i] != '{' {
			return nil, fmt.Errorf("expected { after %s", name)
		}
		end, err := skipBalanced(src, i)
		if err != nil {
			return nil, err
		}
		out = append(out, rawSection{Name: name, Raw: src[start:end], Start: start, End: end})
		i = end
	}
	return out, nil
}

func skipIdle(src string, i int) int {
	n := len(src)
	for i < n {
		switch src[i] {
		case ' ', '\t', '\n', '\r':
			i++
		case '#':
			for i < n && src[i] != '\n' {
				i++
			}
		case '/':
			if i+1 < n && src[i+1] == '/' {
				for i < n && src[i] != '\n' {
					i++
				}
				continue
			}
			return i
		default:
			return i
		}
	}
	return i
}

func skipBalanced(src string, openBrace int) (int, error) {
	n := len(src)
	depth := 0
	i := openBrace
	for i < n {
		c := src[i]
		switch c {
		case '\'', '"':
			next, err := skipQuoted(src, i)
			if err != nil {
				return 0, err
			}
			i = next
		case '#':
			for i < n && src[i] != '\n' {
				i++
			}
		case '/':
			if i+1 < n && src[i+1] == '/' {
				for i < n && src[i] != '\n' {
					i++
				}
				continue
			}
			i++
		case '{':
			depth++
			i++
		case '}':
			depth--
			i++
			if depth == 0 {
				return i, nil
			}
		default:
			i++
		}
	}
	return 0, fmt.Errorf("unclosed {")
}

func skipQuoted(src string, i int) (int, error) {
	quote := src[i]
	i++
	n := len(src)
	for i < n {
		if src[i] == '\\' && i+1 < n {
			i += 2
			continue
		}
		if src[i] == quote {
			return i + 1, nil
		}
		i++
	}
	return 0, fmt.Errorf("unclosed string")
}

func isIdentStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

func isIdentPart(r rune) bool {
	return isIdentStart(r) || unicode.IsDigit(r)
}
