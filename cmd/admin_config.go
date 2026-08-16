/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

const (
	adminSecretPlaceholder = "***"
	adminMaxConfigBytes    = 2 << 20
	adminConfigFileMode    = 0o600
)

var nodeURIScheme = regexp.MustCompile(`(?i)(hy2|hysteria2?|ssr?|vmess|vless|trojan|tuic|juicity|anytls|socks5?)://`)
var adminSecretAssign = regexp.MustCompile(`(?m)^([ \t]*admin_secret[ \t]*:[ \t]*)('[^']*'|"[^"]*"|[^\s#]+)`)

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

func loadAdminConfig(configDir string) (adminConfigResponse, error) {
	configPath, routingPath, err := adminConfigPaths(configDir)
	if err != nil {
		return adminConfigResponse{}, err
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return adminConfigResponse{}, err
	}
	extracted, err := extractNamedSections(string(raw), "global", "routing")
	if err != nil {
		return adminConfigResponse{}, err
	}
	extracted = stripNodeURILines(rewriteAdminSecret(extracted, adminSecretPlaceholder))
	routing := ""
	if body, readErr := os.ReadFile(routingPath); readErr == nil {
		routing = stripNodeURILines(string(body))
	} else if !os.IsNotExist(readErr) {
		return adminConfigResponse{}, readErr
	}
	return adminConfigResponse{Config: extracted, Routing: routing}, nil
}

func applyAdminConfig(configDir string, incoming adminConfigBody, reload adminReloadFunc) (queued bool, err error) {
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
		if err := rejectDisallowedAdminConfig(*incoming.Routing, true); err != nil {
			return false, err
		}
		mergedRouting = *incoming.Routing
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
	restore := func() {
		_ = os.Rename(configBak, configPath)
		if routingExists {
			_ = os.Rename(routingBak, routingPath)
		} else {
			_ = os.Remove(routingPath)
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
	if _, _, err := readConfig(configPath); err != nil {
		restore()
		return false, fmt.Errorf("%s", sanitizeAdminError(err))
	}
	_ = os.Remove(configBak)
	_ = os.Remove(routingBak)
	if reload == nil {
		return false, nil
	}
	return reload(), nil
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
	if len(msg) > 400 {
		return msg[:400]
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
