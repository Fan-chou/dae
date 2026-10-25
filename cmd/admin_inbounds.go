/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

// Where an inbound is defined. Only the ones in config.dae can be edited
// through the admin API; the others belong to a file the API does not own
// (routing.dae is edited as text, anything else is typically generated, e.g.
// by the OpenWrt LuCI page from /etc/config/dae).
const (
	inboundOriginConfig  = "config"
	inboundOriginRouting = "routing"
	inboundOriginManaged = "managed"

	// inboundStatePending is an inbound that was saved but is not running with
	// that definition yet: a reload has not happened or has not succeeded.
	inboundStatePending = "pending"
)

const adminMaxInboundBytes = 64 << 10

// adminInboundsMu serializes edits of config.dae's inbound section.
var adminInboundsMu sync.Mutex

type adminInbound struct {
	control.InboundStatus
	Origin   string `json:"origin"`
	Editable bool   `json:"editable"`
}

type adminInboundsBody struct {
	Inbounds []adminInbound `json:"inbounds"`
	// Editable is whether the admin API can change anything at all, i.e.
	// whether config.dae is writable here.
	Editable bool `json:"editable"`
}

// adminInboundPut is one inbound as a client sends it. A nil Password keeps
// the one already saved under the same name; an empty one removes it.
type adminInboundPut struct {
	Name         string  `json:"name"`
	Listen       string  `json:"listen"`
	Username     string  `json:"username"`
	Password     *string `json:"password"`
	UDP          *bool   `json:"udp"`
	UDPAdvertise string  `json:"udp_advertise"`
	Sniff        string  `json:"sniff"`
	Resolve      string  `json:"resolve"`
}

type adminInboundsPutBody struct {
	Inbounds []adminInboundPut `json:"inbounds"`
}

// inboundsInFile returns the inbounds that a file defines.
func inboundsInFile(path string) ([]config.Inbound, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return inboundsInText(string(raw))
}

func inboundsInText(src string) ([]config.Inbound, error) {
	extracted, err := extractNamedSections(src, "inbound")
	if err != nil {
		return nil, err
	}
	if extracted == "" {
		return nil, nil
	}
	return config.ParseInbounds(extracted)
}

// loadAdminInbounds merges what the files define with what is running. The
// running state wins for anything a client reads as "state"; the definition of
// a config.dae inbound comes from the file, so a saved change shows at once
// (as pending) instead of after the reload.
func loadAdminInbounds(configDir string, running []control.InboundStatus) (adminInboundsBody, error) {
	configPath, routingPath, err := adminConfigPaths(configDir)
	if err != nil {
		return adminInboundsBody{}, err
	}
	inConfig, err := inboundsInFile(configPath)
	if err != nil {
		return adminInboundsBody{}, err
	}
	inRouting, err := inboundsInFile(routingPath)
	if err != nil {
		return adminInboundsBody{}, err
	}

	byName := make(map[string]control.InboundStatus, len(running))
	for _, st := range running {
		byName[st.Name] = st
	}
	seen := make(map[string]bool)
	out := adminInboundsBody{Inbounds: []adminInbound{}, Editable: configWritable(configPath)}

	add := func(def config.Inbound, origin string) {
		st, isRunning := byName[def.Name]
		item := adminInbound{Origin: origin, Editable: origin == inboundOriginConfig && out.Editable}
		switch {
		case !isRunning:
			item.InboundStatus = statusFromDefinition(def)
			item.State = inboundStatePending
		case statusDiffers(st, def):
			// Show what is saved; the running listener still has the old one.
			item.InboundStatus = statusFromDefinition(def)
			item.State, item.Error = inboundStatePending, st.Error
			item.Conns, item.Associations, item.UDPSessions = st.Conns, st.Associations, st.UDPSessions
			item.Accepted, item.Since = st.Accepted, st.Since
		default:
			item.InboundStatus = st
		}
		out.Inbounds = append(out.Inbounds, item)
		seen[def.Name] = true
	}
	for i := range inConfig {
		add(inConfig[i], inboundOriginConfig)
	}
	for i := range inRouting {
		if !seen[inRouting[i].Name] {
			add(inRouting[i], inboundOriginRouting)
		}
	}
	routingNames := make(map[string]bool, len(inRouting))
	for _, in := range inRouting {
		routingNames[in.Name] = true
	}
	for _, st := range running {
		if seen[st.Name] {
			continue
		}
		origin := inboundOriginManaged
		if routingNames[st.Name] {
			origin = inboundOriginRouting
		}
		out.Inbounds = append(out.Inbounds, adminInbound{InboundStatus: st, Origin: origin})
		seen[st.Name] = true
	}
	return out, nil
}

func configWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func statusFromDefinition(in config.Inbound) control.InboundStatus {
	return control.InboundStatus{
		Name:         in.Name,
		Protocol:     in.Protocol,
		Listen:       in.Listen,
		Username:     in.Username,
		HasPassword:  in.Password != "",
		UDP:          in.UDP,
		UDPAdvertise: in.UDPAdvertise,
		Sniff:        in.Sniff,
		Resolve:      in.Resolve,
	}
}

// statusDiffers reports whether the running listener was started from a
// different definition than def. The password is not part of a status, so a
// change of it alone is not detected; it takes effect at the next reload.
func statusDiffers(st control.InboundStatus, def config.Inbound) bool {
	want := statusFromDefinition(def)
	return st.Listen != want.Listen || st.Username != want.Username || st.HasPassword != want.HasPassword ||
		st.UDP != want.UDP || st.UDPAdvertise != want.UDPAdvertise ||
		!strings.EqualFold(st.Sniff, want.Sniff) || !strings.EqualFold(st.Resolve, want.Resolve)
}

// buildInbounds turns client input into definitions, keeping the saved
// credentials where the client left the password out.
func buildInbounds(in []adminInboundPut, saved []config.Inbound) ([]config.Inbound, error) {
	byName := make(map[string]config.Inbound, len(saved))
	for _, s := range saved {
		byName[s.Name] = s
	}
	out := make([]config.Inbound, 0, len(in))
	for _, p := range in {
		name := strings.TrimSpace(p.Name)
		if err := config.ValidateInboundName(name); err != nil {
			return nil, err
		}
		def := config.Inbound{
			Name:         name,
			Protocol:     config.InboundProtocolSocks5,
			Listen:       strings.TrimSpace(p.Listen),
			Username:     p.Username,
			UDP:          true,
			UDPAdvertise: strings.TrimSpace(p.UDPAdvertise),
			Sniff:        strings.ToLower(strings.TrimSpace(p.Sniff)),
			Resolve:      strings.ToLower(strings.TrimSpace(p.Resolve)),
		}
		if p.UDP != nil {
			def.UDP = *p.UDP
		}
		if def.Sniff == "" {
			def.Sniff = config.InboundSniffAuto
		}
		if def.Resolve == "" {
			def.Resolve = config.InboundResolveLocal
		}
		switch {
		case p.Password != nil:
			def.Password = *p.Password
		default:
			def.Password = byName[name].Password
		}
		if def.Username == "" {
			// Without a user name there is no authentication to keep a
			// password for.
			def.Password = ""
		}
		out = append(out, def)
	}
	return out, nil
}

// quoteDaeValue quotes v for the configuration. dae does not interpret
// escapes inside a quoted string, so the quote that v does not contain is used.
func quoteDaeValue(field, v string) (string, error) {
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", fmt.Errorf("%s cannot contain line breaks", field)
	}
	switch {
	case !strings.Contains(v, "'"):
		return "'" + v + "'", nil
	case !strings.Contains(v, `"`):
		return `"` + v + `"`, nil
	}
	return "", fmt.Errorf("%s cannot contain both ' and \"", field)
}

// renderInboundSection writes the inbound section for defs, or "" for none.
func renderInboundSection(defs []config.Inbound) (string, error) {
	if len(defs) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteString("inbound {\n")
	for _, d := range defs {
		fmt.Fprintf(&b, "    %s {\n", d.Name)
		put := func(key, value string) error {
			q, err := quoteDaeValue(key, value)
			if err != nil {
				return fmt.Errorf("inbound %q: %w", d.Name, err)
			}
			fmt.Fprintf(&b, "        %s: %s\n", key, q)
			return nil
		}
		if err := put("listen", d.Listen); err != nil {
			return "", err
		}
		if d.Username != "" {
			if err := put("username", d.Username); err != nil {
				return "", err
			}
			if err := put("password", d.Password); err != nil {
				return "", err
			}
		}
		if !d.UDP {
			b.WriteString("        udp: false\n")
		}
		if d.UDPAdvertise != "" {
			if err := put("udp_advertise", d.UDPAdvertise); err != nil {
				return "", err
			}
		}
		if d.Sniff != "" && d.Sniff != config.InboundSniffAuto {
			fmt.Fprintf(&b, "        sniff: %s\n", d.Sniff)
		}
		if d.Resolve != "" && d.Resolve != config.InboundResolveLocal {
			fmt.Fprintf(&b, "        resolve: %s\n", d.Resolve)
		}
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// rewriteNamedSection replaces every section called name in src with raw,
// placed where the first one was; with raw == "" they are removed. A missing
// section is appended.
func rewriteNamedSection(src, name, raw string) (string, error) {
	sections, err := scanTopLevelSections(src)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	last, placed := 0, false
	for _, sec := range sections {
		if !strings.EqualFold(sec.Name, name) {
			continue
		}
		b.WriteString(src[last:sec.Start])
		if !placed {
			b.WriteString(raw)
			placed = true
		}
		last = sec.End
	}
	b.WriteString(src[last:])
	out := b.String()
	if !placed && raw != "" {
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += "\n" + raw
	}
	return out, nil
}

// applyAdminInbounds replaces the inbound section of config.dae with the
// requested inbounds and checks the whole configuration. A file that does not
// load is put back exactly as it was.
func applyAdminInbounds(configDir string, in []adminInboundPut, reload adminReloadFunc) (queued bool, err error) {
	adminInboundsMu.Lock()
	defer adminInboundsMu.Unlock()

	configPath, _, err := adminConfigPaths(configDir)
	if err != nil {
		return false, err
	}
	disk, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}
	saved, err := inboundsInText(string(disk))
	if err != nil {
		return false, err
	}
	defs, err := buildInbounds(in, saved)
	if err != nil {
		return false, err
	}
	if err := config.ValidateInbounds(defs, 0); err != nil {
		return false, err
	}
	section, err := renderInboundSection(defs)
	if err != nil {
		return false, err
	}
	// What was rendered must read back as what was asked for; this is what
	// keeps a value from altering the file around it.
	if section != "" {
		back, perr := config.ParseInbounds(section)
		if perr != nil || !sameInbounds(back, defs) {
			return false, fmt.Errorf("an inbound value cannot be written to the configuration safely")
		}
	}
	merged, err := rewriteNamedSection(string(disk), "inbound", section)
	if err != nil {
		return false, err
	}

	bak := configPath + ".admin-bak"
	if err := writeFileAtomic(bak, disk, adminConfigFileMode); err != nil {
		return false, err
	}
	restore := func() { _ = os.Rename(bak, configPath) }
	if err := writeFileAtomic(configPath, []byte(merged), adminConfigFileMode); err != nil {
		restore()
		return false, err
	}
	if err := validateLoadedAdminConfig(configDir); err != nil {
		restore()
		return false, fmt.Errorf("%s", sanitizeAdminError(err))
	}
	_ = os.Remove(bak)
	if reload == nil {
		return false, nil
	}
	return reload(), nil
}

func sameInbounds(a, b []config.Inbound) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// restoreRoutingInboundPasswords puts the saved password back into a
// routing.dae that a client read back with the passwords hidden. A hidden
// password of an inbound the file did not have stays hidden, and the save is
// refused later.
func restoreRoutingInboundPasswords(incoming, disk string) (string, error) {
	if !hasRedactedInboundPassword(incoming) {
		return incoming, nil
	}
	sent, err := inboundsInText(incoming)
	if err != nil {
		return "", err
	}
	saved, err := inboundsInText(disk)
	if err != nil {
		return "", err
	}
	byName := make(map[string]config.Inbound, len(saved))
	for _, s := range saved {
		byName[s.Name] = s
	}
	for i := range sent {
		if sent[i].Password != adminSecretPlaceholder {
			continue
		}
		if old, ok := byName[sent[i].Name]; ok && old.Password != "" {
			sent[i].Password = old.Password
		}
	}
	for _, in := range sent {
		if in.Password == adminSecretPlaceholder {
			return incoming, nil
		}
	}
	section, err := renderInboundSection(sent)
	if err != nil {
		return "", err
	}
	return rewriteNamedSection(incoming, "inbound", section)
}

func (s *adminServer) handleInbounds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var running []control.InboundStatus
		if s.inbounds != nil {
			running = s.inbounds()
		}
		body, err := loadAdminInbounds(s.configDir, running)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, sanitizeAdminError(err))
			return
		}
		writeAdminJSON(w, http.StatusOK, body)
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, adminMaxInboundBytes)
		var body adminInboundsPutBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid json")
			return
		}
		queued, err := applyAdminInbounds(s.configDir, body.Inbounds, s.reload)
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, sanitizeAdminError(err))
			return
		}
		writeAdminJSON(w, http.StatusOK, adminReloadBody{Queued: queued})
	default:
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
