/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

const inboundTestConfig = `global {
    tproxy_port: 12345
    wan_interface: auto
    lan_interface: lo
}
routing {
    fallback: direct
}
`

func inboundTestDir(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	writeRestrictedDae(t, filepath.Join(dir, "config.dae"), inboundTestConfig+extra)
	return dir
}

func boolPtr(v bool) *bool { return &v }

func TestRenderInboundSectionRoundTrips(t *testing.T) {
	in := []adminInboundPut{
		{Name: "s1", Listen: "127.0.0.1:1080"},
		{Name: "lan", Listen: "192.168.1.1:1081", Username: "alice", Password: strPtr("it's secret"), UDP: boolPtr(false),
			UDPAdvertise: "203.0.113.7", Sniff: "off", Resolve: "deferred"},
	}
	defs, err := buildInbounds(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	section, err := renderInboundSection(defs)
	if err != nil {
		t.Fatal(err)
	}
	back, err := config.ParseInbounds(section)
	if err != nil {
		t.Fatalf("rendered section does not parse: %v\n%s", err, section)
	}
	if !sameInbounds(back, defs) {
		t.Fatalf("round trip changed the inbounds:\n got %+v\nwant %+v\n%s", back, defs, section)
	}
	if strings.Contains(section, "udp: true") || strings.Contains(section, "sniff: auto") {
		t.Fatalf("defaults should not be written out:\n%s", section)
	}
	if empty, err := renderInboundSection(nil); err != nil || empty != "" {
		t.Fatalf("no inbounds must render nothing: %q %v", empty, err)
	}
}

func TestRenderInboundSectionRefusesValuesThatBreakOut(t *testing.T) {
	for name, put := range map[string]adminInboundPut{
		"newline in listen":   {Name: "a", Listen: "127.0.0.1:1\n}\nglobal {"},
		"newline in password": {Name: "a", Listen: "127.0.0.1:1", Username: "u", Password: strPtr("x\ny")},
		"both quote kinds":    {Name: "a", Listen: "127.0.0.1:1", Username: "u", Password: strPtr(`a'b"c`)},
	} {
		defs, err := buildInbounds([]adminInboundPut{put}, nil)
		if err != nil {
			continue
		}
		if _, err := renderInboundSection(defs); err == nil {
			t.Errorf("%s was written to the configuration", name)
		}
	}
}

func TestBuildInboundsKeepsOrClearsPassword(t *testing.T) {
	saved := []config.Inbound{{Name: "lan", Username: "alice", Password: "kept"}}
	keep, err := buildInbounds([]adminInboundPut{{Name: "lan", Listen: "192.168.1.1:1", Username: "alice"}}, saved)
	if err != nil || keep[0].Password != "kept" {
		t.Fatalf("an omitted password must keep the saved one: %+v %v", keep, err)
	}
	set, _ := buildInbounds([]adminInboundPut{{Name: "lan", Listen: "192.168.1.1:1", Username: "alice", Password: strPtr("new")}}, saved)
	if set[0].Password != "new" {
		t.Fatalf("a sent password must replace it: %+v", set)
	}
	// Dropping the user name drops authentication, and with it the password.
	off, _ := buildInbounds([]adminInboundPut{{Name: "lan", Listen: "127.0.0.1:1"}}, saved)
	if off[0].Username != "" || off[0].Password != "" {
		t.Fatalf("authentication was not switched off: %+v", off)
	}
	// A new name never inherits another inbound's password.
	fresh, _ := buildInbounds([]adminInboundPut{{Name: "other", Listen: "192.168.1.1:2", Username: "bob"}}, saved)
	if fresh[0].Password != "" {
		t.Fatalf("password leaked to another inbound: %+v", fresh)
	}
	if _, err := buildInbounds([]adminInboundPut{{Name: "bad name", Listen: "127.0.0.1:1"}}, nil); err == nil {
		t.Fatal("an invalid name must be refused")
	}
}

func TestApplyAdminInboundsAddEditRemove(t *testing.T) {
	dir := inboundTestDir(t, "")
	reloads := 0
	reload := func() bool { reloads++; return true }

	queued, err := applyAdminInbounds(dir, []adminInboundPut{
		{Name: "s1", Listen: "127.0.0.1:11080"},
		{Name: "lan", Listen: "192.168.1.1:11081", Username: "alice", Password: strPtr("secret")},
	}, reload)
	if err != nil || !queued || reloads != 1 {
		t.Fatalf("add: queued=%v err=%v reloads=%d", queued, err, reloads)
	}
	got, _ := inboundsInFile(filepath.Join(dir, "config.dae"))
	if len(got) != 2 || got[1].Password != "secret" {
		t.Fatalf("saved inbounds = %+v", got)
	}

	// Edit without resending the password: it must survive.
	if _, err := applyAdminInbounds(dir, []adminInboundPut{
		{Name: "s1", Listen: "127.0.0.1:11080"},
		{Name: "lan", Listen: "192.168.1.1:11082", Username: "alice"},
	}, reload); err != nil {
		t.Fatal(err)
	}
	got, _ = inboundsInFile(filepath.Join(dir, "config.dae"))
	if got[1].Listen != "192.168.1.1:11082" || got[1].Password != "secret" {
		t.Fatalf("edit lost the password or the change: %+v", got)
	}

	// The rest of the file is untouched.
	raw, _ := os.ReadFile(filepath.Join(dir, "config.dae"))
	if !strings.Contains(string(raw), "tproxy_port: 12345") || !strings.Contains(string(raw), "fallback: direct") {
		t.Fatalf("other sections were damaged:\n%s", raw)
	}

	// Removing them all drops the section.
	if _, err := applyAdminInbounds(dir, nil, reload); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "config.dae"))
	if strings.Contains(string(raw), "inbound") {
		t.Fatalf("section was not removed:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.dae.admin-bak")); err == nil {
		t.Fatal("backup left behind")
	}
}

func TestApplyAdminInboundsRestoresOnInvalidConfig(t *testing.T) {
	dir := inboundTestDir(t, "inbound {\n    s1 {\n        listen: '127.0.0.1:11080'\n    }\n}\n")
	before, _ := os.ReadFile(filepath.Join(dir, "config.dae"))

	for name, put := range map[string]adminInboundPut{
		"open proxy":         {Name: "x", Listen: "0.0.0.0:11090"},
		"tproxy port":        {Name: "x", Listen: "127.0.0.1:12345"},
		"half credentials":   {Name: "x", Listen: "127.0.0.1:11090", Username: "u"},
		"bad sniff":          {Name: "x", Listen: "127.0.0.1:11090", Sniff: "maybe"},
		"same port as other": {Name: "x", Listen: "127.0.0.1:11080"},
	} {
		if _, err := applyAdminInbounds(dir, []adminInboundPut{{Name: "s1", Listen: "127.0.0.1:11080"}, put}, nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "config.dae"))
		if string(after) != string(before) {
			t.Fatalf("%s: config.dae changed after a refused edit:\n%s", name, after)
		}
	}
}

func TestApplyAdminInboundsRefusesRemovingAReferencedInbound(t *testing.T) {
	dir := t.TempDir()
	writeRestrictedDae(t, filepath.Join(dir, "config.dae"), `global {
    tproxy_port: 12345
    wan_interface: auto
    lan_interface: lo
}
inbound {
    s1 {
        listen: '127.0.0.1:11080'
    }
}
routing {
    inbound(s1) -> direct
    fallback: direct
}
`)
	before, _ := os.ReadFile(filepath.Join(dir, "config.dae"))
	if _, err := applyAdminInbounds(dir, nil, nil); err == nil {
		t.Fatal("removing an inbound that a rule names must be refused")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "config.dae"))
	if string(after) != string(before) {
		t.Fatalf("config.dae changed:\n%s", after)
	}
}

func TestRestoreRoutingInboundPasswords(t *testing.T) {
	disk := "routing {\n    fallback: direct\n}\ninbound {\n    lan {\n        listen: '192.168.1.1:1'\n        username: 'alice'\n        password: 'real'\n    }\n}\n"
	read := redactInboundPasswords(disk)
	restored, err := restoreRoutingInboundPasswords(read, disk)
	if err != nil {
		t.Fatal(err)
	}
	if hasRedactedInboundPassword(restored) {
		t.Fatalf("placeholder still present:\n%s", restored)
	}
	ins, _ := inboundsInText(restored)
	if len(ins) != 1 || ins[0].Password != "real" || ins[0].Listen != "192.168.1.1:1" {
		t.Fatalf("restored inbound = %+v", ins)
	}
	if !strings.Contains(restored, "fallback: direct") {
		t.Fatalf("other sections lost:\n%s", restored)
	}

	// A text without a placeholder is passed through byte for byte.
	plain := "# note\n" + disk
	if got, _ := restoreRoutingInboundPasswords(plain, disk); got != plain {
		t.Fatalf("untouched text was rewritten:\n%s", got)
	}

	// A placeholder for a name the file does not have stays, so the save is refused.
	renamed := strings.ReplaceAll(read, "lan {", "wan {")
	got, err := restoreRoutingInboundPasswords(renamed, disk)
	if err != nil || !hasRedactedInboundPassword(got) {
		t.Fatalf("a renamed inbound must keep the placeholder: %v\n%s", err, got)
	}
	if err := rejectDisallowedAdminConfig(got, true); err == nil {
		t.Fatal("the placeholder must be refused")
	}
}

func TestApplyAdminConfigKeepsRoutingInboundPassword(t *testing.T) {
	dir := inboundTestDir(t, "")
	routing := "inbound {\n    lan {\n        listen: '192.168.1.1:11081'\n        username: 'alice'\n        password: 'real'\n    }\n}\nrouting {\n    fallback: direct\n}\n"
	writeRestrictedDae(t, filepath.Join(dir, "routing.dae"), routing)
	writeRestrictedDae(t, filepath.Join(dir, "config.dae"), inboundTestConfig+"include {\n    routing.dae\n}\n")

	body, err := loadAdminConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body.Routing, "real") {
		t.Fatalf("GET leaked the password:\n%s", body.Routing)
	}
	edited := strings.Replace(body.Routing, "fallback: direct", "fallback: direct\n    dport(22) -> direct", 1)
	if _, err := applyAdminConfig(dir, adminConfigBody{Routing: &edited}, nil); err != nil {
		t.Fatalf("saving the text that was read must work: %v", err)
	}
	saved, _ := os.ReadFile(filepath.Join(dir, "routing.dae"))
	if !strings.Contains(string(saved), "password: 'real'") || !strings.Contains(string(saved), "dport(22)") {
		t.Fatalf("routing.dae after save:\n%s", saved)
	}
}

func TestLoadAdminInboundsOriginsAndPending(t *testing.T) {
	dir := inboundTestDir(t, "inbound {\n    a {\n        listen: '127.0.0.1:11080'\n    }\n    b {\n        listen: '127.0.0.1:11081'\n    }\n    c {\n        listen: '127.0.0.1:11082'\n    }\n}\n")
	writeRestrictedDae(t, filepath.Join(dir, "routing.dae"), "inbound {\n    r {\n        listen: '127.0.0.1:11083'\n    }\n}\n")
	running := []control.InboundStatus{
		{Name: "a", Protocol: "socks5", Listen: "127.0.0.1:11080", UDP: true, Sniff: "auto", Resolve: "local", State: control.InboundStateListening, Conns: 2},
		// b is running on its old port; the file has moved it.
		{Name: "b", Protocol: "socks5", Listen: "127.0.0.1:19999", UDP: true, Sniff: "auto", Resolve: "local", State: control.InboundStateListening},
		{Name: "c", Protocol: "socks5", Listen: "127.0.0.1:11082", UDP: true, Sniff: "auto", Resolve: "local", State: control.InboundStateFailed, Error: "address already in use"},
		{Name: "r", Protocol: "socks5", Listen: "127.0.0.1:11083", UDP: true, Sniff: "auto", Resolve: "local", State: control.InboundStateListening},
		{Name: "gen", Protocol: "socks5", Listen: "127.0.0.1:11084", UDP: true, Sniff: "auto", Resolve: "local", State: control.InboundStateListening},
	}
	body, err := loadAdminInbounds(dir, running)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]adminInbound{}
	for _, in := range body.Inbounds {
		by[in.Name] = in
	}
	if len(by) != 5 {
		t.Fatalf("inbounds = %+v", body.Inbounds)
	}
	if a := by["a"]; a.Origin != "config" || !a.Editable || a.State != "listening" || a.Conns != 2 {
		t.Errorf("a = %+v", a)
	}
	if b := by["b"]; b.State != "pending" || b.Listen != "127.0.0.1:11081" {
		t.Errorf("b should show the saved listen as pending: %+v", b)
	}
	if c := by["c"]; c.State != "failed" || c.Error == "" {
		t.Errorf("c = %+v", c)
	}
	if r := by["r"]; r.Origin != "routing" || r.Editable {
		t.Errorf("r = %+v", r)
	}
	if g := by["gen"]; g.Origin != "managed" || g.Editable {
		t.Errorf("gen = %+v", g)
	}
	// A saved inbound that is not running yet is pending.
	if err := os.WriteFile(filepath.Join(dir, "config.dae"), []byte(inboundTestConfig+"inbound {\n    n {\n        listen: '127.0.0.1:11085'\n    }\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "routing.dae"))
	body, _ = loadAdminInbounds(dir, nil)
	if len(body.Inbounds) != 1 || body.Inbounds[0].State != "pending" {
		t.Fatalf("new inbound = %+v", body.Inbounds)
	}
}

func TestHandleInboundsNeverReturnsPassword(t *testing.T) {
	dir := inboundTestDir(t, "inbound {\n    lan {\n        listen: '192.168.1.1:11081'\n        username: 'alice'\n        password: 'topsecret'\n    }\n}\n")
	s := &adminServer{configDir: dir, secret: "x"}
	s.inbounds = func() []control.InboundStatus {
		return []control.InboundStatus{{Name: "lan", Protocol: "socks5", Listen: "192.168.1.1:11081", Username: "alice", HasPassword: true, UDP: true, Sniff: "auto", Resolve: "local", State: "listening"}}
	}
	rec := httptest.NewRecorder()
	s.handleInbounds(rec, httptest.NewRequest(http.MethodGet, "/v1/inbounds", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "topsecret") {
		t.Fatalf("password leaked: %s", rec.Body)
	}
	var out adminInboundsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Inbounds) != 1 || !out.Inbounds[0].HasPassword {
		t.Fatalf("body = %s (%v)", rec.Body, err)
	}

	rec = httptest.NewRecorder()
	s.handleInbounds(rec, httptest.NewRequest(http.MethodPut, "/v1/inbounds", strings.NewReader(`{"inbounds":[{"name":"lan","listen":"192.168.1.1:11099","username":"alice"}]}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status %d: %s", rec.Code, rec.Body)
	}
	saved, _ := inboundsInFile(filepath.Join(dir, "config.dae"))
	if len(saved) != 1 || saved[0].Password != "topsecret" || saved[0].Listen != "192.168.1.1:11099" {
		t.Fatalf("saved = %+v", saved)
	}

	rec = httptest.NewRecorder()
	s.handleInbounds(rec, httptest.NewRequest(http.MethodDelete, "/v1/inbounds", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE status %d", rec.Code)
	}
}
