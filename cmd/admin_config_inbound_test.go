/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"strings"
	"testing"
)

func TestRedactInboundPasswords(t *testing.T) {
	src := "inbound {\n  lan {\n    listen: '192.168.1.1:1081'\n    username: alice\n    password: 'real-secret'\n  }\n  other {\n    password: plain\n  }\n}\n"
	got := redactInboundPasswords(src)
	if strings.Contains(got, "real-secret") || strings.Contains(got, "plain") {
		t.Fatalf("password leaked:\n%s", got)
	}
	if !strings.Contains(got, "username: alice") || !strings.Contains(got, "listen: '192.168.1.1:1081'") {
		t.Fatalf("non-secret lines were altered:\n%s", got)
	}
	if strings.Count(got, "password: '***'") != 2 {
		t.Fatalf("expected both passwords redacted:\n%s", got)
	}
}

func TestHasRedactedInboundPassword(t *testing.T) {
	if !hasRedactedInboundPassword("a {\n password: '***'\n}") {
		t.Fatal("placeholder not detected")
	}
	if hasRedactedInboundPassword("a {\n password: 'hunter2'\n}") {
		t.Fatal("real password reported as placeholder")
	}
	if hasRedactedInboundPassword("a {\n listen: '1.2.3.4:5'\n}") {
		t.Fatal("no password line reported as placeholder")
	}
}

func TestRejectDisallowedAdminConfigRefusesRedactedPasswordInRouting(t *testing.T) {
	routing := redactInboundPasswords("routing {\n  fallback: direct\n}\ninbound {\n  a {\n    password: 'x'\n  }\n}\n")
	if err := rejectDisallowedAdminConfig(routing, true); err == nil {
		t.Fatal("writing back a redacted password must be refused")
	}
}
