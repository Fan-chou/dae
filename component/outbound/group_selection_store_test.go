/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupSelectionStorePersistsIdentityAndUses0600AtomicState(t *testing.T) {
	configDir := t.TempDir()
	store := NewDefaultGroupSelectionStore(configDir)
	if got, want := store.Path(), filepath.Join(configDir, GroupSelectionStateRelativePath); got != want {
		t.Fatalf("store.Path() = %q, want %q", got, want)
	}

	if err := store.Set("proxy-group", "node-two"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	stateInfo, err := os.Stat(store.Path())
	if err != nil {
		t.Fatalf("Stat(state) error = %v", err)
	}
	if got := stateInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("state permissions = %04o, want 0600", got)
	}
	body, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("ReadFile(state) error = %v", err)
	}
	if !strings.Contains(string(body), "node-two") || strings.Contains(string(body), "://") || strings.Contains(string(body), "password") {
		t.Fatalf("state body contains unexpected material: %s", body)
	}

	reloaded := NewDefaultGroupSelectionStore(configDir)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	result := reloaded.Apply("proxy-group", []string{"node-one", "node-two"})
	if result.Index != 1 || result.SelectedMember != "node-two" || result.UsedFallback || result.Warning != "" {
		t.Fatalf("Apply() = %#v, want persisted identity at index 1", result)
	}

	entries, err := os.ReadDir(filepath.Dir(store.Path()))
	if err != nil {
		t.Fatalf("ReadDir(state directory) error = %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".state-") {
			t.Fatalf("temporary state file was left behind: %q", entry.Name())
		}
	}
}

func TestGroupSelectionStoreMissingOrStaleStateFallsBackSafely(t *testing.T) {
	store := NewDefaultGroupSelectionStore(t.TempDir())
	if err := store.Load(); err != nil {
		t.Fatalf("Load() for missing state error = %v", err)
	}
	missing := store.Apply("proxy-group", []string{"node-one", "node-two"})
	if missing.Index != 0 || missing.SelectedMember != "node-one" || !missing.UsedFallback || missing.Warning == "" {
		t.Fatalf("missing-state Apply() = %#v, want first-member fallback warning", missing)
	}

	if err := store.Set("proxy-group", "node-two"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	stale := store.Apply("proxy-group", []string{"node-one", "node-three"})
	if stale.Index != 0 || stale.SelectedMember != "node-one" || !stale.UsedFallback || !strings.Contains(stale.Warning, "no longer present") {
		t.Fatalf("stale-state Apply() = %#v, want first-member fallback warning", stale)
	}
}

func TestGroupSelectionStoreInvalidStateDoesNotBlockApply(t *testing.T) {
	store := NewDefaultGroupSelectionStore(t.TempDir())
	if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(store.Path(), []byte(`{"version":1,"selections":{"proxy-group":"https://user:password@example.invalid"}}`), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid state) error = %v", err)
	}
	if err := store.Load(); err == nil {
		t.Fatal("Load() error = nil for unsafe state")
	}
	result := store.Apply("proxy-group", []string{"node-one"})
	if result.Index != 0 || result.SelectedMember != "node-one" || !result.UsedFallback {
		t.Fatalf("Apply() = %#v, want safe first-member fallback", result)
	}
}

func TestGroupSelectionStoreRejectsNonIdentifierState(t *testing.T) {
	store := NewDefaultGroupSelectionStore(t.TempDir())
	for _, test := range []struct {
		group  string
		member string
	}{
		{group: "proxy group", member: "node-one"},
		{group: "proxy-group", member: "https://example.invalid/link"},
	} {
		if err := store.Set(test.group, test.member); err == nil {
			t.Fatalf("Set(%q, %q) error = nil", test.group, test.member)
		}
	}
}
