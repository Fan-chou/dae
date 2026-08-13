/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestApplyPersistedGroupSelectionUsesIdentityAfterReordering(t *testing.T) {
	store := outbound.NewGroupSelectionStore(t.TempDir() + "/state.json")
	if err := store.Set("proxy-group", "node-two"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	policy := &outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}
	group := config.Group{
		Name:             "proxy-group",
		SelectionMembers: []string{"node-one", "node-two"},
		Policy:           &config_parser.Function{Name: "fixed", Params: []*config_parser.Param{{Val: "0"}}},
	}
	applyPersistedGroupSelection(store, group, policy, []string{"node-two", "node-one"}, nil)
	if policy.Policy != consts.DialerSelectionPolicy_Fixed || policy.FixedIndex != 0 {
		t.Fatalf("policy = %#v, want identity node-two at current index 0", policy)
	}
}

func TestApplyPersistedGroupSelectionFallsBackAndLeavesNativeGroupAlone(t *testing.T) {
	store := outbound.NewGroupSelectionStore(t.TempDir() + "/state.json")
	if err := store.Set("proxy-group", "node-gone"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	policy := &outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 7}
	generated := config.Group{Name: "proxy-group", SelectionMembers: []string{"node-one", "node-two"}}
	applyPersistedGroupSelection(store, generated, policy, []string{"node-one", "node-two"}, nil)
	if policy.FixedIndex != 0 {
		t.Fatalf("stale generated selection index = %d, want safe fallback 0", policy.FixedIndex)
	}

	nativePolicy := &outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 7}
	native := config.Group{Name: "native", Policy: &config_parser.Function{Name: "fixed"}}
	applyPersistedGroupSelection(store, native, nativePolicy, []string{"node-one", "node-two"}, nil)
	if nativePolicy.FixedIndex != 7 {
		t.Fatalf("native fixed index = %d, want unchanged 7", nativePolicy.FixedIndex)
	}
}
