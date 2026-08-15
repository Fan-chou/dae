/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"slices"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

type groupSelectionStoreContextKey struct{}

// WithGroupSelectionStore attaches the optional user-space selection store to
// a control-plane build. The context is an injection seam so the public
// control-plane constructor signatures, outbound IDs, and routing ABI remain
// unchanged.
func WithGroupSelectionStore(ctx context.Context, store *outbound.GroupSelectionStore) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, groupSelectionStoreContextKey{}, store)
}

func groupSelectionStoreFromContext(ctx context.Context) *outbound.GroupSelectionStore {
	if ctx == nil {
		return nil
	}
	store, _ := ctx.Value(groupSelectionStoreContextKey{}).(*outbound.GroupSelectionStore)
	return store
}

func applyPersistedGroupSelection(
	store *outbound.GroupSelectionStore,
	group config.Group,
	policy *outbound.DialerSelectionPolicy,
	members []string,
	log *logrus.Logger,
) {
	// Native dae groups have no sideband metadata and must retain their exact
	// fixed(index), random, and latency policy behavior.
	if store == nil || policy == nil || len(group.SelectionMembers) == 0 {
		return
	}
	result := store.Apply(group.Name, members)
	if result.Warning != "" && log != nil {
		log.Warnf("Mihomo select group %q: %s", group.Name, result.Warning)
	}
	if result.Index < 0 || result.Index >= len(members) {
		return
	}
	policy.Policy = consts.DialerSelectionPolicy_Fixed
	policy.FixedIndex = result.Index
}

// SetGroupSelection is the user-space setting seam for a converted Mihomo
// select group. It validates the member against the current generation before
// persisting and changing the live group policy. The optional admin HTTP
// API calls this without a full reload.
func (c *ControlPlane) SetGroupSelection(groupName, memberName string) error {
	if c == nil {
		return fmt.Errorf("control plane is nil")
	}
	if c.groupSelectionStore == nil {
		return fmt.Errorf("group selection persistence is unavailable")
	}
	members := c.groupSelectionMembers[groupName]
	index := slices.Index(members, memberName)
	if index < 0 {
		return fmt.Errorf("group %q has no member %q", groupName, memberName)
	}
	var target *outbound.DialerGroup
	for _, group := range c.outbounds {
		if group != nil && group.Name == groupName {
			target = group
			break
		}
	}
	if target == nil {
		return fmt.Errorf("group %q is not a selectable outbound", groupName)
	}
	if err := c.groupSelectionStore.Set(groupName, memberName); err != nil {
		return fmt.Errorf("persist selection for group %q: %w", groupName, err)
	}
	target.SetSelectionPolicy(outbound.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: index,
	})
	return nil
}
