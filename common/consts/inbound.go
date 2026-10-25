/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import "hash/fnv"

// Function_Inbound is the routing function that matches the user-space
// inbound (see section "inbound") a flow entered dae through.
const Function_Inbound = "inbound"

// MatchType_Inbound is a user-space-only match type. It is deliberately kept
// out of the generated eBPF enum: the kernel only ever sees transparent
// traffic, which never entered through an inbound, so the kernel projection
// of an inbound() match is a constant FALSE (see rewriteKernRulesWithRingLpmIndex).
// The value is above every generated MatchType.
const MatchType_Inbound MatchType = 0x80

// InboundID derives the stable routing identity of an inbound from its name.
// It is never 0: 0 means "not from an inbound" (transparent traffic), so a
// zero ID can never satisfy an inbound() match. Deriving the ID from the name
// keeps the compiled rule set and the listener independent of config order;
// config validation rejects the (astronomically unlikely) name collisions.
func InboundID(name string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	id := h.Sum32()
	if id == 0 {
		id = 1
	}
	return id
}
