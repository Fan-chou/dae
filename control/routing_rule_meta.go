/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"strings"
)

// UnknownRuleMatchIndex is the sentinel match-set index used when no compiled
// routing rule could be attributed (compatible with a future u16 eBPF field).
const UnknownRuleMatchIndex uint16 = 0xFFFF

// RoutingRuleMeta describes the user-configured or expanded routing rule
// attributed to a connection.
type RoutingRuleMeta struct {
	Index      int    `json:"index"`
	Raw        string `json:"raw"`
	Origin     string `json:"origin,omitempty"`
	MatchIndex uint16 `json:"match_index,omitempty"`
}

func (m *RoutingMatcher) RuleMetaForMatchIndex(idx uint16) *RoutingRuleMeta {
	if m == nil || idx == UnknownRuleMatchIndex || int(idx) >= len(m.ruleMetaByMatchIndex) {
		return nil
	}
	return m.ruleMetaByMatchIndex[idx]
}

func pnameString(pname [16]uint8) string {
	b := pname[:]
	if nul := bytes.IndexByte(b, 0); nul >= 0 {
		b = b[:nul]
	}
	return strings.TrimSpace(string(b))
}
