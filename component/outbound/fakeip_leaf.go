/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// FakeIPLeafIsProxy reports whether this group's live selection walks to a
// proxy node. DNS FakeIP uses this instead of Select(): it must not activate
// lazy health checks. Builtin direct/block and a fixed(i) member that is
// direct/block are not proxy. url-test / min / random / first_alive is PROXY
// if any member can be a proxy node.
func (g *DialerGroup) FakeIPLeafIsProxy() bool {
	return g.fakeIPLeafIsProxy(nil)
}

func (g *DialerGroup) fakeIPLeafIsProxy(seen map[*DialerGroup]struct{}) bool {
	if g == nil {
		return false
	}
	switch g.Name {
	case consts.OutboundDirect.String(), consts.OutboundBlock.String():
		return false
	}
	if _, dup := seen[g]; dup {
		return false
	}
	next := make(map[*DialerGroup]struct{}, len(seen)+1)
	for group := range seen {
		next[group] = struct{}{}
	}
	next[g] = struct{}{}

	policy := g.CurrentSelectionPolicy()
	if len(g.nestedMembers) > 0 {
		if policy.Policy == consts.DialerSelectionPolicy_Fixed {
			i := policy.FixedIndex
			if i < 0 || i >= len(g.nestedMembers) {
				return false
			}
			return g.nestedMembers[i].fakeIPLeafIsProxy(next)
		}
		for _, member := range g.nestedMembers {
			if member.fakeIPLeafIsProxy(next) {
				return true
			}
		}
		return false
	}
	if len(g.Dialers) == 0 {
		return false
	}
	if policy.Policy == consts.DialerSelectionPolicy_Fixed {
		i := policy.FixedIndex
		if i < 0 || i >= len(g.Dialers) {
			return false
		}
		return !fakeIPDialerIsReserved(g.Dialers[i])
	}
	for _, d := range g.Dialers {
		if !fakeIPDialerIsReserved(d) {
			return true
		}
	}
	return false
}

func (m dialerGroupMember) fakeIPLeafIsProxy(seen map[*DialerGroup]struct{}) bool {
	if m.group != nil {
		return m.group.fakeIPLeafIsProxy(seen)
	}
	return !fakeIPDialerIsReserved(m.dialer)
}

func fakeIPDialerIsReserved(d *dialer.Dialer) bool {
	if d == nil {
		return true
	}
	property := d.Property()
	if property == nil {
		return false
	}
	switch property.Name {
	case consts.OutboundDirect.String(), consts.OutboundBlock.String():
		return true
	default:
		return false
	}
}
