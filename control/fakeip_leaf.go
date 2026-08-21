/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common/consts"
)

func (c *ControlPlane) fakeIPOutboundLeafIsProxy(idx consts.OutboundIndex) bool {
	if c == nil || idx.IsReserved() {
		return false
	}
	if int(idx) >= len(c.outbounds) || c.outbounds[idx] == nil {
		return false
	}
	return c.outbounds[idx].FakeIPLeafIsProxy()
}

func (c *ControlPlane) bindFakeIPLeafResolver() {
	if c == nil || c.routingMatcher == nil {
		return
	}
	c.routingMatcher.fakeIPLeafIsProxy = c.fakeIPOutboundLeafIsProxy
}
