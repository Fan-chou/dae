/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2laya.org>
 */

package control

import (
	"testing"
)

// TestDnsCorpus_LegacyBaseline runs the DNS compatibility corpus against the
// current DnsController implementation. Each fixture builds a fresh
// controller, installs its forwarder factory, and replays the cases.
//
// This test pins observable DNS behavior (UDP/TCP transport, stale cache,
// reject-before-cache, negative responses) so subsequent refactors cannot
// regress user-visible semantics.
func TestDnsCorpus_LegacyBaseline(t *testing.T) {
	for _, fixture := range DnsCorpusFixtures() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			ReplayDns(t, fixture)
		})
	}
}
