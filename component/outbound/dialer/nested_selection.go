/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// SelectionLatency returns the health-check latency used by a group selection
// policy. Nested groups need this when a direct dialer is one member beside a
// child group; keeping the lookup here preserves the dialer's existing health
// and backoff accounting.
func (d *Dialer) SelectionLatency(typ *NetworkType, policy consts.DialerSelectionPolicy) (time.Duration, bool) {
	if d == nil || typ == nil {
		return 0, false
	}
	return d.snapshotLatencyForPolicy(typ, policy)
}
