/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"math/bits"
)

// egressGuardReservedMarkMask covers fwmark bits dae and the usual router
// stack already use: the internal so_mark_from_dae bit (0x100), TPROXY_MARK
// (0x8000000) and the routing/Tailscale marks between them.
const egressGuardReservedMarkMask uint32 = 0x0fffff00

// ValidateEgressGuardProofMark checks egress_guard_proof_mark. 0 disables the
// feature; otherwise the value must be a single fwmark bit that does not
// overlap bits reserved for routing/TPROXY/Tailscale or an explicit
// so_mark_from_dae.
func (g *Global) ValidateEgressGuardProofMark() error {
	mark := g.EgressGuardProofMark
	if mark == 0 {
		return nil
	}
	if bits.OnesCount32(mark) != 1 {
		return fmt.Errorf("egress_guard_proof_mark %#x must be a single fwmark bit", mark)
	}
	if mark&egressGuardReservedMarkMask != 0 {
		return fmt.Errorf("egress_guard_proof_mark %#x overlaps reserved routing/TPROXY marks (%#x)", mark, egressGuardReservedMarkMask)
	}
	if mark&g.SoMarkFromDae != 0 {
		return fmt.Errorf("egress_guard_proof_mark %#x overlaps so_mark_from_dae %#x", mark, g.SoMarkFromDae)
	}
	return nil
}
