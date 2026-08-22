// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import "testing"

func TestEncodeOutboundConnectivityValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		alive        bool
		kernelDirect bool
		want         uint32
	}{
		{false, false, 0},
		{true, false, outboundConnAliveBit},
		{false, true, outboundKernelDirectBit},
		{true, true, outboundConnAliveBit | outboundKernelDirectBit},
	}
	for _, tc := range cases {
		if got := encodeOutboundConnectivityValue(tc.alive, tc.kernelDirect); got != tc.want {
			t.Fatalf("encodeOutboundConnectivityValue(%v, %v) = %d, want %d",
				tc.alive, tc.kernelDirect, got, tc.want)
		}
	}
}
