/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func TestRoutingEpochIngressGateCapsPackets(t *testing.T) {
	var g routingEpochIngressGate
	for i := 0; i < udpIngressSystemMaxPackets; i++ {
		if !g.tryAcquire(1) {
			t.Fatalf("tryAcquire(%d) rejected below packet cap", i)
		}
	}
	if g.tryAcquire(1) {
		t.Fatal("tryAcquire accepted past packet cap")
	}
	g.release(1)
	if !g.tryAcquire(1) {
		t.Fatal("tryAcquire rejected after a packet slot was released")
	}
}

func TestRoutingEpochIngressGateCapsBytes(t *testing.T) {
	var g routingEpochIngressGate
	if !g.tryAcquire(udpIngressSystemMaxBytes) {
		t.Fatal("tryAcquire of exact byte cap rejected")
	}
	if g.tryAcquire(1) {
		t.Fatal("tryAcquire accepted past byte cap")
	}
	g.release(udpIngressSystemMaxBytes)
	if !g.tryAcquire(1) {
		t.Fatal("tryAcquire rejected after byte budget was released")
	}
}
