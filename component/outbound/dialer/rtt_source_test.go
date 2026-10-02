// SPDX-License-Identifier: AGPL-3.0-only
package dialer

import (
	"github.com/daeuniverse/dae/common/consts"
	"testing"
	"time"
)

func TestBusinessHandshakeCannotChangeProbeHealth(t *testing.T) {
	d := newNamedTestDialer(t, "mixed-rtt")
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	now := time.Now()
	for i := 0; i < 3; i++ {
		d.health.observeProbe(typ.Index(), true, 65*time.Millisecond, now)
	}
	for cycle := 0; cycle < 10; cycle++ {
		for i := 0; i < 20; i++ {
			d.ObserveHandshake(typ, 20*time.Millisecond)
		}
		d.health.observeProbe(typ.Index(), true, 65*time.Millisecond, now)
		if d.AdmissionState(typ) != AdmissionAlive {
			t.Fatal("mixed measurements caused false degradation")
		}
	}
	for i := 0; i < 3; i++ {
		d.health.observeProbe(typ.Index(), true, 200*time.Millisecond, now)
	}
	if d.AdmissionState(typ) != AdmissionDegraded {
		t.Fatal("persistent probe slowdown not detected")
	}
	for i := 0; i < 20; i++ {
		d.ObserveHandshake(typ, time.Millisecond)
	}
	if d.AdmissionState(typ) != AdmissionDegraded {
		t.Fatal("business handshake recovered probe health")
	}
}

func TestProbeRTTRequiresConsecutiveSlowSamples(t *testing.T) {
	var h nodeHealth
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.observeProbe(IdxTcp4, true, 50*time.Millisecond, now)
	}
	for i := 0; i < 2; i++ {
		h.observeProbe(IdxTcp4, true, 76*time.Millisecond, now)
	}
	if h.admission(IdxTcp4, true) != AdmissionAlive {
		t.Fatal("isolated slow probes degraded node")
	}
	h.observeProbe(IdxTcp4, true, 76*time.Millisecond, now)
	if h.admission(IdxTcp4, true) != AdmissionDegraded {
		t.Fatal("baseline adaptation hid persistent slowdown")
	}
	h.observeProbe(IdxTcp4, true, 50*time.Millisecond, now)
	if h.admission(IdxTcp4, true) != AdmissionDegraded {
		t.Fatal("one success recovered node")
	}
	h.observeProbe(IdxTcp4, true, 50*time.Millisecond, now)
	if h.admission(IdxTcp4, true) != AdmissionAlive {
		t.Fatal("two normal probes did not recover")
	}
}

func TestNormalProbeBreaksSlowRun(t *testing.T) {
	var h nodeHealth
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.observeProbe(IdxTcp4, true, 50*time.Millisecond, now)
	}
	for cycle := 0; cycle < 4; cycle++ {
		for i := 0; i < 2; i++ {
			h.observeProbe(IdxTcp4, true, 200*time.Millisecond, now)
		}
		h.observeProbe(IdxTcp4, true, 50*time.Millisecond, now)
		if h.admission(IdxTcp4, true) != AdmissionAlive {
			t.Fatal("nonconsecutive spikes accumulated")
		}
	}
	h.observeFailure(IdxTcp4, now)
	if h.fallbackAdmission(IdxTcp4, true) != AdmissionDegraded {
		t.Fatal("RTT debounce masked connection failure")
	}
}

func TestFailedActiveProbeImmediatelyDegrades(t *testing.T) {
	for _, udpTransport := range []bool{false, true} {
		h := nodeHealth{udpTransport: udpTransport}
		now := time.Now()
		for i := 0; i < 3; i++ {
			h.observeProbe(IdxTcp4, true, 50*time.Millisecond, now)
		}
		need := 1
		if udpTransport {
			need = nodeHealthUDPTransportFailStreak
		}
		for i := 1; i <= need; i++ {
			h.observeProbe(IdxTcp4, false, 0, now)
			want := AdmissionAlive
			if i == need {
				want = AdmissionDegraded
			}
			if got := h.fallbackAdmission(IdxTcp4, true); got != want {
				t.Fatalf("udpTransport=%v failures=%d: got %v want %v", udpTransport, i, got, want)
			}
		}
		if h.admission(IdxTcp4, false) != AdmissionDead {
			t.Fatal("unreachable node remained eligible")
		}
	}
}
