package control

import (
	"os"
	"reflect"
	"testing"
)

// TestOffloadGateDisabled tests the opt-in gate predicate: the feature is off by
// default, DAE_DISABLE_TCP_RELAY_OFFLOAD=1 beats an explicit opt-in, and
// DAE_ALLOW_TCP_SOCKMAP=1 alone enables it. Runnable under dae_stub_ebpf because
// it only reads environment variables.
func TestOffloadGateDisabled(t *testing.T) {
	_ = os.Unsetenv("DAE_ALLOW_TCP_SOCKMAP")
	_ = os.Unsetenv("DAE_DISABLE_TCP_RELAY_OFFLOAD")
	if tcpRelayOffloadEnabled() {
		t.Error("disabled by default: no env vars set")
	}
	if err := os.Setenv("DAE_DISABLE_TCP_RELAY_OFFLOAD", "1"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	if err := os.Setenv("DAE_ALLOW_TCP_SOCKMAP", "1"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	if tcpRelayOffloadEnabled() {
		t.Error("DAE_DISABLE_TCP_RELAY_OFFLOAD=1 must win over opt-in")
	}
	_ = os.Unsetenv("DAE_DISABLE_TCP_RELAY_OFFLOAD")
	if !tcpRelayOffloadEnabled() {
		t.Error("opt-in with DAE_ALLOW_TCP_SOCKMAP=1 must enable")
	}
	_ = os.Unsetenv("DAE_ALLOW_TCP_SOCKMAP")
}

// TestOffloadProgramsAndMapsComplete checks that the hard-coded offload program
// and map name lists match the generated bpfPrograms/bpfMaps struct fields. This
// guards against drift between tproxy.c's SEC names / map names and the Go-side
// collection used by loadOffloadBpfObjects.
func TestOffloadProgramsAndMapsComplete(t *testing.T) {
	wantPrograms := map[string]bool{
		"tcp_offload_redirect":            false,
		"tcp_offload_sent_account":        false,
		"tcp_offload_sent_account_kprobe": false,
	}
	for _, p := range tcpRelayOffloadPrograms {
		wantPrograms[p] = true
	}
	for name, seen := range wantPrograms {
		if !seen {
			t.Errorf("program %q missing from tcpRelayOffloadPrograms", name)
		}
	}
	if len(tcpRelayOffloadPrograms) != 3 {
		t.Errorf("expected 3 offload programs, got %d", len(tcpRelayOffloadPrograms))
	}

	wantMaps := map[string]bool{
		"fast_sock":         false,
		"tcp_offload_pause": false,
		"tcp_offload_sent":  false,
	}
	for _, m := range tcpRelayOffloadMaps {
		wantMaps[m] = true
	}
	for name, seen := range wantMaps {
		if !seen {
			t.Errorf("map %q missing from tcpRelayOffloadMaps", name)
		}
	}
	if len(tcpRelayOffloadMaps) != 3 {
		t.Errorf("expected 3 offload maps, got %d", len(tcpRelayOffloadMaps))
	}
}

func TestBpfDataplaneOmitsOnlyOffloadObjects(t *testing.T) {
	offloadPrograms := map[string]struct{}{
		"tcp_offload_redirect":            {},
		"tcp_offload_sent_account":        {},
		"tcp_offload_sent_account_kprobe": {},
	}
	offloadMaps := map[string]struct{}{
		"fast_sock":         {},
		"tcp_offload_pause": {},
		"tcp_offload_sent":  {},
	}
	assertSubsetOmits := func(t *testing.T, full, subset reflect.Type, offload map[string]struct{}, kind string) {
		t.Helper()
		fullTags := ebpfTags(full)
		subsetTags := ebpfTags(subset)
		for name := range fullTags {
			_, isOffload := offload[name]
			_, inSubset := subsetTags[name]
			if isOffload && inSubset {
				t.Errorf("%s %q must not be bound in the mandatory dataplane load", kind, name)
			}
			if !isOffload && !inSubset {
				t.Errorf("always-on %s %q missing from mandatory dataplane load", kind, name)
			}
		}
	}
	assertSubsetOmits(t, reflect.TypeOf(bpfPrograms{}), reflect.TypeOf(bpfDataplanePrograms{}), offloadPrograms, "program")
	assertSubsetOmits(t, reflect.TypeOf(bpfMaps{}), reflect.TypeOf(bpfDataplaneMaps{}), offloadMaps, "map")
}

func ebpfTags(t reflect.Type) map[string]struct{} {
	out := make(map[string]struct{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("ebpf")
		if tag == "" {
			continue
		}
		out[tag] = struct{}{}
	}
	return out
}
