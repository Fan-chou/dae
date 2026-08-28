//go:build !dae_stub_ebpf

package control

import (
	"reflect"
	"testing"
)

// TestOffloadObjectsInSpec verifies that the hard-coded offload program and map
// name lists correspond to objects that actually exist in the real eBPF
// collection (bpf_bpfel.o, embedded via loadBpf). If a tproxy.c SEC name or map
// name drifts from the Go-side list, loadOffloadBpfObjects would report an
// incomplete spec and the offload feature would silently never enable — this test
// catches that drift. Only runnable in the !dae_stub_ebpf build where the real
// .o is embedded.
func TestOffloadObjectsInSpec(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}
	for _, name := range tcpRelayOffloadPrograms {
		if spec.Programs[name] == nil {
			t.Errorf("offload program %q missing from embedded spec", name)
		}
	}
	for _, name := range tcpRelayOffloadMaps {
		if spec.Maps[name] == nil {
			t.Errorf("offload map %q missing from embedded spec", name)
		}
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
