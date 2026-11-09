//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestTCPOffloadFlowLeaseOutlivesGenerationHandles(t *testing.T) {
	var maps [3]*ebpf.Map
	for i := range maps {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 4})
		if err != nil {
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				t.Skipf("BPF privileges required: %v", err)
			}
			t.Fatal(err)
		}
		maps[i] = m
		t.Cleanup(func() { _ = m.Close() })
	}
	bpf := &bpfObjects{}
	bpf.FastSock, bpf.TcpOffloadPause, bpf.TcpOffloadSent = maps[0], maps[1], maps[2]
	var closed int
	if _, err := attachTCPOffloadLinks(bpf, func() (tcpOffloadLinks, error) { return tcpOffloadLinks{verdict: countingCloser{&closed}}, nil }); err != nil {
		t.Fatal(err)
	}
	a, err := acquireTCPOffloadRuntime(bpf)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	b, err := acquireTCPOffloadRuntime(bpf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if a.maps != b.maps {
		t.Fatal("map handles must be shared per resource set")
	}
	releaseTCPOffloadLinks(bpf)
	for _, m := range maps {
		_ = m.Close()
	}
	if closed != 0 {
		t.Fatal("generation release detached active links")
	}
	for _, m := range a.maps {
		if err := m.Update(uint32(1), uint32(42), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	a.close()
	a.close()
	if closed != 0 {
		t.Fatal("first flow released another flow's links")
	}
	b.close()
	b.close()
	if closed != 1 {
		t.Fatalf("link closed %d times", closed)
	}
	for _, m := range b.maps {
		if m.FD() != -1 {
			t.Fatal("last lease leaked cloned map handle")
		}
	}
}
