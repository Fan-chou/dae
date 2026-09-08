//go:build linux && !dae_stub_ebpf

package control

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestUDPCrossFamilyKernelPrefixesWithoutDNSFakeIP(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LPMTrie, KeySize: 20, ValueSize: 4, MaxEntries: 64, Flags: unix.BPF_F_NO_PREALLOC})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("BPF privileges unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer m.Close()
	s := openCrossFamilyTestStore(t, t.TempDir())
	objects := &bpfObjects{}
	objects.FakeipLpmMap = m
	cp := &ControlPlane{core: &controlPlaneCore{}, udpCrossFamily: s}
	cp.core.bpf.Store(objects)
	if err := cp.syncFakeIPKernelPrefixes(); err != nil {
		t.Fatal(err)
	}
	if err := cp.syncFakeIPKernelPrefixes(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"198.19.0.8/32", "fd00:cafe::8/128"} {
		var value uint32
		if err := m.Lookup(cidrToBpfLpmKey(netip.MustParsePrefix(raw)), &value); err != nil {
			t.Fatalf("kernel cannot intercept %s: %v", raw, err)
		}
	}
}
