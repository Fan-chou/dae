//go:build linux && !dae_stub_ebpf

package control

import (
	"errors"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"net/netip"
	"testing"
)

func TestRoutingPrefixFamiliesKernel(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		prefixes := []netip.Prefix{netip.MustParsePrefix("::/0")}
		if mixed {
			prefixes = append(prefixes, netip.MustParsePrefix("192.168.124.0/24"))
		}
		prefixes = canonicalizePrefixes(prefixes)
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LPMTrie, KeySize: 20, ValueSize: 4, MaxEntries: uint32(len(prefixes)), Flags: 1})
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("kernel LPM unavailable: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		for _, p := range prefixes {
			if err = m.Put(cidrToBpfLpmKey(p), uint32(1)); err != nil {
				t.Fatal(err)
			}
		}
		for _, tc := range []struct {
			addr string
			want bool
		}{
			{"192.168.124.220", mixed}, {"192.0.2.1", false}, {"2001:db8::1", true}, {"::1", true}, {"::", true},
		} {
			a := netip.MustParseAddr(tc.addr)
			var v uint32
			err = m.Lookup(cidrToBpfLpmKey(netip.PrefixFrom(a, a.BitLen())), &v)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatal(err)
			}
			if got := err == nil && v == 1; got != tc.want {
				t.Errorf("mixed=%v addr=%s got=%v want=%v", mixed, a, got, tc.want)
			}
		}
	}
}
