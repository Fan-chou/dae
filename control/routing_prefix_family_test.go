package control

import (
	"github.com/daeuniverse/dae/pkg/trie"
	"net/netip"
	"testing"
)

func TestRoutingPrefixAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		prefixes []string
		target   string
		want     bool
	}{
		{[]string{"::/0"}, "192.168.124.220", false},
		{[]string{"::/0"}, "2001:db8::1", true},
		{[]string{"::/0"}, "::1", true},
		{[]string{"::/0"}, "::", true},
		{[]string{"::/0", "192.168.124.0/24"}, "192.168.124.220", true},
		{[]string{"::/0", "192.168.124.0/24"}, "192.0.2.1", false},
		{[]string{"0.0.0.0/0"}, "192.0.2.1", true},
		{[]string{"0.0.0.0/0"}, "2001:db8::1", false},
		{[]string{"::/80"}, "192.0.2.1", false},
		{[]string{"::/80"}, "::1234", true},
		{[]string{"::ffff:192.0.2.0/120"}, "192.0.2.1", true},
	} {
		var ps []netip.Prefix
		for _, p := range tc.prefixes {
			ps = append(ps, netip.MustParsePrefix(p))
		}
		normalized := canonicalizePrefixes(ps)
		tr, err := trie.NewTrieFromPrefixes(normalized)
		if err != nil {
			t.Fatal(err)
		}
		addr := netip.MustParseAddr(tc.target)
		got := tr.HasPrefix(trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(addr.As16()), 128)))
		if got != tc.want {
			t.Errorf("%v target %s got %v want %v", tc.prefixes, addr, got, tc.want)
		}
	}
}
