package trie

import (
	"net/netip"
	"testing"
)

func TestZeroLengthPrefix(t *testing.T) {
	p := netip.MustParsePrefix("::/0")
	if got := Prefix2bin128(p); got != "" {
		t.Fatalf("zero-length prefix encoded as %d bits", len(got))
	}
	tr, err := NewTrieFromPrefixes([]netip.Prefix{p})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"::", "::1", "2001:db8::1"} {
		key := Prefix2bin128(netip.PrefixFrom(netip.MustParseAddr(ip), 128))
		if !tr.HasPrefix(key) {
			t.Errorf("zero prefix did not match %s", ip)
		}
	}
}
