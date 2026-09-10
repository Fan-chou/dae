package control

import "net/netip"

// Both datapaths encode IPv4 as ::ffff:a.b.c.d. Exclude that reserved
// representation from broad IPv6 CIDRs at compilation time, so one LPM lookup
// remains sufficient even for a mixed IPv4/IPv6 set. At most 96 siblings are
// needed for ::/0; narrower ordinary IPv6 routes remain unchanged.
func routingAddressFamilyPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	mapped := netip.MustParsePrefix("::ffff:0:0/96")
	var out []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is4() {
			out = append(out, p)
			continue
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96))
			continue
		}
		if p.Bits() > 96 || !p.Contains(mapped.Addr()) {
			out = append(out, p)
			continue
		}
		// Walk the excluded prefix, retaining the sibling at each split.
		for bit := p.Bits(); bit < 96; bit++ {
			sibling := mapped.Addr().As16()
			sibling[bit/8] ^= 1 << (7 - uint(bit%8))
			out = append(out, netip.PrefixFrom(netip.AddrFrom16(sibling), bit+1).Masked())
		}
	}
	return out
}
