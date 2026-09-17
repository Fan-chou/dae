package control

import (
	"github.com/daeuniverse/dae/component/routing"
	"net/netip"
)

func routingAddressFamilyPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	return routing.AddressFamilyPrefixes(prefixes)
}
