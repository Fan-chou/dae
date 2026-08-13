//go:build !linux

package main

import (
	D "github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/anytls"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	_ "github.com/daeuniverse/outbound/protocol/anytls"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	_ "github.com/daeuniverse/outbound/protocol/socks5"
	_ "github.com/daeuniverse/outbound/transport/shadowtls"
	_ "github.com/daeuniverse/outbound/transport/simpleobfs"
	_ "github.com/daeuniverse/outbound/transport/tls"
	_ "github.com/daeuniverse/outbound/transport/ws"
)

// The full dae dialer package contains Linux socket-option constants. Keep
// rule-sync testable on other hosts by using the same outbound link registry
// directly there; production Linux builds use dae's NewFromLink above.
func validateMihomoLinkWithDae(link string) error {
	_, _, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &D.ExtraOption{TlsImplementation: "tls", UtlsImitate: "chrome_auto"}, link)
	return err
}
