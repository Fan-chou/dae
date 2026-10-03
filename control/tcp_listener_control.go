package control

import (
	"syscall"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

// TCP and UDP controls stay separate: the IPv4 UDP fallback must never inherit
// TCP_MAXSEG. This applies options only to freshly created TCP listeners;
// cloned listeners keep their process-scoped settings across reloads.
func tcpIngressListenControl(c syscall.RawConn, mss int) error {
	if err := dialer.TproxyControl(c); err != nil {
		return err
	}
	return netproxy.TCPMaxSegControl(c, mss)
}

func udpIPv4ListenControl(c syscall.RawConn) error {
	return dialer.TproxyControl(c)
}
