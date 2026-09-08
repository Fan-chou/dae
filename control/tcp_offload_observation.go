package control

import (
	"expvar"
	"sync/atomic"
)

var tcpOffloadActive, tcpOffloadFINPending atomic.Int64
var tcpOffloadTerminalReaped atomic.Uint64

func init() {
	expvar.Publish("dae_tcp_offload", expvar.Func(func() any {
		return map[string]any{
			"active":          tcpOffloadActive.Load(),
			"fin_pending":     tcpOffloadFINPending.Load(),
			"terminal_reaped": tcpOffloadTerminalReaped.Load(),
		}
	}))
}
