/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

// canResolveTCPRelayOffloadConn reports whether the connection is
// offload-capable (both ends resolve to concrete TCP sockets), so link logs
// can annotate offload outcome and skip reasons.
func canResolveTCPRelayOffloadConn(conn netproxy.Conn) bool {
	if conn == nil {
		return false
	}
	_, ok := unwrapRelayTCPConn(conn)
	return ok
}

// A per-flow lease on shared offload resources. Disabled offload uses nil.
type tcpRelayOffloadRuntime struct {
	maps    [3]*ebpf.Map
	log     *logrus.Logger
	release func()
	once    sync.Once
}

func (r *tcpRelayOffloadRuntime) close() {
	if r != nil {
		r.once.Do(func() {
			if r.release != nil {
				r.release()
			}
		})
	}
}
