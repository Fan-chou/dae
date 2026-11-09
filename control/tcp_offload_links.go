/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
)

// tcpOffloadLinks owns the sk_skb stream-verdict link on fast_sock and the
// backlog-fuse accounting link for one bpfObjects set.
//
// bpfObjects survive config reloads (EjectBpf/InjectBpf handover), while
// every reload serves a fresh controlPlaneCore whose tcpSockmapOffloadReady
// starts false. Registering the links only in the per-core cleanup list
// therefore re-attaches on each reload while the previous generation's link
// is still alive, and the kernel rejects the second attach with EBUSY -
// silently disabling the offload on every other generation (repro: SIGUSR1
// reload with DAE_ALLOW_TCP_SOCKMAP=1). Reference-counting the links by the
// shared *bpfObjects keeps exactly one attach alive across reloads and
// closes it when the last plane or established-flow lease goes away.
type tcpOffloadLinks struct {
	verdict io.Closer // sk_skb stream verdict on fast_sock
	account io.Closer // skb_send_sock fentry/kprobe; nil when accounting is disabled
}

type tcpOffloadLinkEntry struct {
	refs int
	l    tcpOffloadLinks
	maps [3]*ebpf.Map
}

var (
	tcpOffloadLinkMu       sync.Mutex
	tcpOffloadLinkRegistry = map[*bpfObjects]*tcpOffloadLinkEntry{}
)

// attachTCPOffloadLinks takes a reference on the links already registered
// for bpf (reused=true), or attaches them via the callback and registers
// the result (reused=false). The callback must clean up after itself when
// it returns an error.
func attachTCPOffloadLinks(bpf *bpfObjects, attach func() (tcpOffloadLinks, error)) (reused bool, err error) {
	tcpOffloadLinkMu.Lock()
	defer tcpOffloadLinkMu.Unlock()
	if entry, ok := tcpOffloadLinkRegistry[bpf]; ok {
		entry.refs++
		return true, nil
	}
	links, err := attach()
	if err != nil {
		return false, err
	}
	tcpOffloadLinkRegistry[bpf] = &tcpOffloadLinkEntry{refs: 1, l: links}
	return false, nil
}

// releaseTCPOffloadLinks drops one reference taken by attachTCPOffloadLinks.
// The links are closed and unregistered once the last reference is gone.
func releaseTCPOffloadLinks(bpf *bpfObjects) {
	tcpOffloadLinkMu.Lock()
	entry := tcpOffloadLinkRegistry[bpf]
	if entry == nil {
		tcpOffloadLinkMu.Unlock()
		return
	}
	entry.refs--
	keep := entry.refs > 0
	if !keep {
		delete(tcpOffloadLinkRegistry, bpf)
	}
	l := entry.l
	tcpOffloadLinkMu.Unlock()
	if keep {
		return
	}
	closeQuietly(l.verdict)
	closeQuietly(l.account)
	for _, m := range entry.maps {
		if m != nil {
			_ = m.Close()
		}
	}
}

func closeQuietly(c io.Closer) {
	if c != nil {
		_ = c.Close()
	}
}

// acquireTCPOffloadRuntime retains the links and one shared set of independent
// map handles. The caller holds core.mu, excluding Close during first clone.
// Flow leases keep only BPF resources, never a generation's core or matcher.
func acquireTCPOffloadRuntime(bpf *bpfObjects) (*tcpRelayOffloadRuntime, error) {
	tcpOffloadLinkMu.Lock()
	defer tcpOffloadLinkMu.Unlock()
	entry := tcpOffloadLinkRegistry[bpf]
	if entry == nil {
		return nil, fmt.Errorf("offload links unavailable")
	}
	if entry.maps[0] == nil {
		var cloned [3]*ebpf.Map
		for i, m := range [3]*ebpf.Map{bpf.FastSock, bpf.TcpOffloadPause, bpf.TcpOffloadSent} {
			if m == nil {
				for _, c := range cloned {
					if c != nil {
						_ = c.Close()
					}
				}
				return nil, fmt.Errorf("offload map unavailable")
			}
			var err error
			cloned[i], err = m.Clone()
			if err != nil {
				for _, c := range cloned {
					if c != nil {
						_ = c.Close()
					}
				}
				return nil, err
			}
		}
		entry.maps = cloned
	}
	entry.refs++
	return &tcpRelayOffloadRuntime{maps: entry.maps, release: func() { releaseTCPOffloadLinks(bpf) }}, nil
}
