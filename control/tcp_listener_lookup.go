package control

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
)

// Normal reloads share bpfObjects. Keep one namespace hook until the last
// control plane using those objects retires, just like the TCP offload hooks.
var tcpListenerLookups = struct {
	sync.Mutex
	entries map[*bpfObjects]*tcpListenerLookupEntry
}{entries: make(map[*bpfObjects]*tcpListenerLookupEntry)}

type tcpListenerLookupEntry struct {
	refs int
	link io.Closer
}

func acquireTCPListenerLookup(bpf *bpfObjects, attach func() (io.Closer, error)) error {
	tcpListenerLookups.Lock()
	defer tcpListenerLookups.Unlock()
	if entry := tcpListenerLookups.entries[bpf]; entry != nil {
		entry.refs++
		return nil
	}
	l, err := attach()
	if err != nil {
		return err
	}
	tcpListenerLookups.entries[bpf] = &tcpListenerLookupEntry{refs: 1, link: l}
	return nil
}

func releaseTCPListenerLookup(bpf *bpfObjects) error {
	tcpListenerLookups.Lock()
	defer tcpListenerLookups.Unlock()
	entry := tcpListenerLookups.entries[bpf]
	if entry == nil {
		return nil
	}
	if entry.refs > 1 {
		entry.refs--
		return nil
	}
	if err := entry.link.Close(); err != nil {
		return err
	}
	delete(tcpListenerLookups.entries, bpf)
	return nil
}

func (c *controlPlaneCore) bindTCPListenerLookup(ns *DaeNetns, bpf *bpfObjects) error {
	err := acquireTCPListenerLookup(bpf, func() (io.Closer, error) {
		var attached link.Link
		err := ns.WithRequired("attach TCP listener lookup", func() error {
			// WithRequired locks this goroutine to the thread inside daens.
			fd, err := os.Open("/proc/thread-self/ns/net")
			if err != nil {
				return err
			}
			defer fd.Close()
			attached, err = link.AttachNetNs(int(fd.Fd()), bpf.TproxyTcpListener)
			return err
		})
		if err != nil {
			closeQuietly(attached)
			return nil, err
		}
		return attached, nil
	})
	if err != nil {
		return fmt.Errorf("install TCP listener lookup: %w", err)
	}
	c.addManagedBpfHookCleanup(func() error { return releaseTCPListenerLookup(bpf) })
	return nil
}
