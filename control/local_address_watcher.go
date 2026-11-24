/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type localAddressMap interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
	Delete(key interface{}) error
}

type localAddressSet struct {
	target        localAddressMap
	installed     map[[16]byte]struct{}
	initialized   bool
	globalAddrs   map[[16]byte]struct{}
}

// Reconcile a complete snapshot, rather than replaying NEWADDR/DELADDR. This
// handles duplicate addresses on different interfaces and notifications queued
// while the initial dump was in progress without resurrecting removed IPs.
func (s *localAddressSet) replace(addrs []netlink.Addr) error {
	_, err := s.replaceWithChange(addrs)
	return err
}

func (s *localAddressSet) replaceWithChange(addrs []netlink.Addr) (bool, error) {
	next := make(map[[16]byte]struct{}, len(addrs))
	nextGlobal := make(map[[16]byte]struct{}, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet == nil || addr.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
			continue
		}
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		unmapped := ip.Unmap()
		key := unmapped.As16()
		next[key] = struct{}{}
		if unmapped.IsGlobalUnicast() {
			nextGlobal[key] = struct{}{}
		}
	}
	globalChanged := false
	if s.initialized && addrs != nil && !equalAddrSets(s.globalAddrs, nextGlobal) {
		globalChanged = true
	}
	if addrs != nil {
		s.globalAddrs = nextGlobal
		s.initialized = true
	}
	var errs []error
	// Remove stale permissions before adding new ones.
	for key := range s.installed {
		if _, ok := next[key]; ok {
			continue
		}
		if err := s.target.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		} else {
			delete(s.installed, key)
		}
	}
	for key := range next {
		if _, ok := s.installed[key]; ok {
			continue
		}
		if err := s.target.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			errs = append(errs, err)
		} else {
			s.installed[key] = struct{}{}
		}
	}
	return globalChanged, errors.Join(errs...)
}

func equalAddrSets(a, b map[[16]byte]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

const globalAddrChangeDebounce = 500 * time.Millisecond

type localAddressWatcher struct {
	refs int
	stop chan struct{}
	done chan struct{}

	cbMu         sync.Mutex
	nextCBID     uint64
	callbacks    map[uint64]func()
	lastNotified time.Time
}

func (w *localAddressWatcher) addCallback(fn func()) uint64 {
	if fn == nil {
		return 0
	}
	w.cbMu.Lock()
	defer w.cbMu.Unlock()
	w.nextCBID++
	id := w.nextCBID
	if w.callbacks == nil {
		w.callbacks = make(map[uint64]func())
	}
	w.callbacks[id] = fn
	return id
}

func (w *localAddressWatcher) removeCallback(id uint64) {
	if id == 0 {
		return
	}
	w.cbMu.Lock()
	delete(w.callbacks, id)
	w.cbMu.Unlock()
}

func (w *localAddressWatcher) notifyGlobalAddrChange() {
	now := time.Now()
	w.cbMu.Lock()
	if !w.lastNotified.IsZero() && now.Sub(w.lastNotified) < globalAddrChangeDebounce {
		w.cbMu.Unlock()
		return
	}
	w.lastNotified = now
	fns := make([]func(), 0, len(w.callbacks))
	for _, fn := range w.callbacks {
		fns = append(fns, fn)
	}
	w.cbMu.Unlock()

	if len(fns) == 0 {
		return
	}
	go func() {
		for _, fn := range fns {
			fn()
		}
	}()
}

// Same-BPF reloads share one writer. Fresh BPF objects have unpinned maps and
// independent writers. A draining/rolled-back generation only releases its ref.
var localAddressWatchers = struct {
	sync.Mutex
	entries map[*bpfObjects]*localAddressWatcher
}{entries: make(map[*bpfObjects]*localAddressWatcher)}

func acquireLocalAddressWatcher(bpf *bpfObjects, log *logrus.Logger) (func(), error) {
	return acquireLocalAddressWatcherWithCallback(bpf, log, nil)
}

func acquireLocalAddressWatcherWithCallback(bpf *bpfObjects, log *logrus.Logger, onGlobalAddrChange func()) (func(), error) {
	if bpf == nil || bpf.LocalAddrMap == nil {
		return nil, fmt.Errorf("missing local_addr_map")
	}
	localAddressWatchers.Lock()
	defer localAddressWatchers.Unlock()
	w := localAddressWatchers.entries[bpf]
	if w == nil {
		var err error
		w, err = startLocalAddressWatcher(bpf.LocalAddrMap, log)
		if err != nil {
			return nil, err
		}
		localAddressWatchers.entries[bpf] = w
	}
	w.refs++
	cbID := w.addCallback(onGlobalAddrChange)
	var once sync.Once
	return func() {
		once.Do(func() {
			w.removeCallback(cbID)
			localAddressWatchers.Lock()
			defer localAddressWatchers.Unlock()
			w.refs--
			if w.refs == 0 {
				close(w.stop)
				<-w.done // Join before the owning core can close its maps.
				delete(localAddressWatchers.entries, bpf)
			}
		})
	}, nil
}

func startLocalAddressWatcher(target localAddressMap, log *logrus.Logger) (*localAddressWatcher, error) {
	// Capture the host namespace once; the goroutine must not depend on whichever
	// OS thread it later runs on (dae also uses an isolated network namespace).
	ns, err := netns.Get()
	if err != nil {
		return nil, err
	}
	handle, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		ns.Close()
		return nil, err
	}
	if err := handle.SetSocketTimeout(3 * time.Second); err != nil {
		handle.Close()
		ns.Close()
		return nil, err
	}
	w := &localAddressWatcher{stop: make(chan struct{}), done: make(chan struct{})}
	set := &localAddressSet{target: target, installed: make(map[[16]byte]struct{})}
	refresh := func() error {
		addrs, err := handle.AddrList(nil, netlink.FAMILY_ALL)
		if err != nil {
			// Losing authoritative state must not leave stale bypass permissions.
			return errors.Join(err, set.replace(nil))
		}
		globalChanged, rerr := set.replaceWithChange(addrs)
		if globalChanged {
			w.notifyGlobalAddrChange()
		}
		return rerr
	}
	failures := make(chan struct{}, 1)
	subscribe := func() (chan netlink.AddrUpdate, chan struct{}, error) {
		updates := make(chan netlink.AddrUpdate, 64)
		done := make(chan struct{})
		err := netlink.AddrSubscribeWithOptions(updates, done, netlink.AddrSubscribeOptions{
			Namespace: &ns,
			ErrorCallback: func(error) {
				select {
				case failures <- struct{}{}:
				default:
				}
			},
		})
		if err != nil {
			close(done)
			return nil, nil, err
		}
		return updates, done, nil
	}
	// Subscribe before dumping so a concurrent address change cannot be lost.
	updates, subscriptionDone, err := subscribe()
	if err != nil {
		handle.Close()
		ns.Close()
		return nil, err
	}
	stopSubscription := func() {
		if subscriptionDone != nil {
			close(subscriptionDone)
			for range updates {
			} // Unblock a library sender before joining it.
			subscriptionDone = nil
			updates = nil
		}
	}
	if err := refresh(); err != nil {
		stopSubscription()
		handle.Close()
		ns.Close()
		return nil, err
	}
	go func() {
		defer close(w.done)
		// An ejected BPF object can outlive its last core and later be reused.
		// Do not leave permissions from this watcher's snapshot behind.
		defer func() {
			if err := set.replace(nil); err != nil {
				log.WithError(err).Warn("Failed to clear host addresses")
			}
		}()
		defer ns.Close()
		defer handle.Close()
		defer stopSubscription()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-w.stop:
				return
			case _, ok := <-updates:
				if !ok {
					stopSubscription()
				}
			case <-failures:
				stopSubscription()
			case <-ticker.C:
				if updates == nil {
					updates, subscriptionDone, err = subscribe()
					if err != nil {
						log.WithError(err).Warn("Failed to resubscribe to host address updates")
					}
				}
			}
			// Notifications are invalidations, not state. Coalesce bursts and read
			// current addresses; periodic dumps also repair lost netlink notifications.
			for len(updates) > 0 {
				<-updates
			}
			if err := refresh(); err != nil {
				log.WithError(err).Warn("Failed to synchronize host addresses")
			}
		}
	}()
	return w, nil
}
