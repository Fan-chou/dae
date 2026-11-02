/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"runtime"
	"testing"
	"time"
	"weak"
)

// newPreparedHookRuntime returns a runtime whose upstream is already
// available, so the warmup wait in startPreparedDNSListener returns at once.
func newPreparedHookRuntime(delayStart bool) *controlPlaneDNSRuntime {
	r := newControlPlaneDNSRuntime(delayStart)
	r.noteDNSUpstreamAvailable()
	return &r
}

// The hooks installed for a staged reload capture the previous generation
// (through the reload handoff). When the DNS listener is reused, the start
// hook is skipped; it must not stay on the new generation, or every
// generation keeps the one before it alive for the rest of the process.
func TestStartPreparedDNSListenerDropsStartHookWhenListenerIsReused(t *testing.T) {
	r := newPreparedHookRuntime(true)

	startRan := false
	r.setPreparedDNSReuseHook(func() error {
		// What reuseDNSListenerFrom does on a successful listener reuse.
		r.delayDNSListenerStart = false
		return nil
	})
	r.setPreparedDNSStartHook(func() error {
		startRan = true
		return nil
	})

	if err := r.startPreparedDNSListenerWithWarmupTimeout(context.Background(), nil, nil, nil, time.Second); err != nil {
		t.Fatalf("startPreparedDNSListener() error = %v", err)
	}
	if startRan {
		t.Fatal("start hook ran although the listener was reused")
	}
	if r.preparedDNSReuseHook != nil {
		t.Fatal("reuse hook is still installed after it ran")
	}
	if r.preparedDNSStartHook != nil {
		t.Fatal("start hook is still installed after the listener was reused; it keeps the previous generation reachable")
	}
}

// With nothing left to defer, hooks that were installed for the handoff have
// no further use and must not be kept.
func TestStartPreparedDNSListenerDropsHooksWhenStartIsNotDeferred(t *testing.T) {
	r := newPreparedHookRuntime(false)
	r.setPreparedDNSReuseHook(func() error { return nil })
	r.setPreparedDNSStartHook(func() error { return nil })

	if err := r.startPreparedDNSListenerWithWarmupTimeout(context.Background(), nil, nil, nil, time.Second); err != nil {
		t.Fatalf("startPreparedDNSListener() error = %v", err)
	}
	if r.preparedDNSReuseHook != nil || r.preparedDNSStartHook != nil {
		t.Fatal("prepared DNS hooks remain installed although the listener start was not deferred")
	}
}

// previousGeneration stands in for the old ControlPlane that the handoff
// hooks reference.
type previousGeneration struct {
	payload [1 << 16]byte
}

// installHooksReferencing installs hooks that close over a fresh stand-in for
// the previous generation and returns only a weak reference to it, so nothing
// in the caller keeps it alive.
func installHooksReferencing(r *controlPlaneDNSRuntime) weak.Pointer[previousGeneration] {
	prev := &previousGeneration{}
	r.setPreparedDNSReuseHook(func() error {
		r.delayDNSListenerStart = false
		return nil
	})
	r.setPreparedDNSStartHook(func() error {
		_ = prev.payload[0]
		return nil
	})
	return weak.Make(prev)
}

// A hook that closes over the previous generation must not pin it once the
// listener has been reused.
func TestStartPreparedDNSListenerReleasesPreviousGeneration(t *testing.T) {
	r := newPreparedHookRuntime(true)
	weakPrev := installHooksReferencing(r)

	// Sanity check: while the hook is installed the generation is reachable.
	for range 3 {
		runtime.GC()
	}
	if weakPrev.Value() == nil {
		t.Fatal("test setup is wrong: the start hook does not keep the stand-in alive")
	}

	if err := r.startPreparedDNSListenerWithWarmupTimeout(context.Background(), nil, nil, nil, time.Second); err != nil {
		t.Fatalf("startPreparedDNSListener() error = %v", err)
	}
	for range 3 {
		runtime.GC()
	}
	// r stands for the new generation, which stays alive for a long time.
	reachable := weakPrev.Value() != nil
	runtime.KeepAlive(r)
	if reachable {
		t.Fatal("previous generation is still reachable through the new generation's DNS runtime")
	}
}
