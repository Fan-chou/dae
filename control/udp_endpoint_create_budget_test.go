/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type ctxWaitDialer struct{}

func (d *ctxWaitDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func newCtxWaitTestEndpointDialer() *componentdialer.Dialer {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return componentdialer.NewDialer(
		&ctxWaitDialer{},
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		componentdialer.InstanceOption{DisableCheck: true},
		&componentdialer.Property{},
	)
}

func TestCreateEndpointHonorsParentDeadline(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)

	d := newCtxWaitTestEndpointDialer()
	t.Cleanup(func() { _ = d.Close() })

	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.10:40000")}
	parent, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	var dials atomic.Int32
	opts := &UdpEndpointOptions{
		Handler: func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		Ctx:     parent,
		GetDialOption: func(ctx context.Context) (*DialOption, error) {
			dials.Add(1)
			return &DialOption{
				Dialer:  d,
				Network: "udp+4",
				Target:  "198.51.100.1:443",
			}, nil
		},
	}

	start := time.Now()
	_, _, err := pool.GetOrCreate(key, opts)
	elapsed := time.Since(start)
	if !stderrors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetOrCreate err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > time.Second {
		t.Fatalf("create took %s, want parent 250ms budget (not stacked 8s stages)", elapsed)
	}
	if dials.Load() != 1 {
		t.Fatalf("dial attempts = %d, want 1 (retry skipped after parent exhausted)", dials.Load())
	}

	// Parent deadline must not be written into the negative cache.
	dials.Store(0)
	parent2, cancel2 := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel2()
	opts.Ctx = parent2
	_, _, err = pool.GetOrCreate(key, opts)
	if stderrors.Is(err, ErrEndpointFailed) {
		t.Fatal("parent DeadlineExceeded was cached as a flow failure")
	}
	if !stderrors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second GetOrCreate err = %v, want context.DeadlineExceeded", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("second create dial attempts = %d, want a fresh dial", dials.Load())
	}
}

func TestUdpCreateBudgetInheritedFromParent(t *testing.T) {
	now := time.Now()
	parent, cancel := context.WithDeadline(context.Background(), now.Add(250*time.Millisecond))
	defer cancel()
	create, createCancel := context.WithTimeout(parent, consts.DefaultDialTimeout)
	defer createCancel()
	if !udpCreateBudgetInheritedFromParent(parent, create) {
		t.Fatal("short parent deadline should count as inherited")
	}

	longParent, cancelLong := context.WithDeadline(context.Background(), now.Add(30*time.Second))
	defer cancelLong()
	createOwn, createOwnCancel := context.WithTimeout(longParent, consts.DefaultDialTimeout)
	defer createOwnCancel()
	if udpCreateBudgetInheritedFromParent(longParent, createOwn) {
		t.Fatal("own 8s cap tighter than parent should not count as inherited")
	}

	createBare, createBareCancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
	defer createBareCancel()
	if udpCreateBudgetInheritedFromParent(context.Background(), createBare) {
		t.Fatal("no parent deadline should not count as inherited")
	}
}

func TestCreateEndpointSelectHonorsCreateBudget(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)

	key := UdpEndpointKey{Src: netip.MustParseAddrPort("192.0.2.11:40001")}
	parent, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	opts := &UdpEndpointOptions{
		Handler: func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
		Ctx:     parent,
		GetDialOption: func(ctx context.Context) (*DialOption, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	start := time.Now()
	_, _, err := pool.GetOrCreate(key, opts)
	elapsed := time.Since(start)
	if !stderrors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetOrCreate err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > time.Second {
		t.Fatalf("select took %s, want parent 250ms budget", elapsed)
	}
}
