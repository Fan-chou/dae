/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestChildTimeoutUsesEarlierDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	child, childCancel := childTimeout(parent, consts.DefaultDialTimeout)
	defer childCancel()

	parentDL, ok := parent.Deadline()
	if !ok {
		t.Fatal("parent missing deadline")
	}
	childDL, ok := child.Deadline()
	if !ok {
		t.Fatal("child missing deadline")
	}
	if childDL.After(parentDL) {
		t.Fatalf("child deadline %v is after parent %v", childDL, parentDL)
	}
}

func newFallbackBudgetController(t *testing.T) *DnsController {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	ctrl := newTestDnsController()
	ctrl.log = logger
	setTestDnsControllerRuntime(ctrl, func(rt *dnsControllerRuntimeState) {
		rt.bestDialerChooser = func(_ context.Context, _ DnsRequestSnapshot, upstream *componentdns.Upstream) (*dialArgument, error) {
			l4 := consts.L4ProtoStr_UDP
			if upstream != nil && upstream.Scheme == componentdns.UpstreamScheme_TCP {
				l4 = consts.L4ProtoStr_TCP
			}
			return &dialArgument{
				l4proto:    l4,
				ipversion:  consts.IpVersionStr_4,
				bestTarget: netip.MustParseAddrPort("192.0.2.53:53"),
			}, nil
		}
	})
	return ctrl
}

func tcpUDPUpstream() *componentdns.Upstream {
	return &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_TCP_UDP,
		Hostname: "192.0.2.53",
		Port:     53,
	}
}

func udpPrimaryDialArg() *dialArgument {
	return &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestTarget: netip.MustParseAddrPort("192.0.2.53:53"),
	}
}

func TestForwardWithFallbackBlackholeStaysWithinParentBudget(t *testing.T) {
	ctrl := newFallbackBudgetController(t)
	original := dnsForwarderFactory
	var udpCalls, tcpCalls atomic.Int32
	dnsForwarderFactory = func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			udpCalls.Add(1)
			return &stubDnsForwarder{forward: func(ctx context.Context, _ []byte) (*dnsmessage.Msg, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}}, nil
		case consts.L4ProtoStr_TCP:
			tcpCalls.Add(1)
			return &stubDnsForwarder{forward: func(ctx context.Context, _ []byte) (*dnsmessage.Msg, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return dnsAResponseMsg("budget.test.", "198.51.100.53"), nil
			}}, nil
		default:
			return nil, context.Canceled
		}
	}
	t.Cleanup(func() { dnsForwarderFactory = original })

	parent, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := ctrl.forwardWithFallback(parent, &udpRequest{}, tcpUDPUpstream(), udpPrimaryDialArg(), []byte{0})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("blackhole UDP must not succeed via stacked TCP budget")
	}
	if elapsed > time.Second {
		t.Fatalf("blackhole took %s, want parent 250ms (not 8s+8s)", elapsed)
	}
	if udpCalls.Load() != 1 {
		t.Fatalf("UDP calls = %d, want 1", udpCalls.Load())
	}
	if tcpCalls.Load() != 0 {
		t.Fatalf("TCP calls = %d, want 0 after parent expired", tcpCalls.Load())
	}
}

func TestForwardWithFallbackCancelReturnsImmediately(t *testing.T) {
	ctrl := newFallbackBudgetController(t)
	original := dnsForwarderFactory
	dnsForwarderFactory = func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(ctx context.Context, _ []byte) (*dnsmessage.Msg, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}, nil
	}
	t.Cleanup(func() { dnsForwarderFactory = original })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, _, err := ctrl.forwardWithFallback(ctx, &udpRequest{}, tcpUDPUpstream(), udpPrimaryDialArg(), []byte{0})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("cancelled parent must fail")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("cancelled forward took %s, want immediate return", elapsed)
	}
}

func TestForwardWithFallbackFastUDPFailureStillTriesTCP(t *testing.T) {
	ctrl := newFallbackBudgetController(t)
	original := dnsForwarderFactory
	var tcpCalls atomic.Int32
	dnsForwarderFactory = func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				return nil, io.ErrUnexpectedEOF
			}}, nil
		case consts.L4ProtoStr_TCP:
			tcpCalls.Add(1)
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				return dnsAResponseMsg("budget.test.", "198.51.100.53"), nil
			}}, nil
		default:
			return nil, io.ErrUnexpectedEOF
		}
	}
	t.Cleanup(func() { dnsForwarderFactory = original })

	msg, used, err := ctrl.forwardWithFallback(context.Background(), &udpRequest{}, tcpUDPUpstream(), udpPrimaryDialArg(), []byte{0})
	if err != nil {
		t.Fatalf("fast UDP failure should fall back to TCP: %v", err)
	}
	if used == nil || used.l4proto != consts.L4ProtoStr_TCP {
		t.Fatalf("used dial arg = %+v, want TCP", used)
	}
	if tcpCalls.Load() != 1 {
		t.Fatalf("TCP calls = %d, want 1", tcpCalls.Load())
	}
	if ip := dnsAnswerIPv4(t, msg); ip != "198.51.100.53" {
		t.Fatalf("answer = %s, want 198.51.100.53", ip)
	}
}
