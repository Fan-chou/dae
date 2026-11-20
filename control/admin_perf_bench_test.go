/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

var (
	benchMetricsSink AdminMetricsSnapshot
	benchSummarySink AdminTrafficSummary
	benchDialSink    *proxyDialResult
)

func setupBenchControlPlaneWithTCPFlows(b *testing.B, flowCount int) (*ControlPlane, *SessionManager) {
	b.Helper()
	manager := NewSessionManager(context.Background())
	runtime := newEgressRuntime(nil, nil)
	b.Cleanup(func() {
		_ = manager.Close()
		_ = runtime.releaseOwner()
	})

	proxyGroup := &outbound.DialerGroup{Name: "proxy"}
	rule := &RoutingRuleMeta{Index: 1, Raw: "domain(suffix:example.com) -> proxy"}
	for i := 0; i < flowCount; i++ {
		f, err := manager.adoptTCP(
			&memoryLayoutConn{id: uint64(i + 1)},
			nil,
			TcpFlowBinding{
				Process: "curl",
				Route:   TcpRouteBinding{Rule: rule},
				Egress: TcpEgressBinding{
					Outbound:      proxyGroup,
					SniffedDomain: fmt.Sprintf("host%d.example.com", i%64),
					Target:        fmt.Sprintf("host%d.example.com:443", i%64),
				},
			},
			runtime,
			nil,
			netip.MustParseAddrPort(fmt.Sprintf("192.168.%d.%d:%d", (i/200)%250+1, (i%200)+10, 10000+i)),
			netip.MustParseAddrPort("93.184.216.34:443"),
		)
		if err != nil {
			b.Fatalf("adoptTCP %d failed: %v", i, err)
		}
		f.recordUpload(1024 + int64(i))
		f.recordDownload(4096 + int64(i*2))
	}

	c := &ControlPlane{runtimeStats: newRuntimeStats()}
	if err := c.AttachSessionManager(manager); err != nil {
		b.Fatal(err)
	}
	return c, manager
}

func BenchmarkAdminMetricsSnapshot(b *testing.B) {
	c, _ := setupBenchControlPlaneWithTCPFlows(b, 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchMetricsSink = c.AdminMetricsSnapshot()
	}
}

func BenchmarkTrafficAccountingRecordClosed(b *testing.B) {
	flow := AdminClosedFlow{
		ID:          "tcp:1",
		Network:     "tcp4",
		SrcIP:       "192.168.1.10",
		DstIP:       "93.184.216.34",
		Domain:      "api.example.com",
		Rule:        &RoutingRuleMeta{Index: 1, Raw: "domain(suffix:example.com) -> proxy"},
		Outbound:    "proxy",
		Dialer:      "hk-01",
		Process:     "curl",
		Upload:      1024,
		Download:    4096,
		EndTime:     "2026-11-20T00:00:00Z",
		CloseReason: "normal",
	}
	var marked atomic.Bool
	onRecorded := func() { marked.Store(true) }

	b.Run("NoBaseline", func(b *testing.B) {
		a := NewTrafficAccounting()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			a.RecordClosedWithMark(flow, onRecorded)()
		}
	})

	b.Run("WithActiveBaselines1024", func(b *testing.B) {
		a := NewTrafficAccounting()
		a.mu.Lock()
		for i := 0; i < 1024; i++ {
			a.activeBaselines[fmt.Sprintf("live:%d", i)] = flowTrafficBaseline{upload: 100, download: 200}
		}
		a.mu.Unlock()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			a.RecordClosedWithMark(flow, onRecorded)()
		}
	})
}

func BenchmarkTrafficAccountingSummary(b *testing.B) {
	for _, n := range []int{100, 1024, 2000} {
		b.Run(fmt.Sprintf("flows=%d", n), func(b *testing.B) {
			c, _ := setupBenchControlPlaneWithTCPFlows(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSummarySink = c.AdminTrafficSummary(50)
			}
		})
	}
}

func BenchmarkTrafficAccountingReset(b *testing.B) {
	for _, n := range []int{1024, 2000} {
		b.Run(fmt.Sprintf("flows=%d", n), func(b *testing.B) {
			c, _ := setupBenchControlPlaneWithTCPFlows(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.AdminResetTrafficSummary()
			}
		})
	}
}

func BenchmarkChooseProxyDialerOptionA(b *testing.B) {
	var rb strings.Builder
	for i := 0; i < 99; i++ {
		fmt.Fprintf(&rb, "domain(suffix: rule%d.bench.invalid) -> proxy\n", i)
	}
	rb.WriteString("domain(suffix: example.com) -> proxy\n")
	rb.WriteString("fallback: direct")
	m := testFakeIPMatcher(b, rb.String(), []string{"proxy"})

	logger := logrus.New()
	option := &componentdialer.GlobalOption{
		Log:           logger,
		CheckInterval: 15 * time.Second,
	}
	underlay, property := componentdialer.NewDirectDialer(option, true)
	d := componentdialer.NewDialer(underlay, option, componentdialer.InstanceOption{}, property)
	b.Cleanup(func() { _ = d.Close() })

	directGroup := outbound.NewDialerGroupWithRuntimeOptions(
		option,
		"direct",
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *componentdialer.NetworkType, bool) {},
		outbound.DialerGroupRuntimeOptions{},
	)
	b.Cleanup(func() { _ = directGroup.Close() })

	proxyGroup := outbound.NewDialerGroupWithRuntimeOptions(
		option,
		"proxy",
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *componentdialer.NetworkType, bool) {},
		outbound.DialerGroupRuntimeOptions{},
	)
	b.Cleanup(func() { _ = proxyGroup.Close() })

	outbounds := make([]*outbound.DialerGroup, consts.OutboundUserDefinedMin+1)
	outbounds[consts.OutboundDirect] = directGroup
	outbounds[consts.OutboundUserDefinedMin] = proxyGroup

	cp := &ControlPlane{
		log: logger,
		controlPlaneGenerationState: controlPlaneGenerationState{
			routingMatcher: m,
			outbounds:      outbounds,
		},
	}

	ctx := context.Background()
	src := netip.MustParseAddrPort("192.168.1.10:50000")
	dst := netip.MustParseAddrPort("198.51.100.10:443")

	cases := []struct {
		name     string
		outbound consts.OutboundIndex
		domain   string
	}{
		{name: "MatchSameOutbound", outbound: consts.OutboundUserDefinedMin, domain: "api.example.com"},
		{name: "MismatchDomainFallback", outbound: consts.OutboundDirect, domain: "api.example.com"},
		{name: "NoDomainDirect", outbound: consts.OutboundDirect, domain: ""},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			param := &proxyDialParam{
				Outbound: tc.outbound,
				Network:  "tcp",
				Src:      src,
				Dest:     dst,
				Domain:   tc.domain,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := cp.chooseProxyDialer(ctx, param)
				if err != nil {
					b.Fatal(err)
				}
				benchDialSink = res
			}
		})
	}
}
