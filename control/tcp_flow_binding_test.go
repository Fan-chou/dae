/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
)

func TestTcpFlowBindingCapturesFinalRouteAndEgress(t *testing.T) {
	program, err := routing.NewNormalizedProgram(nil, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	identity, err := routing.NewPolicyIdentity(9, program)
	if err != nil {
		t.Fatalf("NewPolicyIdentity() error = %v", err)
	}
	d := newTestEndpointDialer()
	outbound := newTestFixedOutboundGroup(d)
	networkType := dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	result := &proxyDialResult{
		OutboundIndex:           consts.OutboundUserDefinedMin,
		Outbound:                outbound,
		Dialer:                  d,
		DialTarget:              "198.51.100.10:443",
		Network:                 "tcp+0x2a",
		Mark:                    42,
		Must:                    true,
		SniffedDomain:           "example.com",
		IsDialIp:                true,
		SelectionNetworkTypeObj: &networkType,
	}

	binding := newTcpFlowBinding(identity.Epoch(), result, [6]uint8{2, 0, 0, 0, 0, 1})
	if binding.Route.PolicyEpoch != identity.Epoch() || binding.Route.Outbound != result.OutboundIndex || binding.Route.Mark != result.Mark || !binding.Route.Must {
		t.Fatalf("route binding = %+v", binding.Route)
	}
	if binding.Egress.Dialer != d || binding.Egress.Outbound != outbound || binding.Egress.Target != result.DialTarget || binding.Egress.Network != result.Network || binding.Egress.NetworkType != networkType || binding.Egress.SniffedDomain != result.SniffedDomain || !binding.Egress.IsDialIp || binding.Mac != [6]uint8{2, 0, 0, 0, 0, 1} {
		t.Fatalf("egress binding = %+v", binding.Egress)
	}

	result.Mark = 7
	result.DialTarget = "203.0.113.20:443"
	networkType.IpVersion = consts.IpVersionStr_6
	if binding.Route.Mark != 42 || binding.Egress.Target != "198.51.100.10:443" || binding.Egress.NetworkType.IpVersion != consts.IpVersionStr_4 {
		t.Fatalf("binding changed after result mutation: %+v", binding)
	}
}

func TestAdoptTCPStoresConnectionIdentity(t *testing.T) {
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })
	src := netip.MustParseAddrPort("192.168.124.202:44321")
	dst := netip.MustParseAddrPort("198.51.100.10:443")
	mac := [6]uint8{0x3e, 0x0a, 0xa5, 0xde, 0xae, 0xa3}
	flow, err := manager.adoptTCP(
		&memoryLayoutConn{id: 1},
		nil,
		TcpFlowBinding{Mac: mac},
		runtime,
		nil,
		src,
		dst,
	)
	if err != nil {
		t.Fatal(err)
	}
	if flow.id == 0 || flow.src != src || flow.dst != dst || flow.mac != mac || flow.network != "tcp4" || flow.startUnixNano == 0 {
		t.Fatalf("identity = id=%d src=%v dst=%v mac=%x net=%s start=%d", flow.id, flow.src, flow.dst, flow.mac, flow.network, flow.startUnixNano)
	}
	flow.finish()
}

func TestFlowRuntimeRecordsBytesWithoutMapLookup(t *testing.T) {
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })
	flow, err := manager.adoptTCP(
		&memoryLayoutConn{id: 2},
		nil,
		TcpFlowBinding{},
		runtime,
		nil,
		netip.MustParseAddrPort("192.0.2.1:1"),
		netip.MustParseAddrPort("198.51.100.1:443"),
	)
	if err != nil {
		t.Fatal(err)
	}
	flow.recordUpload(100)
	flow.recordDownload(250)
	if flow.uploadBytes.Load() != 100 || flow.downloadBytes.Load() != 250 {
		t.Fatalf("bytes up=%d down=%d", flow.uploadBytes.Load(), flow.downloadBytes.Load())
	}
	flow.finish()
}

func TestRouteDialReturnsFailedTcpSelection(t *testing.T) {
	d, _ := newTestEndpointErrorDialer("hysteria2", "proxy.example:443", io.ErrUnexpectedEOF)
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(d))

	conn, result, err := cp.routeDial(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("192.0.2.10:42687"),
		Dest:     netip.MustParseAddrPort("198.51.100.10:443"),
		Network:  "tcp",
	})
	if err == nil {
		t.Fatal("routeDial() error = nil, want dial error")
	}
	if conn != nil {
		t.Fatalf("routeDial() connection = %v, want nil", conn)
	}
	if result == nil {
		t.Fatal("routeDial() result = nil, want failed selection result")
	}
}
