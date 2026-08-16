/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/outbound"
)

func TestAdminConnectionsSnapshotFiltersAndOmitsURI(t *testing.T) {
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })
	group := &outbound.DialerGroup{Name: "AI"}
	mac := [6]uint8{0x3e, 0x0a, 0xa5, 0xde, 0xae, 0xa3}
	flow, err := manager.adoptTCP(
		&memoryLayoutConn{id: 9},
		nil,
		TcpFlowBinding{
			Mac: mac,
			Egress: TcpEgressBinding{
				Outbound:      group,
				SniffedDomain: "hy2://should-not-leak",
				Target:        "api2.cursor.sh:443",
			},
		},
		runtime,
		nil,
		netip.MustParseAddrPort("192.168.124.202:44321"),
		netip.MustParseAddrPort("198.51.100.10:443"),
	)
	if err != nil {
		t.Fatal(err)
	}
	flow.recordUpload(32)
	snap := manager.adminConnectionsSnapshot(256, adminConnectionFilter{outbound: "AI"})
	if snap.Total != 1 || len(snap.Connections) != 1 {
		t.Fatalf("snap = %+v", snap)
	}
	item := snap.Connections[0]
	if item.Outbound != "AI" || item.Src != "192.168.124.202:44321" || item.Mac != "3e:0a:a5:de:ae:a3" || item.Upload != 32 {
		t.Fatalf("item = %+v", item)
	}
	if item.Domain != "" {
		t.Fatalf("domain should drop URI, got %q", item.Domain)
	}
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "://") {
		t.Fatalf("connections JSON leaked a URI: %s", body)
	}
	empty := manager.adminConnectionsSnapshot(256, adminConnectionFilter{outbound: "Cherry_Proxy"})
	if empty.Total != 0 {
		t.Fatalf("filter missed: %+v", empty)
	}
	flow.finish()
}

func TestAdminConnectionsSnapshotHidesInvalidAddrPort(t *testing.T) {
	mac := [6]uint8{0x3e, 0x0a, 0xa5, 0xde, 0xae, 0xa3}
	group := &outbound.DialerGroup{Name: "proxy"}
	ue := &UdpEndpoint{
		DialTarget: "1.2.3.4:443",
		poolKey: UdpEndpointKey{
			Src: netip.MustParseAddrPort("192.168.124.202:50000"),
		},
	}
	ue.hasRoutingCache = true
	ue.routingCache.Mac = mac
	ue.routingCacheDst = netip.MustParseAddrPort("1.2.3.4:443")
	ue.udpConnStateLastPair.Store(&udpConnStateTuplePairSnapshot{
		src: netip.MustParseAddrPort("192.168.124.202:50000"),
		dst: netip.MustParseAddrPort("1.2.3.4:443"),
	})
	item := adminConnectionFromUDP(&UDPFlowRuntime{
		id:       9,
		network:  "udp4",
		src:      ue.poolKey.Src,
		endpoint: ue,
		binding: UdpFlowBinding{
			Mac: mac,
			Egress: UdpEgressBinding{
				Outbound: group,
				Target:   "1.2.3.4:443",
				IsDialIp: true,
			},
		},
	})
	if item.Dst != "1.2.3.4:443" {
		t.Fatalf("dst = %q", item.Dst)
	}
	if item.Mac != "3e:0a:a5:de:ae:a3" {
		t.Fatalf("mac = %q", item.Mac)
	}
	if item.Dst == "invalid AddrPort" || item.Src == "invalid AddrPort" {
		t.Fatalf("leaked zero AddrPort: %+v", item)
	}
	if formatAddrPort(netip.AddrPort{}) != "" {
		t.Fatalf("zero AddrPort should render empty")
	}
}

func TestAdminConnectionsSnapshotTruncates(t *testing.T) {
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })
	group := &outbound.DialerGroup{Name: "AI"}
	for i := 0; i < 3; i++ {
		_, err := manager.adoptTCP(
			&memoryLayoutConn{id: uint64(i + 1)},
			nil,
			TcpFlowBinding{Egress: TcpEgressBinding{Outbound: group, Target: "example.com:443"}},
			runtime,
			nil,
			netip.MustParseAddrPort(fmt.Sprintf("192.168.124.202:%d", 40000+i)),
			netip.MustParseAddrPort("198.51.100.10:443"),
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	snap := manager.adminConnectionsSnapshot(2, adminConnectionFilter{})
	if snap.Total != 3 || !snap.Truncated || len(snap.Connections) != 2 {
		t.Fatalf("truncated snap = %+v", snap)
	}
	if clampAdminConnectionLimit(0) != adminConnectionsDefaultLimit || clampAdminConnectionLimit(4096) != adminConnectionsMaxLimit {
		t.Fatalf("clamp 0=%d 4096=%d", clampAdminConnectionLimit(0), clampAdminConnectionLimit(4096))
	}
}
