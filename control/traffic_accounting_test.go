/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound"
)

func TestTrafficAccountingClosedFlowRingDimensionsResetAndAbort(t *testing.T) {
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })

	var observed []AdminClosedFlow
	manager.accounting.SetClosedFlowObserver(func(f AdminClosedFlow) {
		observed = append(observed, f)
	})

	proxyGroup := &outbound.DialerGroup{Name: "proxy"}
	directGroup := &outbound.DialerGroup{Name: "direct"}

	flow1, err := manager.adoptTCP(
		&memoryLayoutConn{id: 1},
		nil,
		TcpFlowBinding{
			Process: "curl",
			Route: TcpRouteBinding{
				Rule: &RoutingRuleMeta{Index: 1, Raw: "domain(suffix:example.com) -> proxy"},
			},
			Egress: TcpEgressBinding{
				Outbound:      proxyGroup,
				SniffedDomain: "api.example.com",
				Target:        "api.example.com:443",
			},
		},
		runtime,
		nil,
		netip.MustParseAddrPort("192.168.1.10:50001"),
		netip.MustParseAddrPort("93.184.216.34:443"),
	)
	if err != nil {
		t.Fatal(err)
	}
	flow1.recordUpload(100)
	flow1.recordDownload(400)

	flow2, err := manager.adoptTCP(
		&memoryLayoutConn{id: 2},
		nil,
		TcpFlowBinding{
			Egress: TcpEgressBinding{
				Outbound: directGroup,
				Target:   "1.1.1.1:80",
				IsDialIp: true,
			},
		},
		runtime,
		nil,
		netip.MustParseAddrPort("192.168.1.20:50002"),
		netip.MustParseAddrPort("1.1.1.1:80"),
	)
	if err != nil {
		t.Fatal(err)
	}
	flow2.recordUpload(50)
	flow2.recordDownload(150)

	// Abort flow1 by ID and verify close reason + removal from active list.
	id1 := fmt.Sprintf("tcp:%d", flow1.id)
	if !manager.CloseConnectionByID(id1) {
		t.Fatalf("expected CloseConnectionByID(%s) to succeed", id1)
	}
	if manager.CloseConnectionByID(id1) {
		t.Fatalf("expected second CloseConnectionByID(%s) to return false", id1)
	}
	if len(observed) != 1 || observed[0].CloseReason != "aborted" || observed[0].ID != id1 {
		t.Fatalf("unexpected observed closed flow: %+v", observed)
	}

	// Summary overlays closed flow1 (500 bytes) + live flow2 (200 bytes).
	activeSnap := manager.adminConnectionsSnapshot(256, AdminConnectionFilter{})
	summary := manager.accounting.Summary(activeSnap.Connections, 50)
	if summary.UploadTotal != 150 || summary.DownloadTotal != 550 || summary.ClosedConnections != 1 || summary.ActiveConnections != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	// Reset baselines against active flow2, then transfer more on flow2 and close normally.
	manager.accounting.Reset(activeSnap.Connections)
	flow2.recordUpload(25)
	flow2.finish()

	summaryAfter := manager.accounting.Summary(nil, 50)
	if summaryAfter.UploadTotal != 25 || summaryAfter.DownloadTotal != 0 || summaryAfter.ClosedConnections != 1 {
		t.Fatalf("expected post-reset delta (up=25, down=0, closed=1), got %+v", summaryAfter)
	}
	if len(observed) != 2 || observed[1].CloseReason != "normal" {
		t.Fatalf("expected second flow to finish normally, got %+v", observed)
	}

	closedSnap := manager.accounting.SnapshotClosed(10, AdminConnectionFilter{})
	if closedSnap.Total != 2 || len(closedSnap.Flows) != 2 || closedSnap.Flows[0].ID != fmt.Sprintf("tcp:%d", flow2.id) {
		t.Fatalf("expected newest-first closed flows, got %+v", closedSnap)
	}
}

func TestBoundedDimMapFoldsOverflowIntoOther(t *testing.T) {
	m := newBoundedDimMap(2)
	m.add("a", 100, 0, 1)
	m.add("b", 200, 0, 1)
	m.add("c", 50, 10, 1)
	m.add("d", 25, 5, 1)
	buckets := m.sortedTop(10)
	if len(buckets) != 3 {
		t.Fatalf("expected 2 tracked + other = 3 buckets, got %+v", buckets)
	}
	if buckets[2].Key != "other" || buckets[2].Upload != 75 || buckets[2].Download != 15 || buckets[2].Connections != 2 {
		t.Fatalf("unexpected other bucket: %+v", buckets[2])
	}
}

func TestParseKernelCloseTupleValidation(t *testing.T) {
	if _, _, _, err := parseKernelCloseTuple(AdminKernelCloseRequest{Protocol: "icmp", SrcIP: "1.2.3.4", SrcPort: 1, DstIP: "5.6.7.8", DstPort: 80}); err == nil {
		t.Fatal("expected unsupported protocol error")
	}
	if _, _, _, err := parseKernelCloseTuple(AdminKernelCloseRequest{Protocol: "tcp", SrcIP: "192.168.1.2", SrcPort: 0, DstIP: "1.1.1.1", DstPort: 443}); err == nil {
		t.Fatal("expected zero port error")
	}
	if _, _, _, err := parseKernelCloseTuple(AdminKernelCloseRequest{Protocol: "udp", SrcIP: "192.168.1.2", SrcPort: 1234, DstIP: "2001:db8::1", DstPort: 443}); err == nil {
		t.Fatal("expected address family mismatch error")
	}
	proto, src, dst, err := parseKernelCloseTuple(AdminKernelCloseRequest{Protocol: "TCP", SrcIP: "::ffff:192.168.1.2", SrcPort: 50000, DstIP: "1.1.1.1", DstPort: 443})
	if err != nil || proto != 6 || src.Addr().String() != "192.168.1.2" || dst.Port() != 443 {
		t.Fatalf("unexpected valid parse result: proto=%d src=%v dst=%v err=%v", proto, src, dst, err)
	}
}

func TestTrafficAccountingOver1024ActiveFlowsNoTruncation(t *testing.T) {
	t.Parallel()
	const flowCount = 1100

	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })

	c := &ControlPlane{runtimeStats: newRuntimeStats()}
	if err := c.AttachSessionManager(manager); err != nil {
		t.Fatal(err)
	}

	directGroup := &outbound.DialerGroup{Name: "direct"}
	flows := make([]*FlowRuntime, 0, flowCount)
	var expectedUp, expectedDown uint64
	for i := 0; i < flowCount; i++ {
		f, err := manager.adoptTCP(
			&memoryLayoutConn{id: uint64(i + 1)},
			nil,
			TcpFlowBinding{
				Egress: TcpEgressBinding{
					Outbound: directGroup,
					Target:   "1.1.1.1:443",
					IsDialIp: true,
				},
			},
			runtime,
			nil,
			netip.MustParseAddrPort(fmt.Sprintf("192.168.2.%d:%d", (i/200)+10, 10000+i)),
			netip.MustParseAddrPort("1.1.1.1:443"),
		)
		if err != nil {
			t.Fatalf("adoptTCP %d failed: %v", i, err)
		}
		up := uint64(100 + i)
		down := uint64(200 + i*2)
		f.recordUpload(int64(up))
		f.recordDownload(int64(down))
		expectedUp += up
		expectedDown += down
		flows = append(flows, f)
	}

	sum := c.AdminTrafficSummary(50)
	if sum.ActiveConnections != flowCount {
		t.Fatalf("ActiveConnections = %d, want %d (must not truncate at 1024)", sum.ActiveConnections, flowCount)
	}
	if sum.UploadTotal != expectedUp || sum.DownloadTotal != expectedDown {
		t.Fatalf("summary totals got (%d, %d), want (%d, %d)", sum.UploadTotal, sum.DownloadTotal, expectedUp, expectedDown)
	}

	c.AdminResetTrafficSummary()
	// Add post-reset delta specifically on a flow beyond the 1024th slot.
	flows[flowCount-1].recordUpload(333)
	flows[flowCount-1].recordDownload(777)

	for _, f := range flows {
		f.finish()
	}

	after := c.AdminTrafficSummary(50)
	if after.ActiveConnections != 0 || after.ClosedConnections != flowCount {
		t.Fatalf("post-finish counts: active=%d closed=%d", after.ActiveConnections, after.ClosedConnections)
	}
	if after.UploadTotal != 333 || after.DownloadTotal != 777 {
		t.Fatalf("post-reset totals got (%d, %d), want (333, 777)", after.UploadTotal, after.DownloadTotal)
	}
	manager.accounting.mu.Lock()
	leftoverBaselines := len(manager.accounting.activeBaselines)
	manager.accounting.mu.Unlock()
	if leftoverBaselines != 0 {
		t.Fatalf("expected 0 activeBaselines after all flows closed, got %d", leftoverBaselines)
	}
}

func TestTrafficAccountingConcurrentSummaryResetAndCloseRace(t *testing.T) {
	t.Parallel()
	manager := NewSessionManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	runtime := newEgressRuntime(nil, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })

	c := &ControlPlane{runtimeStats: newRuntimeStats()}
	if err := c.AttachSessionManager(manager); err != nil {
		t.Fatal(err)
	}

	directGroup := &outbound.DialerGroup{Name: "direct"}
	stopReaders := make(chan struct{})
	var readerWG sync.WaitGroup
	for r := 0; r < 3; r++ {
		readerWG.Add(1)
		go func(id int) {
			defer readerWG.Done()
			for i := 0; ; i++ {
				select {
				case <-stopReaders:
					return
				default:
				}
				_ = c.AdminTrafficSummary(20)
				if (i+id)%5 == 0 {
					c.AdminResetTrafficSummary()
				}
				time.Sleep(time.Millisecond)
			}
		}(r)
	}

	var workerWG sync.WaitGroup
	for w := 0; w < 6; w++ {
		workerWG.Add(1)
		go func(worker int) {
			defer workerWG.Done()
			for i := 0; i < 40; i++ {
				src := netip.MustParseAddrPort(fmt.Sprintf("192.168.10.%d:%d", worker+1, 20000+i))
				dst := netip.MustParseAddrPort("1.1.1.1:443")
				tcpFlow, err := manager.adoptTCP(
					&memoryLayoutConn{id: uint64(worker*100 + i + 1)},
					nil,
					TcpFlowBinding{Egress: TcpEgressBinding{Outbound: directGroup, Target: "1.1.1.1:443", IsDialIp: true}},
					runtime,
					nil,
					src,
					dst,
				)
				if err != nil {
					t.Errorf("adoptTCP: %v", err)
					return
				}
				tcpFlow.recordUpload(64)
				tcpFlow.recordDownload(128)

				ue := &UdpEndpoint{poolKey: UdpEndpointKey{Src: src, Dst: dst}}
				udpFlow, err := manager.adoptUDP(
					ue,
					UdpFlowBinding{Egress: UdpEgressBinding{Outbound: directGroup, Target: "1.1.1.1:443", IsDialIp: true}},
					runtime,
				)
				if err != nil {
					t.Errorf("adoptUDP: %v", err)
					return
				}
				udpFlow.uploadBytes.Add(32)
				udpFlow.downloadBytes.Add(96)

				tcpFlow.finish()
				udpFlow.finish()
			}
		}(w)
	}

	workerWG.Wait()
	close(stopReaders)
	readerWG.Wait()

	final := c.AdminTrafficSummary(50)
	if final.ActiveConnections != 0 {
		t.Fatalf("expected 0 active connections after all workers finished, got %d", final.ActiveConnections)
	}
	manager.accounting.mu.Lock()
	leftoverBaselines := len(manager.accounting.activeBaselines)
	manager.accounting.mu.Unlock()
	if leftoverBaselines != 0 {
		t.Fatalf("expected 0 orphaned activeBaselines after concurrent resets/closes, got %d", leftoverBaselines)
	}
}
