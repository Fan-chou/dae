//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/observation"
)

// This deliberately shares one node and collector across all four flows.
// Node windows overlap; they must not be summed as independent flow bytes.
func TestSpliceCaptureLiveSharedNodeAccounting(t *testing.T) {
	if os.Getenv("KDAE_SPLICE_LIVE_CHECK") != "1" {
		t.Skip("target-machine measurement; opt in explicitly")
	}
	d := newTestEndpointDialer()
	t.Cleanup(func() { d.Close() })
	c, err := observation.New(1000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const flowCount = 4
	const chunkBytes = 256 << 10
	const chunks = 80
	const flowBytes = chunkBytes * chunks
	type transfer struct {
		sourcePeer, source, destination, destinationPeer *net.TCPConn
		flow                                             *FlowRuntime
		capture                                          *observation.Flow
		upload                                           bool
	}
	pair := func() (*net.TCPConn, *net.TCPConn) {
		ln, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer ln.Close()
		client, e := net.Dial("tcp4", ln.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		server, e := ln.Accept()
		if e != nil {
			client.Close()
			t.Fatal(e)
		}
		a, b := client.(*net.TCPConn), server.(*net.TCPConn)
		deadline := time.Now().Add(40 * time.Second)
		a.SetDeadline(deadline)
		b.SetDeadline(deadline)
		t.Cleanup(func() { a.Close(); b.Close() })
		return a, b
	}
	flows := make([]transfer, flowCount)
	for i := range flows {
		d.LoadStart()
		defer d.LoadFinish()
		f := &flows[i]
		f.sourcePeer, f.source = pair()
		f.destination, f.destinationPeer = pair()
		f.upload = i < flowCount/2
		f.capture = c.Start(observation.Scope{Site: fmt.Sprintf("shared-%d.test", i), Node: "shared-node", Group: "shared", Network: "tcp4", Path: "direct"}, d.LoadTotals)
		if f.capture == nil {
			t.Fatal("shared flow registration failed")
		}
		f.capture.Userspace()
		f.flow = &FlowRuntime{binding: TcpFlowBinding{Egress: TcpEgressBinding{Dialer: d}}}
		f.flow.capture.Store(f.capture)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	begin := make(chan struct{})
	var workers sync.WaitGroup
	results := make(chan error, flowCount)
	for i := range flows {
		f := &flows[i]
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-begin
			writerDone := make(chan error, 1)
			readerDone := make(chan error, 1)
			go func() {
				data := make([]byte, chunkBytes)
				for range chunks {
					n, e := f.sourcePeer.Write(data)
					if e != nil || n != len(data) {
						writerDone <- fmt.Errorf("source write %d/%d: %v", n, len(data), e)
						return
					}
					time.Sleep(250 * time.Millisecond)
				}
				writerDone <- f.sourcePeer.CloseWrite()
			}()
			go func() {
				n, e := io.Copy(io.Discard, f.destinationPeer)
				if e == nil && n != flowBytes {
					e = fmt.Errorf("destination received %d, want %d", n, flowBytes)
				}
				readerDone <- e
			}()
			record := f.flow.recordDownload
			if f.upload {
				record = f.flow.recordUpload
			}
			n, e := relayFastCopy(ctx, f.destination, f.source, record, func(int64) {})
			if e == nil && n != flowBytes {
				e = fmt.Errorf("splice transferred %d, want %d", n, flowBytes)
			}
			if e != nil {
				f.sourcePeer.Close()
				f.destination.Close()
			} else if closeErr := f.destination.CloseWrite(); closeErr != nil {
				e = closeErr
				f.destination.Close()
			}
			if writeErr := <-writerDone; e == nil {
				e = writeErr
			}
			if readErr := <-readerDone; e == nil {
				e = readErr
			}
			f.capture.Finish("relay_ended")
			results <- e
		}()
	}
	started := time.Now()
	close(begin)
	workers.Wait()
	close(results)
	for e := range results {
		if e != nil {
			t.Fatal(e)
		}
	}
	up, down, ok := d.LoadTotals()
	const directionBytes = flowBytes * (flowCount / 2)
	if !ok || up != directionBytes || down != directionBytes {
		t.Fatalf("shared node totals up=%d down=%d, want %d each", up, down, directionBytes)
	}
	var records []observation.Record
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		records = nil
		ended := 0
		for _, raw := range c.Snapshot(0).Records {
			var r observation.Record
			if e := json.Unmarshal(raw, &r); e != nil {
				t.Fatal(e)
			}
			records = append(records, r)
			if r.Partial {
				ended++
			}
		}
		if ended == flowCount {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	type sum struct {
		up, down        uint64
		complete, ended int
	}
	byFlow := make(map[string]*sum)
	var archivedUp, archivedDown uint64
	type nodeWindow struct {
		endMS                          int64
		minUp, maxUp, minDown, maxDown uint64
		count                          int
	}
	var windows []*nodeWindow
	valid := 0
	for _, r := range records {
		if r.Up == nil || r.Down == nil {
			t.Fatal("shared splice flow marked unmeasured")
		}
		s := byFlow[r.Episode]
		if s == nil {
			s = &sum{}
			byFlow[r.Episode] = s
		}
		s.up += *r.Up
		s.down += *r.Down
		archivedUp += *r.Up
		archivedDown += *r.Down
		if r.Partial {
			s.ended++
			continue
		}
		if r.NodeUp == nil || r.NodeDown == nil || *r.NodeUp < *r.Up || *r.NodeDown < *r.Down {
			t.Fatalf("invalid shared node window: %s", r.Missing.Node)
		}
		// A flow can miss a tick by starting a fraction of a millisecond
		// later. Compare node snapshots only at the same sampling boundary;
		// later boundaries legitimately include additional shared traffic.
		endMS := r.StartMS + r.DurationMS
		var window *nodeWindow
		for _, w := range windows {
			if endMS >= w.endMS-1 && endMS <= w.endMS+1 {
				window = w
				break
			}
		}
		if window == nil {
			window = &nodeWindow{endMS: endMS, minUp: *r.NodeUp, minDown: *r.NodeDown}
			windows = append(windows, window)
		}
		if *r.NodeUp < window.minUp {
			window.minUp = *r.NodeUp
		}
		if *r.NodeDown < window.minDown {
			window.minDown = *r.NodeDown
		}
		if *r.NodeUp > window.maxUp {
			window.maxUp = *r.NodeUp
		}
		if *r.NodeDown > window.maxDown {
			window.maxDown = *r.NodeDown
		}
		window.count++
		valid++
		s.complete++
	}
	if len(byFlow) != flowCount || archivedUp != up || archivedDown != down {
		t.Fatalf("flows=%d archived=(%d,%d) node=(%d,%d)", len(byFlow), archivedUp, archivedDown, up, down)
	}
	for _, s := range byFlow {
		if s.up+s.down != flowBytes || s.complete < 1 || s.ended != 1 {
			t.Fatalf("incomplete shared flow: %+v", s)
		}
	}
	const spreadLimit = flowCount * relaySpliceMaxStep
	var spreadUp, spreadDown uint64
	comparable := 0
	for _, w := range windows {
		if w.count < 2 {
			continue
		}
		comparable += w.count
		if w.maxUp-w.minUp > spreadUp {
			spreadUp = w.maxUp - w.minUp
		}
		if w.maxDown-w.minDown > spreadDown {
			spreadDown = w.maxDown - w.minDown
		}
	}
	if comparable < 2 || spreadUp > spreadLimit || spreadDown > spreadLimit {
		t.Fatalf("shared comparable windows=%d spread=(%d,%d), limit=%d", comparable, spreadUp, spreadDown, spreadLimit)
	}
	stats := c.Snapshot(0).Stats
	if stats.InvalidWindow != 0 || stats.QueueDropped != 0 {
		t.Fatal(stats)
	}
	result := map[string]any{"scope": "shared_node_four_loopback_splice_flows", "flows": flowCount, "node_up_bytes": up, "node_down_bytes": down, "archived_up_bytes": archivedUp, "archived_down_bytes": archivedDown, "valid_windows": valid, "same_boundary_windows": comparable, "sampling_boundaries": len(windows), "window_spread_up_bytes": spreadUp, "window_spread_down_bytes": spreadDown, "window_spread_limit_bytes": spreadLimit, "invalid_window": stats.InvalidWindow, "queue_dropped": stats.QueueDropped, "duration_seconds": time.Since(started).Seconds()}
	raw, _ := json.Marshal(result)
	fmt.Printf("SHARED_SPLICE_CAPTURE_RESULT %s\n", raw)
}
