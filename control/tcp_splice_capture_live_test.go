//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/observation"
)

// Opt in on the target machine: this measures real kernel splice and the
// production FlowRuntime accounting callbacks over a complete capture window.
func TestSpliceCaptureLiveAccounting(t *testing.T) {
	if os.Getenv("KDAE_SPLICE_LIVE_CHECK") != "1" {
		t.Skip("target-machine measurement; opt in explicitly")
	}
	testSpliceCaptureLiveAccounting(t, false)
}

func TestSpliceCaptureLiveConcurrentAccounting(t *testing.T) {
	if os.Getenv("KDAE_SPLICE_LIVE_CHECK") != "1" {
		t.Skip("target-machine measurement; opt in explicitly")
	}
	for _, name := range []string{"download-0", "download-1", "upload-0", "upload-1"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testSpliceCaptureLiveAccounting(t, strings.HasPrefix(name, "upload"))
		})
	}
}

func testSpliceCaptureLiveAccounting(t *testing.T, upload bool) {
	pair := func() (*net.TCPConn, *net.TCPConn) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		client, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := ln.Accept()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		a, b := client.(*net.TCPConn), server.(*net.TCPConn)
		t.Cleanup(func() { a.Close(); b.Close() })
		return a, b
	}
	sourcePeer, source := pair()
	destination, destinationPeer := pair()
	if !shouldUseRelayFastPath(destination, source) {
		t.Fatal("TCP pair does not qualify for splice")
	}
	d := newTestEndpointDialer()
	t.Cleanup(func() { d.Close() })
	d.LoadStart()
	defer d.LoadFinish()
	c, err := observation.New(1000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	captured := c.Start(observation.Scope{Site: "isolated-splice.test", Node: "isolated", Group: "isolated", Network: "tcp4", Path: "direct"}, d.LoadTotals)
	if captured == nil {
		t.Fatal("isolated flow registration failed")
	}
	captured.Userspace()
	f := &FlowRuntime{binding: TcpFlowBinding{Egress: TcpEgressBinding{Dialer: d}}}
	f.capture.Store(captured)
	const chunk = 256 << 10
	const chunks = 80
	const expected = chunk * chunks
	writerDone := make(chan error, 1)
	readerDone := make(chan struct {
		n   int64
		err error
	}, 1)
	go func() {
		data := make([]byte, chunk)
		for i := 0; i < chunks; i++ {
			remaining := data
			for len(remaining) > 0 {
				n, e := sourcePeer.Write(remaining)
				if e != nil {
					writerDone <- e
					return
				}
				if n == 0 {
					writerDone <- io.ErrShortWrite
					return
				}
				remaining = remaining[n:]
			}
			time.Sleep(250 * time.Millisecond)
		}
		writerDone <- sourcePeer.CloseWrite()
	}()
	go func() {
		n, e := io.Copy(io.Discard, destinationPeer)
		readerDone <- struct {
			n   int64
			err error
		}{n, e}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	started := time.Now()
	// Calls the same explicit splice loop selected by relayFastCopy in production.
	record := f.recordDownload
	direction := "download"
	if upload {
		record = f.recordUpload
		direction = "upload"
	}
	transferred, err := relayFastCopy(ctx, destination, source, record, func(int64) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	if err := destination.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	received := <-readerDone
	if received.err != nil {
		t.Fatal(received.err)
	}
	captured.Finish("relay_ended")
	flowBytes := f.downloadBytes.Load()
	if upload {
		flowBytes = f.uploadBytes.Load()
	}
	if transferred != expected || received.n != expected || flowBytes != expected {
		t.Fatalf("transfer=%d receive=%d flow=%d expected=%d", transferred, received.n, flowBytes, expected)
	}
	nodeUp, node, ok := d.LoadTotals()
	if upload {
		node = nodeUp
	}
	if !ok || node != expected {
		t.Fatalf("node=%d expected=%d", node, expected)
	}
	var records []observation.Record
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		records = nil
		ended := false
		for _, raw := range c.Snapshot(0).Records {
			var r observation.Record
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			records = append(records, r)
			ended = ended || r.Partial
		}
		if ended {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var sum uint64
	valid, partial := 0, 0
	var maxDifference uint64
	for _, r := range records {
		flowWindow, nodeWindow := r.Down, r.NodeDown
		if upload {
			flowWindow, nodeWindow = r.Up, r.NodeUp
		}
		if flowWindow == nil {
			t.Fatal("splice bytes marked unmeasured")
		}
		sum += *flowWindow
		if r.Partial {
			partial++
			continue
		}
		if nodeWindow == nil {
			t.Fatalf("node window missing: %s", r.Missing.Node)
		}
		valid++
		difference := *nodeWindow - *flowWindow
		if *nodeWindow < *flowWindow {
			t.Fatal("node count smaller than isolated flow")
		}
		if difference > maxDifference {
			maxDifference = difference
		}
	}
	if valid < 1 || partial != 1 || sum != expected {
		t.Fatalf("valid=%d partial=%d archived=%d expected=%d", valid, partial, sum, expected)
	}
	if maxDifference > relaySpliceMaxStep {
		t.Fatalf("isolated snapshot skew %d exceeds one splice step %d", maxDifference, relaySpliceMaxStep)
	}
	stats := c.Snapshot(0).Stats
	if stats.InvalidWindow != 0 || stats.QueueDropped != 0 {
		t.Fatal(stats)
	}
	result := map[string]any{"test_case": t.Name(), "direction": direction, "bytes_sent": expected, "bytes_received": received.n, "splice_bytes": transferred, "node_bytes": node, "flow_bytes": flowBytes, "archived_bytes": sum, "valid_windows": valid, "partial_windows": partial, "max_window_snapshot_difference_bytes": maxDifference, "snapshot_difference_limit_bytes": relaySpliceMaxStep, "invalid_window": stats.InvalidWindow, "queue_dropped": stats.QueueDropped, "duration_seconds": time.Since(started).Seconds(), "scope": "isolated_loopback_tcp_actual_splice_production_accounting"}
	raw, _ := json.Marshal(result)
	fmt.Printf("SPLICE_CAPTURE_RESULT %s\n", raw)
}
