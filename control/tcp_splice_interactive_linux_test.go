//go:build linux

package control

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestExactSpliceDeliversSmallWriteBeforeNextRead(t *testing.T) {
	src, client := offloadTCPPair(t)
	dst, server := offloadTCPPair(t)
	var accounted atomic.Int64
	done := make(chan error, 1)
	go func() {
		n, err := relayFastCopy(context.Background(), dst, src, func(n int64) { accounted.Add(n) }, nil)
		if err == nil && n != 1 {
			t.Errorf("copied %d bytes, want 1", n)
		}
		done <- err
	}()
	// Keep the source open: the request must reach the peer without another
	// packet or EOF. MORE would hold it for Linux's roughly 200 ms cork timer.
	if _, err := client.Write([]byte{0x7b}); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, readErr := io.ReadFull(server, b[:])
	_ = client.CloseWrite()
	if readErr != nil {
		_ = src.Close()
		_ = dst.Close()
	}
	select {
	case err := <-done:
		if readErr == nil && err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("splice did not finish after EOF/close")
	}
	if readErr != nil {
		t.Fatalf("interactive write stalled: %v", readErr)
	}
	if b[0] != 0x7b || accounted.Load() != 1 {
		t.Fatalf("data=%x accounted=%d", b, accounted.Load())
	}
}
