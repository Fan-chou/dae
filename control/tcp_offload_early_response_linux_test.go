//go:build linux

package control

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
)

func TestTCPOffloadEarlyResponseDrainsUpload(t *testing.T) {
	coll := loadOffloadVerifyCollection(t)
	defer coll.Close()
	fast := coll.Maps["fast_sock"]
	lnk, e := link.AttachRawLink(link.RawLinkOptions{Target: fast.FD(), Program: coll.Programs["tcp_offload_redirect"], Attach: ebpf.AttachSkSKBStreamVerdict})
	if e != nil {
		t.Fatal(e)
	}
	defer lnk.Close()
	left, client := offloadTCPPair(t)
	server, right := offloadTCPPair(t)
	require.NoError(t, server.SetReadBuffer(4096))
	require.NoError(t, right.SetWriteBuffer(4096))
	s, e := newTCPRelayOffloadSession(nil, fast, coll.Maps["tcp_offload_pause"], coll.Maps["tcp_offload_sent"], left, right, func(int64) {}, func(int64) {})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, e := s.Run(ctx); left.Close(); right.Close(); done <- e }()
	payload := bytes.Repeat([]byte("upload"), 32768)
	require.NoError(t, client.SetDeadline(time.Now().Add(15*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(15*time.Second)))
	if _, e = client.Write(payload); e != nil {
		t.Fatal(e)
	}
	if e = client.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	// Server responds and half-closes before consuming the upload, as with an early HTTP error.
	if _, e = server.Write([]byte("early response")); e != nil {
		t.Fatal(e)
	}
	if e = server.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(client)
	if e != nil {
		t.Fatal(e)
	}
	require.Equal(t, "early response", string(got))
	time.Sleep(100 * time.Millisecond)
	received := make(chan []byte, 1)
	go func() {
		b, err := io.ReadAll(server)
		if err != nil {
			t.Errorf("server read: %v", err)
		}
		received <- b
	}()
	select {
	case e := <-done:
		t.Logf("relay exit=%v", e)
	case <-time.After(10 * time.Second):
		cancel()
		<-done
		t.Error("relay failed to retire")
	}
	select {
	case b := <-received:
		if !bytes.Equal(b, payload) {
			t.Errorf("upload tail corrupted: %d/%d", len(b), len(payload))
		}
	case <-time.After(15 * time.Second):
		t.Error("server still waiting")
	}
}
