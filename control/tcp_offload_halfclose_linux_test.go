//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func offloadTCPPair(t *testing.T) (relay, peer *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err = net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	relay, err = listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	if err := relay.SetReadBuffer(1 << 20); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return relay, peer
}

func TestTCPOffloadHalfCloseStopsReadinessAndSurvivesFuseRearm(t *testing.T) {
	left, client := offloadTCPPair(t)
	right, server := offloadTCPPair(t)
	leftFD, err := tcpConnFD(left)
	if err != nil {
		t.Fatal(err)
	}
	rightFD, err := tcpConnFD(right)
	if err != nil {
		t.Fatal(err)
	}
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(epfd)
	poller := tcpOffloadPoller{epfd: epfd, fds: [2]int{leftFD, rightFD}}
	if err := poller.arm(); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var events [2]unix.EpollEvent
	n, err := unix.EpollWait(epfd, events[:], 1000)
	if err != nil || n != 1 || events[0].Fd != 0 {
		t.Fatalf("EOF readiness n=%d err=%v events=%v", n, err, events)
	}
	s := &tcpRelayOffloadSession{left: left, right: right}
	last := time.Now()
	closed, err := s.relayPassData(0, &last)
	if err != nil || !closed {
		t.Fatalf("EOF closed=%v err=%v", closed, err)
	}
	if err := poller.closeRead(0); err != nil {
		t.Fatal(err)
	}
	// Fuse engagement/recovery must not resurrect the permanently readable EOF.
	if err := poller.disarm(); err != nil {
		t.Fatal(err)
	}
	if err := poller.arm(); err != nil {
		t.Fatal(err)
	}
	if err := poller.arm(); err != nil {
		t.Fatal(err)
	}
	n, err = unix.EpollWait(epfd, events[:], 25)
	if err != nil || n != 0 {
		t.Fatalf("EOF remained armed: n=%d err=%v events=%v", n, err, events)
	}
	// Unregistering read readiness must leave the same socket writable.
	want := []byte("response after client half-close")
	if _, err := server.Write(want); err != nil {
		t.Fatal(err)
	}
	n, err = unix.EpollWait(epfd, events[:], 1000)
	if err != nil || n != 1 || events[0].Fd != 1 {
		t.Fatalf("response readiness n=%d err=%v events=%v", n, err, events)
	}
	closed, err = s.relayPassData(1, &last)
	if err != nil || closed {
		t.Fatalf("response closed=%v err=%v", closed, err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("response=%q", got)
	}
}

func TestTCPOffloadRunDrainsBothFINQueues(t *testing.T) {
	left, client := offloadTCPPair(t)
	right, server := offloadTCPPair(t)
	leftFD, err := tcpConnFD(left)
	if err != nil {
		t.Fatal(err)
	}
	rightFD, err := tcpConnFD(right)
	if err != nil {
		t.Fatal(err)
	}
	// FIN accompanies more data than one relayPassData call can consume.
	upload := bytes.Repeat([]byte{0x35}, 3*relayCopyBufferSize)
	download := bytes.Repeat([]byte{0x79}, 3*relayCopyBufferSize)
	for _, side := range []struct {
		peer *net.TCPConn
		data []byte
	}{{client, upload}, {server, download}} {
		if _, err := side.peer.Write(side.data); err != nil {
			t.Fatal(err)
		}
		if err := side.peer.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	// Ensure both FINs have reached their sockets before Run sees events.
	for _, fd := range []int{leftFD, rightFD} {
		deadline := time.Now().Add(500 * time.Millisecond)
		for {
			info, err := unix.GetsockoptTCPInfo(fd, unix.SOL_TCP, unix.TCP_INFO)
			if err != nil {
				t.Fatal(err)
			}
			if info.State == 8 {
				break
			} // TCP_CLOSE_WAIT
			if time.Now().After(deadline) {
				t.Fatal("FIN did not arrive")
			}
			time.Sleep(time.Millisecond)
		}
	}
	s := &tcpRelayOffloadSession{left: left, right: right, leftFD: leftFD, rightFD: rightFD}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, _, err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := s.fusePassBytes, uint64(len(upload)+len(download)); got != want {
		t.Fatalf("forwarded %d bytes, want %d; FIN retired queued data early", got, want)
	}
	for _, side := range []struct {
		peer *net.TCPConn
		want []byte
	}{{server, upload}, {client, download}} {
		got := make([]byte, len(side.want))
		if _, err := io.ReadFull(side.peer, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, side.want) {
			t.Fatal("queued payload changed")
		}
	}
}
