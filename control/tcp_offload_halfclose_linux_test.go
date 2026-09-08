//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestTCPOffloadFINRealRedirect(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("needs root for isolated BPF map")
	}
	for _, reset := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "reset"}[reset], func(t *testing.T) {
			coll := loadOffloadVerifyCollection(t)
			defer coll.Close()
			fast := coll.Maps["fast_sock"]
			lnk, err := link.AttachRawLink(link.RawLinkOptions{Target: fast.FD(), Program: coll.Programs["tcp_offload_redirect"], Attach: ebpf.AttachSkSKBStreamVerdict})
			if err != nil {
				t.Fatal(err)
			}
			defer lnk.Close()
			left, client := offloadTCPPair(t)
			server, right := offloadTCPPair(t) // production egress is dialed
			s, err := newTCPRelayOffloadSession(nil, fast, coll.Maps["tcp_offload_pause"], coll.Maps["tcp_offload_sent"], left, right, func(int64) {}, func(int64) {})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, _, e := s.Run(ctx); done <- e }()
			payload := bytes.Repeat([]byte("tail"), 16384)
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(server)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("request tail: n=%d err=%v", len(got), err)
			}
			if reset {
				if err := server.SetLinger(0); err != nil {
					t.Fatal(err)
				}
				if err := server.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := server.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err := server.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(client)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("response tail: n=%d err=%v", len(got), err)
				}
			}
			<-done // reset may report its socket error; it must not wait for ctx
			if ctx.Err() != nil {
				t.Fatal("relay failed to retire before cancellation")
			}
		})
	}
}

// A reset may arrive after EOF readiness was removed. TCP_CLOSE must end
// FIN accounting even when bytes accepted by the dead peer cannot catch up.
func TestTCPOffloadFINStopsWaitingForResetPeer(t *testing.T) {
	left, client := offloadTCPPair(t)
	right, server := offloadTCPPair(t)
	rx, _, err := tcpOffloadBaseline(left)
	if err != nil {
		t.Fatal(err)
	}
	_, tx, err := tcpOffloadBaseline(right)
	if err != nil {
		t.Fatal(err)
	}
	s := &tcpRelayOffloadSession{left: left, right: right, leftRxBase: rx, txBase: [2]uint64{0, tx}, fastSock: &ebpf.Map{}}
	if _, err := client.Write([]byte("unaccepted tail")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(left); err != nil {
		t.Fatal(err)
	}
	if err := server.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		info, err := tcpConnInfo(right)
		if err != nil {
			t.Fatal(err)
		}
		if info.State == 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reset did not reach relay")
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.propagateFIN(1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dead peer must terminate FIN wait, got %v", err)
	}
}

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

func TestTCPOffloadRunPropagatesFINBeforeLateReply(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "upload", true: "download"}[reverse], func(t *testing.T) {
			left, client := offloadTCPPair(t)
			right, server := offloadTCPPair(t)
			if reverse {
				left, right = right, left
				client, server = server, client
			}
			lfd, err := tcpConnFD(left)
			if err != nil {
				t.Fatal(err)
			}
			rfd, err := tcpConnFD(right)
			if err != nil {
				t.Fatal(err)
			}
			s := &tcpRelayOffloadSession{left: left, right: right, leftFD: lfd, rightFD: rfd}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, _, err := s.Run(ctx); done <- err }()
			want := bytes.Repeat([]byte("request"), 3*relayCopyBufferSize/7)
			if _, err := client.Write(want); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(server)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("request tail lost")
			}
			if _, err := server.Write([]byte("late response")); err != nil {
				t.Fatal(err)
			}
			if err := server.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(client)
			if err != nil {
				t.Fatal(err)
			}
			if string(reply) != "late response" {
				t.Fatalf("reply=%q", reply)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil {
				t.Fatal("relay only ended on cancellation")
			}
		})
	}
}

func TestTCPOffloadFINWaitsForAcceptedTail(t *testing.T) {
	left, client := offloadTCPPair(t)
	right, server := offloadTCPPair(t)
	rx, _, err := tcpOffloadBaseline(left)
	if err != nil {
		t.Fatal(err)
	}
	_, tx, err := tcpOffloadBaseline(right)
	if err != nil {
		t.Fatal(err)
	}
	s := &tcpRelayOffloadSession{left: left, right: right, leftRxBase: rx, txBase: [2]uint64{0, tx}, fastSock: &ebpf.Map{}}
	if _, err := client.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(left)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.propagateFIN(1); err != nil {
		t.Fatal(err)
	}
	if s.finSent != 0 {
		t.Fatal("FIN passed data not yet accepted by destination TCP")
	}
	if _, err := right.Write(tail); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for s.finSent == 0 {
		if err := s.propagateFIN(1); err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			info, _ := tcpConnInfo(right)
			in, _ := tcpConnRxBytes(left)
			out, _ := tcpConnOutQueue(right)
			t.Fatalf("accepted tail did not release FIN: rx=%d base=%d ack=%d out=%d txbase=%d", in, rx, info.Bytes_acked, out, tx)
		}
		if s.finSent == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "tail" {
		t.Fatalf("tail=%q", got)
	}
}
