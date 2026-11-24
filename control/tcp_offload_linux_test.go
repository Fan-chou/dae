//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestEpollCtlAddIgnoreExist(t *testing.T) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("EpollCreate1: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(epfd) })

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	ev := &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
	if err := epollCtlAddIgnoreExist(epfd, fd, ev); err != nil {
		t.Fatalf("first ADD: %v", err)
	}
	if err := epollCtlAddIgnoreExist(epfd, fd, ev); err != nil {
		t.Fatalf("second ADD (EEXIST) = %v, want nil", err)
	}
}

func TestTCPOffloadMaxPeerBacklogForRAM(t *testing.T) {
	if got := tcpOffloadMaxPeerBacklogForRAM(1024 << 20); got != tcpOffloadLowMemMaxPeerBacklog {
		t.Fatalf("1 GiB host backlog = %d, want %d", got, tcpOffloadLowMemMaxPeerBacklog)
	}
	if got := tcpOffloadMaxPeerBacklogForRAM(10240 << 20); got != tcpOffloadMaxPeerBacklog {
		t.Fatalf("10 GiB host backlog = %d, want %d", got, tcpOffloadMaxPeerBacklog)
	}
}
