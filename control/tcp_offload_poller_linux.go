//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// tcpOffloadPoller tracks read readiness independently for each direction.
// Run owns it; a fuse pause may disarm both directions, but recovery must
// never rearm a direction that has already reached EOF.
type tcpOffloadPoller struct {
	epfd   int
	fds    [2]int
	armed  uint8
	closed uint8
}

func (p *tcpOffloadPoller) arm() error {
	for index, fd := range p.fds {
		bit := uint8(1 << index)
		if (p.armed|p.closed)&bit != 0 {
			continue
		}
		event := &unix.EpollEvent{
			Events: unix.EPOLLRDHUP | unix.EPOLLHUP | unix.EPOLLERR | unix.EPOLLIN,
			Fd:     int32(index),
		}
		if err := epollCtlAddIgnoreExist(p.epfd, fd, event); err != nil {
			return fmt.Errorf("epoll add direction %d: %w", index, err)
		}
		p.armed |= bit
	}
	return nil
}

func (p *tcpOffloadPoller) remove(index int32) error {
	bit := uint8(1 << uint(index))
	if p.armed&bit == 0 {
		return nil
	}
	if err := unix.EpollCtl(p.epfd, unix.EPOLL_CTL_DEL, p.fds[index], nil); err != nil && err != unix.ENOENT {
		return fmt.Errorf("epoll remove direction %d: %w", index, err)
	}
	p.armed &^= bit
	return nil
}

func (p *tcpOffloadPoller) closeRead(index int32) error {
	if err := p.remove(index); err != nil {
		return err
	}
	p.closed |= 1 << uint(index)
	return nil
}

func (p *tcpOffloadPoller) disarm() error {
	for index := range p.fds {
		if err := p.remove(int32(index)); err != nil {
			return err
		}
	}
	return nil
}
