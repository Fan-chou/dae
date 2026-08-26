/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"testing"
	"time"
)

func TestSniffUdpAfterClose(t *testing.T) {
	s := NewPacketSniffer(nil, time.Second)
	s.AppendData([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s.AppendData([]byte{0x01, 0x02})
	d, err := s.SniffUdp()
	if d != "" {
		t.Fatalf("domain = %q, want empty", d)
	}
	if err != ErrNotApplicable {
		t.Fatalf("err = %v, want ErrNotApplicable", err)
	}
	if _, err := s.SniffQuic(); err != ErrNotApplicable {
		t.Fatalf("SniffQuic after Close: %v, want ErrNotApplicable", err)
	}
}
