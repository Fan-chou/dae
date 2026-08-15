/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
)

type capturingPacketConn struct {
	net.PacketConn
	got chan []byte
}

func (c *capturingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case c.got <- append([]byte(nil), p...):
	default:
	}
	return c.PacketConn.WriteTo(p, addr)
}

func TestLiveQUICInitialFromQuicGo(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer func() { _ = server.Close() }()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer func() { _ = client.Close() }()

	got := make(chan []byte, 8)
	capConn := &capturingPacketConn{PacketConn: client, got: got}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		tlsConf := &tls.Config{
			ServerName:         "quic.live.test",
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: true,
		}
		conn, err := quic.DialEarly(ctx, capConn, server.LocalAddr(), tlsConf, nil)
		if err == nil {
			_ = conn.CloseWithError(0, "")
		}
	}()

	var sniffer *Sniffer
	defer func() {
		if sniffer != nil {
			_ = sniffer.Close()
		}
	}()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-got:
			if !IsLikelyQuicInitialPacket(pkt) {
				t.Logf("skip non-initial datagram (%d bytes)", len(pkt))
				continue
			}
			t.Logf("captured QUIC Initial %d bytes first=%#02x version=%#08x",
				len(pkt), pkt[0], binary.BigEndian.Uint32(pkt[1:5]))
			if sniffer == nil {
				sniffer = NewPacketSniffer(pkt, 500*time.Millisecond)
			} else {
				sniffer.AppendData(pkt)
			}
			domain, err := sniffer.SniffUdp()
			if err != nil {
				if sniffer.NeedMore() {
					t.Logf("NeedMore after %d bytes, waiting for another Initial", sniffer.buf.Len())
					continue
				}
				t.Fatalf("SniffUdp: %v", err)
			}
			t.Logf("quic-go Initial sniffed %q", domain)
			if domain != "quic.live.test" {
				t.Fatalf("domain = %q, want quic.live.test", domain)
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for quic-go Initial SNI")
		}
	}
}
