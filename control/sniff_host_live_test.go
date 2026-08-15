/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

// sniffTcpLikeHandleConnection mirrors handleConnection: prefetch 16 bytes,
// gate on HTTP/TLS prefix, then ConnSniffer.SniffTcp.
func sniffTcpLikeHandleConnection(t *testing.T, conn net.Conn, timeout time.Duration) string {
	t.Helper()
	probeConn, prefetched, ready, err := prefetchForTcpSniff(conn, timeout, tcpSniffPrefetchBytes)
	if err != nil {
		t.Fatalf("prefetchForTcpSniff: %v", err)
	}
	if !ready {
		t.Fatal("prefetch returned ready=false")
	}
	if !isLikelyHttpOrTLSPrefix(prefetched) {
		t.Fatalf("prefix %q not recognized as HTTP/TLS", prefetched)
	}
	sniffer := sniffing.NewConnSniffer(probeConn, timeout)
	defer func() { _ = sniffer.Close() }()
	domain, err := sniffer.SniffTcp()
	if err != nil {
		t.Fatalf("SniffTcp: %v (prefetched %q)", err, prefetched)
	}
	return domain
}

func TestLiveHTTPHostArrivesAfterPrefetch(t *testing.T) {
	// "GET / HTTP/1.1\r\n" is exactly tcpSniffPrefetchBytes (16). Before the
	// NeedMore fix this was a hard miss: prefetch consumed the request line
	// and sniffHTTPHostHeader returned ErrNotFound without waiting for Host.
	requestLine := []byte("GET / HTTP/1.1\r\n")
	if len(requestLine) != tcpSniffPrefetchBytes {
		t.Fatalf("request line is %d bytes, want %d so this matches production prefetch", len(requestLine), tcpSniffPrefetchBytes)
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	errCh := make(chan error, 1)
	go func() {
		if _, err := client.Write(requestLine); err != nil {
			errCh <- err
			return
		}
		time.Sleep(25 * time.Millisecond)
		_, err := client.Write([]byte("Host: delayed.example.com\r\n\r\n"))
		errCh <- err
	}()

	start := time.Now()
	got := sniffTcpLikeHandleConnection(t, server, 300*time.Millisecond)
	t.Logf("HTTP delayed Host sniffed %q in %s", got, time.Since(start).Round(time.Millisecond))
	if got != "delayed.example.com" {
		t.Fatalf("domain = %q, want delayed.example.com", got)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client write: %v", err)
	}
}

func TestLiveHTTPConnectWithoutHostHeader(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		_, _ = client.Write([]byte("CONNECT odin.game.daum.net:443 HTTP/1.1\r\n\r\n"))
	}()

	got := sniffTcpLikeHandleConnection(t, server, 300*time.Millisecond)
	t.Logf("CONNECT fallback sniffed %q", got)
	if got != "odin.game.daum.net" {
		t.Fatalf("domain = %q, want odin.game.daum.net", got)
	}
}

func TestLiveTLSClientHelloFromCryptoTLS(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	errCh := make(chan error, 1)
	go func() {
		tlsConn := tls.Client(client, &tls.Config{
			ServerName:         "www.google.com",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS12,
		})
		errCh <- tlsConn.Handshake()
	}()

	got := sniffTcpLikeHandleConnection(t, server, 2*time.Second)
	t.Logf("crypto/tls ClientHello sniffed %q", got)
	if got != "www.google.com" {
		t.Fatalf("domain = %q, want www.google.com", got)
	}
	_ = client.Close()
	<-errCh
}
