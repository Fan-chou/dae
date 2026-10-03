//go:build linux

package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type gatherTLSWriteCounter struct {
	net.Conn
	writes atomic.Int64
}

func (c *gatherTLSWriteCounter) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

// Exercise opaque TLS connections, where net.Buffers cannot use TCP writev.
// The production prefix sources currently expose one segment; use one prefix
// plus one body instead of benchmarking only artificial many-fragment inputs.
func BenchmarkWrappedGatherTLS(b *testing.B) {
	for _, sizes := range [][2]int{{1024, 1024}, {4096, 4096}, {1024, 32768}, {1024, 0}} {
		for _, enabled := range []bool{false, true} {
			b.Run(fmt.Sprintf("%d+%d/coalesce=%v", sizes[0], sizes[1], enabled), func(b *testing.B) {
				benchmarkWrappedGatherTLS(b, sizes, enabled)
			})
		}
	}
}

func benchmarkWrappedGatherTLS(b *testing.B, sizes [2]int, enabled bool) {
	b.StopTimer()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gather-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	rawClient, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer rawClient.Close()
	rawServer, err := listener.Accept()
	if err != nil {
		b.Fatal(err)
	}
	defer rawServer.Close()
	if err := rawClient.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	if err := rawServer.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	counter := &gatherTLSWriteCounter{Conn: rawClient}
	client := tls.Client(counter, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	server := tls.Server(rawServer, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13})
	segments := [2][]byte{bytes.Repeat([]byte{'P'}, sizes[0]), bytes.Repeat([]byte{'B'}, sizes[1])}
	want := bytes.Join(segments[:], nil)
	type readResult struct {
		count int
		err   error
	}
	done := make(chan readResult, 1)
	go func() {
		frame := make([]byte, len(want))
		count := 0
		for {
			_, err := io.ReadFull(server, frame)
			if err == io.EOF {
				done <- readResult{count, nil}
				return
			}
			if err != nil {
				done <- readResult{count, err}
				return
			}
			if !bytes.Equal(frame, want) {
				done <- readResult{count, fmt.Errorf("TLS prefix/body mismatch")}
				return
			}
			count++
		}
	}()
	if err := client.Handshake(); err != nil {
		b.Fatal(err)
	}
	before := counter.writes.Load()
	b.ReportAllocs()
	b.SetBytes(int64(len(want)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		// net.Buffers advances slice headers. Each call receives fresh headers.
		p := segments
		n, err := relayGatherWriteToWithOptions(client, p[:], enabled)
		if err != nil || n != len(want) {
			b.Fatalf("written=%d err=%v", n, err)
		}
	}
	b.StopTimer()
	writes := counter.writes.Load() - before
	if err := client.CloseWrite(); err != nil {
		b.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.count != b.N {
			b.Fatalf("TLS frames=%d want=%d err=%v", result.count, b.N, result.err)
		}
	case <-time.After(5 * time.Second):
		b.Fatal("TLS receiver did not finish")
	}
	b.ReportMetric(float64(writes)/float64(b.N), "socket-writes/op")
}
