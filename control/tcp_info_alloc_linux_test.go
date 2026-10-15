//go:build linux

package control

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTCPConnInfoDoesNotAllocateTCPInfo(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		done <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	server := <-done
	defer server.Close()
	conn := client.(*net.TCPConn)

	info, err := tcpConnInfo(conn)
	require.NoError(t, err)
	require.Equal(t, uint8(1), info.State, "ESTABLISHED")

	// The fuse polls tcp_info per relay leg; each read used to heap-allocate it.
	allocs := testing.AllocsPerRun(200, func() {
		if _, err := tcpConnInfo(conn); err != nil {
			t.Fatal(err)
		}
	})
	require.Zero(t, allocs)
}
