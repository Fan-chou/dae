//go:build linux

package control

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ingressSocketOpt(t *testing.T, socket interface {
	SyscallConn() (syscall.RawConn, error)
}, level, opt int) int {
	t.Helper()
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var optErr error
	if err := raw.Control(func(fd uintptr) { value, optErr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	if optErr != nil {
		t.Fatal(optErr)
	}
	return value
}

func TestTCPIngressMSSSurvivesClone(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			bind := "127.0.0.1:0"
			if network == "tcp6" {
				bind = "[::1]:0"
			}
			lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return tcpIngressListenControl(raw, 1380) }}
			listener, err := lc.Listen(context.Background(), network, bind)
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				t.Skipf("TPROXY requires privilege: %v", err)
			}
			if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EADDRNOTAVAIL) {
				t.Skip("IPv6 unavailable")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			clone, err := cloneTCPListener(listener)
			if err != nil {
				t.Fatal(err)
			}
			defer clone.Close()
			for _, l := range []net.Listener{listener, clone} {
				tcp := l.(*net.TCPListener)
				if got := ingressSocketOpt(t, tcp, unix.IPPROTO_TCP, unix.TCP_MAXSEG); got != 1380 {
					t.Fatalf("listener MSS = %d", got)
				}
				if got := ingressSocketOpt(t, tcp, unix.IPPROTO_TCP, unix.TCP_FASTOPEN); got != 0 {
					t.Fatalf("listener TFO = %d", got)
				}
			}
			client, err := net.DialTimeout(network, clone.Addr().String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := clone.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			for _, c := range []net.Conn{client, server} {
				if got := ingressSocketOpt(t, c.(*net.TCPConn), unix.IPPROTO_TCP, unix.TCP_MAXSEG); got <= 0 || got > 1380 {
					t.Fatalf("accepted MSS = %d", got)
				}
			}
		})
	}
}

func TestUDPIPv4FallbackHasNoTCPOptions(t *testing.T) {
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return udpIPv4ListenControl(raw) }}
	conn, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("TPROXY requires privilege: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	udp := conn.(*net.UDPConn)
	if ingressSocketOpt(t, udp, unix.IPPROTO_IP, unix.IP_TRANSPARENT) != 1 {
		t.Fatal("lost transparent UDP")
	}
	if ingressSocketOpt(t, udp, unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR) != 1 {
		t.Fatal("lost original destination")
	}
	sender, err := net.Dial("udp4", conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := sender.Write([]byte("udp-fallback")); err != nil {
		t.Fatal(err)
	}
	var b [64]byte
	n, _, err := conn.ReadFrom(b[:])
	if err != nil || string(b[:n]) != "udp-fallback" {
		t.Fatalf("UDP fallback data = %q, %v", b[:n], err)
	}
}
