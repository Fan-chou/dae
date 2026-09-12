package control

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// A bounded slow-reader regression for retry overcounting and pause recovery.
func TestTCPOffloadBacklogUsesAcceptedBytes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load/attach")
	}
	c := loadOffloadVerifyCollection(t)
	defer c.Close()
	fast := c.Maps["fast_sock"]
	sent := c.Maps["tcp_offload_sent"]
	h, name, err := attachTCPOffloadAccount(c.Programs["tcp_offload_sent_account"], c.Programs["tcp_offload_sent_account_kprobe"])
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	t.Log("hook", name)
	v, err := link.AttachRawLink(link.RawLinkOptions{Target: fast.FD(), Program: c.Programs["tcp_offload_redirect"], Attach: ebpf.AttachSkSKBStreamVerdict})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	pair := func() (*net.TCPConn, *net.TCPConn) {
		l, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		a, e := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
		if e != nil {
			t.Fatal(e)
		}
		b, e := l.AcceptTCP()
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { a.Close(); b.Close() })
		a.SetDeadline(time.Now().Add(25 * time.Second))
		b.SetDeadline(time.Now().Add(25 * time.Second))
		return a, b
	}
	client, left := pair()
	right, up := pair()
	right.SetWriteBuffer(32768)
	up.SetReadBuffer(32768)
	s, e := newTCPRelayOffloadSession(nil, fast, c.Maps["tcp_offload_pause"], sent, left, right, func(int64) {}, func(int64) {})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	done := make(chan error, 1)
	expected := sha256.New()
	go func() {
		chunk := make([]byte, 65536)
		for n := 0; n < 256; n++ {
			chunk[0] = byte(n)
			expected.Write(chunk)
			if _, e := client.Write(chunk); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	time.Sleep(500 * time.Millisecond)
	// A bogus entry counter must not make genuine unaccepted data disappear.
	count := make([]uint64, 1)
	cpus, e := ebpf.PossibleCPU()
	if e != nil {
		t.Fatal(e)
	}
	count = make([]uint64, cpus)
	count[0] = 1 << 30
	if e = sent.Update(&s.leftKey, count, ebpf.UpdateAny); e != nil {
		t.Fatal(e)
	}
	debt, e := s.offloadBacklog()
	if e != nil {
		t.Fatal(e)
	}
	if debt < 8<<20 {
		t.Fatalf("unaccepted backlog lost: %d", debt)
	}
	s.fused = true
	one := uint8(1)
	if e = s.pauseMap.Update(&s.leftKey, &one, ebpf.UpdateAny); e != nil {
		t.Fatal(e)
	}
	if e = s.pauseMap.Update(&s.rightKey, &one, ebpf.UpdateAny); e != nil {
		t.Fatal(e)
	}
	progress := time.Now()
	_, lift, e := s.fuseStep(&progress)
	if e != nil {
		t.Fatal(e)
	}
	if lift {
		t.Fatal("resumed with undelivered data")
	}
	t.Logf("blocked: backlog=%d despite bogus sent counter", debt)
	up.SetReadBuffer(1 << 20)
	actual := sha256.New()
	if n, e := io.CopyN(actual, up, 16<<20); e != nil {
		t.Fatalf("drain %d: %v", n, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(actual.Sum(nil), expected.Sum(nil)) {
		t.Fatal("payload checksum mismatch")
	}
	// SK_PASS bytes waiting in the bounded source queue must not keep
	// redirection paused after the original kernel tail has drained.
	if e = left.SetReadBuffer(4 << 20); e != nil {
		t.Fatal(e)
	}
	extra := bytes.Repeat([]byte{0x5a}, 2<<20)
	extraWrite := make(chan error, 1)
	go func() { _, e := client.Write(extra); extraWrite <- e }()
	until := time.Now().Add(3 * time.Second)
	for {
		n, e := tcpConnPendingBytes(left)
		if e != nil {
			t.Fatal(e)
		}
		if n >= len(extra) {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("SK_PASS input did not queue: %d", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	extraRead := make(chan error, 1)
	go func() {
		buf := make([]byte, len(extra))
		_, e := io.ReadFull(up, buf)
		if e == nil && !bytes.Equal(buf, extra) {
			e = fmt.Errorf("fallback payload mismatch")
		}
		extraRead <- e
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, lift, e = s.fuseStep(&progress)
		if e != nil {
			t.Fatal(e)
		}
		if lift {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("did not resume after drain")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e = <-extraWrite; e != nil {
		t.Fatal(e)
	}
	if e = <-extraRead; e != nil {
		t.Fatal(e)
	}
	t.Log("resumed after complete transfer including queued SK_PASS data")
}
