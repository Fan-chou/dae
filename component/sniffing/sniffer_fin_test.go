package sniffing

import (
	"errors"
	"net"
	"testing"
	"time"
)

type eofAfterPartialConn struct {
	payload []byte
	served  bool
}

func (c *eofAfterPartialConn) Read(p []byte) (int, error) {
	if !c.served {
		c.served = true
		return copy(p, c.payload), nil
	}
	return 0, nil
}
func (c *eofAfterPartialConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *eofAfterPartialConn) Close() error                { return nil }
func (c *eofAfterPartialConn) LocalAddr() net.Addr         { return nil }
func (c *eofAfterPartialConn) RemoteAddr() net.Addr        { return nil }
func (c *eofAfterPartialConn) SetDeadline(time.Time) error { return nil }
func (c *eofAfterPartialConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *eofAfterPartialConn) SetWriteDeadline(time.Time) error { return nil }

// TestSniffTcpEndsOnCleanFinWithIncompleteHeaders: a peer that sends a partial
// header block and cleanly closes cannot deliver the missing bytes, so the
// sniff must end as not found instead of re-reading an unchanged buffer until
// the deadline.
func TestSniffTcpEndsOnCleanFinWithIncompleteHeaders(t *testing.T) {
	conn := &eofAfterPartialConn{payload: []byte("GET /path HTTP/1.1\r\nHost: exam")}
	sniffer := NewStreamSniffer(conn, 10*time.Second)
	start := time.Now()
	_, err := sniffer.SniffTcp()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound on a clean FIN with incomplete headers", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("sniff took %v; it must end at the FIN, not wait out the 10s deadline", elapsed)
	}
}
