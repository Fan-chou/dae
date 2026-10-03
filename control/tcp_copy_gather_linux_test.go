//go:build linux

package control

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type gatherTestConn struct {
	reader io.Reader
	output bytes.Buffer
	write  func([]byte) (int, error)
}

func (c *gatherTestConn) Read(p []byte) (int, error) {
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}
func (c *gatherTestConn) Write(p []byte) (int, error) {
	if c.write != nil {
		return c.write(p)
	}
	return c.output.Write(p)
}
func (*gatherTestConn) Close() error                     { return nil }
func (*gatherTestConn) SetDeadline(time.Time) error      { return nil }
func (*gatherTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*gatherTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestWrappedGatherOrderAndBounds(t *testing.T) {
	large := bytes.Repeat([]byte{'L'}, relayCoalesceSegmentLimit+1)
	segments := [][]byte{[]byte("prefix"), nil, []byte("body"), large,
		bytes.Repeat([]byte{'a'}, 4096), bytes.Repeat([]byte{'b'}, 4096), []byte("tail")}
	var output bytes.Buffer
	var sizes []int
	dst := &gatherTestConn{write: func(p []byte) (int, error) {
		sizes = append(sizes, len(p))
		if len(p) == len(large) && &p[0] != &large[0] {
			t.Fatal("large segment copied")
		}
		return output.Write(p)
	}}
	want := bytes.Join(segments, nil)
	n, err := relayGatherWriteToWithOptions(dst, segments, true)
	if err != nil || n != len(want) || !bytes.Equal(output.Bytes(), want) {
		t.Fatalf("order/accounting: written=%d err=%v", n, err)
	}
	if !equalGatherSizes(sizes, []int{10, len(large), 8192, 4}) {
		t.Fatalf("write sizes=%v", sizes)
	}
}

func equalGatherSizes(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWrappedGatherPartialWritesStopAtActualBytes(t *testing.T) {
	failure := errors.New("transport failed")
	for _, tc := range []struct {
		name      string
		n         int
		err, want error
	}{
		{"partial-error", 3, failure, failure},
		{"partial-nil", 3, nil, io.ErrShortWrite},
		{"zero-nil", 0, nil, io.ErrShortWrite},
		{"full-error", 8, failure, failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			dst := &gatherTestConn{write: func(p []byte) (int, error) {
				calls++
				if string(p) != "headbody" {
					t.Fatalf("payload=%q", p)
				}
				return tc.n, tc.err
			}}
			n, err := relayGatherWriteToWithOptions(dst, [][]byte{[]byte("head"), []byte("body"), bytes.Repeat([]byte{'x'}, 8193)}, true)
			if n != tc.n || !errors.Is(err, tc.want) || calls != 1 {
				t.Fatalf("written=%d err=%v calls=%d", n, err, calls)
			}
		})
	}
}

func TestWrappedGatherDefaultAndInvalidEnvironment(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{{"", false}, {"false", false}, {"true", true}, {"invalid", false}} {
		t.Setenv("DAE_TCP_WRAPPED_GATHER", tc.value)
		if got := relayWrappedGatherFromEnv(); got != tc.want {
			t.Fatalf("%q: %v", tc.value, got)
		}
	}
	for _, enabled := range []bool{false, true} {
		calls := 0
		dst := &gatherTestConn{write: func(p []byte) (int, error) { calls++; return len(p), nil }}
		_, err := relayGatherWriteToWithOptions(dst, [][]byte{[]byte("head"), []byte("body")}, enabled)
		want := 2
		if enabled {
			want = 1
		}
		if err != nil || calls != want {
			t.Fatalf("enabled=%v calls=%d err=%v", enabled, calls, err)
		}
	}
}

type gatherPrefixTestConn struct {
	gatherTestConn
	prefix []byte
}

func (c *gatherPrefixTestConn) TakeRelayPrefix() []byte {
	p := c.prefix
	c.prefix = nil
	return p
}

func TestGatherCanceledContextKeepsPrefix(t *testing.T) {
	src := &gatherPrefixTestConn{prefix: []byte("head")}
	dst := &gatherTestConn{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err, handled := tryRelayGatherWrite(ctx, dst, src, nil, nil)
	if n != 0 || !errors.Is(err, context.Canceled) || !handled || string(src.prefix) != "head" || dst.output.Len() != 0 {
		t.Fatalf("written=%d err=%v handled=%v prefix=%q", n, err, handled, src.prefix)
	}
}

func TestGatherPartialFailureCountsOnce(t *testing.T) {
	src := &gatherPrefixTestConn{prefix: []byte("head")}
	failure := errors.New("write failed")
	dst := &gatherTestConn{write: func([]byte) (int, error) { return 2, failure }}
	var count int64
	calls := 0
	n, err, handled := tryRelayGatherWrite(context.Background(), dst, src, func(n int64) { count += n; calls++ }, nil)
	if n != 2 || count != 2 || calls != 1 || !errors.Is(err, failure) || !handled {
		t.Fatalf("written=%d count=%d calls=%d err=%v handled=%v", n, count, calls, err, handled)
	}
}

type gatherSegmentsTestConn struct {
	gatherTestConn
	segments [][]byte
}

func (c *gatherSegmentsTestConn) TakeRelaySegments() [][]byte {
	p := c.segments
	c.segments = nil
	return p
}

func TestGatherCandidateCountsWrittenPrefixAndContinuationOnce(t *testing.T) {
	old := relayWrappedGatherEnabled
	relayWrappedGatherEnabled = true
	t.Cleanup(func() { relayWrappedGatherEnabled = old })
	src := &gatherSegmentsTestConn{
		gatherTestConn: gatherTestConn{reader: bytes.NewReader([]byte("tail"))},
		segments:       [][]byte{[]byte("head"), []byte("body")},
	}
	var output bytes.Buffer
	writes := 0
	dst := &gatherTestConn{write: func(p []byte) (int, error) {
		writes++
		return output.Write(p)
	}}
	var counts []int64
	n, err, handled := tryRelayGatherWrite(context.Background(), dst, src, func(n int64) { counts = append(counts, n) }, nil)
	if err != nil || !handled || n != 12 || output.String() != "headbodytail" || writes != 2 || len(counts) != 2 || counts[0] != 8 || counts[1] != 4 {
		t.Fatalf("written=%d counts=%v writes=%d output=%q err=%v", n, counts, writes, output.String(), err)
	}
}

type gatherBlockingTestConn struct {
	gatherTestConn
	closed chan struct{}
	once   sync.Once
}

func (c *gatherBlockingTestConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *gatherBlockingTestConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestGatherCandidateRelayCancellationUnblocksPartialWrite(t *testing.T) {
	old := relayWrappedGatherEnabled
	relayWrappedGatherEnabled = true
	t.Cleanup(func() { relayWrappedGatherEnabled = old })
	src := &gatherSegmentsTestConn{segments: [][]byte{[]byte("head"), []byte("body")}}
	entered := make(chan []byte, 1)
	dst := &gatherBlockingTestConn{closed: make(chan struct{})}
	defer dst.Close()
	dst.write = func(p []byte) (int, error) {
		entered <- bytes.Clone(p)
		<-dst.closed
		return 2, net.ErrClosed
	}
	var up, down atomic.Int64
	core := newRelayCore(src, dst, defaultRelayCopyEngine{}, func(n int64) { up.Add(n) }, func(n int64) { down.Add(n) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- core.run(ctx) }()
	select {
	case p := <-entered:
		if string(p) != "headbody" || up.Load() != 0 || down.Load() != 0 {
			t.Fatalf("payload=%q up=%d down=%d", p, up.Load(), down.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("coalesced write did not block")
	}
	cancel()
	select {
	case <-done:
		if up.Load()+down.Load() != 2 || up.Load()*down.Load() != 0 {
			t.Fatalf("actual written count: up=%d down=%d", up.Load(), down.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("relay cancellation did not release the coalesced write")
	}
}

// The prefix aliases bufio's buffer. Refilling a reader larger than the copy
// buffer must not replace the prefix before its synchronous write completes.
func TestGatherLargeBufioPrefixSurvivesPendingReadAndHalfClose(t *testing.T) {
	for _, size := range []int{4096, 65536} {
		t.Run(stringSize(size), func(t *testing.T) {
			relay, peer := offloadTCPPair(t)
			if err := relay.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			prefix := bytes.Repeat([]byte{'P'}, 128)
			body := bytes.Repeat([]byte{'B'}, 1024)
			if _, err := peer.Write(prefix); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReaderSize(relay, size)
			if _, err := reader.Peek(len(prefix)); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write(body); err != nil {
				t.Fatal(err)
			}
			if err := peer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for {
				pending, err := tcpConnHasPendingReadData(relay)
				if err != nil {
					t.Fatal(err)
				}
				if pending {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("body did not reach source socket")
				}
				time.Sleep(time.Millisecond)
			}
			dst := &gatherTestConn{}
			var count int64
			n, err, handled := tryRelayGatherWrite(context.Background(), dst, &bufioConn{Conn: relay, reader: reader}, func(n int64) { count += n }, nil)
			want := append(prefix, body...)
			if err != nil || !handled || n != int64(len(want)) || count != n || !bytes.Equal(dst.output.Bytes(), want) {
				t.Fatalf("prefix/half-close/accounting: written=%d count=%d err=%v", n, count, err)
			}
		})
	}
}

func stringSize(size int) string {
	if size == 4096 {
		return "4KiB"
	}
	return "64KiB"
}

func TestRelayReadActivityPrecedesBlockedWrite(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(map[bool]string{false: "loop", true: "direct"}[direct], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			var activity, count atomic.Int64
			dst := &gatherTestConn{write: func(p []byte) (int, error) { close(entered); <-release; return len(p), nil }}
			src := &gatherTestConn{reader: bytes.NewReader([]byte("body"))}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				copyFn := relayCopyLoop
				var err error
				if direct {
					_, err = relayCopyDirect(ctx, dst, src, make([]byte, 32), func(n int64) { count.Add(n) }, func(n int64) { activity.Add(n) })
				} else {
					_, err = copyFn(ctx, dst, src, make([]byte, 32), func(n int64) { count.Add(n) }, func(n int64) { activity.Add(n) })
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("writer did not block")
			}
			if activity.Load() != 4 || count.Load() != 0 {
				t.Fatalf("read activity=%d written count=%d", activity.Load(), count.Load())
			}
			cancel()
			// A canceled copy cannot interrupt a generic writer until the owning
			// relay closes/nudges it. Release here models that transport wakeup.
			release <- struct{}{}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) || count.Load() != 4 {
					t.Fatalf("err=%v count=%d", err, count.Load())
				}
			case <-time.After(time.Second):
				t.Fatal("copy did not return after canceled writer released")
			}
		})
	}
}

type gatherRawTestConn struct{ polls int }

func (*gatherRawTestConn) Control(f func(uintptr)) error   { f(1); return nil }
func (*gatherRawTestConn) Read(f func(uintptr) bool) error { return nil }
func (c *gatherRawTestConn) Write(f func(uintptr) bool) error {
	for i := 0; i < 10; i++ {
		c.polls++
		if f(1) {
			return nil
		}
	}
	return errors.New("write polling did not finish")
}

func TestGatherWritevPartialRetryAndRawTCPPreference(t *testing.T) {
	old := relayWritevFunc
	t.Cleanup(func() { relayWritevFunc = old })
	call := 0
	var got bytes.Buffer
	relayWritevFunc = func(_ int, p [][]byte) (int, error) {
		call++
		switch call {
		case 1:
			return 0, syscall.EINTR
		case 2:
			return 0, syscall.EAGAIN
		case 3:
			got.Write(p[0][:2])
			return 2, nil
		default:
			n := 0
			for _, s := range p {
				got.Write(s)
				n += len(s)
			}
			return n, nil
		}
	}
	raw := &gatherRawTestConn{}
	n, err := relayWritevAll(raw, [][]byte{[]byte("head"), []byte("body")})
	if err != nil || n != 8 || got.String() != "headbody" || raw.polls != 2 {
		t.Fatalf("written=%d err=%v polls=%d output=%q", n, err, raw.polls, got.String())
	}
	relayWritevFunc = old
	relay, peer := offloadTCPPair(t)
	writevCalls := 0
	relayWritevFunc = func(fd int, p [][]byte) (int, error) { writevCalls++; return old(fd, p) }
	if _, err := relayGatherWriteToWithOptions(relay, [][]byte{[]byte("head"), []byte("body")}, true); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 8)
	if _, err := io.ReadFull(peer, p); err != nil {
		t.Fatal(err)
	}
	if writevCalls == 0 || string(p) != "headbody" {
		t.Fatalf("writev calls=%d output=%q", writevCalls, p)
	}
}
