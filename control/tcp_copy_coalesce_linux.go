//go:build linux

package control

import (
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const (
	relayCoalesceSegmentLimit = 4 << 10
	relayCoalesceBufferSize   = 8 << 10
)

// This process-scoped experiment defaults off. It only joins already available
// adjacent small segments; it never waits for another read or retains data.
var relayWrappedGatherEnabled = relayWrappedGatherFromEnv()

func relayWrappedGatherFromEnv() bool {
	raw := os.Getenv("DAE_TCP_WRAPPED_GATHER")
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		logrus.StandardLogger().Warnf("invalid DAE_TCP_WRAPPED_GATHER=%q, using false", raw)
		return false
	}
	return enabled
}

var relayCoalescePool = sync.Pool{New: func() any { return new([relayCoalesceBufferSize]byte) }}

func relayCoalesceWrappedWrite(dst netproxy.Conn, segments [][]byte) (written int, err error) {
	var scratch *[relayCoalesceBufferSize]byte
	defer func() {
		if scratch != nil {
			relayCoalescePool.Put(scratch)
		}
	}()
	for i := 0; i < len(segments); {
		if len(segments[i]) == 0 {
			i++
			continue
		}
		end, total := i, 0
		for end < len(segments) {
			size := len(segments[end])
			if size > relayCoalesceSegmentLimit || size > relayCoalesceBufferSize-total {
				break
			}
			total += size
			end++
		}
		data := segments[i]
		next := i + 1
		if end > i+1 {
			if scratch == nil {
				scratch = relayCoalescePool.Get().(*[relayCoalesceBufferSize]byte)
			}
			data = scratch[:total]
			offset := 0
			for _, segment := range segments[i:end] {
				offset += copy(data[offset:], segment)
			}
			next = end
		}
		n, err := dst.Write(data)
		written += n
		if err != nil {
			return written, err
		}
		if n != len(data) {
			return written, io.ErrShortWrite
		}
		i = next
	}
	return written, nil
}
