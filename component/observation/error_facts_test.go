// SPDX-License-Identifier: AGPL-3.0-only
package observation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

func TestErrorClassWrappedAndOpaque(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "none"}, {context.Canceled, "canceled"}, {context.DeadlineExceeded, "timeout"},
		{fmt.Errorf("private target: %w", syscall.ECONNRESET), "connection_reset"},
		{&net.OpError{Op: "dial", Err: syscall.ENETUNREACH}, "network_unreachable"},
		{syscall.EHOSTUNREACH, "host_unreachable"}, {syscall.ECONNREFUSED, "connection_refused"},
		{syscall.EPIPE, "broken_pipe"}, {net.ErrClosed, "closed"},
		{errors.New("connection reset by peer secret.example"), "unknown"},
	} {
		if got := ErrorClass(tc.err); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}
