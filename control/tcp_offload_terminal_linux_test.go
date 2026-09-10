//go:build linux

package control

import (
	"errors"
	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"testing"
	"time"
)

// The deliberately consumed, unforwarded bytes model the observed counter
// deficit, not the historical packet-loss mechanism that produced it.
func TestTCPOffloadTerminalSourceDebt(t *testing.T) {
	left, client := offloadTCPPair(t)
	server, right := offloadTCPPair(t)
	for _, c := range []*net.TCPConn{left, client, server, right} {
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	}
	lr, lt, err := tcpOffloadBaseline(left)
	require.NoError(t, err)
	rr, rt, err := tcpOffloadBaseline(right)
	require.NoError(t, err)
	_, err = client.Write([]byte("terminal unforwarded tail"))
	require.NoError(t, err)
	require.NoError(t, client.CloseWrite())
	_, err = io.ReadAll(left)
	require.NoError(t, err)
	require.NoError(t, server.CloseWrite())
	_, err = io.ReadAll(right)
	require.NoError(t, err)
	require.NoError(t, left.CloseWrite())
	_, err = io.ReadAll(client)
	require.NoError(t, err)
	require.Eventually(t, func() bool { info, err := tcpConnInfo(left); return err == nil && info.State == 7 }, time.Second, time.Millisecond)
	s := &tcpRelayOffloadSession{left: left, right: right, leftRxBase: lr, rightRxBase: rr, txBase: [2]uint64{lt, rt}, finSent: 2, fastSock: &ebpf.Map{}}
	require.NoError(t, s.propagateFIN(3), "do not close at the first observation")
	require.Eventually(t, func() bool {
		err := s.propagateFIN(3)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("propagate FIN: %v", err)
		}
		return errors.Is(err, net.ErrClosed)
	}, 2*time.Second, 10*time.Millisecond)
}

func TestTCPTerminalDebtProgressResetsWindow(t *testing.T) {
	var o tcpTerminalDebtObservation
	now := time.Now()
	require.False(t, o.observe(now, true, 100, 20))
	require.False(t, o.observe(now.Add(900*time.Millisecond), true, 100, 21))
	require.False(t, o.observe(now.Add(time.Second), true, 100, 21))
	require.False(t, o.observe(now.Add(2*time.Second), false, 100, 21))
	require.False(t, o.observe(now.Add(3*time.Second), true, 100, 21))
	require.True(t, o.observe(now.Add(4*time.Second), true, 100, 21))
}
