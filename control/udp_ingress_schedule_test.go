package control

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/stretchr/testify/require"
)

type ingressBurstTask struct {
	packet    pool.PB
	delivered chan<- uint32
}

func (t ingressBurstTask) Run()     { t.delivered <- binary.BigEndian.Uint32(t.packet); t.packet.Put() }
func (t ingressBurstTask) Discard() { t.packet.Put() }

func TestUDPIngressScheduleDeliversSocketBurst(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return enableUDPDualStackSocket(raw) }}
	pc, err := lc.ListenPacket(context.Background(), "udp6", "[::]:0")
	require.NoError(t, err)
	defer pc.Close()
	conn := pc.(*net.UDPConn)
	require.NoError(t, conn.SetReadBuffer(1<<20))
	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: conn.LocalAddr().(*net.UDPAddr).Port})
	require.NoError(t, err)
	defer sender.Close()
	tasks := NewUdpTaskPool()
	defer tasks.Close()
	key := NewUdpFlowKey(sender.LocalAddr().(*net.UDPAddr).AddrPort(), conn.LocalAddr().(*net.UDPAddr).AddrPort())
	ready := make(chan struct{})
	require.True(t, tasks.EmitTask(key, udpTaskFunc(func() { close(ready) })))
	<-ready
	const total = 200
	for i := 0; i < total; i++ {
		b := make([]byte, 38)
		binary.BigEndian.PutUint32(b, uint32(i))
		_, err = sender.Write(b)
		require.NoError(t, err)
	}
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	reader := newUDPIngressBatchReader(conn, 0)
	defer reader.Close()
	delivered := make(chan uint32, total)
	var budget udpIngressScheduleBudget
	received := 0
	for received < total {
		n, err := reader.ReadBatch()
		require.NoError(t, err)
		for i := 0; i < n; i++ {
			b, _, _, ok := reader.Take(i)
			require.True(t, ok)
			received++
			require.True(t, tasks.EmitTask(key, ingressBurstTask{b, delivered}))
			budget.packetHandled()
		}
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for i := 0; i < total; i++ {
		select {
		case id := <-delivered:
			require.Equal(t, uint32(i), id)
		case <-deadline.C:
			t.Fatalf("only %d/%d packets delivered", i, total)
		}
	}
}
