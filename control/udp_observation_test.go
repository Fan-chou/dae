package control

import (
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
	"time"
)

func TestUDPOverloadObservesActiveWriteAndClearsReference(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ue := newTestEndpoint(&observedWritePacketConn{mockPacketConn: &mockPacketConn{writeToFn: func(b []byte, _ string) (int, error) { close(entered); <-release; return len(b), nil }}})
	ue.Dialer = newNamedTestEndpointDialer("direct")
	q := &UdpTaskQueue{ch: make(chan UdpTask, 1), key: NewUdpFlowKey(netip.MustParseAddrPort("192.0.2.1:1000"), netip.MustParseAddrPort("192.0.2.2:443"))}
	d := UdpFlowDecision{observationQueue: q}
	go func() { defer close(done); _, _ = d.writeTo(ue, []byte("a"), q.key.Dst.String()) }()
	<-entered
	udpLastOverloadAt.Store(0)
	recordUDPOverload(q, "packet_limit")
	e := udpLastOverload.Load()
	require.Equal(t, int32(3), e.ActiveStage)
	require.Equal(t, &udpTransportWriteState{LockWaiters: 1, LockHeld: true, DatagramPending: 256}, e.TransportWrite)
	require.Equal(t, "direct", e.Dialer)
	require.NotEmpty(t, e.Endpoint)
	require.GreaterOrEqual(t, e.WriteCallMilliseconds, float64(0))
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("write did not finish")
	}
	require.Nil(t, q.activeEndpoint.Load())
	require.Zero(t, q.writeCallStarted.Load())
}

func TestUDPReplyOverloadRecordsConsumerStage(t *testing.T) {
	ue := newTestEndpoint(&mockPacketConn{})
	ue.replyQueueCh = make(chan *udpEndpointReply, 1)
	from := netip.MustParseAddrPort("192.0.2.2:443")
	ue.observeReplyStage(udpReplySocketWrite)
	require.True(t, ue.enqueueReceivedReply([]byte("first"), from, nil))
	released := false
	udpLastReplyOverloadAt.Store(0)
	require.True(t, ue.enqueueReceivedReply([]byte("overflow"), from, func() { released = true }))
	require.True(t, released)
	e := udpLastReplyOverload.Load()
	require.Equal(t, "socket_write", e.Stage)
	require.Equal(t, 1, e.Pending)
	recycleUdpEndpointReply(<-ue.replyQueueCh, false)
}

type observedWritePacketConn struct{ *mockPacketConn }

func (*observedWritePacketConn) UDPWriteState() (int32, bool, int) { return 1, true, 256 }
