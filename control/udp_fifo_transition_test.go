package control

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUdpFIFOTransitionProducerConsumer(t *testing.T) {
	q := &UdpTaskQueue{ch: make(chan UdpTask, UdpTaskQueueLength)}
	got := make(chan int, 1)
	q.enqueueMu.Lock()
	go func() {
		task, ok := q.popReadyTask()
		if !ok {
			got <- -1
			return
		}
		task.Run()
	}()
	// Stop the consumer precisely after its empty channel probe, at the
	// overflow lock. A producer can fill both tiers in this existing gap.
	blocked := false
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		buf := make([]byte, 65536)
		n := runtime.Stack(buf, true)
		if strings.Contains(string(buf[:n]), "(*UdpTaskQueue).popReadyTask(") {
			blocked = true
			break
		}
		runtime.Gosched()
	}
	if !blocked {
		q.enqueueMu.Unlock()
		<-got
		t.Fatal("consumer did not reach the overflow lock")
	}
	for i := 0; i < UdpTaskQueueLength; i++ {
		index := i
		q.ch <- udpTaskFunc(func() { got <- index })
	}
	q.overflowMode = true
	q.overflow = []UdpTask{udpTaskFunc(func() { got <- UdpTaskQueueLength })}
	q.enqueueMu.Unlock()
	first := <-got
	if first != 0 {
		t.Fatalf("FIFO transition violated: executed task %d while %d older tasks remain in channel", first, len(q.ch))
	}
}
