package control

import "runtime"

// Account across short reads as well as full batches. Otherwise a perpetually
// readable socket can fill per-flow queues before runnable consumers execute.
// Only the ingress reader owns this budget; no queue locks are held on yield.
type udpIngressScheduleBudget uint32

func (b *udpIngressScheduleBudget) packetHandled() {
	*b++
	if *b >= 64 {
		*b = 0
		runtime.Gosched()
	}
}
