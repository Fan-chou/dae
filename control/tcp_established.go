// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/observation"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// establishedTCPTask owns the sockets and buffered readers after admission.
// It must never retain a control plane, its core, or a callback into either.
// All generation-dependent snapshots are prepared before adoptTCPFlow releases
// the generation's drain ticket. Only flow is assigned after that commit.
type establishedTCPTask struct {
	flow           *FlowRuntime
	ingress        net.Conn
	left, right    netproxy.Conn
	log            *logrus.Logger
	src, dst       netip.AddrPort
	target         string
	logFields      logrus.Fields
	offload        *tcpRelayOffloadRuntime
	captured       *observation.Flow
	trace          *observation.Trace
	scope          observation.Scope
	captureAllowed bool
	dns            *establishedTCPDNS
}

// fallback is only used by standalone private-manager callers. Process-owned
// DNS transports resolve the active controller per query and leave it nil.
type establishedTCPDNS struct {
	reader   *bufio.Reader
	first    *dnsmessage.Msg
	frameLen int
	routing  *bpfRoutingResult
	fallback *ControlPlane
}

var establishedTCPPanicCount atomic.Uint64

func runEstablishedTCPTask(task *establishedTCPTask) {
	defer func() {
		if recovered := recover(); recovered != nil {
			reportPacketPathPanic("tcp_conn", "established", &establishedTCPPanicCount, recovered)
		}
	}()
	if err := task.run(); err != nil && task.log != nil {
		task.log.Warnln("handleConn:", err)
	}
}

func (t *establishedTCPTask) run() (err error) {
	// Register lifecycle cleanup first so it also runs if capture/offload panics.
	defer closeEstablishedTCPFlow(t.right, t.flow)
	defer func() {
		if t.left != nil {
			_ = t.left.Close()
		} else if t.ingress != nil {
			_ = t.ingress.Close()
		}
	}()
	defer t.offload.close()
	if t.dns != nil {
		return t.dns.run(t)
	}

	t.flow.capture.Store(t.captured)
	start := time.Now()
	outcome := "relay_ended"
	facts := &observation.ErrorFacts{Class: "none", Stage: "relay"}
	if t.trace != nil {
		if t.captureAllowed {
			linked := "success"
			if t.captured == nil {
				linked = "unmeasured"
			}
			t.trace.Stage(t.scope, t.target, t.src.Addr().String(), "flow_link", start, linked, t.captured.EpisodeID())
		}
		defer func() {
			if t.flow.Context().Err() != nil {
				outcome = "canceled"
			}
			t.captured.Finish(outcome)
			if t.captureAllowed {
				t.trace.StageError(t.scope, t.target, t.src.Addr().String(), "relay_end", start, outcome, t.captured.EpisodeID(), facts)
			}
		}()
	}
	offloaded, reason, offloadErr := t.offload.run(t.flow.Context(), t.left, t.right, t.flow.recordDownload, t.flow.recordUpload, t.flow.offloadLiveAccounting())
	if offloadErr != nil {
		outcome = "offload_error"
		facts.Class, facts.Stage = observation.ErrorClass(offloadErr), "offload"
		return fmt.Errorf("handleTCP offloaded relay error: %w", offloadErr)
	}
	if t.log != nil && t.log.IsLevelEnabled(logrus.DebugLevel) {
		if !offloaded && reason != "" {
			logOffloadSkipRateLimited(t.log, reason)
		}
		if canResolveTCPRelayOffloadConn(t.right) && t.logFields != nil {
			t.logFields["ebpf_offload"] = offloaded
			if !offloaded && reason != "" && !isOffloadGloballyDisabledReason(reason) {
				t.logFields["ebpf_offload_reason"] = reason
			}
		}
		t.log.WithFields(t.logFields).Debugf("%v <-> %v", RefineSourceToShow(t.src, t.dst.Addr()), t.target)
	}
	if offloaded {
		facts.Stage = "offload"
		t.captured.Offloaded()
		return nil
	}
	t.captured.Userspace()
	err = relayEstablishedTCPFlow(t.flow, t.left, t.right, t.log, t.src, t.dst)
	facts.Class = observation.ErrorClass(err)
	if err != nil {
		outcome = "relay_error"
	}
	return err
}
