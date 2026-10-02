// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"context"
	"errors"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/observation"
	"time"
)

func (c *ControlPlane) captureScope(res *proxyDialResult, host string) (observation.Scope, bool) {
	if host == "" && res != nil {
		host = res.SniffedDomain
	}
	s := observation.Scope{Site: host, Network: "unknown", Path: "unknown", PolicyEpoch: uint64(c.PolicyEpoch())}
	if res != nil {
		if res.SelectionNetworkTypeObj != nil {
			s.Network = res.SelectionNetworkTypeObj.StringWithoutDns()
		}
		if res.Outbound != nil {
			s.Group = res.Outbound.Name
		}
		if res.Dialer != nil && res.Dialer.Property() != nil {
			p := res.Dialer.Property()
			s.Node = p.Name + "\x00" + p.Link
			if p.Name == consts.OutboundDirect.String() && p.Link == "" {
				s.Path = "direct"
			} else if p.Link != "" {
				s.Path = "proxy"
			}
		}
	}
	return s, c.captureGroup == "" || c.captureGroup == s.Group
}
func (c *ControlPlane) startCapture(res *proxyDialResult, host string) *observation.Flow {
	return c.startCaptureLinked(res, host, nil, false)
}
func (c *ControlPlane) startCaptureLinked(res *proxyDialResult, host string, trace *observation.Trace, linked bool) *observation.Flow {
	if c.capture == nil || (linked && trace == nil) {
		return nil
	}
	scope, ok := c.captureScope(res, host)
	if !ok {
		return nil
	}
	var totals observation.Totals
	var counts func() (int64, uint64, bool)
	if res != nil && res.Dialer != nil {
		totals = res.Dialer.LoadTotals
		counts = res.Dialer.LoadCounts
	}
	if linked {
		return c.capture.StartLinked(scope, totals, trace, counts)
	}
	return c.capture.Start(scope, totals)
}
func (c *ControlPlane) captureRoute(res *proxyDialResult, host string, start time.Time, ctx context.Context, err error) {
	if c.capture == nil {
		return
	}
	scope, ok := c.captureScope(res, host)
	if !ok {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "route_error"
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			outcome = "canceled"
		}
	}
	c.capture.Route(scope, start, outcome)
}
func (c *ControlPlane) AdminCapture(after uint64) observation.Snapshot {
	return c.capture.Snapshot(after)
}

func (c *ControlPlane) captureStage(p *proxyDialParam, res *proxyDialResult, stage string, start time.Time, err error) {
	if p.captureTrace == nil {
		return
	}
	scope, ok := c.captureScope(res, p.Domain)
	if !ok {
		return
	}
	target := p.Dest.String()
	if res != nil {
		target = res.DialTarget
		if res.SniffedDomain != "" {
			scope.Site = res.SniffedDomain
		}
	}
	p.captureTrace.StageError(scope, target, p.Src.Addr().String(), stage, start, observation.ErrorOutcome(err), "", &observation.ErrorFacts{Class: observation.ErrorClass(err), Stage: stage})
}
func (c *ControlPlane) AdminEvidence(after uint64) observation.EvidenceSnapshot {
	return c.capture.EvidenceSnapshot(after)
}
