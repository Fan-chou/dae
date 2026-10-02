/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"time"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/quality"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
)

// Deliberately exposes only netproxy.Conn: the observed userspace relay must
// write through this method. Kernel offload is attempted before wrapping.
type qualityWriteConn struct {
	netproxy.Conn
	flow *outbound.QualityFlow
}

func (c *qualityWriteConn) Write(p []byte) (int, error) {
	if !c.flow.MeasureWrites() {
		n, err := c.Conn.Write(p)
		c.flow.ObserveWrite(n, 0)
		return n, err
	}
	start := time.Now()
	n, err := c.Conn.Write(p)
	c.flow.ObserveWrite(n, time.Since(start))
	return n, err
}
func (c *qualityWriteConn) CloseWrite() error { closeWriteRelayConn(c.Conn); return nil }

func localQualityOptions(g config.Group, w *quality.ModelWorker) outbound.QualityOptions {
	if g.QualityMode == "" || g.QualityMode == "off" {
		return outbound.QualityOptions{}
	}
	p, err := g.SpeedPolicy()
	if err != nil {
		return outbound.QualityOptions{}
	}
	o := outbound.QualityOptions{Mode: g.QualityMode, Policy: p, RequiredDownloadBytes: float64(g.QualityRequiredDownloadBytes), MinDownloadBytes: float64(g.QualityMinDownloadBytes)}
	if w != nil {
		o.Report = w.Submit
	}
	return o
}

// Only the downstream copy is measured; upstream prefix/splice capabilities and
// the relay core's half-close handling retain the original connections.
type qualityRelayCopyEngine struct {
	ingress netproxy.Conn
	flow    *outbound.QualityFlow
}

func (e qualityRelayCopyEngine) Copy(ctx context.Context, dst, src netproxy.Conn, record, onActive func(int64)) (int64, error) {
	if dst == e.ingress && !shouldUseRelayFastPath(dst, src) {
		dst = &qualityWriteConn{Conn: dst, flow: e.flow}
	}
	return (defaultRelayCopyEngine{}).Copy(ctx, dst, src, record, onActive)
}
