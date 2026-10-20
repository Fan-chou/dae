/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// tcpOffloadLiveAccounting lets an offloaded TCP relay report byte growth
// while it runs. The kernel moves the payload, so userspace only learns the
// totals from tcp_info; without periodic reports a flow shows zero traffic
// until it closes and the global rate history gets a single spike at the end.
//
// Download never measures time-to-first-byte: a periodic report time is not
// the time the first byte arrived (and session end is the flow lifetime),
// so feeding either to the dialer quality tracker would mark healthy dialers
// slow. The first non-zero report only confirms the first byte arrived, which
// happens within one report interval of it. Only the early-data drain before
// registration, which runs through the full recorder, yields a measured TTFB.
type tcpOffloadLiveAccounting struct {
	Upload   func(int64)
	Download func(int64)
}

func (f *FlowRuntime) offloadLiveAccounting() *tcpOffloadLiveAccounting {
	if f == nil {
		return nil
	}
	return &tcpOffloadLiveAccounting{
		Upload:   f.recordUpload,
		Download: f.recordDownloadLive,
	}
}
