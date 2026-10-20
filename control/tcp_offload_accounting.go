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
// Download deliberately skips the first-byte (TTFB) observation: a periodic
// report time is not the time the first byte arrived, and feeding it to the
// dialer quality tracker would bias it. DownloadDone performs that
// observation once at session end instead, matching the behaviour before
// live reporting existed.
type tcpOffloadLiveAccounting struct {
	Upload       func(int64)
	Download     func(int64)
	DownloadDone func()
}

func (f *FlowRuntime) offloadLiveAccounting() *tcpOffloadLiveAccounting {
	if f == nil {
		return nil
	}
	return &tcpOffloadLiveAccounting{
		Upload:       f.recordUpload,
		Download:     f.recordDownloadBytes,
		DownloadDone: f.observeFirstByte,
	}
}
