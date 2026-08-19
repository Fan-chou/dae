/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import "testing"

func TestEnablesHealthCheckIgnoresLazyAlone(t *testing.T) {
	if (Group{Lazy: true}).EnablesHealthCheck() {
		t.Fatal("lazy: true must not enable a parent health layer")
	}
	if (Group{LazySet: true}).EnablesHealthCheck() {
		t.Fatal("lazy: false (LazySet) must not enable a parent health layer")
	}
}

func TestEnablesHealthCheckStillTrueForProbeSettings(t *testing.T) {
	if !(Group{TcpCheckUrl: []string{"http://cp.cloudflare.com"}}).EnablesHealthCheck() {
		t.Fatal("tcp_check_url must enable health checks")
	}
	if !(Group{CheckIntervalSet: true}).EnablesHealthCheck() {
		t.Fatal("explicit check_interval must enable health checks")
	}
}
