/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestHysteria2ClonePreservesSalamanderObfs(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     30 * time.Second,
	}
	src, err := dialer.NewFromLink(option, dialer.InstanceOption{DisableCheck: true},
		"hysteria2://user:pass@127.0.0.1:443?obfs=salamander&obfs-password=secret1#hy2-a", "")
	if err != nil {
		t.Fatalf("NewFromLink() error = %v", err)
	}
	defer src.Close()

	link := src.Property().Link
	if !strings.Contains(link, "obfs=salamander") || !strings.Contains(link, "obfs-password=secret1") {
		t.Fatalf("Property.Link = %q, want salamander obfs fields", link)
	}

	clone := src.Clone()
	defer clone.Close()
	clonedLink := clone.Property().Link
	if !strings.Contains(clonedLink, "obfs=salamander") || !strings.Contains(clonedLink, "obfs-password=secret1") {
		t.Fatalf("cloned Property.Link = %q, want salamander obfs fields", clonedLink)
	}

	other, err := dialer.NewFromLink(option, dialer.InstanceOption{DisableCheck: true},
		"hysteria2://user:pass@127.0.0.1:443?obfs=salamander&obfs-password=secret2#hy2-b", "")
	if err != nil {
		t.Fatalf("NewFromLink() other error = %v", err)
	}
	defer other.Close()
	if healthDialerIdentity(src) == healthDialerIdentity(other) {
		t.Fatalf("nodes that differ only in obfs-password share cache identity %q", healthDialerIdentity(src))
	}
}
