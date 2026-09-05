/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/daedns"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func TestParseGroupOverrideOptionWithRuntimePreservesGenerationDependencies(t *testing.T) {
	router := &daedns.Router{}
	directDialers := direct.NewDirectDialers("1.1.1.1:53")
	systemDNSResolver := netutils.NewSystemDNSResolver(netip.MustParseAddrPort("1.1.1.1:53"))
	src := &componentdialer.GlobalOption{
		DaeDNS:                  router,
		TransportCacheNamespace: "reload-generation-1",
	}
	src.SetRuntimeDependencies(directDialers.Symmetric, directDialers.Fullcone, systemDNSResolver)

	dst, err := parseGroupOverrideOptionWithRuntime(config.Group{
		CheckInterval: time.Minute,
	}, config.Global{}, logrus.New(), src)
	if err != nil {
		t.Fatalf("parseGroupOverrideOptionWithRuntime() error = %v", err)
	}
	if dst == nil {
		t.Fatal("expected group override option")
	}

	if dst.DaeDNS != router {
		t.Fatal("group override dropped dae DNS router")
	}
	if dst.TransportCacheNamespace != src.TransportCacheNamespace {
		t.Fatalf("TransportCacheNamespace = %q, want %q", dst.TransportCacheNamespace, src.TransportCacheNamespace)
	}
	if dst.DirectDialer != directDialers.Symmetric || dst.FullconeDirectDialer != directDialers.Fullcone {
		t.Fatal("group override dropped generation-scoped direct dialers")
	}
	if dst.SystemDNSResolver != systemDNSResolver {
		t.Fatal("group override dropped generation-scoped system DNS resolver")
	}
	if dst.TcpCheckOptionRaw.DirectDialer != directDialers.Symmetric || dst.TcpCheckOptionRaw.SystemDNSResolver != systemDNSResolver {
		t.Fatal("group override dropped TCP check runtime dependencies")
	}
	if dst.CheckDnsOptionRaw.DirectDialer != directDialers.Symmetric || dst.CheckDnsOptionRaw.SystemDNSResolver != systemDNSResolver {
		t.Fatal("group override dropped DNS check runtime dependencies")
	}
}

func TestParseGroupOverrideOptionPreservesExplicitZeroDurations(t *testing.T) {
	global := config.Global{
		CheckInterval:  30 * time.Second,
		CheckTolerance: 250 * time.Millisecond,
	}
	option, err := ParseGroupOverrideOption(config.Group{
		CheckIntervalSet:  true,
		CheckToleranceSet: true,
	}, global, logrus.New())
	if err != nil {
		t.Fatalf("ParseGroupOverrideOption() error = %v", err)
	}
	if option == nil {
		t.Fatal("expected explicit zero duration override")
	}
	if option.CheckInterval != 0 || option.CheckTolerance != 0 {
		t.Fatalf("override durations = %v/%v, want zero/zero", option.CheckInterval, option.CheckTolerance)
	}
}
