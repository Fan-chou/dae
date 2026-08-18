/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

func TestChooseDialTargetNilDnsController(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	plane := &ControlPlane{
		log:                           logrus.New(),
		ctx:                           ctx,
		controlPlaneGenerationState:   controlPlaneGenerationState{dialMode: consts.DialMode_Domain},
		controlPlaneRealDomainRuntime: newControlPlaneRealDomainRuntime(),
	}
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	target, shouldReroute, dialIP := plane.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, "example.com")
	if target != dst.String() {
		t.Fatalf("dial target = %q, want %q", target, dst.String())
	}
	if shouldReroute {
		t.Fatal("shouldReroute = true, want false when DNS controller is nil")
	}
	if !dialIP {
		t.Fatal("dialIp = false, want true when DNS controller is nil")
	}
}

func TestChooseDialTargetUsesActiveDnsControllerKnowledge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	controller := newTestDnsController()
	dst := netip.MustParseAddrPort("203.0.113.10:443")
	key := controller.cacheKey("example.com", common.AddrToDnsType(dst.Addr()))
	controller.dnsKnowledge.Store(key, dnsKnowledgeEntry{
		expiresAt:  time.Now().Add(time.Hour).UnixNano(),
		cacheCount: 1,
	})

	plane := &ControlPlane{
		log:                           logrus.New(),
		ctx:                           ctx,
		controlPlaneGenerationState:   controlPlaneGenerationState{dialMode: consts.DialMode_Domain},
		controlPlaneDNSRuntime:        controlPlaneDNSRuntime{dnsController: controller},
		controlPlaneRealDomainRuntime: newControlPlaneRealDomainRuntime(),
	}
	target, shouldReroute, dialIP := plane.ChooseDialTarget(consts.OutboundUserDefinedMin, dst, "example.com")
	if target != "example.com:443" {
		t.Fatalf("dial target = %q, want example.com:443", target)
	}
	if !shouldReroute {
		t.Fatal("shouldReroute = false, want true when DNS knowledge exists")
	}
	if dialIP {
		t.Fatal("dialIp = true, want false for a real domain")
	}
}
