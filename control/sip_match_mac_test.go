/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/sirupsen/logrus"
)

func newTestControlPlaneWithSipMatchMac(t *testing.T, cidr string) *ControlPlane {
	t.Helper()

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_SourceIp,
					Params: []*config_parser.Param{
						{Key: consts.RoutingSipKey_MatchMac, Val: cidr},
					},
				},
			},
			Outbound: config_parser.Function{Name: "block"},
		},
	}

	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		rules,
		map[string]uint8{
			"direct": uint8(consts.OutboundDirect),
			"block":  uint8(consts.OutboundBlock),
		},
		nil,
		config.FunctionOrString("direct"),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder(%q): %v", cidr, err)
	}

	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace(%q): %v", cidr, err)
	}

	return &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: matcher}}
}

func TestSipMatchMacExtendsToLearnedIP(t *testing.T) {
	plane := newTestControlPlaneWithSipMatchMac(t, "192.0.2.10/32")
	mac, err := common.ParseMac("02:42:ac:11:00:02")
	if err != nil {
		t.Fatalf("ParseMac: %v", err)
	}
	learned := netip.MustParseAddr("192.0.2.10").As16()
	plane.routingMatcher.lookupMacAssoc = func(got [6]byte) []string {
		if got != mac {
			return nil
		}
		return []string{trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(learned), 128))}
	}

	src := netip.MustParseAddrPort("198.51.100.20:12345")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	outbound, _, _, err := plane.Route(src, dst, "", consts.L4ProtoType_TCP, &bpfRoutingResult{Mac: mac})
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if outbound != consts.OutboundBlock {
		t.Fatalf("outbound = %v, want block for learned MAC association", outbound)
	}
}

func TestSipMatchMacWithoutMACFallsBackToSip(t *testing.T) {
	plane := newTestControlPlaneWithSipMatchMac(t, "192.0.2.10/32")
	plane.routingMatcher.lookupMacAssoc = func([6]byte) []string {
		t.Fatal("lookup should not run for zero MAC")
		return nil
	}

	src := netip.MustParseAddrPort("198.51.100.20:12345")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	outbound, _, _, err := plane.Route(src, dst, "", consts.L4ProtoType_TCP, &bpfRoutingResult{})
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if outbound != consts.OutboundDirect {
		t.Fatalf("outbound = %v, want direct when source IP is outside CIDR and MAC is empty", outbound)
	}
}

func TestSipMatchMacDirectSipStillMatches(t *testing.T) {
	plane := newTestControlPlaneWithSipMatchMac(t, "192.0.2.10/32")
	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	outbound, _, _, err := plane.Route(src, dst, "", consts.L4ProtoType_TCP, &bpfRoutingResult{})
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if outbound != consts.OutboundBlock {
		t.Fatalf("outbound = %v, want block for sip in CIDR", outbound)
	}
}

func TestSipRejectsUnknownKey(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_SourceIp,
					Params: []*config_parser.Param{
						{Key: "nope", Val: "192.0.2.10/32"},
					},
				},
			},
			Outbound: config_parser.Function{Name: "block"},
		},
	}
	_, err := NewRoutingMatcherBuilder(
		logrus.New(),
		rules,
		map[string]uint8{
			"direct": uint8(consts.OutboundDirect),
			"block":  uint8(consts.OutboundBlock),
		},
		nil,
		config.FunctionOrString("direct"),
	)
	if err == nil {
		t.Fatal("expected unknown sip key to fail")
	}
}
