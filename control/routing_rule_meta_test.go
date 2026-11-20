/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestRoutingMatcherAttributesUserspaceAndOrderedAndFallbackRules(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: example.com) -> proxy
ip(192.0.2.0/24) -> direct
fallback: direct`, []string{"proxy"})

	_, _, _, matchIdx, err := m.MatchInboundWithRule(
		0,
		netip.MustParseAddr("192.168.1.2").As16(),
		netip.MustParseAddr("198.51.100.1").As16(),
		12345,
		443,
		consts.IpVersion_4,
		consts.L4ProtoType_TCP,
		"api.example.com",
		[16]byte{},
		0,
		[16]byte{},
	)
	if err != nil {
		t.Fatal(err)
	}
	meta := m.RuleMetaForMatchIndex(matchIdx)
	if meta == nil || meta.Index != 1 || meta.Origin != "config" || meta.MatchIndex != matchIdx {
		t.Fatalf("unexpected rule meta for domain match: %+v (idx=%d)", meta, matchIdx)
	}
	if meta.Raw != "domain(suffix:example.com) -> proxy" {
		t.Fatalf("unexpected raw summary: %q", meta.Raw)
	}

	// Unmatched flow hits fallback rule.
	_, _, _, fbIdx, err := m.MatchInboundWithRule(
		0,
		netip.MustParseAddr("192.168.1.2").As16(),
		netip.MustParseAddr("203.0.113.5").As16(),
		12345,
		443,
		consts.IpVersion_4,
		consts.L4ProtoType_TCP,
		"other.invalid",
		[16]byte{},
		0,
		[16]byte{},
	)
	if err != nil {
		t.Fatal(err)
	}
	fbMeta := m.RuleMetaForMatchIndex(fbIdx)
	if fbMeta == nil || fbMeta.Index != 0 || fbMeta.Origin != "fallback" || fbMeta.Raw != "fallback -> direct" {
		t.Fatalf("unexpected fallback rule meta: %+v", fbMeta)
	}
	if m.RuleMetaForMatchIndex(UnknownRuleMatchIndex) != nil {
		t.Fatal("expected nil meta for UnknownRuleMatchIndex")
	}
}

func TestChooseProxyDialerAttributesEBPFRoutedFlowWithoutAlteringOutbound(t *testing.T) {
	m := testFakeIPMatcher(t, `
domain(suffix: example.com) -> proxy
fallback: direct`, []string{"proxy"})

	logger := logrus.New()
	option := &componentdialer.GlobalOption{
		Log:           logger,
		CheckInterval: 15 * time.Second,
	}
	underlay, property := componentdialer.NewDirectDialer(option, true)
	d := componentdialer.NewDialer(underlay, option, componentdialer.InstanceOption{}, property)
	defer d.Close()

	directGroup := outbound.NewDialerGroupWithRuntimeOptions(
		option,
		"direct",
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *componentdialer.NetworkType, bool) {},
		outbound.DialerGroupRuntimeOptions{},
	)
	defer directGroup.Close()

	proxyGroup := outbound.NewDialerGroupWithRuntimeOptions(
		option,
		"proxy",
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *componentdialer.NetworkType, bool) {},
		outbound.DialerGroupRuntimeOptions{},
	)
	defer proxyGroup.Close()

	outbounds := make([]*outbound.DialerGroup, consts.OutboundUserDefinedMin+1)
	outbounds[consts.OutboundDirect] = directGroup
	outbounds[consts.OutboundUserDefinedMin] = proxyGroup

	cp := &ControlPlane{
		log: logger,
		controlPlaneGenerationState: controlPlaneGenerationState{
			routingMatcher: m,
			outbounds:      outbounds,
		},
	}

	// Case 1: kernel outbound matches rule outbound -> Option A attributes matching rule.
	res, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Network:  "tcp",
		Src:      netip.MustParseAddrPort("192.168.1.10:50000"),
		Dest:     netip.MustParseAddrPort("198.51.100.10:443"),
		Domain:   "sub.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OutboundIndex != consts.OutboundUserDefinedMin {
		t.Fatalf("kernel outbound altered: got %v want %v", res.OutboundIndex, consts.OutboundUserDefinedMin)
	}
	if res.Rule == nil || res.Rule.Raw != "domain(suffix:example.com) -> proxy" {
		t.Fatalf("expected Option A rule attribution on matching proxy flow, got %+v", res.Rule)
	}
	if res.RuleMatchIndex != res.Rule.MatchIndex {
		t.Fatalf("RuleMatchIndex mismatch: %d != %d", res.RuleMatchIndex, res.Rule.MatchIndex)
	}

	// Case 2: kernel chose OutboundDirect, while sniffed domain matches -> proxy;
	// Option A must fall back to the no-domain lookup (fallback -> direct) rather than
	// emitting a proxy rule that contradicts OutboundDirect.
	resDirect, err := cp.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundDirect,
		Network:  "tcp",
		Src:      netip.MustParseAddrPort("192.168.1.10:50001"),
		Dest:     netip.MustParseAddrPort("198.51.100.10:443"),
		Domain:   "sub.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resDirect.OutboundIndex != consts.OutboundDirect {
		t.Fatalf("kernel outbound altered: got %v want %v", resDirect.OutboundIndex, consts.OutboundDirect)
	}
	if resDirect.Rule == nil || resDirect.Rule.Origin != "fallback" || resDirect.Rule.Raw != "fallback -> direct" {
		t.Fatalf("expected direct fallback attribution when sniffed domain rule conflicts, got %+v", resDirect.Rule)
	}

	// Case 3: even no-domain lookup hits -> proxy (mismatch with kernel OutboundDirect);
	// Option A must leave Rule nil rather than attributing a mismatched rule.
	mMismatch := testFakeIPMatcher(t, `
ip(198.51.100.0/24) -> proxy
fallback: direct`, []string{"proxy"})
	cpMismatch := &ControlPlane{
		log: logger,
		controlPlaneGenerationState: controlPlaneGenerationState{
			routingMatcher: mMismatch,
			outbounds:      outbounds,
		},
	}
	resNilRule, err := cpMismatch.chooseProxyDialer(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundDirect,
		Network:  "tcp",
		Src:      netip.MustParseAddrPort("192.168.1.10:50002"),
		Dest:     netip.MustParseAddrPort("198.51.100.10:443"),
		Domain:   "sub.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resNilRule.OutboundIndex != consts.OutboundDirect {
		t.Fatalf("kernel outbound altered: got %v want %v", resNilRule.OutboundIndex, consts.OutboundDirect)
	}
	if resNilRule.Rule != nil || resNilRule.RuleMatchIndex != UnknownRuleMatchIndex {
		t.Fatalf("expected nil rule attribution when all lookups mismatch kernel outbound, got rule=%+v idx=%d", resNilRule.Rule, resNilRule.RuleMatchIndex)
	}
}
