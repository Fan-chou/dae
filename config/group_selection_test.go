/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestGroupSelectionMembersRoundTrip(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    Proxy {
        filter: name('node-one', 'node-two')
        selection_members: "node-one,node-two"
        policy: fixed(0)
    }
}
routing {}
`)
	if err != nil {
		t.Fatalf("config_parser.Parse() error = %v", err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(conf.Group) != 1 || len(conf.Group[0].SelectionMembers) != 2 || conf.Group[0].SelectionMembers[1] != "node-two" {
		t.Fatalf("group selection metadata = %#v", conf.Group)
	}
}

func TestGroupFirstAlivePolicyParses(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    fallback_group {
        filter: name('node-one')
        policy: first_alive
    }
}
routing {}
`)
	if err != nil {
		t.Fatalf("config_parser.Parse() error = %v", err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(conf.Group) != 1 {
		t.Fatalf("groups = %#v, want one group", conf.Group)
	}
	policy, err := ParseFunctionListOrString(conf.Group[0].Policy)
	if err != nil {
		t.Fatalf("ParseFunctionListOrString() error = %v", err)
	}
	if len(policy) != 1 || policy[0].Name != "first_alive" {
		t.Fatalf("parsed policy = %#v, want first_alive", policy)
	}
}

func TestGroupHealthOptionsRoundTripPreservesExplicitValues(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    Proxy {
        filter: name('node-one')
        policy: fixed(0)
        tcp_check_url: "https://example.com/check"
        check_interval: 0s
        check_tolerance: 0ms
        lazy: false
    }
}
routing {}
`)
	if err != nil {
		t.Fatalf("config_parser.Parse() error = %v", err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(conf.Group) != 1 {
		t.Fatalf("groups = %#v, want one group", conf.Group)
	}
	group := conf.Group[0]
	if len(group.TcpCheckUrl) != 1 || group.TcpCheckUrl[0] != "https://example.com/check" {
		t.Fatalf("tcp_check_url = %#v", group.TcpCheckUrl)
	}
	if group.CheckInterval != 0 || !group.CheckIntervalSet {
		t.Fatalf("check interval = %v, set = %v; want explicit zero", group.CheckInterval, group.CheckIntervalSet)
	}
	if group.CheckTolerance != 0 || !group.CheckToleranceSet {
		t.Fatalf("check tolerance = %v, set = %v; want explicit zero", group.CheckTolerance, group.CheckToleranceSet)
	}
	if group.Lazy || !group.LazySet {
		t.Fatalf("lazy = %v, set = %v; want explicit false", group.Lazy, group.LazySet)
	}

	marshaled, err := conf.Marshal(2)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	sections, err = config_parser.Parse(string(marshaled))
	if err != nil {
		t.Fatalf("config_parser.Parse(marshaled) error = %v", err)
	}
	roundTripped, err := New(sections)
	if err != nil {
		t.Fatalf("New(round-tripped) error = %v", err)
	}
	roundTripGroup := roundTripped.Group[0]
	if roundTripGroup.CheckInterval != 0 || !roundTripGroup.CheckIntervalSet ||
		roundTripGroup.CheckTolerance != 0 || !roundTripGroup.CheckToleranceSet ||
		roundTripGroup.Lazy || !roundTripGroup.LazySet {
		t.Fatalf("round-tripped health options = %#v", roundTripGroup)
	}
	if roundTripGroup.CheckInterval != time.Duration(0) {
		t.Fatalf("round-tripped interval = %v", roundTripGroup.CheckInterval)
	}
}

func TestGroupHealthOptionsRoundTripPreservesOmission(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    Proxy {
        filter: name('node-one')
        policy: fixed(0)
    }
}
routing {}
`)
	if err != nil {
		t.Fatalf("config_parser.Parse() error = %v", err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	marshaled, err := conf.Marshal(2)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	output := string(marshaled)
	groupStart := strings.Index(output, "\n  Proxy {")
	if groupStart < 0 {
		t.Fatalf("marshaled output has no Proxy group: %s", output)
	}
	groupEnd := strings.Index(output[groupStart+1:], "\n  }")
	if groupEnd < 0 {
		t.Fatalf("marshaled output has unterminated Proxy group: %s", output)
	}
	groupOutput := output[groupStart : groupStart+1+groupEnd]
	for _, field := range []string{"tcp_check_url", "check_interval", "check_tolerance", "lazy"} {
		if strings.Contains(groupOutput, field+":") {
			t.Fatalf("marshaled group unexpectedly contains %s: %s", field, groupOutput)
		}
	}
	sections, err = config_parser.Parse(output)
	if err != nil {
		t.Fatalf("config_parser.Parse(marshaled) error = %v", err)
	}
	roundTripped, err := New(sections)
	if err != nil {
		t.Fatalf("New(round-tripped) error = %v", err)
	}
	group := roundTripped.Group[0]
	if group.CheckIntervalSet || group.CheckToleranceSet || group.LazySet {
		t.Fatalf("round-tripped presence bits = interval:%v tolerance:%v lazy:%v; want all false", group.CheckIntervalSet, group.CheckToleranceSet, group.LazySet)
	}
}
