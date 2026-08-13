/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"

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
