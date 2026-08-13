/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func newTestExactNestedGroupFilter(name string) []*config_parser.Function {
	return []*config_parser.Function{{
		Name:   "group",
		Params: []*config_parser.Param{{Val: name}},
	}}
}

func newTestExactNestedGroupConfig(name string, references ...string) config.Group {
	filters := make([][]*config_parser.Function, 0, len(references))
	annotations := make([][]*config_parser.Param, 0, len(references))
	for _, reference := range references {
		filters = append(filters, newTestExactNestedGroupFilter(reference))
		annotations = append(annotations, []*config_parser.Param{})
	}
	return config.Group{Name: name, Filter: filters, FilterAnnotation: annotations}
}

func TestPlanNestedGroupBuildRecognizesBuiltinOutboundReferences(t *testing.T) {
	plans, buildOrder, err := planNestedGroupBuild([]config.Group{
		newTestExactNestedGroupConfig("proxy", "direct", "block"),
	})
	if err != nil {
		t.Fatalf("planNestedGroupBuild() error = %v", err)
	}
	if len(plans) != 1 || len(buildOrder) != 1 || buildOrder[0] != 0 {
		t.Fatalf("plans/buildOrder = %#v/%#v", plans, buildOrder)
	}
	if plans[0].references[0] != "direct" || plans[0].references[1] != "block" {
		t.Fatalf("builtin references = %#v", plans[0].references)
	}
}

func TestPlanNestedGroupBuildRejectsBuiltinGroupNameConflict(t *testing.T) {
	for _, name := range []string{"direct", "block"} {
		_, _, err := planNestedGroupBuild([]config.Group{{Name: name}})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("planNestedGroupBuild(%q) error = %v, want reserved-name error", name, err)
		}
	}
}

func TestPlanNestedGroupBuildRejectsUnknownAndIllegalGroupReferences(t *testing.T) {
	_, _, err := planNestedGroupBuild([]config.Group{
		newTestExactNestedGroupConfig("proxy", "missing"),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown nested group") {
		t.Fatalf("unknown reference error = %v", err)
	}

	invalid := newTestExactNestedGroupConfig("proxy", "direct")
	invalid.Filter[0] = append(invalid.Filter[0], &config_parser.Function{Name: "name", Params: []*config_parser.Param{{Val: "node"}}})
	_, _, err = planNestedGroupBuild([]config.Group{invalid})
	if err == nil || !strings.Contains(err.Error(), "exact group") {
		t.Fatalf("illegal reference error = %v", err)
	}
}
