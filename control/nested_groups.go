/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
)

const maxRuntimeNestedGroupDepth = 32

// nestedGroupBuildPlan keeps source declaration order separate from dependency
// order. Groups are built child-first, then published in source order so the
// outbound index ABI remains unchanged.
type nestedGroupBuildPlan struct {
	index          int
	group          config.Group
	references     map[int]string
	referenceOrder []string
}

func (p nestedGroupBuildPlan) hasNestedReferences() bool {
	return len(p.references) != 0
}

func planNestedGroupBuild(groups []config.Group) ([]nestedGroupBuildPlan, []int, error) {
	plans := make([]nestedGroupBuildPlan, len(groups))
	byName := make(map[string]int, len(groups))
	for i, group := range groups {
		if group.Name == "" {
			return nil, nil, fmt.Errorf("group has empty name")
		}
		if _, exists := byName[group.Name]; exists {
			return nil, nil, fmt.Errorf("duplicated group name %q", group.Name)
		}
		byName[group.Name] = i
		refs, err := outbound.ExactGroupMemberReferences(group.Filter, group.FilterAnnotation)
		if err != nil {
			return nil, nil, fmt.Errorf("group %q: %w", group.Name, err)
		}
		plans[i] = nestedGroupBuildPlan{
			index:          i,
			group:          group,
			references:     make(map[int]string, len(refs)),
			referenceOrder: make([]string, 0, len(refs)),
		}
		for _, ref := range refs {
			plans[i].references[ref.FilterIndex] = ref.Name
			plans[i].referenceOrder = append(plans[i].referenceOrder, ref.Name)
		}
	}

	for _, plan := range plans {
		for _, childName := range plan.referenceOrder {
			if _, exists := byName[childName]; !exists {
				return nil, nil, fmt.Errorf("group %q references unknown nested group %q", plan.group.Name, childName)
			}
		}
	}

	const (
		unseen = iota
		visiting
		visited
	)
	state := make([]int, len(plans))
	buildOrder := make([]int, 0, len(plans))
	var visit func(int, int) error
	visit = func(index, depth int) error {
		if depth > maxRuntimeNestedGroupDepth {
			return fmt.Errorf("nested group depth exceeds %d at %q", maxRuntimeNestedGroupDepth, plans[index].group.Name)
		}
		switch state[index] {
		case visiting:
			return fmt.Errorf("nested group cycle includes %q", plans[index].group.Name)
		case visited:
			return nil
		}
		state[index] = visiting
		for _, childName := range plans[index].referenceOrder {
			if err := visit(byName[childName], depth+1); err != nil {
				return err
			}
		}
		state[index] = visited
		buildOrder = append(buildOrder, index)
		return nil
	}
	for i := range plans {
		if err := visit(i, 1); err != nil {
			return nil, nil, err
		}
	}
	return plans, buildOrder, nil
}
