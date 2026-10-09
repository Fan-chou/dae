/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// dae routes traffic to outbounds that are groups, not to single nodes. A
// Mihomo rule can name a proxy directly, so each proxy used that way gets a
// one-member group around it.
type nodeWrapper struct {
	Original string // Mihomo proxy name the rules use
	Node     string // internal node name it wraps
	Group    string // internal name of the wrapper group
}

func isBuiltinTarget(t string) bool {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "DIRECT", "REJECT", "REJECT-DROP":
		return true
	}
	return false
}

// planNodeWrappers decides which proxies need a wrapper and what each is
// called. Targets that are built-ins, groups, or unknown names get none.
// used holds every internal name already taken by a node or a group.
func planNodeWrappers(targets []string, nodes []Node, groups []Group, used map[string]struct{}) ([]nodeWrapper, error) {
	nodeSafe := make(map[string]string, len(nodes))
	for _, n := range nodes {
		nodeSafe[n.Name] = n.Safe
	}
	isGroup := make(map[string]bool, len(groups))
	for _, g := range groups {
		isGroup[g.Name] = true
	}
	taken := make(map[string]struct{}, len(used))
	for name := range used {
		taken[name] = struct{}{}
	}
	var out []nodeWrapper
	for _, target := range targets {
		if isBuiltinTarget(target) || isGroup[target] {
			continue
		}
		safe, ok := nodeSafe[target]
		if !ok {
			continue
		}
		name, err := wrapperName(safe, taken)
		if err != nil {
			return nil, fmt.Errorf("allocate group for node action %q: %w", target, err)
		}
		taken[name] = struct{}{}
		out = append(out, nodeWrapper{Original: target, Node: safe, Group: name})
	}
	return out, nil
}

func collapseUnderscores(s string) string {
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return strings.Trim(s, "_")
}

// wrapperName picks node_<name>, falling back to progressively more
// mechanical spellings when that is taken.
func wrapperName(node string, taken map[string]struct{}) (string, error) {
	base := collapseUnderscores("node_" + strings.ReplaceAll(node, "-", "_"))
	short := sha256.Sum256([]byte(node))
	candidates := []string{
		base,
		base + "_g",
		collapseUnderscores("node_" + fmt.Sprintf("%x", short[:3])),
		collapseUnderscores("node_" + hashedName(node)),
	}
	for _, c := range candidates {
		if !groupIdentifier.MatchString(c) || len(c) > maxIdentifier || reservedOutbound(c) {
			continue
		}
		if _, exists := taken[c]; exists {
			continue
		}
		return c, nil
	}
	return "", fmt.Errorf("no unused dae group name for node %q", node)
}

// buildWrapperGroups returns the one-member groups, decoded the same way as
// every other group so defaults and presence bits agree.
func buildWrapperGroups(wrappers []nodeWrapper, nodes []Node) ([]Group, error) {
	if len(wrappers) == 0 {
		return nil, nil
	}
	display := make(map[string]string, len(nodes))
	for _, n := range nodes {
		display[n.Safe] = n.Name
	}
	section := &config_parser.Section{Name: "group"}
	for _, w := range wrappers {
		section.Items = append(section.Items, &config_parser.Item{
			Type: config_parser.ItemType_Section,
			Value: &config_parser.Section{Name: w.Group, Items: []*config_parser.Item{
				param("selection_members", w.Node),
				funcParam("filter", "name", w.Node),
				policyItem("fixed(0)"),
			}},
		})
	}
	decoded, err := config.DecodeGroups(section)
	if err != nil {
		return nil, fmt.Errorf("decode node-action groups: %w", err)
	}
	out := make([]Group, len(wrappers))
	for i, w := range wrappers {
		out[i] = Group{Name: display[w.Node], Safe: w.Group, Config: decoded[i], Wrapper: true}
	}
	return out, nil
}
