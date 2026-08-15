package main

import (
	"fmt"
	"sort"
	"strings"
)

type mihomoNodeActionGroup struct {
	Original  string
	NodeName  string
	GroupName string
}

func applyMihomoNodeActionGroups(ir MihomoRuleIR, groupsText string, nodeNames map[string]string, report *GroupConversionReport) (string, []mihomoNodeActionGroup, error) {
	if report == nil || report.NameMap == nil {
		return "", nil, fmt.Errorf("group conversion report is incomplete")
	}
	wrappers, err := planMihomoNodeActionGroups(ir, nodeNames, report.NameMap)
	if err != nil {
		return "", nil, err
	}
	if len(wrappers) == 0 {
		return groupsText, nil, nil
	}
	groupsText, err = appendMihomoNodeActionGroups(groupsText, wrappers)
	if err != nil {
		return "", nil, err
	}
	for _, wrapper := range wrappers {
		if previous, exists := report.NameMap[wrapper.GroupName]; exists && previous != wrapper.GroupName {
			return "", nil, fmt.Errorf("node-action group %q collides with mapped group %q", wrapper.GroupName, previous)
		}
		report.NameMap[wrapper.GroupName] = wrapper.GroupName
		report.Converted++
	}
	if err := validateMihomoOutputNames(nodeNames, report.NameMap); err != nil {
		return "", nil, err
	}
	return groupsText, wrappers, nil
}

func remapMihomoNodeActionOutbounds(outboundMap map[string]string, wrappers []mihomoNodeActionGroup) {
	for _, wrapper := range wrappers {
		outboundMap[wrapper.Original] = wrapper.GroupName
	}
}

func planMihomoNodeActionGroups(ir MihomoRuleIR, nodeNames, groupNames map[string]string) ([]mihomoNodeActionGroup, error) {
	used := make(map[string]struct{}, len(nodeNames)+len(groupNames))
	for _, safeName := range nodeNames {
		used[safeName] = struct{}{}
	}
	for _, safeName := range groupNames {
		used[safeName] = struct{}{}
	}
	targets := uniqueMihomoActionTargets(ir)
	wrappers := make([]mihomoNodeActionGroup, 0)
	seenNodes := make(map[string]struct{})
	for _, target := range targets {
		if isMihomoBuiltinOutbound(target) {
			continue
		}
		if _, isGroup := groupNames[target]; isGroup {
			continue
		}
		nodeName, isNode := nodeNames[target]
		if !isNode || nodeName == "" {
			continue
		}
		if _, seen := seenNodes[target]; seen {
			continue
		}
		seenNodes[target] = struct{}{}
		groupName, err := allocateNodeActionGroupName(nodeName, used)
		if err != nil {
			return nil, fmt.Errorf("allocate group for node action %q: %w", target, err)
		}
		used[groupName] = struct{}{}
		wrappers = append(wrappers, mihomoNodeActionGroup{
			Original:  target,
			NodeName:  nodeName,
			GroupName: groupName,
		})
	}
	return wrappers, nil
}

func uniqueMihomoActionTargets(ir MihomoRuleIR) []string {
	seen := make(map[string]struct{})
	add := func(rules []MihomoRuleIRRule) {
		for _, rule := range rules {
			target := strings.TrimSpace(rule.Action.Target)
			if target == "" {
				continue
			}
			seen[target] = struct{}{}
		}
	}
	add(ir.Rules)
	for _, subRule := range ir.SubRules {
		add(subRule.Rules)
	}
	targets := make([]string, 0, len(seen))
	for target := range seen {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

func isMihomoBuiltinOutbound(target string) bool {
	switch strings.ToUpper(strings.TrimSpace(target)) {
	case "DIRECT", "REJECT", "REJECT-DROP":
		return true
	default:
		return false
	}
}

func allocateNodeActionGroupName(nodeName string, used map[string]struct{}) (string, error) {
	base := collapseIdentifierUnderscores("node_" + strings.ReplaceAll(nodeName, "-", "_"))
	candidates := []string{
		base,
		base + "_g",
		collapseIdentifierUnderscores("node_" + identifierDisambiguator(nodeName)),
		collapseIdentifierUnderscores("node_" + hashedMihomoIdentifier(nodeName)),
	}
	for _, candidate := range candidates {
		if !daeIdentifierPattern.MatchString(candidate) || len(candidate) > maxSafeIdentifier {
			continue
		}
		if candidate == "direct" || candidate == "block" {
			continue
		}
		if _, exists := used[candidate]; exists {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("no unused dae group name for node %q", nodeName)
}

func appendMihomoNodeActionGroups(groupsText string, wrappers []mihomoNodeActionGroup) (string, error) {
	trimmed := strings.TrimRight(groupsText, "\n")
	if !strings.HasSuffix(trimmed, "}") {
		return "", fmt.Errorf("generated groups are missing a closing brace")
	}
	body := strings.TrimSuffix(trimmed, "}")
	var output strings.Builder
	output.WriteString(body)
	for _, wrapper := range wrappers {
		if err := validateDaeLiteral(wrapper.GroupName); err != nil {
			return "", fmt.Errorf("node-action group %q: %w", wrapper.GroupName, err)
		}
		if err := validateDaeLiteral(wrapper.NodeName); err != nil {
			return "", fmt.Errorf("node-action member %q: %w", wrapper.NodeName, err)
		}
		fmt.Fprintf(&output, "    %s {\n", wrapper.GroupName)
		fmt.Fprintf(&output, "        selection_members: %s\n", daeQuote(wrapper.NodeName))
		fmt.Fprintf(&output, "        filter: name(%s)\n", daeQuote(wrapper.NodeName))
		output.WriteString("        policy: fixed(0)\n")
		output.WriteString("    }\n")
	}
	output.WriteString("}\n")
	return output.String(), nil
}
