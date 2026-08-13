package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type MihomoConfig struct {
	Proxies []MihomoProxy `yaml:"proxies"`
	Groups  []MihomoGroup `yaml:"proxy-groups"`
}

type MihomoProxy struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
}

type MihomoGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
	Use     []string `yaml:"use"`
}

type GroupUnsupported struct {
	Group  string
	Reason string
}

type GroupConversionReport struct {
	Converted    int
	Approximated int
	Unsupported  []GroupUnsupported
	NameMap      map[string]string
}

var daeIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// maxNestedGroupDepth bounds recursive selection in the generated group graph.
// Mihomo group files are provider input, so an unbounded graph must never reach
// the runtime even when it is acyclic.
const maxNestedGroupDepth = 32

func specialMihomoGroupReference(member string) (string, bool) {
	switch member {
	case "DIRECT":
		return "direct", true
	case "REJECT":
		return "block", true
	default:
		return "", false
	}
}

func ParseMihomoConfig(data []byte) (MihomoConfig, error) {
	var config MihomoConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return MihomoConfig{}, fmt.Errorf("parse mihomo config: %w", err)
	}
	return config, nil
}

func GenerateFlatDaeGroups(config MihomoConfig) (string, GroupConversionReport, error) {
	proxies := make(map[string]struct{}, len(config.Proxies))
	for _, proxy := range config.Proxies {
		if proxy.Name == "" {
			return "", GroupConversionReport{}, errors.New("proxy has empty name")
		}
		if _, exists := proxies[proxy.Name]; exists {
			return "", GroupConversionReport{}, fmt.Errorf("duplicate proxy %q", proxy.Name)
		}
		proxies[proxy.Name] = struct{}{}
	}
	groups := make(map[string]struct{}, len(config.Groups))
	for _, group := range config.Groups {
		if group.Name == "" {
			return "", GroupConversionReport{}, fmt.Errorf("group has empty name")
		}
		if _, exists := groups[group.Name]; exists {
			return "", GroupConversionReport{}, fmt.Errorf("duplicate group %q", group.Name)
		}
		groups[group.Name] = struct{}{}
	}

	report := GroupConversionReport{NameMap: make(map[string]string, len(config.Groups))}
	safeNames := make(map[string]string, len(config.Groups))
	for _, group := range config.Groups {
		safeName := safeDaeIdentifier(group.Name)
		if previous, exists := safeNames[safeName]; exists {
			return "", GroupConversionReport{}, fmt.Errorf("groups %q and %q map to the same dae name %q", previous, group.Name, safeName)
		}
		safeNames[safeName] = group.Name
		report.NameMap[group.Name] = safeName
	}

	_, hasNestedMembers, err := validateMihomoGroupGraph(config.Groups, groups)
	if err != nil {
		return "", GroupConversionReport{}, err
	}
	convertibleGroups := convertibleMihomoGroups(config.Groups, proxies, groups)
	var output strings.Builder
	output.WriteString("group {\n")
	for groupIndex, group := range config.Groups {
		members := make([]string, 0, len(group.Proxies))
		var reasons []string
		for _, member := range group.Proxies {
			switch member {
			case "DIRECT", "REJECT":
				members = append(members, member)
				hasNestedMembers[groupIndex] = true
			default:
				if _, nested := groups[member]; nested {
					if !convertibleGroups[member] {
						reasons = append(reasons, "nested group "+member+" is not convertible")
						continue
					}
					members = append(members, member)
					continue
				}
				if _, node := proxies[member]; !node {
					return "", GroupConversionReport{}, fmt.Errorf("group %q has unknown member %q", group.Name, member)
				}
				if err := validateDaeLiteral(member); err != nil {
					return "", GroupConversionReport{}, fmt.Errorf("group %q member %q: %w", group.Name, member, err)
				}
				members = append(members, member)
			}
		}
		if len(group.Use) > 0 {
			reasons = append(reasons, "proxy provider members are unsupported")
		}
		if len(group.Proxies) == 0 && len(group.Use) == 0 {
			return "", GroupConversionReport{}, fmt.Errorf("group %q has no members", group.Name)
		}
		if len(members) == 0 {
			if len(reasons) > 0 {
				report.Unsupported = append(report.Unsupported, GroupUnsupported{Group: group.Name, Reason: strings.Join(reasons, "; ")})
			}
			continue
		}

		policy, approximate, err := flatGroupPolicy(group.Type)
		if err != nil {
			report.Unsupported = append(report.Unsupported, GroupUnsupported{Group: group.Name, Reason: err.Error()})
			continue
		}
		if len(reasons) > 0 {
			report.Unsupported = append(report.Unsupported, GroupUnsupported{Group: group.Name, Reason: strings.Join(reasons, "; ")})
		}
		report.Converted++
		if approximate || len(reasons) > 0 {
			report.Approximated++
		}
		fmt.Fprintf(&output, "    %s {\n", report.NameMap[group.Name])
		if !hasNestedMembers[groupIndex] {
			fmt.Fprintf(&output, "        filter: name(")
			for i, member := range members {
				if i > 0 {
					output.WriteString(", ")
				}
				output.WriteString(daeQuote(member))
			}
			output.WriteString(")\n")
		} else {
			for _, member := range members {
				if reference, special := specialMihomoGroupReference(member); special {
					fmt.Fprintf(&output, "        filter: group(%s)\n", daeQuote(reference))
					continue
				}
				if _, nested := groups[member]; nested {
					fmt.Fprintf(&output, "        filter: group(%s)\n", daeQuote(report.NameMap[member]))
					continue
				}
				fmt.Fprintf(&output, "        filter: name(%s)\n", daeQuote(member))
			}
		}
		fmt.Fprintf(&output, "        policy: %s\n", policy)
		output.WriteString("    }\n")
	}
	output.WriteString("}\n")
	return output.String(), report, nil
}

// convertibleMihomoGroups is a deterministic post-order availability pass for
// rendered declarations. A parent must never emit group(child) when the child
// is omitted because it has no usable member or an unsupported policy.
func convertibleMihomoGroups(groupsIn []MihomoGroup, proxies, groups map[string]struct{}) map[string]bool {
	byName := make(map[string]MihomoGroup, len(groupsIn))
	for _, group := range groupsIn {
		byName[group.Name] = group
	}
	convertible := make(map[string]bool, len(groupsIn))
	seen := make(map[string]bool, len(groupsIn))
	var visit func(string) bool
	visit = func(name string) bool {
		if seen[name] {
			return convertible[name]
		}
		seen[name] = true
		group := byName[name]
		if _, _, err := flatGroupPolicy(group.Type); err != nil {
			return false
		}
		for _, member := range group.Proxies {
			if _, special := specialMihomoGroupReference(member); special {
				convertible[name] = true
				return true
			}
			if _, nested := groups[member]; nested {
				if visit(member) {
					convertible[name] = true
					return true
				}
				continue
			}
			if member != "DIRECT" && member != "REJECT" {
				if _, proxy := proxies[member]; proxy {
					convertible[name] = true
					return true
				}
			}
		}
		return false
	}
	for _, group := range groupsIn {
		visit(group.Name)
	}
	return convertible
}

// validateMihomoGroupGraph validates the graph before it is rendered. The
// returned bool slice records which declarations need explicit group(...) edges
// for nested or built-in groups; declarations are intentionally rendered in
// source order so existing outbound ordering remains stable.
func validateMihomoGroupGraph(groupsIn []MihomoGroup, groups map[string]struct{}) (map[string][]string, []bool, error) {
	dependencies := make(map[string][]string, len(groupsIn))
	hasNested := make([]bool, len(groupsIn))
	for i, group := range groupsIn {
		for _, member := range group.Proxies {
			if _, ok := groups[member]; ok {
				dependencies[group.Name] = append(dependencies[group.Name], member)
				hasNested[i] = true
			}
		}
	}

	const (
		unseen = iota
		visiting
		visited
	)
	state := make(map[string]int, len(groupsIn))
	var visit func(string, int) error
	visit = func(name string, depth int) error {
		if depth > maxNestedGroupDepth {
			return fmt.Errorf("nested group depth exceeds %d at %q", maxNestedGroupDepth, name)
		}
		switch state[name] {
		case visiting:
			return fmt.Errorf("nested group cycle includes %q", name)
		case visited:
			return nil
		}
		state[name] = visiting
		for _, child := range dependencies[name] {
			if err := visit(child, depth+1); err != nil {
				return err
			}
		}
		state[name] = visited
		return nil
	}
	for _, group := range groupsIn {
		if err := visit(group.Name, 1); err != nil {
			return nil, nil, err
		}
	}
	return dependencies, hasNested, nil
}

func flatGroupPolicy(groupType string) (policy string, approximate bool, err error) {
	switch strings.ToLower(groupType) {
	case "select":
		return "fixed(0)", true, nil
	case "fallback":
		return "min_moving_avg", true, nil
	case "url-test":
		return "min_avg10", true, nil
	default:
		return "", false, fmt.Errorf("group type %q is unsupported for flat conversion", groupType)
	}
}

func safeDaeIdentifier(name string) string {
	if daeIdentifierPattern.MatchString(name) {
		return name
	}
	digest := sha256.Sum256([]byte(name))
	return fmt.Sprintf("mihomo_%x", digest[:6])
}
