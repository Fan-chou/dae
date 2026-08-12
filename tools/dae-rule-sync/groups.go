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
	for _, group := range config.Groups {
		report.NameMap[group.Name] = safeDaeIdentifier(group.Name)
	}
	var output strings.Builder
	output.WriteString("group {\n")
	for _, group := range config.Groups {
		members := make([]string, 0, len(group.Proxies))
		var reasons []string
		for _, member := range group.Proxies {
			switch member {
			case "DIRECT", "REJECT":
				reasons = append(reasons, member+" member")
			default:
				if _, nested := groups[member]; nested {
					reasons = append(reasons, "nested group "+member)
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
		fmt.Fprintf(&output, "        filter: name(")
		for i, member := range members {
			if i > 0 {
				output.WriteString(", ")
			}
			output.WriteString(daeQuote(member))
		}
		output.WriteString(")\n")
		fmt.Fprintf(&output, "        policy: %s\n", policy)
		output.WriteString("    }\n")
	}
	output.WriteString("}\n")
	return output.String(), report, nil
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
