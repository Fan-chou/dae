package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type MihomoConfig struct {
	Proxies []MihomoProxy `yaml:"proxies"`
	Groups  []MihomoGroup `yaml:"proxy-groups"`
}

type MihomoProxy struct {
	Name              string         `yaml:"name"`
	Type              string         `yaml:"type"`
	Server            string         `yaml:"server"`
	Port              int            `yaml:"port"`
	Username          string         `yaml:"username"`
	Password          string         `yaml:"password"`
	Cipher            string         `yaml:"cipher"`
	SNI               string         `yaml:"sni"`
	ServerName        string         `yaml:"servername"`
	ClientFingerprint string         `yaml:"client-fingerprint"`
	TLS               *bool          `yaml:"tls"`
	SkipCertVerify    *bool          `yaml:"skip-cert-verify"`
	UDP               *bool          `yaml:"udp"`
	Plugin            string         `yaml:"plugin"`
	PluginOpts        map[string]any `yaml:"plugin-opts"`
}

type MihomoGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
	Use     []string `yaml:"use"`

	// Pointers are intentional: Mihomo distinguishes an omitted option from an
	// explicit false/zero value, and conversion must not silently replace either
	// with dae's global defaults.
	URL       *string `yaml:"url"`
	Interval  *int64  `yaml:"interval"`
	Lazy      *bool   `yaml:"lazy"`
	Tolerance *int64  `yaml:"tolerance"`
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

// ParseMihomoConfigStrict is used by complete generation output. Mihomo has a
// large configuration surface; silently dropping a field that this converter
// does not model would make a generation look complete while changing its
// meaning. Compatibility-only groups output retains the permissive parser.
func ParseMihomoConfigStrict(data []byte) (MihomoConfig, error) {
	var config MihomoConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return MihomoConfig{}, fmt.Errorf("parse Mihomo config strictly: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return MihomoConfig{}, errors.New("parse Mihomo config strictly: multiple YAML documents are not allowed")
		}
		return MihomoConfig{}, fmt.Errorf("parse Mihomo config strictly: %w", err)
	}
	return config, nil
}

func GenerateFlatDaeGroups(config MihomoConfig) (string, GroupConversionReport, error) {
	return generateFlatDaeGroups(config, nil)
}

// generateFlatDaeGroups renders the group-only compatibility output. When
// nodeNames is non-nil, ordinary Mihomo proxy references are replaced by the
// generated dae node names before rendering.
func generateFlatDaeGroups(config MihomoConfig, nodeNames map[string]string) (string, GroupConversionReport, error) {
	return generateMihomoGroups(config, nodeNames, false)
}

// generateFullMihomoGroups renders the generation-backed Mihomo conversion.
// The compatibility renderer intentionally reports legacy approximations, but
// the complete generation path only accepts mappings whose runtime semantics
// are represented by dae.
func generateFullMihomoGroups(config MihomoConfig, nodeNames map[string]string) (string, GroupConversionReport, error) {
	return generateMihomoGroups(config, nodeNames, true)
}

func generateMihomoGroups(config MihomoConfig, nodeNames map[string]string, lossless bool) (string, GroupConversionReport, error) {
	proxies := make(map[string]struct{}, len(config.Proxies))
	for _, proxy := range config.Proxies {
		if proxy.Name == "" || strings.TrimSpace(proxy.Name) == "" {
			return "", GroupConversionReport{}, errors.New("proxy has empty name")
		}
		if _, exists := proxies[proxy.Name]; exists {
			return "", GroupConversionReport{}, fmt.Errorf("duplicate proxy %q", proxy.Name)
		}
		proxies[proxy.Name] = struct{}{}
	}
	groups := make(map[string]struct{}, len(config.Groups))
	for _, group := range config.Groups {
		if group.Name == "" || strings.TrimSpace(group.Name) == "" {
			return "", GroupConversionReport{}, fmt.Errorf("group has empty name")
		}
		if _, exists := groups[group.Name]; exists {
			return "", GroupConversionReport{}, fmt.Errorf("duplicate group %q", group.Name)
		}
		groups[group.Name] = struct{}{}
	}
	for _, group := range config.Groups {
		if err := validateMihomoGroupHealth(group); err != nil {
			return "", GroupConversionReport{}, fmt.Errorf("group %q: %w", group.Name, err)
		}
		if hasMihomoNestedMember(group, groups) && hasMihomoGroupHealthOptions(group) {
			return "", GroupConversionReport{}, fmt.Errorf(
				"group %q has explicit health-check options but nested members have no unambiguous group-level health semantics",
				group.Name,
			)
		}
	}

	report := GroupConversionReport{NameMap: make(map[string]string, len(config.Groups))}
	safeNames := make(map[string]string, len(config.Groups))
	for _, group := range config.Groups {
		if lossless && isReservedMihomoGroupName(group.Name) {
			return "", GroupConversionReport{}, fmt.Errorf("group %q conflicts with a reserved Mihomo member or dae outbound", group.Name)
		}
		safeName := safeDaeIdentifier(group.Name)
		if previous, exists := safeNames[safeName]; exists {
			return "", GroupConversionReport{}, fmt.Errorf("groups %q and %q map to the same dae name %q", previous, group.Name, safeName)
		}
		if safeName == "direct" || safeName == "block" {
			return "", GroupConversionReport{}, fmt.Errorf("group %q maps to reserved dae outbound %q", group.Name, safeName)
		}
		safeNames[safeName] = group.Name
		report.NameMap[group.Name] = safeName
	}
	if nodeNames != nil {
		if err := validateMihomoOutputNames(nodeNames, report.NameMap); err != nil {
			return "", GroupConversionReport{}, err
		}
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
		selectionMembers := make([]string, 0, len(group.Proxies))
		var reasons []string
		seenMembers := make(map[string]struct{}, len(group.Proxies))
		for _, member := range group.Proxies {
			if lossless {
				if _, exists := seenMembers[member]; exists {
					return "", GroupConversionReport{}, fmt.Errorf("group %q repeats member %q", group.Name, member)
				}
				seenMembers[member] = struct{}{}
			}
			switch member {
			case "DIRECT", "REJECT":
				members = append(members, member)
				if reference, special := specialMihomoGroupReference(member); special {
					selectionMembers = append(selectionMembers, reference)
				}
				hasNestedMembers[groupIndex] = true
			default:
				if _, nested := groups[member]; nested {
					if !convertibleGroups[member] {
						reasons = append(reasons, "nested group "+member+" is not convertible")
						continue
					}
					members = append(members, member)
					selectionMembers = append(selectionMembers, report.NameMap[member])
					continue
				}
				if _, node := proxies[member]; !node {
					return "", GroupConversionReport{}, fmt.Errorf("group %q has unknown member %q", group.Name, member)
				}
				mappedMember := member
				if nodeNames != nil {
					var ok bool
					mappedMember, ok = nodeNames[member]
					if !ok || mappedMember == "" {
						return "", GroupConversionReport{}, fmt.Errorf("group %q member %q has no generated dae node name", group.Name, member)
					}
				}
				if err := validateDaeLiteral(mappedMember); err != nil {
					return "", GroupConversionReport{}, fmt.Errorf("group %q member %q: %w", group.Name, mappedMember, err)
				}
				members = append(members, mappedMember)
				selectionMembers = append(selectionMembers, mappedMember)
			}
		}
		if len(group.Use) > 0 {
			reasons = append(reasons, "proxy provider members are unsupported")
		}
		if len(group.Proxies) == 0 && len(group.Use) == 0 {
			return "", GroupConversionReport{}, fmt.Errorf("group %q has no members", group.Name)
		}
		if len(members) == 0 {
			if lossless {
				return "", GroupConversionReport{}, fmt.Errorf("group %q cannot be converted: %s", group.Name, strings.Join(reasons, "; "))
			}
			if len(reasons) > 0 {
				report.Unsupported = append(report.Unsupported, GroupUnsupported{Group: group.Name, Reason: strings.Join(reasons, "; ")})
			}
			continue
		}

		policy, approximate, err := flatGroupPolicy(group.Type)
		if err != nil {
			if lossless {
				return "", GroupConversionReport{}, fmt.Errorf("group %q cannot be converted: %w", group.Name, err)
			}
			report.Unsupported = append(report.Unsupported, GroupUnsupported{Group: group.Name, Reason: err.Error()})
			continue
		}
		if lossless {
			policy, approximate, err = fullMihomoGroupPolicy(group.Type, selectionMembers)
			if err != nil {
				return "", GroupConversionReport{}, fmt.Errorf("group %q cannot be converted: %w", group.Name, err)
			}
		}
		if len(reasons) > 0 {
			if lossless {
				return "", GroupConversionReport{}, fmt.Errorf("group %q cannot be converted: %s", group.Name, strings.Join(reasons, "; "))
			}
			report.Unsupported = append(report.Unsupported, GroupUnsupported{Group: group.Name, Reason: strings.Join(reasons, "; ")})
		}
		report.Converted++
		if approximate || len(reasons) > 0 {
			report.Approximated++
		}
		fmt.Fprintf(&output, "    %s {\n", report.NameMap[group.Name])
		if strings.EqualFold(group.Type, "select") && allSafeSelectionIdentities(selectionMembers) {
			fmt.Fprintf(&output, "        selection_members: %s\n", daeQuote(strings.Join(selectionMembers, ",")))
		}
		if group.URL != nil {
			fmt.Fprintf(&output, "        tcp_check_url: %s\n", daeQuote(*group.URL))
		}
		if group.Interval != nil {
			fmt.Fprintf(&output, "        check_interval: %ds\n", *group.Interval)
		}
		if group.Tolerance != nil {
			fmt.Fprintf(&output, "        check_tolerance: %dms\n", *group.Tolerance)
		}
		if group.Lazy != nil {
			fmt.Fprintf(&output, "        lazy: %t\n", *group.Lazy)
		}
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

func isReservedMihomoGroupName(name string) bool {
	switch strings.ToLower(name) {
	case "direct", "reject", "block":
		return true
	default:
		return false
	}
}

func hasMihomoGroupHealthOptions(group MihomoGroup) bool {
	// lazy is ignored for nested groups until dae has unambiguous group-level
	// lazy semantics; explicit check URL, interval, and tolerance remain guarded.
	return group.URL != nil || group.Interval != nil || group.Tolerance != nil
}

func hasMihomoNestedMember(group MihomoGroup, groups map[string]struct{}) bool {
	for _, member := range group.Proxies {
		if _, nested := groups[member]; nested {
			return true
		}
		if _, special := specialMihomoGroupReference(member); special {
			return true
		}
	}
	return false
}

func validateMihomoGroupHealth(group MihomoGroup) error {
	if group.URL != nil {
		raw := *group.URL
		if raw == "" || strings.TrimSpace(raw) != raw {
			return errors.New("url must be a non-empty absolute URL")
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("url is invalid: %w", err)
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("url scheme %q is unsupported; only http and https are allowed", parsed.Scheme)
		}
		if parsed.Hostname() == "" {
			return errors.New("url must include a host")
		}
		if err := validateDaeLiteral(raw); err != nil {
			return fmt.Errorf("url cannot be represented in dae config: %w", err)
		}
	}
	if group.Interval != nil {
		if _, err := mihomoDuration(*group.Interval, time.Second, "interval", false); err != nil {
			return err
		}
	}
	if group.Tolerance != nil {
		if _, err := mihomoDuration(*group.Tolerance, time.Millisecond, "tolerance", true); err != nil {
			return err
		}
	}
	return nil
}

func mihomoDuration(value int64, unit time.Duration, field string, allowZero bool) (time.Duration, error) {
	if value < 0 || (!allowZero && value == 0) {
		if allowZero {
			return 0, fmt.Errorf("%s must be non-negative", field)
		}
		return 0, fmt.Errorf("%s must be greater than zero", field)
	}
	maxDuration := time.Duration(1<<63 - 1)
	if value > int64(maxDuration/unit) {
		return 0, fmt.Errorf("%s duration overflows time.Duration", field)
	}
	return time.Duration(value) * unit, nil
}

// allSafeSelectionIdentities keeps the sideband metadata parseable without
// allowing arbitrary Mihomo names to become a second config-language parser.
// Full node conversion always maps names into this form; the legacy
// groups-only output omits metadata when an original name is not safe.
func allSafeSelectionIdentities(members []string) bool {
	if len(members) == 0 {
		return false
	}
	for _, member := range members {
		if !mihomoNodeIdentifierPattern.MatchString(member) && !daeIdentifierPattern.MatchString(member) {
			return false
		}
	}
	return true
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
		return "first_alive", true, nil
	case "url-test":
		return "min_avg10", true, nil
	default:
		return "", false, fmt.Errorf("group type %q is unsupported for flat conversion", groupType)
	}
}

func fullMihomoGroupPolicy(groupType string, selectionMembers []string) (string, bool, error) {
	policy, approximate, err := flatGroupPolicy(groupType)
	if err != nil {
		return "", false, err
	}
	switch strings.ToLower(groupType) {
	case "select":
		if !allSafeSelectionIdentities(selectionMembers) {
			return "", false, errors.New("select group has no lossless member identity metadata")
		}
		// selection_members plus the persisted user-space choice preserves the
		// Mihomo select identity; fixed(0) is only the safe initial fallback.
		return policy, false, nil
	case "fallback":
		// first_alive is the exact ordered fallback policy implemented by dae.
		return policy, false, nil
	default:
		// url-test currently maps to min_avg10 without Mihomo's complete
		// tolerance/latency semantics, so it remains an explicit approximation.
		return policy, approximate, nil
	}
}

func validateMihomoOutputNames(nodeNames, groupNames map[string]string) error {
	used := make(map[string]string, len(nodeNames)+len(groupNames))
	for original, safeName := range nodeNames {
		if original == "" || safeName == "" || !mihomoNodeIdentifierPattern.MatchString(safeName) {
			return fmt.Errorf("Mihomo node name mapping for %q is invalid", original)
		}
		if safeName == "direct" || safeName == "block" {
			return fmt.Errorf("Mihomo node %q maps to reserved dae outbound %q", original, safeName)
		}
		if previous, exists := used[safeName]; exists {
			return fmt.Errorf("Mihomo node/group names %q and %q map to the same dae outbound %q", previous, original, safeName)
		}
		used[safeName] = original
	}
	for original, safeName := range groupNames {
		if original == "" || safeName == "" || !daeIdentifierPattern.MatchString(safeName) {
			return fmt.Errorf("Mihomo group name mapping for %q is invalid", original)
		}
		if safeName == "direct" || safeName == "block" {
			return fmt.Errorf("Mihomo group %q maps to reserved dae outbound %q", original, safeName)
		}
		if previous, exists := used[safeName]; exists {
			return fmt.Errorf("Mihomo node/group names %q and %q map to the same dae outbound %q", previous, original, safeName)
		}
		used[safeName] = original
	}
	return nil
}

func safeDaeIdentifier(name string) string {
	if daeIdentifierPattern.MatchString(name) {
		return name
	}
	digest := sha256.Sum256([]byte(name))
	return fmt.Sprintf("mihomo_%x", digest[:6])
}
