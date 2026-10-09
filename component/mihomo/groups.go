/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"gopkg.in/yaml.v3"
)

const maxNestedGroupDepth = 32

// Group is one Mihomo proxy-group lowered to a dae group. Name is the
// original Mihomo name (display); Config.Name is the internal dae identifier.
type Group struct {
	Name   string
	Safe   string
	Config config.Group
	// Wrapper marks a one-member group made around a proxy that rules name
	// directly; Name is then the proxy's name.
	Wrapper bool
}

// GroupOptions carries settings that are not part of the Mihomo document.
type GroupOptions struct {
	// IsolateTransportGroups lists internal (dae) group names that get a
	// private transport per node.
	IsolateTransportGroups []string
}

type groupFields struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
	Use     []string `yaml:"use"`

	// Pointers distinguish an omitted option from an explicit zero value;
	// conversion must not replace either with dae's defaults.
	URL       *string `yaml:"url"`
	Interval  *int64  `yaml:"interval"`
	Lazy      *bool   `yaml:"lazy"`
	Tolerance *int64  `yaml:"tolerance"`

	Quality *qualityFields `yaml:"x-kdae-quality"`
}

// qualityFields is the kdae extension for local quality policy. Misspelled
// keys are rejected.
type qualityFields struct {
	MinDownloadBytes *uint64  `yaml:"min-download-bytes"`
	Mode             string   `yaml:"mode"`
	SevereRatio      *float64 `yaml:"severe-speed-ratio"`
	RecoveryRatio    *float64 `yaml:"recovery-speed-ratio"`
}

// groupFieldSet lists every key a group may carry. hidden and icon only
// affect how a client lists the group and never which traffic it carries;
// everything else Mihomo defines (filter, include-all, interface-name, ...)
// changes membership or transport and is rejected instead of being dropped.
var groupFieldSet = map[string]struct{}{
	"name": {}, "type": {}, "proxies": {}, "use": {}, "url": {}, "interval": {},
	"lazy": {}, "tolerance": {}, "x-kdae-quality": {},
	"hidden": {}, "icon": {},
}

var qualityFieldSet = map[string]struct{}{
	"min-download-bytes": {}, "mode": {}, "severe-speed-ratio": {}, "recovery-speed-ratio": {},
}

// ConvertGroups lowers proxy-groups against already converted nodes. Anything
// that cannot be represented with identical behavior fails the conversion:
// unsupported group types, proxy-provider members, unknown or repeated
// members, cycles, and unsupported fields. Groups keep source order.
func ConvertGroups(entries []Entry, nodes []Node, options GroupOptions) ([]Group, error) {
	nodeSafe := make(map[string]string, len(nodes))
	usedByNodes := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		nodeSafe[n.Name] = n.Safe
		usedByNodes[n.Safe] = struct{}{}
	}

	fields := make([]groupFields, len(entries))
	byName := make(map[string]int, len(entries))
	originals := make([]string, len(entries))
	for i, entry := range entries {
		if strings.TrimSpace(entry.Name) == "" {
			return nil, errors.New("group has empty name")
		}
		if !utf8.ValidString(entry.Name) {
			return nil, errors.New("group name is not valid UTF-8")
		}
		switch strings.ToLower(entry.Name) {
		case "direct", "reject", "block":
			return nil, fmt.Errorf("group %q conflicts with a reserved Mihomo member or dae outbound", entry.Name)
		}
		if _, dup := byName[entry.Name]; dup {
			return nil, fmt.Errorf("duplicate group %q", entry.Name)
		}
		if _, clash := nodeSafe[entry.Name]; clash {
			// A Mihomo proxy and group may not share a name: members are
			// resolved by name.
			return nil, fmt.Errorf("group %q has the same name as a proxy", entry.Name)
		}
		byName[entry.Name] = i
		originals[i] = entry.Name

		if field, bad := firstUnsupportedField(entry.Node, groupFieldSet); bad {
			return nil, fmt.Errorf("group %q has unsupported field %q", entry.Name, field)
		}
		if err := entry.Node.Decode(&fields[i]); err != nil {
			return nil, fmt.Errorf("group %q has invalid fields", entry.Name)
		}
		if q := fields[i].Quality; q != nil {
			qnode := mappingValue(entry.Node, "x-kdae-quality")
			if field, bad := firstUnsupportedField(qnode, qualityFieldSet); bad {
				return nil, fmt.Errorf("group %q: unsupported x-kdae-quality field %q", entry.Name, field)
			}
		}
		if err := validateGroupHealth(fields[i]); err != nil {
			return nil, fmt.Errorf("group %q: %w", entry.Name, err)
		}
	}

	safe, err := assignSafeNames(originals, SafeGroupName, groupIdentifier, maxIdentifier, usedByNodes)
	if err != nil {
		return nil, err
	}

	isolate := make(map[string]bool, len(options.IsolateTransportGroups))
	known := make(map[string]struct{}, len(safe))
	for _, s := range safe {
		known[s] = struct{}{}
	}
	for _, name := range options.IsolateTransportGroups {
		if _, ok := known[name]; !ok {
			return nil, fmt.Errorf("isolated transport group %q does not exist", name)
		}
		isolate[name] = true
	}

	if err := checkGroupGraph(entries, fields, byName); err != nil {
		return nil, err
	}

	section := &config_parser.Section{Name: "group"}
	out := make([]Group, len(entries))
	for i, entry := range entries {
		item, err := lowerGroup(entry.Name, safe[i], fields[i], nodeSafe, byName, safe, isolate[safe[i]])
		if err != nil {
			return nil, err
		}
		section.Items = append(section.Items, item)
		out[i] = Group{Name: entry.Name, Safe: safe[i]}
	}
	decoded, err := config.DecodeGroups(section)
	if err != nil {
		return nil, fmt.Errorf("decode generated groups: %w", err)
	}
	if len(decoded) != len(out) {
		return nil, errors.New("decode generated groups: count mismatch")
	}
	for i := range out {
		out[i].Config = decoded[i]
	}
	return out, nil
}

func lowerGroup(name, safe string, f groupFields, nodeSafe map[string]string, groupIndex map[string]int, groupSafe []string, isolate bool) (*config_parser.Item, error) {
	if len(f.Use) > 0 {
		return nil, fmt.Errorf("group %q cannot be converted: proxy provider members are unsupported", name)
	}
	if len(f.Proxies) == 0 {
		return nil, fmt.Errorf("group %q has no members", name)
	}

	var filters []*config_parser.Item
	var selection []string
	seen := make(map[string]struct{}, len(f.Proxies))
	for _, member := range f.Proxies {
		if _, dup := seen[member]; dup {
			return nil, fmt.Errorf("group %q repeats member %q", name, member)
		}
		seen[member] = struct{}{}
		var fn, ref string
		switch {
		case member == "DIRECT":
			fn, ref = "group", "direct"
		case member == "REJECT":
			fn, ref = "group", "block"
		case hasKey(groupIndex, member):
			fn, ref = "group", groupSafe[groupIndex[member]]
		case hasKey(nodeSafe, member):
			fn, ref = "name", nodeSafe[member]
		default:
			return nil, fmt.Errorf("group %q has unknown member %q", name, member)
		}
		if strings.ContainsAny(ref, "\x00\r\n") || (strings.Contains(ref, "'") && strings.Contains(ref, `"`)) {
			return nil, fmt.Errorf("group %q member %q cannot be represented in dae config", name, member)
		}
		filters = append(filters, funcParam("filter", fn, ref))
		selection = append(selection, ref)
	}

	policy, err := groupPolicy(f.Type, selection)
	if err != nil {
		return nil, fmt.Errorf("group %q cannot be converted: %w", name, err)
	}

	var items []*config_parser.Item
	if q := f.Quality; q != nil {
		if q.Mode != "off" && q.Mode != "observe" && q.Mode != "enforce" {
			return nil, fmt.Errorf("group %q: invalid x-kdae-quality mode", name)
		}
		if q.Mode != "off" && f.Type != "fallback" && f.Type != "url-test" {
			return nil, fmt.Errorf("group %q: quality requires fallback or url-test", name)
		}
		severe, recovery := 0.3, 0.6
		if q.SevereRatio != nil {
			severe = *q.SevereRatio
		}
		if q.RecoveryRatio != nil {
			recovery = *q.RecoveryRatio
		}
		if math.IsNaN(severe) || math.IsNaN(recovery) || !(severe > 0 && recovery > severe && recovery <= 1) {
			return nil, fmt.Errorf("group %q: invalid quality ratios", name)
		}
		items = append(items, param("quality_mode", q.Mode))
		if q.MinDownloadBytes != nil {
			items = append(items, param("quality_min_download_bytes", strconv.FormatUint(*q.MinDownloadBytes, 10)))
		}
		if q.SevereRatio != nil {
			items = append(items, param("severe_speed_ratio", strconv.FormatFloat(*q.SevereRatio, 'g', -1, 64)))
		}
		if q.RecoveryRatio != nil {
			items = append(items, param("recovery_speed_ratio", strconv.FormatFloat(*q.RecoveryRatio, 'g', -1, 64)))
		}
	}
	if isolate {
		items = append(items, param("isolate_transport", "true"))
	}
	// Every fixed policy persists its member identities; a lone url-test
	// member is lowered to fixed(0) because there is no latency choice.
	if strings.HasPrefix(policy, "fixed(") {
		items = append(items, param("selection_members", strings.Join(selection, ",")))
	}
	if f.URL != nil {
		items = append(items, param("tcp_check_url", *f.URL))
	}
	if f.Interval != nil {
		items = append(items, param("check_interval", fmt.Sprintf("%ds", *f.Interval)))
	}
	if f.Tolerance != nil {
		items = append(items, param("check_tolerance", fmt.Sprintf("%dms", *f.Tolerance)))
	}
	if f.Lazy != nil {
		items = append(items, param("lazy", strconv.FormatBool(*f.Lazy)))
	}
	// One filter per member keeps Mihomo order: a combined name('a','b') is
	// only an OR match, so node-list order would win for first_alive.
	items = append(items, filters...)
	items = append(items, policyItem(policy))
	return &config_parser.Item{
		Type:  config_parser.ItemType_Section,
		Value: &config_parser.Section{Name: safe, Items: items},
	}, nil
}

func groupPolicy(groupType string, selection []string) (string, error) {
	switch strings.ToLower(groupType) {
	case "select":
		// selection_members plus the persisted user choice is the Mihomo
		// select identity; fixed(0) is only the initial fallback.
		return "fixed(0)", nil
	case "fallback":
		// Declaration order plus Alive/Degraded/Dead admission is the
		// complete mapping, not an approximation of first_alive.
		return "fallback", nil
	case "url-test":
		if len(selection) == 1 && selection[0] == "direct" {
			return "fixed(0)", nil
		}
		return "url_test", nil
	}
	return "", fmt.Errorf("group type %q is unsupported", groupType)
}

func validateGroupHealth(f groupFields) error {
	if f.URL != nil {
		raw := *f.URL
		if raw == "" || strings.TrimSpace(raw) != raw {
			return errors.New("url must be a non-empty absolute URL")
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return errors.New("url is invalid")
		}
		if scheme := strings.ToLower(parsed.Scheme); scheme != "http" && scheme != "https" {
			return fmt.Errorf("url scheme %q is unsupported; only http and https are allowed", parsed.Scheme)
		}
		if parsed.Hostname() == "" {
			return errors.New("url must include a host")
		}
		if strings.ContainsAny(raw, "\x00\r\n") || (strings.Contains(raw, "'") && strings.Contains(raw, `"`)) {
			return errors.New("url cannot be represented in dae config")
		}
	}
	if f.Interval != nil {
		if err := checkDuration(*f.Interval, time.Second, "interval", false); err != nil {
			return err
		}
	}
	if f.Tolerance != nil {
		if err := checkDuration(*f.Tolerance, time.Millisecond, "tolerance", true); err != nil {
			return err
		}
	}
	return nil
}

func checkDuration(value int64, unit time.Duration, field string, allowZero bool) error {
	if value < 0 || (!allowZero && value == 0) {
		if allowZero {
			return fmt.Errorf("%s must be non-negative", field)
		}
		return fmt.Errorf("%s must be greater than zero", field)
	}
	if value > int64(time.Duration(math.MaxInt64)/unit) {
		return fmt.Errorf("%s duration overflows", field)
	}
	return nil
}

// checkGroupGraph rejects nested-group cycles and chains deeper than
// maxNestedGroupDepth; the document is untrusted input.
func checkGroupGraph(entries []Entry, fields []groupFields, byName map[string]int) error {
	const (
		unseen = iota
		visiting
		visited
	)
	state := make([]int, len(entries))
	var visit func(i, depth int) error
	visit = func(i, depth int) error {
		if depth > maxNestedGroupDepth {
			return fmt.Errorf("nested group depth exceeds %d at %q", maxNestedGroupDepth, entries[i].Name)
		}
		switch state[i] {
		case visiting:
			return fmt.Errorf("nested group cycle includes %q", entries[i].Name)
		case visited:
			return nil
		}
		state[i] = visiting
		for _, member := range fields[i].Proxies {
			if child, nested := byName[member]; nested {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
		}
		state[i] = visited
		return nil
	}
	for i := range entries {
		if err := visit(i, 1); err != nil {
			return err
		}
	}
	return nil
}

// ---- AST helpers ----

func param(key, val string) *config_parser.Item {
	return &config_parser.Item{
		Type:  config_parser.ItemType_Param,
		Value: &config_parser.Param{Key: key, Val: val},
	}
}

func funcParam(key, fn, arg string) *config_parser.Item {
	return &config_parser.Item{
		Type: config_parser.ItemType_Param,
		Value: &config_parser.Param{Key: key, AndFunctions: []*config_parser.Function{{
			Name:   fn,
			Params: []*config_parser.Param{{Val: arg}},
		}}},
	}
}

// policyItem builds the policy param the way dae's parser does: fixed(N) is a
// function, bare names such as fallback and url_test are plain strings.
func policyItem(policy string) *config_parser.Item {
	if arg, ok := strings.CutPrefix(policy, "fixed("); ok {
		return funcParam("policy", "fixed", strings.TrimSuffix(arg, ")"))
	}
	return param("policy", policy)
}

func hasKey[V any](m map[string]V, key string) bool {
	_, ok := m[key]
	return ok
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
		if n.Content[i].Tag == "!!merge" {
			if v := mappingValue(n.Content[i+1], key); v != nil {
				return v
			}
		}
	}
	return nil
}
