/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// assignSafeNames maps original names to unique internal dae identifiers.
//
// A name keeps its plain sanitized form (SafeNodeName/SafeGroupName) so that
// state persisted under that identifier stays valid across upgrades. Only
// names that would collide, or that sanitize to a reserved outbound, get a
// suffix derived from their own original text. The suffix does not depend on
// order, so reordering a subscription never renames anything; adding a
// colliding sibling renames the previously unique ones once.
func assignSafeNames(originals []string, safeName func(string) string, pattern *regexp.Regexp, maxLen int) ([]string, error) {
	base := make([]string, len(originals))
	count := make(map[string]int, len(originals))
	for i, name := range originals {
		base[i] = safeName(name)
		count[base[i]]++
	}
	out := make([]string, len(originals))
	taken := make(map[string]struct{}, len(originals))
	var pending []int
	for i := range originals {
		if count[base[i]] == 1 && !reservedOutbound(base[i]) {
			out[i] = base[i]
			taken[base[i]] = struct{}{}
			continue
		}
		pending = append(pending, i)
	}
	for _, i := range pending {
		sum := sha256.Sum256([]byte(originals[i]))
		resolved := false
		// Widen the suffix if the shortened form collides with an existing
		// name; 32 hex digits cannot realistically collide.
		for digits := 6; digits <= 32; digits += 2 {
			suffix := fmt.Sprintf("%x", sum[:])[:digits]
			head := strings.Trim(base[i], "_")
			if reservedOutbound(base[i]) || head == "" {
				head = "mihomo"
			}
			if room := maxLen - 1 - len(suffix); len(head) > room {
				head = strings.Trim(head[:room], "_")
			}
			candidate := head + "_" + suffix
			if _, clash := taken[candidate]; clash || !pattern.MatchString(candidate) {
				continue
			}
			out[i] = candidate
			taken[candidate] = struct{}{}
			resolved = true
			break
		}
		if !resolved {
			return nil, fmt.Errorf("cannot derive a unique dae name for %q", originals[i])
		}
	}
	// A plain name may equal a derived one chosen above only if the derived
	// name already avoided every taken plain name; verify the whole result.
	seen := make(map[string]string, len(out))
	for i, name := range out {
		if other, dup := seen[name]; dup {
			return nil, fmt.Errorf("%q and %q map to the same dae name %q", other, originals[i], name)
		}
		seen[name] = originals[i]
	}
	return out, nil
}

func reservedOutbound(name string) bool {
	return name == "direct" || name == "block"
}

// ---- strict field checking ----

// proxyFieldSet is every key a proxy mapping may carry: the fields the
// lowering reads, plus name and type. Anything else could change how traffic
// is carried (dialer-proxy, interface-name, smux, ...); silently dropping it
// would make a conversion look complete while changing its meaning.
var proxyFieldSet = map[string]struct{}{
	"name": {}, "type": {}, "server": {}, "port": {}, "username": {}, "password": {}, "auth": {},
	"cipher": {}, "sni": {}, "servername": {}, "client-fingerprint": {}, "tls": {},
	"skip-cert-verify": {}, "udp": {}, "plugin": {}, "plugin-opts": {}, "up": {}, "down": {},
	"obfs": {}, "obfs-password": {}, "ports": {}, "hop-interval": {}, "fingerprint": {},
	"alpn": {}, "ca": {}, "ca-str": {}, "cwnd": {}, "udp-mtu": {},
}

// firstUnsupportedField returns the first key of mapping (merge keys
// expanded, source order) that is not in allowed.
func firstUnsupportedField(mapping *yaml.Node, allowed map[string]struct{}) (string, bool) {
	for _, key := range mappingKeys(mapping, 0) {
		if _, ok := allowed[key]; !ok {
			return key, true
		}
	}
	return "", false
}

func mappingKeys(n *yaml.Node, depth int) []string {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode || depth > MaxYAMLDepth {
		return nil
	}
	var keys []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		if key.Tag == "!!merge" {
			value = resolve(value)
			switch {
			case value == nil:
			case value.Kind == yaml.SequenceNode:
				for _, item := range value.Content {
					keys = append(keys, mappingKeys(item, depth+1)...)
				}
			default:
				keys = append(keys, mappingKeys(value, depth+1)...)
			}
			continue
		}
		keys = append(keys, key.Value)
	}
	return keys
}
