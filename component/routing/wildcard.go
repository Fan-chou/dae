/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"errors"
	"regexp"
	"strings"
)

// WildcardDomainRegex converts Mihomo's DOMAIN-WILDCARD pattern (* matches any
// run of characters, ? matches one) to the anchored full-string regular
// expression dae's domain matcher takes. dae matches the domain in lower case,
// so the pattern is lowered before its literal characters are quoted.
func WildcardDomainRegex(pattern string) (string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", errors.New("DOMAIN-WILDCARD has an empty pattern")
	}
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range strings.ToLower(pattern) {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return b.String(), nil
}
