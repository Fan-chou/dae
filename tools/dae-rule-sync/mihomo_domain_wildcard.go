package main

import (
	"fmt"
	"regexp"
	"strings"
)

// mihomoDomainWildcardRegex converts Mihomo's limited DOMAIN-WILDCARD
// language to the full-string regular expression consumed by kdae's domain
// matcher. kdae normalizes the runtime domain to lower case, so normalize the
// source pattern before quoting its literal characters as well.
func mihomoDomainWildcardRegex(pattern string) (string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", fmt.Errorf("DOMAIN-WILDCARD has an empty pattern")
	}

	var expression strings.Builder
	expression.Grow(len(pattern) + 2)
	expression.WriteByte('^')
	for _, character := range strings.ToLower(pattern) {
		switch character {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteByte('.')
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	expression.WriteByte('$')
	return expression.String(), nil
}
