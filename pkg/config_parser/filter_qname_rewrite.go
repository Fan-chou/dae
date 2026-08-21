/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"strings"
	"unicode"
)

// rewriteBareQnameInFilterBlocks turns `qname(...)` inside `filter { }` into
// `qname(...) -> skip` so the dae-config grammar (which requires an outbound)
// can parse the FakeIP filter form from the design doc.
func rewriteBareQnameInFilterBlocks(src string) string {
	const needle = "filter"
	var out strings.Builder
	i := 0
	for i < len(src) {
		j := strings.Index(src[i:], needle)
		if j < 0 {
			out.WriteString(src[i:])
			break
		}
		j += i
		if j > 0 && isFilterIdentChar(rune(src[j-1])) {
			out.WriteString(src[i : j+len(needle)])
			i = j + len(needle)
			continue
		}
		k := j + len(needle)
		if k < len(src) && isFilterIdentChar(rune(src[k])) {
			out.WriteString(src[i : j+len(needle)])
			i = j + len(needle)
			continue
		}
		for k < len(src) && unicode.IsSpace(rune(src[k])) {
			k++
		}
		if k >= len(src) || src[k] != '{' {
			out.WriteString(src[i : j+len(needle)])
			i = j + len(needle)
			continue
		}
		end, ok := matchBrace(src, k)
		if !ok {
			out.WriteString(src[i:])
			break
		}
		out.WriteString(src[i : k+1])
		out.WriteString(rewriteBareQnameLines(src[k+1 : end]))
		out.WriteByte('}')
		i = end + 1
	}
	return out.String()
}

func isFilterIdentChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func matchBrace(src string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func rewriteBareQnameLines(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "->") {
			continue
		}
		core := strings.TrimRight(trim, ";")
		if !isBareQnameCall(core) {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = indent + core + " -> skip"
	}
	return strings.Join(lines, "\n")
}

func isBareQnameCall(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "!") {
		s = strings.TrimSpace(s[1:])
	}
	if !strings.HasPrefix(s, "qname(") || !strings.HasSuffix(s, ")") {
		return false
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
			if depth == 0 && i != len(s)-1 {
				return false
			}
		}
	}
	return depth == 0
}
