/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// QuoteLiteral returns s as a quoted config literal that Parse reads back as
// exactly s.
//
// The parser takes the text between the quotes verbatim: it does not resolve
// escape sequences. A backslash only stops the next quote from ending the
// literal, and is itself kept. Go-style quoting (strconv.Quote) therefore
// corrupts any value with a backslash: a regex "\." written as "\\." is read
// back as two backslashes and then matches a literal backslash plus any
// character instead of a dot.
//
// A double-quoted literal is used when s allows it, otherwise a single-quoted
// one. A value that fits neither (it holds both quote kinds, a control
// character, invalid UTF-8, or ends in a backslash that would escape the
// closing quote) has no faithful spelling; it falls back to strconv.Quote so
// callers keep their previous output.
func QuoteLiteral(s string) string {
	for _, quote := range [...]string{`"`, `'`} {
		if quotable(s, quote[0]) {
			return quote + s + quote
		}
	}
	return strconv.Quote(s)
}

func quotable(s string, quote byte) bool {
	if !utf8.ValidString(s) || strings.IndexByte(s, quote) >= 0 || strings.HasSuffix(s, `\`) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
