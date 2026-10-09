package config_parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func parseOneParam(t *testing.T, literal string) string {
	t.Helper()
	sections, err := Parse("routing {\ndomain(regex: " + literal + ") -> PROXY\n}\n")
	require.NoError(t, err, literal)
	rule := sections[0].Items[0].Value.(*RoutingRule)
	return rule.AndFunctions[0].Params[0].Val
}

func TestQuoteLiteralRoundTripsThroughParser(t *testing.T) {
	for _, value := range []string{
		`plain.example.com`,
		`^.*\.example\.com$`, // the regex the sidecar used to corrupt
		`^a.\.example\..*$`,  // wildcard-derived
		`a\b\\c`,             // backslashes of every kind
		`has"double`,         // forces single quotes
		`has'single`,         // double quotes
		`中文.example.com`,     // non-ASCII is kept as is
		`semi;colon=and&amp`,
		`^(a|b)\d+$`,
	} {
		t.Run(value, func(t *testing.T) {
			require.Equal(t, value, parseOneParam(t, QuoteLiteral(value)))
		})
	}
}

func TestQuoteLiteralKeepsOldOutputForOrdinaryValues(t *testing.T) {
	for _, value := range []string{`example.com`, `1.2.3.0/24`, `a b`, `中文`, ``} {
		require.Equal(t, `"`+value+`"`, QuoteLiteral(value))
	}
}

func TestQuoteLiteralFallsBackWhenNoFaithfulSpelling(t *testing.T) {
	for _, value := range []string{
		`both'and"`,   // both quote kinds
		"line\nbreak", // control character
		`trailing\`,   // backslash would escape the closing quote
		"bad\xffutf8", // invalid UTF-8
	} {
		require.Equal(t, strings.TrimSpace(QuoteLiteral(value)), QuoteLiteral(value))
		require.NotPanics(t, func() { _ = QuoteLiteral(value) })
	}
	// Fallback keeps the old strconv.Quote spelling.
	require.Equal(t, `"line\nbreak"`, QuoteLiteral("line\nbreak"))
}
