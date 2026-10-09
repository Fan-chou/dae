package routing

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWildcardDomainRegex(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    string
		match   []string
		miss    []string
	}{
		{"*.example.com", `^.*\.example\.com$`, []string{"a.example.com", "a.b.example.com"}, []string{"example.com", "aexample.com", "a.example.org"}},
		{"a?.example.*", `^a.\.example\..*$`, []string{"ab.example.com", "a1.example.co.uk"}, []string{"a.example.com", "abc.example.com"}},
		{"Foo+Bar.*.COM", `^foo\+bar\..*\.com$`, []string{"foo+bar.x.com"}, []string{"foobar.x.com"}},
	} {
		got, err := WildcardDomainRegex(tc.pattern)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
		re := regexp.MustCompile(got)
		for _, m := range tc.match {
			require.True(t, re.MatchString(m), "%s should match %s", tc.pattern, m)
		}
		for _, m := range tc.miss {
			require.False(t, re.MatchString(m), "%s should not match %s", tc.pattern, m)
		}
	}
	_, err := WildcardDomainRegex("  ")
	require.Error(t, err)
}
