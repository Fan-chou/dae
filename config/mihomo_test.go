package config

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func newWithMihomo(t *testing.T, body string) (*Config, error) {
	t.Helper()
	sections, err := config_parser.Parse("global {}\n" + body + "\nrouting { fallback: direct }\n")
	require.NoError(t, err)
	return New(sections)
}

func TestMihomoSectionDefaultsAndSubscription(t *testing.T) {
	conf, err := newWithMihomo(t, `mihomo { routing_subscription: 'https://example.com/sub?token=SECRET' }`)
	require.NoError(t, err)
	require.True(t, conf.Mihomo.Enabled())
	require.Equal(t, time.Hour, conf.Mihomo.Interval)
	require.EqualValues(t, MihomoDefaultMaxSize, conf.Mihomo.MaxSize)
	require.NotContains(t, conf.Mihomo.RedactedSource(), "SECRET")
	require.Equal(t, "https://example.com/sub", conf.Mihomo.RedactedSource())
}

func TestMihomoSectionAbsentIsDisabled(t *testing.T) {
	conf, err := newWithMihomo(t, ``)
	require.NoError(t, err)
	require.False(t, conf.Mihomo.Enabled())
}

func TestMihomoSectionFile(t *testing.T) {
	conf, err := newWithMihomo(t, `mihomo { routing_file: 'mihomo.yaml' interval: 30m }`)
	require.NoError(t, err)
	require.Equal(t, "mihomo.yaml", conf.Mihomo.RoutingFile)
	require.Equal(t, 30*time.Minute, conf.Mihomo.Interval)
}

func TestMihomoSectionRejectsBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"both sources":      `mihomo { routing_subscription: 'https://example.com/a' routing_file: 'a.yaml' }`,
		"absolute path":     `mihomo { routing_file: '/etc/passwd' }`,
		"escaping path":     `mihomo { routing_file: '../x.yaml' }`,
		"loopback url":      `mihomo { routing_subscription: 'http://127.0.0.1/a' }`,
		"userinfo url":      `mihomo { routing_subscription: 'https://u:p@example.com/a' }`,
		"bad scheme":        `mihomo { routing_subscription: 'file:///etc/passwd' }`,
		"oversized max":     `mihomo { routing_file: 'a.yaml' max_size: 999999999999 }`,
		"negative interval": `mihomo { routing_file: 'a.yaml' interval: -1h }`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newWithMihomo(t, body)
			require.Error(t, err)
		})
	}
}

func TestMihomoSubscriptionNeverAppearsInErrors(t *testing.T) {
	_, err := newWithMihomo(t, `mihomo { routing_subscription: 'http://127.0.0.1/a?token=SECRET' }`)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "SECRET")
}

func TestMihomoSectionMarshalRoundTrip(t *testing.T) {
	conf, err := newWithMihomo(t, `mihomo { routing_subscription: 'https://example.com/sub?token=SECRET' interval: 2h }`)
	require.NoError(t, err)
	b, err := conf.Marshal(2)
	require.NoError(t, err)
	sections, err := config_parser.Parse(string(b))
	require.NoError(t, err)
	again, err := New(sections)
	require.NoError(t, err)
	require.Equal(t, conf.Mihomo, again.Mihomo)
}

func TestMihomoSectionNodeSettings(t *testing.T) {
	conf, err := newWithMihomo(t, `mihomo {
  routing_file: 'mihomo.yaml'
  isolate_transport_groups: 'PROXY,Region'
  node_resolve_dns {
    'HK 01=8.8.8.8'
    '🇯🇵 日本 01=udp://1.1.1.1:5353'
    jp2: '1.1.1.1:5353'
  }
}`)
	require.NoError(t, err)
	require.Equal(t, []string{"PROXY", "Region"}, conf.Mihomo.IsolateTransportGroups)
	require.Equal(t, map[string]string{"HK 01": "8.8.8.8", "🇯🇵 日本 01": "udp://1.1.1.1:5353", "jp2": "1.1.1.1:5353"}, conf.Mihomo.ResolveDNSMap())

	b, err := conf.Marshal(2)
	require.NoError(t, err)
	sections, err := config_parser.Parse(string(b))
	require.NoError(t, err)
	again, err := New(sections)
	require.NoError(t, err)
	require.Equal(t, conf.Mihomo, again.Mihomo)
}

func TestMihomoNodeSettingsNeedASource(t *testing.T) {
	_, err := newWithMihomo(t, `mihomo { node_resolve_dns { 'n1=8.8.8.8' } }`)
	require.Error(t, err)
}
