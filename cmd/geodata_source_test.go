package cmd

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func sampleSiteDat(t *testing.T, codes ...string) []byte {
	t.Helper()
	list := &geodata.GeoSiteList{}
	for _, code := range codes {
		list.Entry = append(list.Entry, &geodata.GeoSite{
			CountryCode: code,
			Domain:      []*geodata.Domain{{Type: geodata.Domain_RootDomain, Value: strings.ToLower(code) + ".example.com"}},
		})
	}
	body, err := proto.Marshal(list)
	require.NoError(t, err)
	return body
}

func stubGeodataFetch(t *testing.T, bodies map[string][]byte) {
	t.Helper()
	saved := fetchGeodataDocument
	t.Cleanup(func() { fetchGeodataDocument = saved })
	fetchGeodataDocument = func(_ context.Context, p config.RuleProvider, _ string, _ *http.Client, validate func([]byte) error) (ruleprovider.Document, error) {
		body, ok := bodies[p.URL]
		if !ok {
			return ruleprovider.Document{}, errors.New("Get " + p.URL + ": connection refused")
		}
		if err := validate(body); err != nil {
			return ruleprovider.Document{}, err
		}
		return ruleprovider.Document{Body: body}, nil
	}
}

func TestValidateDatFileAcceptsDatAndRejectsOthers(t *testing.T) {
	validate := validateDatFile(t.TempDir())
	require.NoError(t, validate(sampleSiteDat(t, "CN", "US")))
	require.Error(t, validate([]byte("<html>404 not found</html>")))
	good := sampleSiteDat(t, "CN", "US")
	require.Error(t, validate(good[:len(good)-5]), "a truncated download must not pass")
	require.Error(t, validate(nil))
}

func TestSyncGeodataInstallsAndKeepsTheOldCopyOnFailure(t *testing.T) {
	dir := t.TempDir()
	first := sampleSiteDat(t, "CN")
	stubGeodataFetch(t, map[string][]byte{"https://geo.example.com/geosite.dat": first})
	g := config.Geodata{GeoSite: "https://geo.example.com/geosite.dat", MaxSize: config.GeodataDefaultMaxSize}

	changed, err := syncGeodata(context.Background(), g, dir, nil)
	require.NoError(t, err)
	require.True(t, changed)
	got, err := os.ReadFile(filepath.Join(dir, "geosite.dat"))
	require.NoError(t, err)
	require.Equal(t, first, got)
	require.Nil(t, CurrentGeodataStatus().GeoIP)
	require.True(t, CurrentGeodataStatus().GeoSite.Present)

	// Same content again: nothing to reload for.
	changed, err = syncGeodata(context.Background(), g, dir, nil)
	require.NoError(t, err)
	require.False(t, changed)

	// The source goes away, then serves garbage: the copy stays, the error is
	// reported, and the token in the URL does not leak into it.
	g.GeoSite = "https://geo.example.com/tok-SECRET/geosite.dat"
	stubGeodataFetch(t, map[string][]byte{})
	changed, err = syncGeodata(context.Background(), g, dir, nil)
	require.Error(t, err)
	require.False(t, changed)
	require.NotContains(t, err.Error(), "SECRET")
	require.NotContains(t, CurrentGeodataStatus().GeoSite.Error, "SECRET")
	require.True(t, CurrentGeodataStatus().GeoSite.Present)

	stubGeodataFetch(t, map[string][]byte{g.GeoSite: []byte("not a dat file")})
	_, err = syncGeodata(context.Background(), g, dir, nil)
	require.Error(t, err)
	got, _ = os.ReadFile(filepath.Join(dir, "geosite.dat"))
	require.Equal(t, first, got, "an invalid download replaced the good copy")

	// A newer valid file replaces it.
	second := sampleSiteDat(t, "CN", "JP")
	stubGeodataFetch(t, map[string][]byte{g.GeoSite: second})
	changed, err = syncGeodata(context.Background(), g, dir, nil)
	require.NoError(t, err)
	require.True(t, changed)
	got, _ = os.ReadFile(filepath.Join(dir, "geosite.dat"))
	require.Equal(t, second, got)

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		require.NotContains(t, e.Name(), ".geodata-", "temporary file left behind")
	}
}

func TestReadConfigFetchesGeodataAtStartupButNotOnReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.dae")
	require.NoError(t, os.WriteFile(path, []byte(`global {}
geodata { geosite: 'https://geo.example.com/geosite.dat' }
routing { fallback: direct }
`), 0o600))
	calls := 0
	saved := fetchGeodataDocument
	t.Cleanup(func() { fetchGeodataDocument = saved })
	body := sampleSiteDat(t, "CN")
	fetchGeodataDocument = func(_ context.Context, _ config.RuleProvider, _ string, _ *http.Client, _ func([]byte) error) (ruleprovider.Document, error) {
		calls++
		return ruleprovider.Document{Body: body}, nil
	}
	_, _, err := readConfigAtStartup(path)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	_, _, err = readConfig(path)
	require.NoError(t, err)
	require.Equal(t, 1, calls, "a reload fetched again although the file is there")

	require.NoError(t, os.Remove(filepath.Join(dir, "geosite.dat")))
	_, _, err = readConfig(path)
	require.NoError(t, err)
	require.Equal(t, 2, calls, "a reload did not fill in a missing file")
}

func TestGeodataIntervalJoinsTheRefreshSchedule(t *testing.T) {
	conf := &config.Config{Geodata: config.Geodata{GeoIP: "https://geo.example.com/geoip.dat", Interval: 48 * 3600 * 1e9}}
	require.Equal(t, conf.Geodata.Interval, ruleProviderRefreshInterval(conf))
}
