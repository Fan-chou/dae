package cmd

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/stretchr/testify/require"
)

// GEODATA_LIVE=1 fetches the real files from the network, once.
func TestSyncGeodataLive(t *testing.T) {
	if os.Getenv("GEODATA_LIVE") == "" {
		t.Skip("GEODATA_LIVE is not set")
	}
	dir := t.TempDir()
	g := config.Geodata{
		GeoIP:   "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
		GeoSite: "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
		MaxSize: config.GeodataDefaultMaxSize,
	}
	changed, err := syncGeodata(context.Background(), g, dir, http.DefaultClient)
	require.NoError(t, err)
	require.True(t, changed)
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		st, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		t.Logf("%s: %d bytes", name, st.Size())
	}
	changed, err = syncGeodata(context.Background(), g, dir, http.DefaultClient)
	require.NoError(t, err)
	require.False(t, changed)
}
