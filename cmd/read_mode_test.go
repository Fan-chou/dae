/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/config"
)

// The service script validates before every start, so `dae validate` must not
// depend on the uplink; a cold start may reuse what is still fresh, a reload
// must always look.
func TestReadModesSayHowFarTheCacheMayAnswer(t *testing.T) {
	if readValidate.cache != ruleprovider.CacheOnly {
		t.Fatalf("validate cache mode = %v, want CacheOnly", readValidate.cache)
	}
	if readColdStart.cache != ruleprovider.CacheReuseFresh {
		t.Fatalf("cold start cache mode = %v, want CacheReuseFresh", readColdStart.cache)
	}
	if readStrict.cache != ruleprovider.CacheNever {
		t.Fatalf("reload cache mode = %v, want CacheNever", readStrict.cache)
	}
	if readValidate.fetchGeodata {
		t.Fatal("validate must not download the dat files")
	}
}

func TestGeodataFreshNeedsEveryNamedFileWithinTheInterval(t *testing.T) {
	dir := t.TempDir()
	g := config.Geodata{GeoIP: "https://example.com/geoip.dat", GeoSite: "https://example.com/geosite.dat", Interval: time.Hour}
	if geodataFresh(g, dir) {
		t.Fatal("fresh with no files")
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !geodataFresh(g, dir) {
		t.Fatal("not fresh with both files just written")
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "geosite.dat"), old, old); err != nil {
		t.Fatal(err)
	}
	if geodataFresh(g, dir) {
		t.Fatal("fresh although one file is older than the interval")
	}
	g.GeoSite = "" // a file the section does not name does not count
	if !geodataFresh(g, dir) {
		t.Fatal("an unnamed old file made the section stale")
	}
	g.Interval = 0
	if geodataFresh(g, dir) {
		t.Fatal("a zero interval must never count as fresh")
	}
}
