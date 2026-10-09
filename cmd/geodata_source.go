/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/ruleprovider"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protowire"
)

// GeodataFileStatus is how the last attempt to fetch one dat file went.
type GeodataFileStatus struct {
	Source    string    `json:"source"`
	CheckedAt time.Time `json:"checked_at"`
	// Present says a usable copy is on disk, whether or not this attempt worked.
	Present bool   `json:"present"`
	Error   string `json:"error,omitempty"`
}

// GeodataStatus is the state of the in-process geoip.dat / geosite.dat fetch.
type GeodataStatus struct {
	Enabled bool               `json:"enabled"`
	GeoIP   *GeodataFileStatus `json:"geoip,omitempty"`
	GeoSite *GeodataFileStatus `json:"geosite,omitempty"`
}

var geodataState struct {
	mu     sync.RWMutex
	status GeodataStatus
}

func setGeodataStatus(status GeodataStatus) {
	geodataState.mu.Lock()
	geodataState.status = status
	geodataState.mu.Unlock()
}

// CurrentGeodataStatus returns the state after the last fetch.
func CurrentGeodataStatus() GeodataStatus {
	geodataState.mu.RLock()
	defer geodataState.mu.RUnlock()
	return geodataState.status
}

// fetchGeodataDocument is the download step; tests replace it.
var fetchGeodataDocument = ruleprovider.FetchDocument

// validateDatFile accepts a body only if dae's own reader can walk it from
// start to end: a truncated download or an HTML error page is not a dat file.
func validateDatFile(dir string) func([]byte) error {
	return func(body []byte) error {
		// A dat file is a protobuf list whose every top-level item is an entry
		// (field 1). Walking it end to end catches a download cut short.
		rest, entries := body, 0
		for len(rest) > 0 {
			num, typ, tagLen := protowire.ConsumeTag(rest)
			if tagLen < 0 || num != 1 || typ != protowire.BytesType {
				return errors.New("not a geoip/geosite dat file")
			}
			_, valLen := protowire.ConsumeBytes(rest[tagLen:])
			if valLen < 0 {
				return errors.New("not a geoip/geosite dat file: truncated")
			}
			rest = rest[tagLen+valLen:]
			entries++
		}
		if entries == 0 {
			return errors.New("not a geoip/geosite dat file: empty")
		}
		tmp, err := os.CreateTemp(dir, ".geodata-check-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(body); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		// A code no file has: a readable file ends in "code not found", a
		// broken one fails earlier.
		if _, err := geodata.Decode(tmp.Name(), "\x00"); err == nil || err.Error() != "code not found" {
			return fmt.Errorf("not a geoip/geosite dat file: %v", err)
		}
		return nil
	}
}

// installIfChanged puts body at path, atomically, unless it is already there.
func installIfChanged(path string, body []byte) (bool, error) {
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, body) {
		return false, nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".geodata-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), path)
}

// syncGeodata fetches the configured dat files into dir and reports whether
// any changed. A file that cannot be fetched or does not check out never
// replaces the one in place, and never stops dae from starting: a missing
// file only matters to rules that use it, and says so when they are built.
func syncGeodata(ctx context.Context, g config.Geodata, dir string, client *http.Client) (changed bool, err error) {
	if !g.Enabled() {
		setGeodataStatus(GeodataStatus{})
		return false, nil
	}
	status := GeodataStatus{Enabled: true}
	var errs []error
	for _, file := range []struct {
		name, url string
		into      **GeodataFileStatus
	}{
		{"geoip.dat", g.GeoIP, &status.GeoIP},
		{"geosite.dat", g.GeoSite, &status.GeoSite},
	} {
		if file.url == "" {
			continue
		}
		fs := &GeodataFileStatus{Source: config.RedactURL(file.url), CheckedAt: time.Now()}
		*file.into = fs
		dest := filepath.Join(dir, file.name)
		_, statErr := os.Stat(dest)
		fs.Present = statErr == nil

		spec := config.RuleProvider{Name: "geodata-" + file.name[:len(file.name)-4], Type: "http", URL: file.url, MaxSize: g.MaxSize}
		doc, fetchErr := fetchGeodataDocument(ctx, spec, dir, client, validateDatFile(dir))
		if fetchErr == nil {
			var did bool
			if did, fetchErr = installIfChanged(dest, doc.Body); fetchErr == nil {
				changed = changed || did
				fs.Present = true
			}
		}
		if fetchErr != nil {
			fs.Error = config.ScrubURL(fetchErr.Error(), file.url)
			errs = append(errs, errors.New(file.name+": "+fs.Error))
			logrus.WithField("error", fs.Error).Warnf("[Geodata] %s from %s was not updated; keeping the copy in place", file.name, fs.Source)
		}
	}
	setGeodataStatus(status)
	return changed, errors.Join(errs...)
}
