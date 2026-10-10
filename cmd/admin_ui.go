/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"net/http"
	"os"
	"path"
	"strings"
)

const (
	adminUIPrefix     = "/kdae-ui/"
	adminUIDefaultDir = "/usr/share/kdae-ui"
)

// adminUIDir is where the built panel lives. The kdae-ui package puts it in
// /usr/share/kdae-ui; KDAE_UI_DIR points a development build somewhere else.
func adminUIDir() string {
	if dir := strings.TrimSpace(os.Getenv("KDAE_UI_DIR")); dir != "" {
		return dir
	}
	return adminUIDefaultDir
}

// adminUIHandler serves the panel next to the API, so the browser sees one
// origin and needs neither a proxy nor CORS. The files are public; the API
// behind them still wants the secret, which the panel asks for.
func adminUIHandler(dir string) http.Handler {
	files := http.StripPrefix(strings.TrimSuffix(adminUIPrefix, "/"), http.FileServer(noListingFS{http.Dir(dir)}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// Built assets carry a content hash in their name; the page that names
		// them must be fetched fresh so an update shows up at once.
		if strings.HasPrefix(r.URL.Path, adminUIPrefix+"assets/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// noListingFS hides directories that have no index.html, so a path like
// /kdae-ui/assets/ is a plain 404 rather than a listing.
type noListingFS struct{ fs http.FileSystem }

func (n noListingFS) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		index, err := n.fs.Open(path.Join(name, "index.html"))
		if err != nil {
			_ = f.Close()
			return nil, os.ErrNotExist
		}
		_ = index.Close()
	}
	return f, nil
}

func registerAdminUI(mux *http.ServeMux) {
	mux.Handle(adminUIPrefix, adminUIHandler(adminUIDir()))
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, adminUIPrefix, http.StatusFound)
	})
}
