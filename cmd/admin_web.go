/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"syscall"
)

var adminWebMimeFallback = map[string]string{
	".html":        "text/html; charset=utf-8",
	".htm":         "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".webmanifest": "application/manifest+json; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".gif":         "image/gif",
	".webp":        "image/webp",
	".avif":        "image/avif",
	".ico":         "image/x-icon",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".ttf":         "font/ttf",
	".wasm":        "application/wasm",
	".txt":         "text/plain; charset=utf-8",
	".map":         "application/json; charset=utf-8",
}

func sanitizeWebRelPath(raw string) (string, bool) {
	if strings.ContainsRune(raw, '\\') || strings.ContainsRune(raw, '\x00') {
		return "", false
	}
	trimmed := strings.TrimPrefix(raw, "/")
	if trimmed == "" {
		return "", true
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." || seg == "." || strings.HasPrefix(seg, ".") {
			return "", false
		}
	}
	cleaned := path.Clean("/" + trimmed)
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "." {
		return "", true
	}
	return cleaned, true
}

func openRegularWebFile(root *os.Root, name string) (*os.File, fs.FileInfo, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		_ = f.Close()
		subIndex := path.Join(name, "index.html")
		if name == "" {
			subIndex = "index.html"
		}
		f2, err := root.Open(subIndex)
		if err != nil {
			return nil, nil, err
		}
		info2, err := f2.Stat()
		if err != nil || info2.IsDir() {
			_ = f2.Close()
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, fs.ErrNotExist
		}
		return f2, info2, nil
	}
	return f, info, nil
}

func setAdminWebHeaders(w http.ResponseWriter, filename string) {
	w.Header().Set("X-Frame-Options", "DENY")
	ext := strings.ToLower(path.Ext(filename))
	if ctype := adminWebMimeFallback[ext]; ctype != "" {
		w.Header().Set("Content-Type", ctype)
	} else if ctype := mime.TypeByExtension(ext); ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	if ext == ".html" || ext == ".htm" {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		// Allow conditional revalidation (304 Not Modified) while staying fresh on replacement.
		w.Header().Set("Cache-Control", "no-cache")
	}
}

// serveAdminWebDir serves read-only static files from webDir jailed via os.OpenRoot.
// It returns true if it wrote a response, or false if the target was not found.
func serveAdminWebDir(w http.ResponseWriter, r *http.Request, webDir, relPath string, allowSPAFallback bool) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return true
	}

	safeRel, ok := sanitizeWebRelPath(relPath)
	if !ok {
		http.NotFound(w, r)
		return true
	}

	root, err := os.OpenRoot(webDir)
	if err != nil {
		http.Error(w, "web directory unavailable", http.StatusServiceUnavailable)
		return true
	}
	defer root.Close()

	candidate := safeRel
	if candidate == "" {
		candidate = "index.html"
	}

	f, info, err := openRegularWebFile(root, candidate)
	if err != nil && errors.Is(err, fs.ErrNotExist) && allowSPAFallback && path.Ext(safeRel) == "" {
		f, info, err = openRegularWebFile(root, "index.html")
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		if errors.Is(err, fs.ErrPermission) ||
			errors.Is(err, fs.ErrInvalid) ||
			errors.Is(err, syscall.EXDEV) ||
			errors.Is(err, syscall.ELOOP) ||
			errors.Is(err, syscall.ENOTDIR) ||
			strings.Contains(err.Error(), "escapes from parent") {
			http.NotFound(w, r)
			return true
		}
		http.Error(w, "failed to read web asset", http.StatusInternalServerError)
		return true
	}
	defer f.Close()

	setAdminWebHeaders(w, info.Name())
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
	return true
}
