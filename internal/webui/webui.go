// Package webui embeds the built frontend and serves it as an SPA. The
// base path is applied at RUNTIME by rewriting index.html's <base href> —
// prior-art UIs bake it in at build time, which forces image rebuilds just
// to serve under /admin.
package webui

import (
	"bytes"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"
)

// dist holds the Vite build output. A placeholder index.html is committed so
// the backend builds and tests without a frontend build; the Dockerfile
// overwrites it with the real bundle.
//
//go:embed all:dist
var dist embed.FS

// SPAHandler serves static assets with an index.html fallback for
// client-side routes. basePath is "" or "/sub/path" (no trailing slash).
func SPAHandler(basePath string, log *slog.Logger) http.HandlerFunc {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // embed layout is fixed at compile time
	}
	fileServer := http.FileServer(http.FS(sub))

	// index.html is rewritten once at startup: <base href> lets all
	// relative asset URLs and the router work under any BASE_PATH.
	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("webui: dist/index.html missing from embed")
	}
	baseHref := basePath + "/"
	indexHTML = bytes.Replace(indexHTML,
		[]byte(`<base href="/">`),
		[]byte(`<base href="`+baseHref+`">`), 1)
	modTime := time.Now()

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" && p != "index.html" {
			if _, err := fs.Stat(sub, p); err == nil {
				// Hashed Vite assets are immutable; cache aggressively.
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// SPA fallback.
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "index.html", modTime, bytes.NewReader(indexHTML))
	}
}
