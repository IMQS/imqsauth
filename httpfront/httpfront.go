package httpfront

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

// Static holds the compiled frontend assets produced by `npm run build`.
// The build output directory is configured as `../httpfront/static` in vite.config.ts.
//
//go:embed static
var Static embed.FS

// Handler returns an http.Handler that serves the auth management SPA.
// All requests that don't match a static asset fall back to index.html so
// that the Vue router (if added later) or a simple hash-based navigation works.
//
// Mount it at a prefix, e.g.:
//
//	smux.Handle("/ui/", http.StripPrefix("/ui", Handler()))
func Handler() http.Handler {
	// Sub into the "static" subdirectory so the FS root is the build output.
	sub, err := fs.Sub(Static, "static")
	if err != nil {
		// Should only happen if the embed path is wrong – panic at startup.
		panic("httpfront: failed to sub static FS: " + err.Error())
	}

	indexHTML := readRawIndex(sub)
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		// Serve index.html for the root and any unknown paths (SPA routing).
		// No server-side patching needed: the TypeScript derives the API base
		// from window.location.pathname at runtime, so it is always correct
		// regardless of any reverse-proxy prefix.
		if path == "" || path == "index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexHTML)
			return
		}

		if _, err := sub.Open(path); err != nil {
			// Asset not found – fall back to the SPA entry point.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexHTML)
			return
		}

		fileServer.ServeHTTP(w, r)
	})
}

// readRawIndex reads and returns the raw bytes of static/index.html.
func readRawIndex(sub fs.FS) []byte {
	f, err := sub.Open("index.html")
	if err != nil {
		panic("httpfront: index.html not found in embedded FS: " + err.Error())
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	if err != nil {
		panic("httpfront: failed to read index.html: " + err.Error())
	}
	return raw
}
