package httpfront

import (
	"embed"
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
//	smux.Handle("/auth/ui/", http.StripPrefix("/auth/ui", Handler()))
func Handler() http.Handler {
	// Sub into the "static" subdirectory so the FS root is the build output.
	sub, err := fs.Sub(Static, "static")
	if err != nil {
		// Should only happen if the embed path is wrong – panic at startup.
		panic("httpfront: failed to sub static FS: " + err.Error())
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to find the exact file. If not found, serve index.html so that
		// deep-linked URLs load the SPA and let JavaScript handle routing.
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		if _, err := sub.Open(path); err != nil {
			// Asset not found – fall back to the SPA entry point.
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}

		fileServer.ServeHTTP(w, r)
	})
}
