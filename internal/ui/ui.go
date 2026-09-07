package ui

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

func Available() bool {
	f, err := embedded.Open("dist/index.html")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func Handler() http.Handler {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil || !Available() {
		return http.HandlerFunc(notBuilt)
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "." || clean == "/" {
			clean = "index.html"
		}

		f, err := sub.Open(clean)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			serveIndex(w, r, sub)
			return
		}
		if stat, err := f.Stat(); err == nil && stat.IsDir() {
			f.Close()
			serveIndex(w, r, sub)
			return
		}
		f.Close()

		if strings.HasPrefix(clean, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		notBuilt(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(index)
}

func notBuilt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>XeronMX</title>
<style>
 body{font:16px/1.6 system-ui,sans-serif;max-width:42rem;margin:12vh auto;padding:0 1.5rem;color:#1a1a1a}
 code{background:#f4f4f5;padding:.15em .4em;border-radius:4px;font-size:.9em}
 pre{background:#f4f4f5;padding:1rem;border-radius:8px;overflow-x:auto}
 a{color:#2563eb}
 @media(prefers-color-scheme:dark){body{background:#111;color:#eee}code,pre{background:#1e1e21}}
</style></head><body>
<h1>XeronMX is running</h1>
<p>The daemon is up, but this binary was built without the web interface.</p>
<pre>make ui      # build the assets
make build   # rebuild the binary</pre>
<p>The REST API works either way, under <code>/api/v1</code>. See the
<a href="https://github.com/xeron-be/xeron-mx#install">README</a> for the setup
sequence with <code>curl</code>.</p>
</body></html>`))
}
