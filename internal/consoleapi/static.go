package consoleapi

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
)

// ConsoleCSP is the Content-Security-Policy of the console page and its
// assets: scripts, styles, fonts, images and API calls from the admin
// listener only, no inline script or style, no framing, no form posts and
// no remote media (FR-8.26, SR-6.17-1).
const ConsoleCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; " +
	"manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// registerStatic serves the console without bearer authentication (the
// page signs in through the control API). The catch-all pattern "/" has no
// method so that it is less specific than every other route and can never
// conflict with one; the handler itself answers unknown control API paths
// with a JSON 404 and other methods with 405.
func (c *Console) registerStatic(a *adminapi.Server) {
	a.HandlePublic("/", c.serveConsole)
}

func isAPIPath(p string) bool {
	return p == "/api" || p == "/admin" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/admin/")
}

func apiNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "route_not_found", "this Gateway build does not serve "+r.Method+" "+r.URL.Path)
}

func securityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", ConsoleCSP)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
}

// serveConsole serves a file of the built console, or index.html for any
// other path so that deep links (for example /approvals/<id>) open the
// page, which then routes on the client.
func (c *Console) serveConsole(w http.ResponseWriter, r *http.Request) {
	if isAPIPath(r.URL.Path) {
		apiNotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the console page answers GET only")
		return
	}
	securityHeaders(w.Header())
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name != "" && name != "index.html" {
		if b, err := fs.ReadFile(c.d.Assets, name); err == nil {
			ct := mime.TypeByExtension(path.Ext(name))
			if ct == "" {
				ct = "application/octet-stream"
			}
			w.Header().Set("Content-Type", ct)
			if strings.HasPrefix(name, "assets/") {
				// Vite names assets by content hash.
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			_, _ = w.Write(b) //nolint:gosec // G705: the bytes are a file of the embedded build; the request only selects which one
			return
		}
		// A missing file of the build is a 404. Deep links whose last
		// segment has a dot (a package revision such as /library/x/1.2.0,
		// FR-8.28) are page routes, so only build paths count: the assets
		// directory and top-level files.
		if path.Ext(name) != "" && (strings.HasPrefix(name, "assets/") || !strings.Contains(name, "/")) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	b, err := fs.ReadFile(c.d.Assets, "index.html")
	if err != nil {
		http.Error(w, "the console is not built into this binary", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
