package adminapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type browserReq struct {
	cookie, csrf, ifMatch string
	background            bool
	extra                 map[string]string
}

type browserResp struct {
	status int
	body   map[string]any
	etag   string
	set    []*http.Cookie
}

func (f *fixture) browser(method, path string, body any, o browserReq) browserResp {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if o.cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: o.cookie})
	}
	if o.csrf != "" {
		req.Header.Set(CSRFHeader, o.csrf)
	}
	if o.ifMatch != "" {
		req.Header.Set("If-Match", o.ifMatch)
	}
	if o.background {
		req.Header.Set(BackgroundHeader, "1")
	}
	for k, v := range o.extra {
		req.Header.Set(k, v)
	}
	r, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer r.Body.Close()
	out := browserResp{status: r.StatusCode, etag: r.Header.Get("ETag"), set: r.Cookies()}
	_ = json.NewDecoder(r.Body).Decode(&out.body)
	return out
}

func sessionCookieOf(t *testing.T, rs browserResp) *http.Cookie {
	t.Helper()
	for _, c := range rs.set {
		if c.Name == SessionCookie && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie set: %v", rs.set)
	return nil
}

func (f *fixture) browserLogin(old string) (cookie, csrf string, rs browserResp) {
	f.t.Helper()
	rs = f.browser("POST", "/admin/v1/login", map[string]any{"username": "admin", "password": "admin password 12"},
		browserReq{cookie: old, extra: map[string]string{SessionModeHeader: "cookie"}})
	if rs.status != 200 {
		f.t.Fatalf("browser login: %d %v", rs.status, rs.body)
	}
	c := sessionCookieOf(f.t, rs)
	csrf, _ = rs.body["csrf_token"].(string)
	return c.Value, csrf, rs
}

// TestBrowserSessionProfile checks each SR-2.6-1 property of the console
// session. The role of a session is fixed at sign-in; a change of role (the
// only privilege change there is) takes a new sign-in, which rotates the ID
// like any sign-in, as checked below.
func TestBrowserSessionProfile(t *testing.T) {
	reqtest.Verifies(t, "SR-2.6-1")
	hash, _ := keys.HashPassword("admin password 12")
	f := newFixture(t, fmt.Sprintf("password_hash = %q", hash))

	// Without the cookie header the login route still answers a bearer token.
	st, body := f.do("POST", "/admin/v1/login", "", map[string]any{"username": "admin", "password": "admin password 12"}, nil)
	if st != 200 || body["token"] == nil {
		t.Fatalf("bearer login: %d %v", st, body)
	}

	// A pre-login session ID (here one the attacker picked) is not adopted.
	planted := "attacker-chosen-session-id"
	cookie, csrf, rs := f.browserLogin(planted)
	if cookie == planted {
		t.Fatal("pre-login session ID preserved")
	}
	c := sessionCookieOf(t, rs)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || !strings.HasPrefix(c.Name, "__Host-") {
		t.Fatalf("cookie attributes: %+v", c)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(cookie); err != nil || len(raw) != 32 {
		t.Fatalf("session ID is not 256 random bits: %q", cookie)
	}
	if _, ok := rs.body["token"]; ok {
		t.Fatal("browser sign-in returned the bearer token")
	}
	if csrf == "" || rs.body["idle_timeout"] != float64(900) || rs.body["expires_in"] != float64(8*3600) {
		t.Fatalf("session answer: %v", rs.body)
	}
	// The bearer token the login route issued was revoked: no administrator
	// token other than the earlier bearer sign-in remains.
	f.srvMu(func(s *Server) {
		if len(s.sessions) != 1 {
			t.Errorf("bearer sessions after browser sign-in: %d, want 1", len(s.sessions))
		}
	})
	if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie}); got.status != 200 {
		t.Fatalf("cookie request: %d", got.status)
	}
	if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: planted}); got.status != 401 {
		t.Fatalf("planted ID accepted: %d", got.status)
	}

	// Signing in again with a live session rotates the ID and ends the old one.
	cookie2, csrf2, _ := f.browserLogin(cookie)
	if cookie2 == cookie || csrf2 == csrf {
		t.Fatal("session ID or CSRF token not rotated on sign-in")
	}
	if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie}); got.status != 401 {
		t.Fatalf("old session survived a new sign-in: %d", got.status)
	}

	// Logout invalidates at once, also for a request already in flight.
	if got := f.browser("POST", "/admin/v1/session/logout", map[string]any{}, browserReq{cookie: cookie2}); got.status != 403 {
		t.Fatalf("logout without CSRF token: %d", got.status)
	}
	if got := f.browser("POST", "/admin/v1/session/logout", map[string]any{}, browserReq{cookie: cookie2, csrf: csrf2}); got.status != 204 {
		t.Fatalf("logout: %d", got.status)
	}
	if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie2}); got.status != 401 {
		t.Fatalf("session usable after logout: %d", got.status)
	}

	// CP-29 idle limit: background refreshes do not keep a session alive.
	start := f.now
	cookie3, csrf3, _ := f.browserLogin("")
	f.now = start.Add(10 * time.Minute)
	if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie3}); got.status != 200 {
		t.Fatalf("active at 10 min: %d", got.status)
	}
	f.now = start.Add(20 * time.Minute)
	if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie3, background: true}); got.status != 200 {
		t.Fatalf("background at 20 min: %d", got.status)
	}
	f.now = start.Add(25 * time.Minute)
	if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie3}); got.status != 401 {
		t.Fatalf("idle session accepted 15 min after the last user request: %d", got.status)
	}
	_ = csrf3

	// CP-29 absolute limit: steady activity ends at 8 hours.
	start = f.now
	cookie4, _, _ := f.browserLogin("")
	for m := 10; m < 8*60; m += 10 {
		f.now = start.Add(time.Duration(m) * time.Minute)
		if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie4}); got.status != 200 {
			t.Fatalf("active session refused at %d min: %d", m, got.status)
		}
	}
	f.now = start.Add(8 * time.Hour)
	if got := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie4}); got.status != 401 {
		t.Fatalf("session accepted past the absolute limit: %d", got.status)
	}
}

func (f *fixture) srvMu(fn func(s *Server)) {
	s := f.server
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// TestBrowserSessionEndCancelsRequests checks that ending a session stops
// its requests in flight (an open event stream, for example).
func TestBrowserSessionEndCancelsRequests(t *testing.T) {
	reqtest.Partial(t, "SR-2.6-1")
	hash, _ := keys.HashPassword("admin password 12")
	f := newFixture(t, fmt.Sprintf("password_hash = %q", hash))
	started := make(chan struct{})
	f.server.HandleRoles("GET /api/v1/test/stream", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		w.WriteHeader(http.StatusNoContent)
	})
	cookie, csrf, _ := f.browserLogin("")
	done := make(chan int, 1)
	go func() {
		done <- f.browser("GET", "/api/v1/test/stream", nil, browserReq{cookie: cookie}).status
	}()
	<-started
	if got := f.browser("POST", "/admin/v1/session/logout", map[string]any{}, browserReq{cookie: cookie, csrf: csrf}); got.status != 204 {
		t.Fatalf("logout: %d", got.status)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request of an ended session still running")
	}
}

func TestBrowserMutationsNeedCSRFAndIfMatch(t *testing.T) {
	reqtest.Verifies(t, "SR-8.9-1")
	hash, _ := keys.HashPassword("admin password 12")
	f := newFixture(t, fmt.Sprintf("password_hash = %q", hash))
	f.server.HandleRoles("DELETE /api/v1/test/thing", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cookie, csrf, rs := f.browserLogin("")
	tag := rs.etag
	if tag == "" {
		t.Fatal("no ETag on the sign-in answer")
	}
	stop := map[string]any{"reason": "drill"}
	cases := []struct {
		name string
		o    browserReq
		want int
	}{
		{"no CSRF token", browserReq{cookie: cookie, ifMatch: tag}, 403},
		{"wrong CSRF token", browserReq{cookie: cookie, csrf: "wrong", ifMatch: tag}, 403},
		{"no If-Match", browserReq{cookie: cookie, csrf: csrf}, 428},
		{"wildcard If-Match", browserReq{cookie: cookie, csrf: csrf, ifMatch: "*"}, 412},
		{"stale revision", browserReq{cookie: cookie, csrf: csrf, ifMatch: `"stale-0"`}, 412},
	}
	for _, c := range cases {
		if got := f.browser("POST", "/admin/v1/stop", stop, c.o); got.status != c.want {
			t.Errorf("%s: %d, want %d", c.name, got.status, c.want)
		}
		if got := f.browser("DELETE", "/api/v1/test/thing", nil, c.o); got.status != c.want {
			t.Errorf("DELETE %s: %d, want %d", c.name, got.status, c.want)
		}
	}
	if f.ctl.stopped {
		t.Fatal("a refused browser mutation stopped the Gateway")
	}
	if !hasReason(f, "CSRF_TOKEN_INVALID") {
		t.Fatal("CSRF refusal not recorded")
	}
	// The current revision passes once; the same tag is then stale.
	ok := f.browser("POST", "/admin/v1/stop", stop, browserReq{cookie: cookie, csrf: csrf, ifMatch: tag})
	if ok.status != 200 || !f.ctl.stopped {
		t.Fatalf("valid mutation: %d %v", ok.status, ok.body)
	}
	if ok.etag == tag {
		t.Fatal("revision did not advance")
	}
	if got := f.browser("POST", "/admin/v1/resume", map[string]any{}, browserReq{cookie: cookie, csrf: csrf, ifMatch: tag}); got.status != 412 || got.etag != ok.etag {
		t.Fatalf("replayed revision: %d etag %q", got.status, got.etag)
	}
	// A change by another client (smcpctl's bearer token) makes the
	// browser's revision stale.
	if st, _ := f.do("POST", "/admin/v1/resume", f.operator, map[string]any{}, nil); st != 200 {
		t.Fatalf("bearer resume: %d", st)
	}
	if got := f.browser("POST", "/admin/v1/stop", stop, browserReq{cookie: cookie, csrf: csrf, ifMatch: ok.etag}); got.status != 412 {
		t.Fatalf("stale after another client's change: %d", got.status)
	}
	// After re-reading, the mutation passes.
	cur := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie}).etag
	if got := f.browser("POST", "/admin/v1/stop", stop, browserReq{cookie: cookie, csrf: csrf, ifMatch: cur}); got.status != 200 {
		t.Fatalf("after re-read: %d", got.status)
	}
	// Bearer requests need neither (they cannot be sent cross-site).
	if st, _ := f.do("POST", "/admin/v1/resume", f.operator, map[string]any{}, nil); st != 200 {
		t.Fatalf("bearer mutation: %d", st)
	}
}

func hasReason(f *fixture, code string) bool {
	for _, e := range f.rec.Events() {
		if e.ReasonCode == code {
			return true
		}
	}
	return false
}
