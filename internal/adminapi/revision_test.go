package adminapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestParseTagEpochWithDash: the epoch is random base64url text, which may
// contain '-'.
func TestParseTagEpochWithDash(t *testing.T) {
	s := &Server{revEpoch: "a-b-c-d1"}
	if n, ok := s.parseTag(s.tag(42)); !ok || n != 42 {
		t.Fatalf("parseTag(%s) = %d %v", s.tag(42), n, ok)
	}
	for _, bad := range []string{`"a-b-c-d1-"`, `"b-c-d1-4"`, `"a-b-c-d1-x"`, `a-b-c-d1-4`, `""`} {
		if _, ok := s.parseTag(bad); ok {
			t.Errorf("parseTag(%s) accepted", bad)
		}
	}
}

func TestObjectOfPattern(t *testing.T) {
	reqtest.Partial(t, "SR-8.9-1")
	mux := http.NewServeMux()
	got := map[string]string{}
	for _, c := range []struct{ pattern, path string }{
		{"POST /api/v1/principals/{id}/suspend", "/api/v1/principals/agent-a/suspend"},
		{"POST /api/v1/principals/{id}/enable", "/api/v1/principals/agent-b/enable"},
		{"POST /api/v1/principals", "/api/v1/principals"},
		{"POST /api/v1/packages/{id}/{rev}/disable", "/api/v1/packages/pkg/3/disable"},
		{"POST /api/v1/research/campaigns/{id}/{action}", "/api/v1/research/campaigns/c1/submit"},
		{"POST /admin/v1/approvals/{id}", "/admin/v1/approvals/ap1"},
		{"POST /api/v1/approvals/{id}/approve", "/api/v1/approvals/ap1/approve"},
		{"DELETE /api/v1/secrets/{name}", "/api/v1/secrets/reload"},
		{"POST /api/v1/secrets/reload", "/api/v1/secrets/reload"},
		{"POST /admin/v1/stop", "/admin/v1/stop"},
		{"POST /admin/v1/resume", "/admin/v1/resume"},
		{"POST /api/v1/policy/rollback", "/api/v1/policy/rollback"},
	} {
		mux.HandleFunc(c.pattern, func(w http.ResponseWriter, r *http.Request) { got[c.pattern] = objectOf(c.pattern, r) })
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, c.path, nil))
		if c.pattern[:7] == "DELETE " {
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, c.path, nil))
		}
	}
	want := map[string]string{
		"POST /api/v1/principals/{id}/suspend":          "principals/{agent-a}",
		"POST /api/v1/principals/{id}/enable":           "principals/{agent-b}",
		"POST /api/v1/principals":                       "principals",
		"POST /api/v1/packages/{id}/{rev}/disable":      "packages/{pkg}/{3}",
		"POST /api/v1/research/campaigns/{id}/{action}": "research/campaigns/{c1}",
		"POST /admin/v1/approvals/{id}":                 "approvals/{ap1}",
		"POST /api/v1/approvals/{id}/approve":           "approvals/{ap1}",
		"DELETE /api/v1/secrets/{name}":                 "secrets/{reload}",
		"POST /api/v1/secrets/reload":                   "secrets/reload",
		"POST /admin/v1/stop":                           "gateway",
		"POST /admin/v1/resume":                         "gateway",
		"POST /api/v1/policy/rollback":                  "policy",
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: object %q, want %q", p, got[p], w)
		}
	}
}

// TestPerObjectRevisions checks that a browser mutation is refused only
// when its own object changed after the revision it names: a change to
// another object (by any client) leaves the tag usable, a change to the
// same object makes it stale, and of two concurrent mutations of one object
// naming the same tag only one passes.
func TestPerObjectRevisions(t *testing.T) {
	reqtest.Partial(t, "SR-8.9-1")
	hash, _ := keys.HashPassword("admin password 12")
	f := newFixture(t, fmt.Sprintf("password_hash = %q", hash))
	var mu sync.Mutex
	touched := map[string]int{}
	f.server.HandleRoles("POST /api/v1/things/{id}/touch", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		touched[r.PathValue("id")]++
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	cookie, csrf, _ := f.browserLogin("")
	br := func(tag string) browserReq { return browserReq{cookie: cookie, csrf: csrf, ifMatch: tag} }
	read := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie}).etag

	// Another client changes thing b and the run state; thing a is unchanged.
	if st, _ := f.do("POST", "/api/v1/things/b/touch", f.operator, map[string]any{}, nil); st != 200 {
		t.Fatalf("bearer touch b: %d", st)
	}
	if st, _ := f.do("POST", "/admin/v1/stop", f.operator, map[string]any{"reason": "drill"}, nil); st != 200 {
		t.Fatalf("bearer stop: %d", st)
	}
	if got := f.browser("POST", "/api/v1/things/a/touch", map[string]any{}, br(read)); got.status != 200 {
		t.Fatalf("unrelated changes made the tag stale: %d %v", got.status, got.body)
	}
	// Thing b changed after the read: refused, with the current ETag and the object named.
	stale := f.browser("POST", "/api/v1/things/b/touch", map[string]any{}, br(read))
	if stale.status != http.StatusPreconditionFailed || stale.body["error"].(map[string]any)["code"] != "revision_stale" {
		t.Fatalf("changed object: %d %v", stale.status, stale.body)
	}
	if touched["b"] != 1 {
		t.Fatalf("refused mutation reached the handler: %v", touched)
	}
	// Re-read (the 412 carries the current ETag): the mutation passes.
	if got := f.browser("POST", "/api/v1/things/b/touch", map[string]any{}, br(stale.etag)); got.status != 200 {
		t.Fatalf("after re-read: %d %v", got.status, got.body)
	}
	if got := f.browser("POST", "/admin/v1/resume", map[string]any{}, br(read)); got.status != http.StatusPreconditionFailed {
		t.Fatalf("resume with a tag older than the stop: %d", got.status)
	}
	// The answer of a mutation names its object and the new tag; the
	// session's own change makes its older tag stale for that object only.
	cur := f.browser("GET", "/admin/v1/health", nil, browserReq{cookie: cookie}).etag
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v1/things/c/touch", nil)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})
	req.Header.Set(CSRFHeader, csrf)
	req.Header.Set("If-Match", cur)
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get(ObjectHeader) != "things/{c}" || resp.Header.Get("ETag") == cur {
		t.Fatalf("mutation answer: %d object %q etag %q", resp.StatusCode, resp.Header.Get(ObjectHeader), resp.Header.Get("ETag"))
	}
	after := resp.Header.Get("ETag")
	if got := f.browser("POST", "/api/v1/things/c/touch", map[string]any{}, br(cur)); got.status != http.StatusPreconditionFailed {
		t.Fatalf("replayed tag on the same object: %d", got.status)
	}
	if got := f.browser("POST", "/api/v1/things/d/touch", map[string]any{}, br(cur)); got.status != 200 {
		t.Fatalf("same tag on another object: %d", got.status)
	}
	if f.server.ObjectRevision("things/{c}") == 0 {
		t.Fatal("object revision not recorded")
	}
	// A tag from the future or from another epoch is refused.
	for _, bad := range []string{`"` + f.server.revEpoch + `-999999"`, `"other-1"`, `W/"x"`, "*"} {
		if got := f.browser("POST", "/api/v1/things/e/touch", map[string]any{}, br(bad)); got.status != http.StatusPreconditionFailed {
			t.Errorf("If-Match %s: %d, want 412", bad, got.status)
		}
	}

	// Concurrent mutations of one object naming the same tag: one passes.
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = f.browser("POST", "/api/v1/things/c/touch", map[string]any{}, br(after)).status
		}(i)
	}
	wg.Wait()
	passed := 0
	for _, c := range codes {
		if c == 200 {
			passed++
		} else if c != http.StatusPreconditionFailed {
			t.Errorf("concurrent mutation: %d", c)
		}
	}
	if passed != 1 {
		t.Fatalf("%d concurrent mutations with one tag passed, want 1: %v", passed, codes)
	}
}
