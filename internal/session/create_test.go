package session

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// codeFor signs in with the given scope and returns an authorization code.
func (f *oauthFixture) codeFor(scope string) string {
	f.t.Helper()
	v := f.authorizeForm("ethan", "approver password 1")
	v.Set("scope", scope)
	r := f.postForm(pathAuthorize, v)
	r.Body.Close()
	loc, _ := url.Parse(r.Header.Get("Location"))
	if r.StatusCode != 302 || loc.Query().Get("code") == "" {
		f.t.Fatalf("authorize %q: %d %s", scope, r.StatusCode, loc)
	}
	return loc.Query().Get("code")
}

// tokenWith redeems code with extra form fields.
func (f *oauthFixture) tokenWith(code string, extra url.Values) (int, map[string]any) {
	f.t.Helper()
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifier}, "resource": {f.resource}}
	for k, vs := range extra {
		v[k] = vs
	}
	r := f.postForm(pathToken, v)
	defer r.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	return r.StatusCode, body
}

// sessionAPI calls the FR-2.2 session API as the helper client.
func (f *oauthFixture) sessionAPI(body string) (int, map[string]any) {
	f.t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+pathSessions, strings.NewReader(body))
	req.SetBasicAuth("helper", "helper-secret-123")
	req.Header.Set("Content-Type", "application/json")
	r, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer r.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

// gatewayErr returns the smcp_error member of an OAuth error body.
func gatewayErr(body map[string]any) (int, string, string) {
	e, _ := body["smcp_error"].(map[string]any)
	code, _ := e["code"].(float64)
	reason, _ := e["reasonCode"].(string)
	msg, _ := e["message"].(string)
	return int(code), reason, msg
}

// TestSessionCreateFields is FR-2.3: both create paths (the token endpoint
// of FR-2.20 and the session API of FR-2.2) accept harness type, harness
// version, purpose tag, project root, end-user claim and requested
// template, each optional field present and absent, and the session stores
// what was sent. A request without a harness type stores the principal's
// framework type. The creation event records the same values.
func TestSessionCreateFields(t *testing.T) {
	reqtest.Verifies(t, "FR-2.3")
	f := newOAuthFixture(t, authguard.Config{})
	f.oauth.cfg.Limits.SessionsPerPrincipal = 32
	check := func(name, id string, want Session) {
		t.Helper()
		s := f.store.Get(id)
		if s == nil {
			t.Fatalf("%s: session %q not stored", name, id)
		}
		if s.HarnessType != want.HarnessType || s.HarnessVersion != want.HarnessVersion || s.Purpose != want.Purpose ||
			s.Project != want.Project || s.EndUser != want.EndUser || s.Template != want.Template {
			t.Fatalf("%s: stored %+v, want %+v", name, *s, want)
		}
		var found bool
		for _, e := range f.rec.Events() {
			if e.Class == "session" && e.SessionID == id && e.Outcome == "created" {
				d, _ := e.Detail.(map[string]string)
				found = d["harness_type"] == want.HarnessType && d["harness_version"] == want.HarnessVersion && d["purpose"] == want.Purpose &&
					d["project_root"] == want.Project && d["end_user"] == want.EndUser && d["template"] == want.Template
			}
		}
		if !found {
			t.Fatalf("%s: the creation event does not record the fields", name)
		}
	}

	// Token endpoint: everything, then only the required fields.
	st, body := f.tokenWith(f.codeFor("smcp:template:rw smcp:purpose:review smcp:project:/w/p smcp:user:ethan"),
		url.Values{"harness_type": {"claude-code"}, "harness_version": {"2.1.0"}})
	if st != 200 {
		t.Fatalf("token endpoint, all fields: %d %v", st, body)
	}
	check("token endpoint, all fields", body["session_id"].(string),
		Session{HarnessType: "claude-code", HarnessVersion: "2.1.0", Purpose: "review", Project: "/w/p", EndUser: "ethan", Template: "rw"})
	st, body = f.tokenWith(f.codeFor("smcp:purpose:triage"), url.Values{"harness_version": {"2.1.1"}})
	if st != 200 {
		t.Fatalf("token endpoint, required fields: %d %v", st, body)
	}
	check("token endpoint, required fields", body["session_id"].(string),
		Session{HarnessType: "claude-code", HarnessVersion: "2.1.1", Purpose: "triage", Template: "ro"})

	// Session API.
	st, body = f.sessionAPI(`{"harness_type":"hermes","harness_version":"0.9","purpose":"ops","project_root":"/w/q","end_user":"sam","template_id":"rw"}`)
	if st != 201 {
		t.Fatalf("session API, all fields: %d %v", st, body)
	}
	check("session API, all fields", body["session_id"].(string),
		Session{HarnessType: "hermes", HarnessVersion: "0.9", Purpose: "ops", Project: "/w/q", EndUser: "sam", Template: "rw"})
	st, body = f.sessionAPI(`{"harness_type":"hermes","harness_version":"1.0","purpose":"ops"}`)
	if st != 201 {
		t.Fatalf("session API, required fields: %d %v", st, body)
	}
	check("session API, required fields", body["session_id"].(string),
		Session{HarnessType: "hermes", HarnessVersion: "1.0", Purpose: "ops", Template: "ro"})
}

// TestTemplateSelectionAndSessionLimitErrors is FR-2.6 and FR-2.10 on both
// create paths: a permitted template is selected, no template selects the
// Framework Profile's default, and a template the profile does not permit is
// refused with Gateway error -31001; creating one session more than the
// CP-18 limit is refused with -31005, and ending a session frees its slot.
// The OAuth endpoints answer in the RFC 6749 error format and carry the
// Gateway error in smcp_error, with the Appendix B reason code and message.
func TestTemplateSelectionAndSessionLimitErrors(t *testing.T) {
	reqtest.Verifies(t, "FR-2.6", "FR-2.10")
	f := newOAuthFixture(t, authguard.Config{})
	f.oauth.cfg.Limits.SessionsPerPrincipal = 3

	st, body := f.tokenWith(f.codeFor("smcp:template:rw"), nil)
	if st != 200 || body["template_id"] != "rw" {
		t.Fatalf("permitted template: %d %v", st, body)
	}
	first := body["session_id"].(string)
	if st, body = f.sessionAPI(`{"harness_version":"1"}`); st != 201 || body["template_id"] != "ro" {
		t.Fatalf("default template: %d %v", st, body)
	}
	// Not permitted, on both paths.
	st, body = f.tokenWith(f.codeFor("smcp:template:nope"), nil)
	if code, reason, msg := gatewayErr(body); st != 400 || body["error"] != "invalid_scope" || code != -31001 || reason != ReasonTemplateNotPermitted || msg == "" {
		t.Fatalf("token endpoint, template not permitted: %d %v", st, body)
	}
	st, body = f.sessionAPI(`{"template_id":"nope"}`)
	if code, reason, _ := gatewayErr(body); st != 400 || code != -31001 || reason != ReasonTemplateNotPermitted {
		t.Fatalf("session API, template not permitted: %d %v", st, body)
	}

	// The limit: two sessions exist; the third fills it; the fourth is refused.
	if st, body = f.sessionAPI(`{}`); st != 201 {
		t.Fatalf("third session: %d %v", st, body)
	}
	st, body = f.sessionAPI(`{}`)
	if code, reason, msg := gatewayErr(body); st != 429 || code != -31005 || reason != ReasonSessionLimit || msg == "" {
		t.Fatalf("session API over the limit: %d %v", st, body)
	}
	st, body = f.tokenWith(f.codeFor(""), nil)
	if code, reason, _ := gatewayErr(body); st != 429 || code != -31005 || reason != ReasonSessionLimit {
		t.Fatalf("token endpoint over the limit: %d %v", st, body)
	}
	if !f.store.Terminate(first) {
		t.Fatal("terminate")
	}
	if st, body = f.sessionAPI(`{}`); st != 201 {
		t.Fatalf("after a session ended: %d %v", st, body)
	}
}

// TestSessionErrorMessagesMatchAppendixB: the data.message texts of the
// session create errors are those of the Appendix B reason-code table
// (FR-1.51).
func TestSessionErrorMessagesMatchAppendixB(t *testing.T) {
	reqtest.Partial(t, "FR-1.51")
	raw, err := os.ReadFile(filepath.Join("..", "..", "srs_build", "appendix.md"))
	if err != nil {
		t.Fatal(err)
	}
	for reason, msg := range sessionErrorMessages {
		var row string
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "| `"+reason+"` |") {
				row = line
			}
		}
		cells := strings.Split(strings.Trim(row, "|"), "|")
		if len(cells) < 4 || strings.TrimSpace(cells[len(cells)-1]) != msg {
			t.Errorf("%s: Appendix B row %q, message %q", reason, row, msg)
		}
	}
}
