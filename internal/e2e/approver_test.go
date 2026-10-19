package e2e

import (
	"encoding/json"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleauth"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/principals"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// TestSessionApproverAccountFlow is FR-2.23's test: the Administrator
// creates a Session Approver from the control API (refused when the
// password is the Administrator's), a harness signs in with it, the
// sign-in page lists client, principal, template and scopes, the session
// records the Session Approver, and the Session Approver's console token
// reaches no control API operation outside the Appendix C rows of its role.
func TestSessionApproverAccountFlow(t *testing.T) {
	reqtest.Verifies(t, "FR-2.23")
	f := start(t, "")
	dir, err := principals.Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.SetDirectory(dir)
	(&principals.Service{Dir: dir, Sessions: f.app.Store, Snapshot: f.app.Decider.Snapshot, Evidence: f.app.Evidence, Log: diag.Discard()}).Register(f.app.Admin)
	consoleauth.New(consoleauth.Options{Config: f.cfg, Evidence: f.app.Evidence, Log: diag.Discard()}).Register(f.app.Admin)
	if _, err := consoleapi.Attach(f.app, diag.Discard()); err != nil {
		t.Fatal(err)
	}

	// The Administrator signs in and creates the account.
	code, out := f.admin("POST", "/admin/v1/login", "", map[string]any{"username": "admin", "password": "admin password 12"})
	adminTok, _ := out["token"].(string)
	if code != 200 || adminTok == "" {
		t.Fatalf("admin login: %d %v", code, out)
	}
	if code, out := f.admin("POST", "/api/v1/approvers", adminTok, map[string]any{"username": "desk", "password": "admin password 12"}); code != 400 || !strings.Contains(out["error"].(map[string]any)["message"].(string), "Administrator") {
		t.Fatalf("approver with the Administrator's password: %d %v", code, out)
	}
	if code, out := f.admin("POST", "/api/v1/approvers", adminTok, map[string]any{"username": "admin", "password": "desk approver pw 1"}); code != 409 {
		t.Fatalf("approver with the Administrator's username: %d %v", code, out)
	}
	if code, out := f.admin("POST", "/api/v1/approvers", adminTok, map[string]any{"username": "desk", "password": "short"}); code != 400 {
		t.Fatalf("short password: %d %v", code, out)
	}
	const deskPW = "desk approver pw 1"
	if code, out := f.admin("POST", "/api/v1/approvers", adminTok, map[string]any{"username": "desk", "password": deskPW}); code != 201 || out["username"] != "desk" || out["source"] != "console" || out["created_by"] != "admin:admin" {
		t.Fatalf("create approver: %d %v", code, out)
	}
	code, out = f.admin("GET", "/api/v1/approvers", adminTok, nil)
	if code != 200 || len(out["approvers"].([]any)) != 2 || strings.Contains(strings.ToLower(jsonString(out)), "argon2") {
		t.Fatalf("list approvers: %d %v", code, out)
	}

	// A harness signs in with the new account; the page names client,
	// principal, template and scope before the approval.
	scope := "smcp:template:rw smcp:purpose:review"
	_, _, body := f.oauthLoginAs(scope, clientID, "desk", deskPW, func(page string) {
		text := html.UnescapeString(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(page, "\n"))
		for _, want := range []string{"Client\n\n" + clientID, "Principal\n\ncc", "Requested template\n\nrw", "Requested scope\n\n" + scope} {
			if !strings.Contains(text, want) {
				t.Errorf("sign-in page lacks %q:\n%s", want, text)
			}
		}
	})
	s := f.app.Store.Get(body["session_id"].(string))
	if s == nil || s.ApprovedBy != "desk" || body["template_id"] != "rw" {
		t.Fatalf("session: %+v %v", s, body)
	}
	if session.TemplateLabel("") == "" {
		t.Fatal("no label for a scope without a template")
	}

	// The Session Approver's console token reaches only its Appendix C rows.
	code, out = f.admin("POST", "/api/v1/console/login", "", map[string]any{"username": "desk", "password": deskPW, "role": "session_approver"})
	deskTok, _ := out["token"].(string)
	if code != 200 || deskTok == "" {
		t.Fatalf("console login: %d %v", code, out)
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	checked := 0
	for _, rt := range f.app.Admin.Routes() {
		if rt.Public || strings.HasSuffix(rt.Path, "/logout") {
			continue
		}
		allowed := false
		for _, r := range rt.Roles {
			allowed = allowed || r == adminapi.RoleSessionApprover
		}
		if allowed {
			continue
		}
		var reqBody any
		if rt.Method != "GET" {
			reqBody = map[string]any{}
		}
		if code, out := f.admin(rt.Method, param.ReplaceAllString(rt.Path, "x"), deskTok, reqBody); code != 403 {
			t.Errorf("%s reached by the Session Approver: %d %v", rt.Pattern, code, out)
		}
		checked++
	}
	if checked < 40 {
		t.Fatalf("only %d routes checked", checked)
	}

	// Removing the account ends its console token and its sign-in.
	if code, out := f.admin("POST", "/api/v1/approvers/approver/remove", adminTok, map[string]any{}); code != 409 {
		t.Fatalf("remove file approver: %d %v", code, out)
	}
	if code, out := f.admin("POST", "/api/v1/approvers/desk/remove", adminTok, map[string]any{"reason": "left"}); code != 200 {
		t.Fatalf("remove: %d %v", code, out)
	}
	if code, _ := f.admin("GET", "/api/v1/console/session", deskTok, nil); code != 401 {
		t.Fatalf("removed approver's token still accepted: %d", code)
	}
	if f.cfg.FindApprover("desk") != nil {
		t.Fatal("removed approver still found")
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
