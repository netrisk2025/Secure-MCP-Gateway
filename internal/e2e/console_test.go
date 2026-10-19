package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/consoleapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestConsoleOnRunningGateway attaches the console to a started Gateway as
// cmd/smcpd does, serves the embedded build and terminates a real OAuth
// session through the console route.
func TestConsoleOnRunningGateway(t *testing.T) {
	// FR-8.19: list, inspect and terminate; principal management and
	// suspension are not built. FR-8.26: the page and its assets are served
	// from the binary.
	reqtest.Partial(t, "FR-8.19", "FR-8.26")
	f := start(t, "")
	if _, err := consoleapi.Attach(f.app, diag.Discard()); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", f.cfg.AdminURL()+"/approvals/abc", nil)
	r, body := f.do(req)
	if r.StatusCode != 200 || !strings.Contains(string(body), `<div id="root">`) || r.Header.Get("Content-Security-Policy") != consoleapi.ConsoleCSP {
		t.Fatalf("console page: %d %v %s", r.StatusCode, r.Header, body)
	}
	// Every asset the page names is served from the binary.
	for _, part := range strings.Split(string(body), `"/assets/`)[1:] {
		name := part[:strings.IndexByte(part, '"')]
		ar, err := f.client.Get(f.cfg.AdminURL() + "/assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, ar.Body)
		ar.Body.Close()
		if ar.StatusCode != 200 {
			t.Fatalf("asset %s: %d", name, ar.StatusCode)
		}
	}

	access, _, _ := f.oauthLogin("")
	code, out := f.admin("GET", "/api/v1/sessions", f.operator, nil)
	list, _ := out["sessions"].([]any)
	if code != 200 || len(list) != 1 {
		t.Fatalf("sessions: %d %v", code, out)
	}
	s := list[0].(map[string]any)
	if s["approved_by"] != "approver" || s["principal_id"] != "cc" {
		t.Fatalf("session: %v", s)
	}
	id := s["id"].(string)
	if code, out = f.admin("POST", "/api/v1/sessions/"+id+"/terminate", f.operator, map[string]any{"reason": "e2e"}); code != 200 {
		t.Fatalf("terminate: %d %v", code, out)
	}
	if status, _, _ := f.post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, modernHeaders(access, "tools/list")); status != 401 {
		t.Fatalf("terminated session token still accepted: %d", status)
	}
	code, out = f.admin("GET", "/api/v1/servers", f.operator, nil)
	if code != 200 || len(out["servers"].([]any)) != 1 {
		t.Fatalf("servers: %d %v", code, out)
	}
	code, out = f.admin("GET", "/api/v1/audit/events?session_id="+id, f.operator, nil)
	if code != 200 || len(out["events"].([]any)) < 2 {
		t.Fatalf("session events: %d %v", code, out)
	}
	code, out = f.admin("POST", "/api/v1/audit/verify", f.operator, map[string]any{})
	if code != 200 || out["status"] != "verified" {
		t.Fatalf("verify: %d %v", code, out)
	}
}
