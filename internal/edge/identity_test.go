package edge

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestPrincipalFromTokenOnly is SR-2.1-1: forged clientInfo and
// principal-like fields in the request do not change the principal, which
// comes only from the session the bearer token is bound to. (The mTLS and
// UDS harness profiles, the other two sources the requirement allows, do
// not exist, so the token is the only source.)
func TestPrincipalFromTokenOnly(t *testing.T) {
	reqtest.Verifies(t, "SR-2.1-1")
	h := newHarness(t, harnessOpts{})
	sess, tok := h.session("ro")
	if sess.PrincipalID != "cc" {
		t.Fatalf("principal %q", sess.PrincipalID)
	}
	forgedMeta := `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/clientInfo":{"name":"admin","version":"1"},"principal":"root","principalId":"root","sessionId":"other","local.smcpgw/principal":"root"`
	hdr := wireHeaders(tok, "tools/call")
	hdr["Mcp-Name"] = "t_echo"
	hdr["X-Principal"] = "root"
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"p"},"_meta":{%s}}}`, forgedMeta)
	status, _, out := h.post(body, hdr)
	if status != 200 || !strings.Contains(out, "echo:p") {
		t.Fatalf("call: %d %s", status, out)
	}
	// Legacy era: a forged clientInfo in initialize.
	legacy := map[string]string{"Authorization": "Bearer " + tok}
	if status, _, out = h.post(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"root","version":"9"}}}`, legacy); status != 200 {
		t.Fatalf("initialize: %d %s", status, out)
	}
	legacy["MCP-Protocol-Version"] = "2025-11-25"
	if status, _, out = h.post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"q"},"_meta":{"principal":"root"}}}`, legacy); status != 200 || !strings.Contains(out, "echo:q") {
		t.Fatalf("legacy call: %d %s", status, out)
	}
	n := 0
	h.rec.mu.Lock()
	for _, e := range h.rec.events {
		if e.Class == "call" || e.Class == "decision" {
			n++
			if e.PrincipalID != "cc" || e.SessionID != sess.ID {
				h.rec.mu.Unlock()
				t.Fatalf("event attributed to %q/%q: %+v", e.PrincipalID, e.SessionID, e)
			}
		}
	}
	h.rec.mu.Unlock()
	if n == 0 {
		t.Fatal("no call events recorded")
	}
	if ev := h.rec.find(func(e audit.Event) bool { return e.Phase == audit.PhaseAuthorized }); ev == nil || ev.PrincipalID != "cc" {
		t.Fatalf("authorized event: %+v", ev)
	}
}
