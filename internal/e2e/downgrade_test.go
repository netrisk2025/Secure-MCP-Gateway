package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestNoNorthboundDowngrade is SR-5.3-1: a 2026-07-28 request that fails
// authentication, authorization or a modern protocol check is answered with
// that error and is never processed under legacy semantics. For every error
// class below, the response is the modern error (its code, no result), it
// opens no legacy session (no Mcp-Session-Id), it carries no legacy
// initialize result, and no tool call is authorized; afterwards the same
// session still works in the modern era only. A legacy initialize is
// processed under legacy semantics only when it authenticates.
func TestNoNorthboundDowngrade(t *testing.T) {
	reqtest.Verifies(t, "SR-5.3-1")
	f := start(t, "")
	access, _, body := f.oauthLogin("")
	sessionID, _ := body["session_id"].(string)
	call := func(name, args string) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":%q,"arguments":%s,%s}}`, name, args, modernMeta)
	}
	callHdr := func(tok, name string) map[string]string {
		h := modernHeaders(tok, "tools/call")
		h["Mcp-Name"] = name
		return h
	}
	with := func(h map[string]string, k, v string) map[string]string {
		out := map[string]string{}
		for kk, vv := range h {
			out[kk] = vv
		}
		out[k] = v
		return out
	}
	start := time.Now()
	cases := []struct {
		class, name string
		body        string
		hdr         map[string]string
		status      int
		code        int64
	}{
		{"authentication", "no token", call("t_echo", `{"text":"a"}`), with(callHdr("", "t_echo"), "Authorization", ""), 401, edge.CodeSessionInvalid},
		{"authentication", "unknown token", call("t_echo", `{"text":"a"}`), callHdr("forged", "t_echo"), 401, edge.CodeSessionInvalid},
		{"authentication", "unknown token with legacy session headers", call("t_echo", `{"text":"a"}`),
			with(callHdr("forged", "t_echo"), "Mcp-Session-Id", "legacy-session"), 401, edge.CodeSessionInvalid},
		{"authorization", "tool outside the catalog", call("t_secret", `{}`), callHdr(access, "t_secret"), 400, -32602},
		{"authorization", "policy denial (approval refused)", call("t_write", `{}`), callHdr(access, "t_write"), 200, edge.CodeApprovalRequired},
		{"protocol", "header and body disagree", call("t_echo", `{"text":"a"}`), callHdr(access, "t_big"), 400, -32020},
		{"protocol", "unsupported modern version", strings.Replace(call("t_echo", `{"text":"a"}`), "2026-07-28", "2099-01-01", 1),
			with(callHdr(access, "t_echo"), "MCP-Protocol-Version", "2099-01-01"), 400, -32022},
		{"protocol", "missing protocol version in _meta", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"a"}}}`,
			callHdr(access, "t_echo"), 400, -32602},
		{"protocol", "unknown method", fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"prompts/list","params":{%s}}`, modernMeta), modernHeaders(access, "prompts/list"), 404, -32601},
		{"protocol", "invalid arguments", call("t_echo", `{"text":1}`), callHdr(access, "t_echo"), 400, -32602},
	}
	for _, c := range cases {
		status, hdr, body := f.post(c.body, c.hdr)
		rep := decodeRaw(t, body)
		if rep.Error == nil || rep.Result != nil {
			t.Fatalf("%s / %s: not an error: %d %s", c.class, c.name, status, body)
		}
		code, _ := rep.Error.Code.Int64()
		if status != c.status || code != c.code {
			t.Fatalf("%s / %s: %d %d, want %d %d: %s", c.class, c.name, status, code, c.status, c.code, body)
		}
		if hdr.Get("Mcp-Session-Id") != "" || strings.Contains(body, `"protocolVersion"`) {
			t.Fatalf("%s / %s: legacy session or initialize result: %v %s", c.class, c.name, hdr, body)
		}
	}
	if got := f.authorizedAfter(sessionID, start); len(got) != 0 {
		t.Fatalf("%d calls were authorized by the refused requests", len(got))
	}

	// The session still works in the modern era.
	if status, _, body := f.post(call("t_echo", `{"text":"modern"}`), callHdr(access, "t_echo")); status != 200 || !strings.Contains(body, "echo:modern") {
		t.Fatalf("modern call after the errors: %d %s", status, body)
	}
	// A legacy initialize that fails authentication is not processed.
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}`
	if status, hdr, body := f.post(init, map[string]string{"Authorization": "Bearer forged"}); status != 401 || hdr.Get("Mcp-Session-Id") != "" || strings.Contains(body, `"protocolVersion"`) {
		t.Fatalf("unauthenticated legacy initialize: %d %v %s", status, hdr, body)
	}
	// An authenticated legacy initialize is processed under legacy semantics.
	if status, _, body := f.post(init, map[string]string{"Authorization": "Bearer " + access}); status != 200 || !strings.Contains(body, `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("legacy initialize: %d %s", status, body)
	}
}
