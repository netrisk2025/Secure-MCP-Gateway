package edge

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Wire-level tests of the Protocol Mediator (E-02) and the catalog of the
// Access Enforcement Point (E-08). They send raw 2026-07-28 requests so the
// HTTP status, headers and JSON-RPC envelope can be checked exactly.

const wireMeta = `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}`

// wireHeaders are the 2026-07-28 request headers for method.
func wireHeaders(tok, method string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
}

// post sends one raw message to the MCP endpoint.
func (h *harness) post(body string, hdr map[string]string) (int, http.Header, string) {
	h.t.Helper()
	req, err := http.NewRequest("POST", h.srv.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return r.StatusCode, r.Header, string(b)
}

// rpcReply is a decoded JSON-RPC response.
type rpcReply struct {
	ID     json.RawMessage `json:"id"`
	Result map[string]any  `json:"result"`
	Error  *struct {
		Code    json.Number `json:"code"`
		Message string      `json:"message"`
	} `json:"error"`
}

func decodeReply(t *testing.T, body string) rpcReply {
	t.Helper()
	var r rpcReply
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&r); err != nil {
		t.Fatalf("not a JSON-RPC response: %v: %s", err, body)
	}
	return r
}

// wantError checks an HTTP status and an integer JSON-RPC error code.
func wantError(t *testing.T, name string, status int, body string, wantStatus int, wantCode int64) rpcReply {
	t.Helper()
	r := decodeReply(t, body)
	if status != wantStatus || r.Error == nil {
		t.Fatalf("%s: status %d, body %s; want %d with error %d", name, status, body, wantStatus, wantCode)
	}
	code, err := r.Error.Code.Int64()
	if err != nil || code != wantCode {
		t.Fatalf("%s: error code %q, want %d: %s", name, r.Error.Code, wantCode, body)
	}
	return r
}

// TestRequiredRequestMetadata is FR-1.8: a 2026-07-28 request lacking
// either required _meta field is rejected with HTTP 400 and -32602.
func TestRequiredRequestMetadata(t *testing.T) {
	reqtest.Verifies(t, "FR-1.8")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	for name, meta := range map[string]string{
		"protocolVersion":    `"io.modelcontextprotocol/clientCapabilities":{}`,
		"clientCapabilities": `"io.modelcontextprotocol/protocolVersion":"2026-07-28"`,
		"both":               ``,
	} {
		for _, method := range []string{"server/discover", "tools/list"} {
			status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{"_meta":{%s}}}`, method, meta), wireHeaders(tok, method))
			wantError(t, method+" without "+name, status, body, 400, -32602)
		}
	}
	// With both fields present the same request succeeds.
	status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta), wireHeaders(tok, "tools/list"))
	if status != 200 || decodeReply(t, body).Error != nil {
		t.Fatalf("complete request: %d %s", status, body)
	}
}

// TestHeaderBodyAgreement is SR-5.2-1 and SR-5.2-2: a header that differs
// from the body (including a Base64-sentinel encoded value that decodes to
// a different value) or a missing required header is rejected with HTTP
// 400 and -32020 before any processing.
//
// SR-5.2-2 is partial here: header values with control characters are
// refused before any handler runs, which only the full listener shows
// (internal/e2e.TestHeaderControlCharacters).
func TestHeaderBodyAgreement(t *testing.T) {
	reqtest.Verifies(t, "SR-5.2-1")
	reqtest.Partial(t, "SR-5.2-2")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	list := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta)
	call := fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"x"},"_meta":{%s}}}`, wireMeta)
	b64 := func(s string) string { return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?=" }
	with := func(base map[string]string, k, v string) map[string]string {
		out := map[string]string{}
		for kk, vv := range base {
			out[kk] = vv
		}
		if v == "" {
			delete(out, k)
		} else {
			out[k] = v
		}
		return out
	}
	callHdr := with(wireHeaders(tok, "tools/call"), "Mcp-Name", "t_echo")
	cases := []struct {
		name string
		body string
		hdr  map[string]string
	}{
		{"method mismatch", list, with(wireHeaders(tok, "tools/list"), "Mcp-Method", "server/discover")},
		{"version mismatch", list, with(wireHeaders(tok, "tools/list"), "MCP-Protocol-Version", "2025-11-25")},
		{"name mismatch", call, with(callHdr, "Mcp-Name", "t_big")},
		{"encoded name mismatch", call, with(callHdr, "Mcp-Name", b64("t_big"))},
		{"encoded method mismatch", list, with(wireHeaders(tok, "tools/list"), "Mcp-Method", b64("server/discover"))},
		{"missing method", list, with(wireHeaders(tok, "tools/list"), "Mcp-Method", "")},
		{"missing version", list, with(wireHeaders(tok, "tools/list"), "MCP-Protocol-Version", "")},
		{"missing name", call, with(callHdr, "Mcp-Name", "")},
	}
	for _, c := range cases {
		status, _, body := h.post(c.body, c.hdr)
		wantError(t, c.name, status, body, 400, -32020)
	}
	// None of the rejected calls reached the pipeline.
	if ev := h.rec.find(func(e audit.Event) bool { return e.Class == "call" }); ev != nil {
		t.Fatalf("a rejected request produced a call event: %+v", ev)
	}
	// The matching headers are accepted.
	status, _, body := h.post(call, callHdr)
	if status != 200 || !strings.Contains(body, "echo:x") {
		t.Fatalf("matching headers: %d %s", status, body)
	}
}
