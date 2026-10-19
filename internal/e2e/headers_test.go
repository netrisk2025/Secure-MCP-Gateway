package e2e

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestHeaderControlCharacters is SR-5.2-2: on the running Gateway's
// harness listener, a request missing MCP-Protocol-Version, Mcp-Method or
// (for tools/call) Mcp-Name, and a request whose header value or name
// carries a control character (which net/http refuses before any handler
// runs), are each answered with HTTP 400 and JSON-RPC error -32020. A
// well-formed request on the same listener is still served.
func TestHeaderControlCharacters(t *testing.T) {
	reqtest.Verifies(t, "SR-5.2-2")
	f := start(t, "")
	access, _, _ := f.oauthLogin("")
	tc := f.client.Transport.(*http.Transport).TLSClientConfig
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + modernMeta + `}}`
	for name, bad := range map[string]string{
		"control character in a value": "Mcp-Method: tools/\x01list\r\n",
		"escape in a value":            "MCP-Protocol-Version: 2026-07-28\x1b[31m\r\n",
		"control character in a name":  "X-Bad\x02Name: 1\r\n",
	} {
		conn, err := tls.Dial("tcp", f.cfg.Listener.Address, tc)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		req := "POST /mcp HTTP/1.1\r\nHost: " + f.cfg.Listener.Address + "\r\n" +
			"Authorization: Bearer " + access + "\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n" +
			bad + fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		conn.Close()
		var m struct {
			ID    any `json:"id"`
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if resp.StatusCode != 400 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || json.Unmarshal(raw, &m) != nil || m.Error.Code != -32020 {
			t.Fatalf("%s: %d %s %q", name, resp.StatusCode, resp.Header.Get("Content-Type"), raw)
		}
	}
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"x"},` + modernMeta + `}}`
	for _, c := range []struct{ body, method, omit string }{
		{body, "tools/list", "MCP-Protocol-Version"},
		{body, "tools/list", "Mcp-Method"},
		{call, "tools/call", "Mcp-Name"},
	} {
		hdr := modernHeaders(access, c.method)
		hdr["Mcp-Name"] = "t_echo"
		if c.method != "tools/call" {
			delete(hdr, "Mcp-Name")
		}
		delete(hdr, c.omit)
		status, _, b := f.post(c.body, hdr)
		if status != 400 || !strings.Contains(b, `"code":-32020`) {
			t.Fatalf("%s without %s: %d %s", c.method, c.omit, status, b)
		}
	}
	if status, _, b := f.post(body, modernHeaders(access, "tools/list")); status != 200 || !strings.Contains(b, `"tools"`) {
		t.Fatalf("well-formed request after the refusals: %d %s", status, b)
	}
}
