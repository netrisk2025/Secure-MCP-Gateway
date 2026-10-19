package acceptance

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const wireVersion = "2026-07-28"

// wireCall is a stateless 2026-07-28 tools/call with the given _meta
// members added.
func wireCall(id int, tool, args, meta string) string {
	if meta != "" {
		meta = "," + meta
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s,"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}%s}}}`,
		id, tool, args, wireVersion, meta)
}

func wireHeaders(method, name string) map[string]string {
	h := map[string]string{"MCP-Protocol-Version": wireVersion, "Mcp-Method": method}
	if name != "" {
		h["Mcp-Name"] = name
	}
	return h
}

func with(h map[string]string, k, v string) map[string]string {
	out := map[string]string{}
	for kk, vv := range h {
		out[kk] = vv
	}
	out[k] = v
	return out
}

// TestAT01IdentityAndLocalHTTP is acceptance scenario AT-01 against the
// real smcpd: TLS 1.3 only with the Gateway CA's certificate for the
// listener name, OAuth bearer tokens checked on every request, Host and
// Origin validation, header and body agreement, and the CP-06 and CP-07
// bounds, all before dispatch. The principal comes from the token's client
// registration, never from forged clientInfo or body fields.
//
// Partial claims: SR-2.1-1 covers the OAuth path only (the mTLS and UDS
// profiles do not exist); SR-2.1-3 revokes a session token, not a client
// certificate; SR-2.8-1 checks the harness and control listeners' TLS
// version and name; SR-7.11-1 checks the header and body bounds but not
// slow bodies, connection floods or the CP-09 unauthenticated-work limit.
func TestAT01IdentityAndLocalHTTP(t *testing.T) {
	g := newGateway(t, options{limits: "request_body_bytes = 65536"})
	g.start()
	g.scenario("AT-01")
	reqtest.Partial(t, "SR-2.1-1", "SR-2.1-3", "SR-2.8-1", "SR-2.9-1", "SR-2.9-2", "SR-5.2-1", "SR-7.11-1")

	addr := fmt.Sprintf("127.0.0.1:%d", g.port)
	adminAddr := fmt.Sprintf("127.0.0.1:%d", g.adminPort)

	// TLS: 1.2 is refused, a name the certificate does not carry is refused,
	// a client that does not trust the Gateway CA cannot connect.
	for _, a := range []string{addr, adminAddr} {
		cfg := g.tlsConfig()
		cfg.MaxVersion = tls.VersionTLS12
		if c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", a, cfg); err == nil {
			c.Close()
			t.Fatalf("%s accepted TLS 1.2", a)
		}
		cfg = g.tlsConfig()
		cfg.ServerName = "evil.example"
		if c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", a, cfg); err == nil {
			c.Close()
			t.Fatalf("%s presented a certificate valid for evil.example", a)
		}
		if c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", a, &tls.Config{MinVersion: tls.VersionTLS13}); err == nil {
			c.Close()
			t.Fatalf("%s is trusted without the Gateway CA", a)
		}
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", a, g.tlsConfig())
		if err != nil {
			t.Fatalf("%s: TLS 1.3 with the Gateway CA: %v", a, err)
		}
		if v := c.ConnectionState().Version; v != tls.VersionTLS13 {
			t.Fatalf("%s negotiated TLS version %x", a, v)
		}
		c.Close()
	}

	// Authentication: no token and a forged token get 401 with the
	// protected-resource challenge.
	call := wireCall(1, "ref_echo", `{"text":"x"}`, "")
	hdr := wireHeaders("tools/call", "ref_echo")
	for _, tok := range []string{"", "forged-token-0123456789"} {
		resp, body := g.mcpPost(tok, call, hdr)
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
			t.Fatalf("token %q: %d %q %s", tok, resp.StatusCode, resp.Header.Get("WWW-Authenticate"), body)
		}
	}

	tok := g.token("")
	// A valid call, with forged identity fields in _meta and the body.
	forged := wireCall(2, "ref_echo", `{"text":"principal-check"}`,
		`"io.modelcontextprotocol/clientInfo":{"name":"forged-client","version":"1"},"principal":"admin","session":"forged"`)
	resp, body := g.mcpPost(tok, forged, hdr)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "echo") {
		t.Fatalf("valid call: %d %s", resp.StatusCode, body)
	}

	// Host and Origin.
	for _, c := range []struct {
		name string
		h    map[string]string
		want int
	}{
		{"foreign host", with(hdr, "Host", "evil.example:"+fmt.Sprint(g.port)), http.StatusMisdirectedRequest},
		{"foreign origin", with(hdr, "Origin", "https://evil.example"), http.StatusForbidden},
		{"own origin on MCP", with(hdr, "Origin", g.publicURL), http.StatusForbidden},
		{"version header mismatch", with(hdr, "MCP-Protocol-Version", "2025-11-25"), http.StatusBadRequest},
		{"method header mismatch", with(hdr, "Mcp-Method", "tools/list"), http.StatusBadRequest},
		{"name header mismatch", with(hdr, "Mcp-Name", "ref_read_file"), http.StatusBadRequest},
		{"oversized header", with(hdr, "X-Padding", strings.Repeat("a", 20<<10)), http.StatusRequestHeaderFieldsTooLarge},
	} {
		resp, body := g.mcpPost(tok, wireCall(3, "ref_echo", `{"text":"refused"}`, ""), c.h)
		if resp.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d: %s", c.name, resp.StatusCode, c.want, body)
		}
		if c.want == http.StatusBadRequest && !strings.Contains(body, "-32020") {
			t.Errorf("%s: no -32020 in %s", c.name, body)
		}
	}
	// CP-07: a body over request_body_bytes.
	big := wireCall(4, "ref_echo", fmt.Sprintf(`{"text":%q}`, strings.Repeat("b", 70<<10)), "")
	if resp, body := g.mcpPost(tok, big, hdr); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d %s", resp.StatusCode, body)
	}
	// The control API checks Host as well.
	req, _ := http.NewRequest("GET", g.adminURL+"/api/v1/health/status", nil)
	req.Host = "evil.example"
	if resp, err := g.httpClient().Do(req); err != nil || resp.StatusCode < 400 {
		t.Fatalf("control API with a foreign Host: %v %v", err, resp)
	}

	// The sign-in form is accepted from the Gateway's own origin.
	if _, err := g.signIn("", approverPassword); err != nil {
		t.Fatalf("sign-in: %v", err)
	}

	// Per-request authentication: on the same kept-alive client, a token
	// whose session was terminated is refused on the next request.
	evs := g.events()
	sid := ""
	for _, e := range evs {
		if e.str("class") == "call" && e.str("phase") == "requested" {
			sid = e.str("session_id")
		}
	}
	if sid == "" {
		t.Fatal("no session in the journal")
	}
	if code, out := g.api("POST", "/api/v1/sessions/"+sid+"/terminate", map[string]any{"reason": "AT-01"}); code >= 300 {
		t.Fatalf("terminate: %d %v", code, out)
	}
	if resp, body := g.mcpPost(tok, call, hdr); resp.StatusCode == http.StatusOK && !strings.Contains(body, "error") {
		t.Fatalf("terminated session's token still works: %d %s", resp.StatusCode, body)
	}

	g.stop()
	// Evidence: exactly one call was dispatched, and its principal is the
	// client registration's, not the forged fields.
	evs = g.events()
	disp := dispatchedCorrelations(evs)
	if len(disp) != 1 {
		t.Fatalf("%d calls dispatched, want 1", len(disp))
	}
	for _, e := range evs {
		if disp[e.str("correlation_id")] && e.str("principal_id") != "claude-code-local" {
			t.Fatalf("dispatched call principal %q", e.str("principal_id"))
		}
	}
}
