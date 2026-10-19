package adapter_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

func writeCreds(t *testing.T, g *gwtest.Gateway, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "smcp", "credentials.toml")
	c, _ := adapter.LoadOrNew(path)
	c.Gateway = adapter.GatewaySection{URL: g.MCPURL(), CAFile: g.CAFile}
	c.Client = adapter.ClientSection{ID: gwtest.HelperClientID, Secret: gwtest.HelperSecret, Template: "ro"}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCredentialFileMode(t *testing.T) {
	reqtest.Verifies(t, "SR-2.3-2")
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "credentials.toml")
	c, _ := adapter.LoadOrNew(path)
	c.Gateway.URL = srv.URL + "/mcp"
	c.Client = adapter.ClientSection{ID: "x", Secret: "y"}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved with mode %v", fi.Mode())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(stderr io.Writer) int{
		"smcp-session": func(e io.Writer) int { return adapter.SessionMain([]string{"--credentials", path}, io.Discard, e) },
		"smcp-stdio": func(e io.Writer) int {
			return adapter.StdioMain([]string{"--credentials", path}, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"), io.Discard, e)
		},
		"smcp-connect": func(e io.Writer) int {
			return adapter.ConnectMain([]string{"--credentials", path}, strings.NewReader(""), io.Discard, e)
		},
	} {
		var stderr bytes.Buffer
		if code := run(&stderr); code == 0 || !strings.Contains(stderr.String(), path) || !strings.Contains(stderr.String(), "chmod 600") {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr.String())
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d connections made with an unsafe credential file", hits.Load())
	}
}

func listTools(t *testing.T, g *gwtest.Gateway, token string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", g.MCPURL(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	req.Header.Set("Authorization", token)
	resp, err := g.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestSessionHelper(t *testing.T) {
	reqtest.Partial(t, "FR-12.12")
	// Partial: the verification is a demonstration with Claude Code and
	// Codex CLI; this proves the helper's output, session creation through
	// the session API, reuse until half the lifetime, refresh through the
	// token endpoint, and that the printed header authenticates.
	g := gwtest.Start(t, "")
	path := writeCreds(t, g, 0o600)
	adapter.HelperTimeout = time.Minute // Argon2id under the race detector is slow
	defer func() { adapter.HelperTimeout = 9 * time.Second }()
	var out, errb bytes.Buffer
	if code := adapter.SessionMain([]string{"--credentials", path}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var h map[string]string
	if err := json.Unmarshal(out.Bytes(), &h); err != nil || len(h) != 1 || !strings.HasPrefix(h["Authorization"], "Bearer ") {
		t.Fatalf("output %q", out.String())
	}
	if st := listTools(t, g, h["Authorization"]); st != 200 {
		t.Fatalf("helper header refused: %d", st)
	}
	c, err := adapter.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	first := c.Session
	// Reused while fresh.
	out.Reset()
	adapter.SessionMain([]string{"--credentials", path}, &out, &errb)
	if !strings.Contains(out.String(), first.AccessToken) {
		t.Fatal("fresh token not reused")
	}
	// Past half the lifetime: refreshed in the same session.
	c.Session.IssuedAt = time.Now().Add(-time.Duration(c.Session.ExpiresIn) * time.Second)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := adapter.SessionMain([]string{"--credentials", path}, &out, &errb); code != 0 {
		t.Fatalf("refresh exit %d: %s", code, errb.String())
	}
	c2, _ := adapter.Load(path)
	if c2.Session.ID != first.ID || c2.Session.AccessToken == first.AccessToken || c2.Session.RefreshToken == first.RefreshToken {
		t.Fatalf("not refreshed in place: %+v -> %+v", first.ID, c2.Session.ID)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after refresh %v", fi.Mode())
	}
	// --env form for clients with only static headers.
	out.Reset()
	adapter.SessionMain([]string{"--credentials", path, "--env", "SMCP_AUTH"}, &out, &errb)
	if !strings.HasPrefix(out.String(), "SMCP_AUTH=Bearer ") {
		t.Fatalf("env output %q", out.String())
	}
}

// pipeRelay runs smcp-stdio's relay in process and returns an MCP client
// session connected to it over pipes.
func pipeClient(t *testing.T, run func(in io.Reader, out io.Writer)) *mcp.ClientSession {
	t.Helper()
	toRelayR, toRelayW := io.Pipe()
	fromRelayR, fromRelayW := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(toRelayR, fromRelayW)
		fromRelayW.Close()
	}()
	cl := mcp.NewClient(&mcp.Implementation{Name: "relay-test", Version: "1"}, nil)
	cs, err := cl.Connect(context.Background(), &mcp.IOTransport{Reader: fromRelayR, Writer: toRelayW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cs.Close()
		toRelayW.Close()
		<-done
	})
	return cs
}

func TestStdioBridgeWithSDKClient(t *testing.T) {
	reqtest.Partial(t, "FR-12.13")
	// Partial: session creation with the client secret and an MCP SDK
	// client through the bridge (tools/list, a permitted call, a call
	// outside the catalog). The conformance fixtures through the bridge
	// are internal/conformance.TestConformanceThroughAdapters.
	g := gwtest.Start(t, "")
	path := writeCreds(t, g, 0o600)
	cs := pipeClient(t, func(in io.Reader, out io.Writer) {
		adapter.StdioMain([]string{"--credentials", path}, in, out, io.Discard)
	})
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "t_echo" {
		t.Fatalf("tools %+v", tools.Tools)
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "via bridge"}})
	if err != nil {
		t.Fatal(err)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; txt != "echo:via bridge" {
		t.Fatalf("result %q", txt)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_secret"}); err == nil {
		t.Fatal("tool outside the catalog was callable")
	}
}

// normalize drops per-request identifiers so that responses can be
// compared.
var volatile = regexp.MustCompile(`"(correlationId|decisionId)":"[^"]*"`)

func normalize(b []byte) string {
	return volatile.ReplaceAllString(strings.TrimSpace(string(b)), `"$1":"-"`)
}

func TestStdioBridgeRawEquivalence(t *testing.T) {
	reqtest.Partial(t, "FR-12.13")
	g := gwtest.Start(t, "")
	path := writeCreds(t, g, 0o600)
	creds, _ := adapter.Load(path)
	sess, _ := adapter.NewSession(creds)
	tok, err := sess.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	legacy := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"a"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"t_secret","arguments":{}}}`,
	}
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"x","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	modern := []string{
		`{"jsonrpc":"2.0","id":11,"method":"server/discover","params":{` + meta + `}}`,
		`{"jsonrpc":"2.0","id":12,"method":"tools/list","params":{` + meta + `}}`,
		`{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"b"},` + meta + `}}`,
	}
	direct := func(msg, version string) string {
		var env struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal([]byte(msg), &env)
		req, _ := http.NewRequest("POST", g.MCPURL(), strings.NewReader(msg))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Mcp-Method", env.Method)
		if env.Params.Name != "" {
			req.Header.Set("Mcp-Name", env.Params.Name)
		}
		if version != "" {
			req.Header.Set("Mcp-Protocol-Version", version)
		}
		resp, err := g.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "data: ") {
					return normalize([]byte(strings.TrimPrefix(l, "data: ")))
				}
			}
		}
		return normalize(b)
	}
	want := map[string]string{}
	for i, m := range legacy {
		v := "2025-11-25"
		if i == 0 {
			v = ""
		}
		want[m] = direct(m, v)
	}
	for _, m := range modern {
		want[m] = direct(m, "2026-07-28")
	}
	// Through the bridge, one message at a time so the order is fixed.
	for _, set := range [][]string{legacy, modern} {
		for i, m := range set {
			var out, errb bytes.Buffer
			// Each message goes through its own relay run after the
			// initialize of its era, so ordering is deterministic.
			prefix := ""
			if set[0] != m && strings.Contains(set[0], `"initialize"`) {
				prefix = set[0] + "\n"
			}
			if code := adapter.StdioMain([]string{"--credentials", path}, strings.NewReader(prefix+m+"\n"), &out, &errb); code != 0 {
				t.Fatalf("relay exit %d: %s", code, errb.String())
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			got := normalize([]byte(lines[len(lines)-1]))
			if prefix != "" && len(lines) == 2 {
				// The initialize answer and this message's answer may arrive in
				// either order; pick the one with this message's id.
				var a struct {
					ID json.RawMessage `json:"id"`
				}
				var mm struct {
					ID json.RawMessage `json:"id"`
				}
				_ = json.Unmarshal([]byte(m), &mm)
				for _, l := range lines {
					_ = json.Unmarshal([]byte(l), &a)
					if string(a.ID) == string(mm.ID) {
						got = normalize([]byte(l))
					}
				}
			}
			if got != want[m] {
				t.Errorf("message %d differs\n relay:  %s\n direct: %s", i, got, want[m])
			}
		}
	}
	// A request the Gateway refuses with HTTP 400 still gets a JSON-RPC
	// error on standard output, so the framework is not left waiting. The
	// Gateway answers an unknown method with -32601 itself (FR-1.18).
	var out bytes.Buffer
	adapter.StdioMain([]string{"--credentials", path}, strings.NewReader(legacy[0]+"\n"+`{"jsonrpc":"2.0","id":5,"method":"no/such/method","params":{}}`+"\n"), &out, io.Discard)
	if !strings.Contains(out.String(), `"id":5`) || !strings.Contains(out.String(), `"code":-32601`) {
		t.Fatalf("unhandled method: %s", out.String())
	}
}

// TestRelayUnixSocket: with [gateway] socket and uds_key in the
// credential file, smcp-stdio authenticates on the Gateway's UDS harness
// socket and relays newline-delimited messages unchanged in both
// directions (FR-12.13 with the UDS Harness Profile).
func TestRelayUnixSocket(t *testing.T) {
	reqtest.Partial(t, "FR-12.13")
	dir := testport.SocketDir(t)
	sock := filepath.Join(dir, "h.sock")
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	grp, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("primary group: %v", err)
	}
	const key = "adapter uds key 0123456789"
	hash, err := keys.HashPassword(key)
	if err != nil {
		t.Fatal(err)
	}
	gwtest.Start(t, fmt.Sprintf("[uds]\nenabled = true\npath = %q\ngroup = %q\n[[uds.peer]]\nuid = %d\nprincipal = \"cc\"\nkey_hash = %q\n",
		sock, grp.Name, os.Getuid(), hash))
	write := func(k string) string {
		path := filepath.Join(dir, "cred-"+k[:3]+".toml")
		body := fmt.Sprintf("[gateway]\nurl = \"https://unused.invalid/mcp\"\nsocket = %q\nuds_key = %q\n[client]\nid = \"unused\"\n", sock, k)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"via socket"},` + meta + `}}` + "\n"
	var out, errOut bytes.Buffer
	if code := adapter.StdioMain([]string{"--credentials", write(key)}, strings.NewReader(in), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(out.String(), `"t_echo"`) || !strings.Contains(out.String(), "echo:via socket") {
		t.Fatalf("relayed output: %q", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := adapter.StdioMain([]string{"--credentials", write("wrong key 0123456789")}, strings.NewReader(in), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "refused the socket session") {
		t.Fatalf("wrong key: exit %d: %s %s", code, out.String(), errOut.String())
	}
}

// TestRelayTrustsOnlyNamedCA: with ca_file in the credential file, the
// relay trusts only that CA (FR-12.13): a Gateway whose certificate a
// different CA issued is refused at the TLS handshake, so no request and
// no token reaches it, and the framework gets a JSON-RPC error.
func TestRelayTrustsOnlyNamedCA(t *testing.T) {
	reqtest.Partial(t, "FR-12.13")
	g := gwtest.Start(t, "")
	var hits atomic.Int32
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	other.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshake
	other.StartTLS()
	defer other.Close()
	// The named CA is the Gateway's; the server presents another CA's
	// certificate.
	path := filepath.Join(t.TempDir(), "credentials.toml")
	c, _ := adapter.LoadOrNew(path)
	c.Gateway = adapter.GatewaySection{URL: other.URL + "/mcp", CAFile: g.CAFile}
	c.Session = adapter.SessionSection{AccessToken: "tok", IssuedAt: time.Now().UTC(), ExpiresIn: 3600}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	msg := `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}` + "\n"
	if code := adapter.StdioMain([]string{"--credentials", path}, strings.NewReader(msg), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached a server outside the named CA", hits.Load())
	}
	if !strings.Contains(out.String(), `"id":7`) || !strings.Contains(out.String(), `"code":-32000`) || !strings.Contains(out.String(), "certificate") {
		t.Fatalf("framework answer: %s", out.String())
	}
	// The same server's own CA in the file is accepted (the test server's
	// certificate is self-issued by its CA).
	caPath := filepath.Join(t.TempDir(), "other-ca.pem")
	if err := os.WriteFile(caPath, pemCert(other.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Gateway.CAFile = caPath
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	adapter.StdioMain([]string{"--credentials", path}, strings.NewReader(msg), &out, &errOut)
	if hits.Load() != 1 {
		t.Fatalf("named CA: %d requests reached the server", hits.Load())
	}
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }
func (staticToken) Invalidate()                             {}

func TestConnectThroughTunnel(t *testing.T) {
	reqtest.Partial(t, "FR-16.9")
	// Partial: proves dynamic registration, the operator approval wait,
	// device sign-in, the 0600 credential file and relayed tools/list and
	// tools/call through a tunnel. The conformance fixtures through
	// smcp-connect are internal/conformance.TestConformanceThroughAdapters;
	// the npm package is exercised in TestNPMConnect.
	g := gwtest.Start(t, "[remote]\naddress = \"%REMOTE%\"\ndefault_principal = \"cloud\"\ntemplates = [\"remote\"]\n")
	public := g.Tunnel(func() string { return "203.0.113.9" })
	g.EnableRemote(public)
	credPath := filepath.Join(t.TempDir(), "smcp", "credentials.toml")
	creds, _ := adapter.LoadOrNew(credPath)
	creds.Gateway = adapter.GatewaySection{URL: public + "/mcp", CAFile: g.CAFile}
	h, _ := adapter.NewHTTPClient(creds.Gateway)

	pr, pw := io.Pipe()
	login := &adapter.Login{Creds: creds, HTTP: h, Prompt: pw, Scope: "smcp:template:remote",
		Sleep: func(ctx context.Context, d time.Duration) error { return sleep(ctx, 150*time.Millisecond) }}
	errc := make(chan error, 1)
	go func() { _, err := login.Run(context.Background()); pw.Close(); errc <- err }()
	sc := bufio.NewScanner(pr)
	codeRE := regexp.MustCompile(`enter the code ([A-Z]{4}-[A-Z]{4})`)
	for sc.Scan() {
		line := sc.Text()
		if m := regexp.MustCompile(`client (smcp-dcr-\S+) is waiting`).FindStringSubmatch(line); m != nil {
			if st, body := g.Admin("POST", "/api/v1/clients/"+m[1]+"/approve", map[string]any{}); st != 200 {
				t.Fatalf("approve %d %v", st, body)
			}
		}
		if m := codeRE.FindStringSubmatch(line); m != nil {
			form := url.Values{"user_code": {m[1]}, "username": {gwtest.ApproverUser}, "password": {gwtest.ApproverPassword}, "decision": {"approve"}}
			req, _ := http.NewRequest("POST", public+"/oauth/device", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := g.HTTP.Do(req)
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("approve code: %v %v", err, resp)
			}
			resp.Body.Close()
		}
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(credPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file %v %v", fi, err)
	}
	saved, err := adapter.Load(credPath)
	if err != nil || saved.Session.RefreshToken == "" || !strings.HasPrefix(saved.Client.ID, "smcp-dcr-") {
		t.Fatalf("saved %+v %v", saved, err)
	}
	cs := pipeClient(t, func(in io.Reader, out io.Writer) {
		adapter.ConnectMain([]string{"--credentials", credPath}, in, out, io.Discard)
	})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "remote"}})
	if err != nil {
		t.Fatal(err)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; txt != "echo:remote" {
		t.Fatalf("result %q", txt)
	}
	g.WaitEvent(func(e auditEvent) bool {
		return e.Channel == "remote" && e.ClientAddress == "203.0.113.9" && e.Class == "call"
	})
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// TestRelayPlainHTTPError: a response that is not JSON-RPC (a plain-text
// HTTP error from a proxy, for example) still becomes a JSON-RPC error on
// standard output, so the framework is not left waiting.
func TestRelayPlainHTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()
	var out bytes.Buffer
	r := &adapter.Relay{URL: srv.URL + "/mcp", HTTP: srv.Client(), Tokens: staticToken("tok"),
		In: strings.NewReader(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}` + "\n"), Out: &out}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"id":5`) || !strings.Contains(out.String(), `"code":-32000`) {
		t.Fatalf("plain HTTP error: %s", out.String())
	}
}

func TestVersionFlag(t *testing.T) {
	// Release checks run each installed binary with --version (FR-13.1
	// archive contents, docs/release-checklist.md).
	reqtest.Partial(t, "FR-13.1")
	old := adapter.Version
	adapter.Version = "9.9.9-test"
	t.Cleanup(func() { adapter.Version = old })
	for name, run := range map[string]func(*bytes.Buffer, *bytes.Buffer) int{
		"smcp-session": func(o, e *bytes.Buffer) int { return adapter.SessionMain([]string{"--version"}, o, e) },
		"smcp-stdio": func(o, e *bytes.Buffer) int {
			return adapter.StdioMain([]string{"--version"}, strings.NewReader(""), o, e)
		},
		"smcp-connect": func(o, e *bytes.Buffer) int {
			return adapter.ConnectMain([]string{"--version"}, strings.NewReader(""), o, e)
		},
	} {
		var out, errb bytes.Buffer
		if code := run(&out, &errb); code != 0 || out.String() != name+" 9.9.9-test\n" {
			t.Errorf("%s --version: exit %d, stdout %q, stderr %q", name, code, out.String(), errb.String())
		}
	}
}
