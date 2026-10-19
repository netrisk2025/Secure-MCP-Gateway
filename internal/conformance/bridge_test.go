package conformance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// bridge is a stdio adapter command (smcp-stdio or smcp-connect) run in
// process. Every request the suite sends directly is also written to the
// adapter's standard input, and what the adapter writes to its standard
// output must equal the direct response, message for message.
type bridge struct {
	name string
	// run runs the adapter command once with in as standard input.
	run func(in io.Reader, out, errOut io.Writer) int
	// direct sends the request without the adapter. nil means the suite's
	// own direct response is the reference (same listener and session).
	direct func(body []byte, hdr map[string]string) response

	compared int
	skipped  []string
}

// relayHeaders are the MCP headers the relay derives from a message sent
// alone (no initialize before it in the same run): the 2026-07-28
// per-request version, Mcp-Method, and Mcp-Name for tools/call,
// prompts/get and resources/read.
func relayHeaders(body []byte) map[string]string {
	h := map[string]string{}
	var env struct {
		Method string `json:"method"`
		Params struct {
			Name string         `json:"name"`
			URI  string         `json:"uri"`
			Meta map[string]any `json:"_meta"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &env) != nil {
		return h
	}
	if v, ok := env.Params.Meta["io.modelcontextprotocol/protocolVersion"].(string); ok && v != "" {
		h["MCP-Protocol-Version"] = v
	}
	if env.Method != "" {
		h["Mcp-Method"] = env.Method
	}
	switch env.Method {
	case "tools/call", "prompts/get":
		if env.Params.Name != "" {
			h["Mcp-Name"] = env.Params.Name
		}
	case "resources/read":
		if env.Params.URI != "" {
			h["Mcp-Name"] = env.Params.URI
		}
	}
	return h
}

func sameHeaders(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		found := false
		for k2, v2 := range b {
			if strings.EqualFold(k, k2) && v == v2 {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// compare relays body through the adapter and checks the output against
// the direct response. Requests whose headers the relay cannot reproduce
// (deliberately inconsistent headers, a legacy request without its
// initialize) are skipped and listed.
func (b *bridge) compare(t *testing.T, body []byte, hdr map[string]string, direct response) {
	t.Helper()
	if !sameHeaders(hdr, relayHeaders(body)) {
		b.skipped = append(b.skipped, fmt.Sprintf("%.60s", body))
		return
	}
	if b.direct != nil {
		direct = b.direct(body, hdr)
	}
	got := b.relay(t, nil, body)
	if want := normalizeAll(direct.Messages); !reflect.DeepEqual(got, want) {
		t.Errorf("%s: relayed output differs from a direct connection for %.200s\n relay:  %v\n direct: %v (HTTP %d)", b.name, body, got, want, direct.Status)
		return
	}
	b.compared++
}

// relay runs the adapter with the messages before (each sent after the
// previous one's response arrived, so a legacy initialize is complete
// before the next message) and then msg, and returns the normalized
// messages written for msg.
func (b *bridge) relay(t *testing.T, before [][]byte, msg []byte) []string {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errOut bytes.Buffer
	done := make(chan int, 1)
	go func() {
		code := b.run(inR, outW, &errOut)
		outW.Close()
		done <- code
	}()
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 64<<10), adapter.MaxMessageBytes)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	for _, m := range before {
		if _, err := inW.Write(append(append([]byte(nil), m...), '\n')); err != nil {
			t.Fatal(err)
		}
		select {
		case <-lines:
		case <-time.After(20 * time.Second):
			t.Fatalf("%s: no answer to %.80s", b.name, m)
		}
	}
	if _, err := inW.Write(append(append([]byte(nil), msg...), '\n')); err != nil {
		t.Fatal(err)
	}
	inW.Close()
	var raw []json.RawMessage
	for l := range lines {
		raw = append(raw, json.RawMessage(l))
	}
	if code := <-done; code != 0 {
		t.Fatalf("%s exited %d: %s", b.name, code, errOut.String())
	}
	return normalizeAll(raw)
}

// volatileKeys are per-request identifiers that differ between two sends
// of the same request.
var volatileKeys = map[string]bool{"correlationId": true, "decisionId": true}

func scrub(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if volatileKeys[k] {
				x[k] = "-"
			} else {
				x[k] = scrub(e)
			}
		}
	case []any:
		for i, e := range x {
			x[i] = scrub(e)
		}
	}
	return v
}

func normalizeAll(msgs []json.RawMessage) []string {
	out := []string{}
	for _, m := range msgs {
		var v any
		if err := json.Unmarshal(m, &v); err != nil {
			out = append(out, "invalid: "+string(m))
			continue
		}
		b, _ := json.Marshal(scrub(v))
		out = append(out, string(b))
	}
	return out
}

// writeCredentials writes a CP-43 credential file (mode 0600) for url
// trusting only the Gateway server CA.
func writeCredentials(t *testing.T, g *gateway, url, clientID string, sess adapter.SessionSection) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "smcp", "credentials.toml")
	c, err := adapter.LoadOrNew(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Gateway = adapter.GatewaySection{URL: url, CAFile: g.caFile}
	c.Client = adapter.ClientSection{ID: clientID}
	c.Session = sess
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	return path
}

// stdioBridge is smcp-stdio against the CP-02 TLS listener, using the
// suite's session.
func stdioBridge(t *testing.T, g *gateway) *bridge {
	path := writeCredentials(t, g, g.url, "conformance", adapter.SessionSection{AccessToken: g.token, IssuedAt: time.Now().UTC(), ExpiresIn: 3600})
	return &bridge{name: "smcp-stdio", run: func(in io.Reader, out, errOut io.Writer) int {
		return adapter.StdioMain([]string{"--credentials", path}, in, out, errOut)
	}}
}

// connectBridge is smcp-connect against the Remote Access public URL (the
// test tunnel to the remote listener). Its credential file holds only the
// refresh token of a remote session, so its first run refreshes the
// session at the Gateway's token endpoint through the tunnel and stores the
// new tokens in the file; the direct reference requests go through the
// same tunnel with the stored access token.
func connectBridge(t *testing.T, g *gateway) *bridge {
	t.Helper()
	l := g.cfg.Remote.Limits
	_, tok, err := g.app.Store.Create(session.CreateParams{PrincipalID: "cc", ClientID: remoteClientID, Listener: channel.Remote,
		Claims: session.Claims{Template: "all"}, MaxLifetime: l.SessionMaxLifetime.Duration, IdleTimeout: l.SessionIdleTimeout.Duration,
		AllowedTemplates: g.cfg.Remote.Templates})
	if err != nil {
		t.Fatal(err)
	}
	publicMCP := g.public + g.cfg.Listener.MCPPath
	path := writeCredentials(t, g, publicMCP, remoteClientID, adapter.SessionSection{RefreshToken: tok.Refresh})
	b := &bridge{name: "smcp-connect", run: func(in io.Reader, out, errOut io.Writer) int {
		return adapter.ConnectMain([]string{"--credentials", path}, in, out, errOut)
	}}
	// First run: refresh through the tunnel, then a tools/list.
	list, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "connect-first", "method": "tools/list", "params": map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}})
	if out := b.relay(t, nil, list); len(out) != 1 || !strings.Contains(out[0], `"tools"`) {
		t.Fatalf("smcp-connect first run: %v", out)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file mode %v after sign-in refresh", fi.Mode().Perm())
	}
	creds, err := adapter.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Session.AccessToken == "" || creds.Session.RefreshToken == "" || creds.Session.RefreshToken == tok.Refresh {
		t.Fatalf("smcp-connect did not store the refreshed tokens: %+v", creds.Session.ID)
	}
	remoteGW := &gateway{t: t, app: g.app, url: publicMCP, http: g.http, token: creds.Session.AccessToken}
	b.direct = remoteGW.post
	// The session is bound to the remote listener: its token is refused on
	// the CP-02 listener, so the reference requests are remote ones.
	localGW := &gateway{t: t, app: g.app, url: g.url, http: g.http, token: creds.Session.AccessToken}
	if r := localGW.post(list, relayHeaders(list)); r.Status != http.StatusUnauthorized {
		t.Fatalf("remote session token on the local listener: HTTP %d", r.Status)
	}
	return b
}

// legacyEra runs a 2025-11-25 session through the bridge and directly:
// initialize, then tools/list, a permitted call, a call outside the
// catalog and an unknown method, each after the initialize (the relay
// takes the negotiated version from the initialize result).
func legacyEra(t *testing.T, b *bridge, g *gateway) {
	t.Helper()
	init := []byte(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"conformance","version":"1"}}}`)
	post := g.post
	if b.direct != nil {
		post = b.direct
	}
	ir := post(init, nil)
	var res struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if len(ir.Messages) != 1 || json.Unmarshal(ir.Messages[0], &res) != nil || res.Result.ProtocolVersion != "2025-11-25" {
		t.Fatalf("%s: direct legacy initialize: %d %s", b.name, ir.Status, ir.Body)
	}
	if got, want := b.relay(t, nil, init), normalizeAll(ir.Messages); !reflect.DeepEqual(got, want) {
		t.Errorf("%s: legacy initialize differs\n relay:  %v\n direct: %v", b.name, got, want)
	}
	msgs := []struct {
		body string
		name string
	}{
		{`{"jsonrpc":"2.0","id":"l1","method":"tools/list","params":{}}`, ""},
		{`{"jsonrpc":"2.0","id":"l2","method":"tools/call","params":{"name":"` + public("get_weather") + `","arguments":{"location":"New York"}}}`, public("get_weather")},
		{`{"jsonrpc":"2.0","id":"l3","method":"tools/call","params":{"name":"` + public("no_such_tool") + `","arguments":{}}}`, public("no_such_tool")},
		{`{"jsonrpc":"2.0","id":"l4","method":"tools/call","params":{"name":"` + public("get_weather") + `","arguments":{"location":7}}}`, public("get_weather")},
		{`{"jsonrpc":"2.0","id":"l5","method":"no/such/method","params":{}}`, ""},
	}
	for _, m := range msgs {
		hdr := map[string]string{"MCP-Protocol-Version": "2025-11-25"}
		var env struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal([]byte(m.body), &env)
		hdr["Mcp-Method"] = env.Method
		if m.name != "" {
			hdr["Mcp-Name"] = m.name
		}
		want := normalizeAll(post([]byte(m.body), hdr).Messages)
		if len(want) == 0 {
			t.Fatalf("%s: no direct answer to %s", b.name, m.body)
		}
		if got := b.relay(t, [][]byte{init}, []byte(m.body)); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: legacy %s differs\n relay:  %v\n direct: %v", b.name, env.Method, got, want)
			continue
		}
		b.compared++
	}
}

// TestConformanceThroughAdapters runs the northbound checks of the
// conformance suite (FR-12.9) with every request also relayed through
// smcp-stdio to the CP-02 TLS listener and through smcp-connect to the
// Remote Access public URL behind a test tunnel, in the 2026-07-28 era,
// plus a 2025-11-25 session through each, and requires each adapter's
// output to equal a direct connection's response message for message
// (identifiers that differ per request, correlationId and decisionId,
// are masked). smcp-connect starts from a credential file holding only a
// remote refresh token: it refreshes through the tunnel and stores the
// new tokens in the file, which stays mode 0600.
//
// FR-12.13 is verified by this test together with the adapter package
// tests: session creation with the client secret
// (TestStdioBridgeWithSDKClient), trust of only the CA named in the
// credential file (TestRelayTrustsOnlyNamedCA) and the UDS listener
// (TestRelayUnixSocket). FR-16.9 is verified by this test together with
// the device sign-in through the tunnel (TestConnectThroughTunnel) and
// the npm package (TestNPMConnect).
func TestConformanceThroughAdapters(t *testing.T) {
	reqtest.Verifies(t, "FR-12.13", "FR-16.9")
	ex := loadExamples(t)
	s := &suite{t: t, ex: ex, v: newValidator(t), r: &report{}}
	s.be = newBackend(t, ex)
	s.gw = startGatewayWith(t, s.be, true)
	s.bridges = []*bridge{stdioBridge(t, s.gw), connectBridge(t, s.gw)}

	t.Run("discover", s.discover)
	t.Run("tools", s.tools)
	t.Run("call", s.callTool)
	t.Run("server-initiated", s.serverInitiated)
	t.Run("errors", s.errors)
	t.Run("unsupported", s.unsupported)
	t.Run("notifications", s.notifications)
	for _, b := range s.bridges {
		t.Run("legacy-"+b.name, func(t *testing.T) { legacyEra(t, b, s.gw) })
	}
	for _, b := range s.bridges {
		t.Logf("%s: %d requests compared with a direct connection; %d sent with headers the relay does not derive from the body (a header mismatch on purpose, a forced version, Mcp-Name on resources/subscribe, an initialize without Mcp-Method), not compared: %v", b.name, b.compared, len(b.skipped), b.skipped)
		if b.compared < 30 {
			t.Errorf("%s: only %d requests compared", b.name, b.compared)
		}
	}
}
