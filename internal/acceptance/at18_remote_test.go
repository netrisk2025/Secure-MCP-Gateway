package acceptance

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// tunnel is the local stand-in for Tailscale Funnel or cloudflared: a TLS
// reverse proxy with the Gateway's listener certificate in front of the
// remote listener that keeps the Host header and sets X-Forwarded-For, as
// the tunnel connectors do. It returns the public URL.
func (g *gateway) tunnel(remoteAddr string) string {
	g.t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(g.state, "tls", "server.crt"), filepath.Join(g.state, "tls", "server.key"))
	if err != nil {
		g.t.Fatal(err)
	}
	target, _ := url.Parse("https://" + remoteAddr)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header["X-Forwarded-For"] = []string{"203.0.113.7"}
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // as Funnel's https+insecure to the loopback listener
	}
	ts := httptest.NewUnstartedServer(proxy)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	g.t.Cleanup(ts.Close)
	return ts.URL
}

// postAt sends one raw MCP POST to base.
func (g *gateway) postAt(base, token, body string, hdr map[string]string) (int, string) {
	g.t.Helper()
	req, _ := http.NewRequest("POST", base+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		g.t.Fatalf("POST %s: %v", base, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// nonLoopback returns an address of this host that is not loopback, or "".
func nonLoopback() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() && ip.IP.To4() != nil {
			return ip.IP.String()
		}
	}
	return ""
}

// TestAT18RemoteAccess is acceptance scenario AT-18 with the local tunnel
// stand-in, against the real smcpd:
//
//   - every listener (harness, control API, remote) is bound to loopback
//     only: connections to the host's other address fail (SR-2.9-3);
//   - the remote listener serves only through the tunnel's public name: a
//     request with the loopback Host is refused;
//   - a request through the tunnel without a token gets 401 or -31006, and
//     a pending client cannot obtain a token at all (SR-4.14-2);
//   - dynamic registration exists only on the remote listener, is pending
//     until approved with smcpctl clients approve, and authorization while
//     pending is refused with the pending message (FR-16.5);
//   - after approval the remote client's call succeeds through the tunnel
//     and is recorded as remote origin, and its token is refused on the
//     local listener (FR-16.1).
//
// The recorded run through a real tunnel provider is documented in
// docs/verification (FR-15.9); SR-4.14-1 (nftables rules in the Enforced
// profile) is not covered.
// at18Policy is the bootstrap policy with read-only marked remote_allowed.
const at18Policy = `{
  "revision": "at18-r2",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only", "remote_allowed": ["read-only"]}},
  "templates": {
    "read-only": {"rules": [{"id": "ro-ref", "server": "ref", "tools": ["echo", "time_now", "list_files", "read_file"]}]},
    "approval-demo": {"rules": [
      {"id": "demo-free", "server": "ref", "tools": ["echo", "time_now", "list_files"]},
      {"id": "demo-approve", "server": "ref", "tools": ["read_file"], "approval": true}
    ]}
  }
}`

func TestAT18RemoteAccess(t *testing.T) {
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", testport.Free(t))
	g := newGateway(t, options{extra: fmt.Sprintf(`
[[principal]]
id = "cloud"
framework = "grok-bot"
profile = "dev"

[remote]
address = %q
default_principal = "cloud"
templates = ["read-only"]
`, remoteAddr)})
	g.start()
	g.scenario("AT-18")
	reqtest.Partial(t, "FR-16.1", "FR-16.5", "SR-2.9-3", "SR-4.14-2")

	// Remote sessions use only templates the Framework Profile marks
	// remote_allowed (FR-16.12): publish the bootstrap policy with
	// read-only marked.
	g.mustCtl("policy", "publish", writeFile(t, t.TempDir(), "at18.json", at18Policy, 0o644))

	public := g.tunnel(remoteAddr)
	if g.profile() == reqtest.Enforced && os.Geteuid() != 0 {
		// In the Enforced profile remote enable installs the nftables host
		// rules first (SR-4.14-1), which needs root: run it as an operator
		// would, with sudo, and remove the rules again at the end.
		g.mustSudoCtl("remote", "enable", "--provider", "manual", "--public-url", public)
		t.Cleanup(func() {
			if out, err := g.sudoCtl("remote", "disable"); err != nil {
				t.Logf("remote disable: %v\n%s", err, out)
			}
		})
	} else {
		g.mustCtl("remote", "enable", "--provider", "manual", "--public-url", public)
	}

	// Loopback binding.
	if ip := nonLoopback(); ip != "" {
		_, rport, _ := net.SplitHostPort(remoteAddr)
		for _, p := range []string{fmt.Sprint(g.port), fmt.Sprint(g.adminPort), rport} {
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, p), 2*time.Second); err == nil {
				c.Close()
				t.Fatalf("port %s accepts connections on %s", p, ip)
			}
		}
	} else {
		t.Log("no non-loopback address on this host; binding checked through the configuration only")
	}

	call := wireCall(1, "ref_echo", `{"text":"remote"}`, "")
	hdr := wireHeaders("tools/call", "ref_echo")
	// Directly on the remote listener with its loopback Host: refused.
	if code, body := g.postAt("https://"+remoteAddr, "", call, hdr); code < 400 {
		t.Fatalf("remote listener answered its loopback name: %d %s", code, body)
	}
	// Through the tunnel without a token.
	if code, body := g.postAt(public, "", call, hdr); code != 401 && !strings.Contains(body, "-31006") {
		t.Fatalf("no token through the tunnel: %d %s", code, body)
	}

	// Registration only on the remote listener.
	reg := map[string]any{"redirect_uris": []string{"http://127.0.0.1:51235/callback"}, "client_name": "AT-18 agent",
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}}
	b, _ := json.Marshal(reg)
	if resp, err := g.httpClient().Post(g.publicURL+"/oauth/register", "application/json", bytes.NewReader(b)); err != nil || (resp.StatusCode != 404 && resp.StatusCode != 405) {
		t.Fatalf("registration on the local listener: %v %v", err, resp)
	}
	resp, err := g.httpClient().Post(public+"/oauth/register", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var client map[string]any
	_ = json.Unmarshal(raw, &client)
	id, _ := client["client_id"].(string)
	if resp.StatusCode != 201 || id == "" || client["smcp_registration_status"] != "pending" {
		t.Fatalf("registration: %d %s", resp.StatusCode, raw)
	}
	if _, err := g.signInAt(public, id, "http://127.0.0.1:51235/callback", "", approverPassword); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("sign-in of a pending client: %v", err)
	}

	g.mustCtl("clients", "approve", id)
	tok, err := g.signInAt(public, id, "http://127.0.0.1:51235/callback", "", approverPassword)
	if err != nil {
		t.Fatalf("sign-in of the approved client: %v", err)
	}
	code, body := g.postAt(public, tok, call, hdr)
	if code != 200 || !strings.Contains(body, "echo:remote") && !strings.Contains(body, "remote") {
		t.Fatalf("approved remote call: %d %s", code, body)
	}
	if code, body := g.postAt(g.publicURL, tok, call, hdr); code == 200 && !strings.Contains(body, "error") {
		t.Fatalf("a remote token was served on the local listener: %d %s", code, body)
	}
	g.stop()

	remoteCalls := 0
	for _, e := range g.events() {
		if e.str("class") == "call" && e.str("phase") == "delivered" {
			if e.str("channel") != "remote" {
				t.Fatalf("delivered call with channel %q", e.str("channel"))
			}
			if !regexp.MustCompile(`^203\.0\.113\.7`).MatchString(e.str("client_address")) {
				t.Fatalf("remote call client address %q", e.str("client_address"))
			}
			remoteCalls++
		}
	}
	if remoteCalls != 1 {
		t.Fatalf("%d delivered remote calls, want 1", remoteCalls)
	}
}
