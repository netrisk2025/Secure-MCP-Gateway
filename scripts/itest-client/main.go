// Command itest-client drives a running smcpd the way a harness does: it
// discovers the authorization server from the 401 challenge, runs the OAuth
// 2.1 authorization-code flow with PKCE (S256) through the sign-in form,
// opens an MCP session with the access token, lists tools and calls one.
//
// It is used by scripts/ci-integration.sh and the "linux-integration" CI job.
// It never follows redirects to the loopback callback; it reads the code
// from the Location header, as a native client's loopback listener would.
//
// Usage:
//
//	itest-client -url https://127.0.0.1:8443 -ca state/ca.pem -password "$SMCP_ADMIN_PASSWORD" \
//	    -call fs_read_text_file -args '{"path":"/tmp/x/hello.txt"}' -expect hello
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type options struct {
	base, mcpPath, ca, username, password, clientID, redirect, scope string
	call, args, expect                                               string
	timeout                                                          time.Duration
	repeat                                                           int
}

func main() {
	var o options
	flag.StringVar(&o.base, "url", "https://127.0.0.1:8443", "Gateway public URL")
	flag.StringVar(&o.mcpPath, "mcp-path", "/mcp", "MCP endpoint path")
	flag.StringVar(&o.ca, "ca", "", "CA certificate that signs the Gateway's TLS certificate (PEM)")
	flag.StringVar(&o.username, "username", "approver", "Session Approver user name for the sign-in form")
	flag.StringVar(&o.password, "password", os.Getenv("SMCP_SIGNIN_PASSWORD"), "Session Approver password (or SMCP_SIGNIN_PASSWORD)")
	flag.StringVar(&o.clientID, "client-id", "https://claude.ai/api/mcp/oauth/client-metadata", "OAuth client_id registered in smcp.toml")
	flag.StringVar(&o.redirect, "redirect", "http://127.0.0.1:51234/callback", "loopback redirect URI")
	flag.StringVar(&o.scope, "scope", "", "requested scope")
	flag.StringVar(&o.call, "call", "", "tool to call after listing (optional)")
	flag.StringVar(&o.args, "args", "{}", "tool arguments as a JSON object")
	flag.StringVar(&o.expect, "expect", "", "substring the tool result text must contain")
	flag.DurationVar(&o.timeout, "timeout", 60*time.Second, "overall timeout")
	flag.IntVar(&o.repeat, "repeat", 1, "make the tool call this many times in the one session (for example to train a baseline)")
	flag.Parse()
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "itest-client: FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("itest-client: PASS")
}

func step(format string, a ...any) { fmt.Printf("itest-client: "+format+"\n", a...) }

func run(o options) error {
	if o.password == "" {
		return errors.New("-password or SMCP_ADMIN_PASSWORD is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if o.ca != "" {
		pem, err := os.ReadFile(o.ca)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("%s: no certificates", o.ca)
		}
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	hc := &http.Client{
		Transport:     transport,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	endpoint := strings.TrimRight(o.base, "/") + o.mcpPath

	// 1. Unauthenticated request: 401 with a resource_metadata challenge.
	resp, err := hc.Post(endpoint, "application/json", strings.NewReader(`{}`))
	if err != nil {
		return err
	}
	drain(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("unauthenticated POST: status %d, want 401", resp.StatusCode)
	}
	prmURL := challengeParam(resp.Header.Get("WWW-Authenticate"), "resource_metadata")
	if prmURL == "" {
		return fmt.Errorf("401 lacks resource_metadata: %q", resp.Header.Get("WWW-Authenticate"))
	}
	step("401 challenge points to %s", prmURL)

	// 2. Protected resource and authorization server metadata.
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := getJSON(hc, prmURL, &prm); err != nil {
		return err
	}
	if prm.Resource == "" || len(prm.AuthorizationServers) == 0 {
		return fmt.Errorf("protected resource metadata incomplete: %+v", prm)
	}
	var asm struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	}
	if err := getJSON(hc, strings.TrimRight(prm.AuthorizationServers[0], "/")+"/.well-known/oauth-authorization-server", &asm); err != nil {
		return err
	}
	if !contains(asm.CodeChallengeMethods, "S256") {
		return fmt.Errorf("authorization server does not offer S256: %v", asm.CodeChallengeMethods)
	}
	step("authorization server %s (resource %s)", asm.Issuer, prm.Resource)

	// 3. Authorization request with PKCE; the server renders a sign-in form.
	verifier := randomString(48)
	sum := sha256.Sum256([]byte(verifier))
	state := randomString(16)
	q := url.Values{
		"response_type": {"code"}, "client_id": {o.clientID}, "redirect_uri": {o.redirect}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"resource": {prm.Resource},
	}
	if o.scope != "" {
		q.Set("scope", o.scope)
	}
	authURL, err := url.Parse(asm.AuthorizationEndpoint)
	if err != nil {
		return err
	}
	authURL.RawQuery = q.Encode()
	resp, err = hc.Get(authURL.String())
	if err != nil {
		return err
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authorization GET: status %d: %s", resp.StatusCode, page)
	}
	action, fields, err := parseForm(string(page))
	if err != nil {
		return err
	}
	fields.Set("username", o.username)
	fields.Set("password", o.password)
	actionURL, err := authURL.Parse(action)
	if err != nil {
		return err
	}
	step("signing in through the form at %s", actionURL.Path)

	// 4. Submit the form; expect a redirect to the loopback callback.
	resp, err = hc.PostForm(actionURL.String(), fields)
	if err != nil {
		return err
	}
	drain(resp)
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		return fmt.Errorf("sign-in POST: status %d, want a redirect", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return err
	}
	if !strings.HasPrefix(loc.String(), o.redirect) {
		return fmt.Errorf("redirected to %s, want %s", loc, o.redirect)
	}
	cb := loc.Query()
	if e := cb.Get("error"); e != "" {
		return fmt.Errorf("authorization error %s: %s", e, cb.Get("error_description"))
	}
	if cb.Get("state") != state {
		return errors.New("state mismatch in the callback")
	}
	if iss := cb.Get("iss"); iss != "" && iss != asm.Issuer {
		return fmt.Errorf("callback iss %s, want %s", iss, asm.Issuer)
	}
	if cb.Get("code") == "" {
		return errors.New("callback has no code")
	}

	// 5. Token exchange with the PKCE verifier.
	resp, err = hc.PostForm(asm.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "code": {cb.Get("code")}, "redirect_uri": {o.redirect},
		"client_id": {o.clientID}, "code_verifier": {verifier}, "resource": {prm.Resource},
	})
	if err != nil {
		return err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		TemplateID  string `json:"template_id"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token: status %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("token response: %w: %s", err, body)
	}
	if tok.AccessToken == "" {
		return fmt.Errorf("token response has no access_token: %s", body)
	}
	step("token issued (type %s, expires in %ds, template %s)", tok.TokenType, tok.ExpiresIn, tok.TemplateID)

	// 6. MCP session: list tools and call one.
	client := mcp.NewClient(&mcp.Implementation{Name: "smcp-itest-client", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: bearer{tok.AccessToken, transport}},
	}, nil)
	if err != nil {
		return fmt.Errorf("MCP connect: %w", err)
	}
	defer cs.Close()
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("tools/list: %w", err)
	}
	names := make([]string, 0, len(lt.Tools))
	for _, t := range lt.Tools {
		names = append(names, t.Name)
	}
	step("tools/list returned %d tools: %s", len(names), strings.Join(names, " "))
	if len(names) == 0 {
		return errors.New("empty tool catalog")
	}
	if o.call == "" {
		return nil
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(o.args), &args); err != nil {
		return fmt.Errorf("-args: %w", err)
	}
	for i := 0; i < max(o.repeat, 1); i++ {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: o.call, Arguments: args})
		if err != nil {
			return fmt.Errorf("tools/call %s: %w", o.call, err)
		}
		var text strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text.WriteString(tc.Text)
			}
		}
		if res.IsError {
			return fmt.Errorf("tools/call %s returned a tool error: %s", o.call, text.String())
		}
		if o.expect != "" && !strings.Contains(text.String(), o.expect) {
			return fmt.Errorf("tools/call %s result lacks %q: %s", o.call, o.expect, text.String())
		}
		step("tools/call %s returned %d bytes of text", o.call, text.Len())
	}
	return nil
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func getJSON(hc *http.Client, u string, v any) error {
	resp, err := hc.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

var (
	formRe  = regexp.MustCompile(`(?is)<form[^>]*\baction="([^"]*)"`)
	inputRe = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRe  = regexp.MustCompile(`(?is)\b(type|name|value)="([^"]*)"`)
)

// parseForm returns the form action and its hidden fields.
func parseForm(page string) (string, url.Values, error) {
	m := formRe.FindStringSubmatch(page)
	if m == nil {
		return "", nil, errors.New("authorization page has no form")
	}
	fields := url.Values{}
	for _, in := range inputRe.FindAllString(page, -1) {
		attrs := map[string]string{}
		for _, a := range attrRe.FindAllStringSubmatch(in, -1) {
			attrs[strings.ToLower(a[1])] = html.UnescapeString(a[2])
		}
		if strings.EqualFold(attrs["type"], "hidden") && attrs["name"] != "" {
			fields.Set(attrs["name"], attrs["value"])
		}
	}
	return html.UnescapeString(m[1]), fields, nil
}

// challengeParam extracts a parameter from a WWW-Authenticate header.
func challengeParam(h, name string) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `="([^"]*)"`)
	if m := re.FindStringSubmatch(h); m != nil {
		return m[1]
	}
	return ""
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
