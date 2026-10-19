package perf

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	approverPassword = "perf approver password 1"
	adminPassword    = "perf admin password 1"
	clientID         = "https://claude.ai/api/mcp/oauth/client-metadata"
	redirectURI      = "http://127.0.0.1:51234/callback"
)

// instance is one bootstrapped smcpd of the real binaries.
type instance struct {
	bin, dir, cfg, state, sandbox string
	port, adminPort               int
	cmd                           *exec.Cmd
	exited                        chan struct{}
	log                           *os.File
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// newInstance bootstraps an instance in dir with notifications and metrics
// off and limits that let eight callers run unthrottled, then appends
// extra to its configuration and writes policy as its policy file.
func newInstance(bin, dir, extra string, policy []byte) (*instance, error) {
	in := &instance{bin: bin, dir: dir, cfg: filepath.Join(dir, "smcp.toml"), state: filepath.Join(dir, "state"), sandbox: filepath.Join(dir, "sandbox")}
	var err error
	if in.port, err = freePort(); err != nil {
		return nil, err
	}
	if in.adminPort, err = freePort(); err != nil {
		return nil, err
	}
	priv, err := os.MkdirTemp("", "smcp-perf-pw-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(priv)
	for name, pw := range map[string]string{"admin": adminPassword, "approver": approverPassword} {
		if err := os.WriteFile(filepath.Join(priv, name), []byte(pw+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if out, err := in.ctl("bootstrap", "--dir", dir, "--admin-password-file", filepath.Join(priv, "admin"), "--approver-password-file", filepath.Join(priv, "approver"),
		"--refserver", filepath.Join(bin, "smcp-refserver"), "--port", strconv.Itoa(in.port), "--admin-port", strconv.Itoa(in.adminPort),
		"--metrics-port", "0", "--notify", "off"); err != nil {
		return nil, fmt.Errorf("bootstrap: %w: %s", err, out)
	}
	f, err := os.OpenFile(in.cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	_, err = f.WriteString("\n[limits]\nsessions_per_principal = 64\nprincipal_call_burst = 0\nprincipal_calls_per_minute = 1000000\n" + extra + "\n")
	f.Close()
	if err != nil {
		return nil, err
	}
	if policy != nil {
		if err := os.WriteFile(filepath.Join(dir, "policy.json"), policy, 0o644); err != nil {
			return nil, err
		}
	}
	if out, err := in.ctl("config", "validate", "--config", in.cfg); err != nil {
		return nil, fmt.Errorf("config validate: %w: %s", err, out)
	}
	return in, nil
}

func (in *instance) ctl(args ...string) (string, error) {
	cmd := exec.Command(filepath.Join(in.bin, "smcpctl"), args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (in *instance) start() error {
	log, err := os.Create(filepath.Join(in.dir, "smcpd.log"))
	if err != nil {
		return err
	}
	in.log = log
	in.cmd = exec.Command(filepath.Join(in.bin, "smcpd"), "--config", in.cfg)
	in.cmd.Stdout, in.cmd.Stderr = log, log
	if err := in.cmd.Start(); err != nil {
		return err
	}
	in.exited = make(chan struct{})
	go func() { _ = in.cmd.Wait(); close(in.exited) }()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := in.ctl("health", "--config", in.cfg); err == nil {
			return nil
		}
		select {
		case <-in.exited:
			b, _ := os.ReadFile(log.Name())
			return fmt.Errorf("smcpd exited during startup:\n%s", b)
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("smcpd did not become healthy")
}

func (in *instance) stop() {
	if in.cmd == nil {
		return
	}
	_ = in.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-in.exited:
	case <-time.After(30 * time.Second):
		_ = in.cmd.Process.Kill()
		<-in.exited
	}
	in.cmd = nil
	if in.log != nil {
		in.log.Close()
	}
}

// rssBytes returns the resident memory of the running smcpd.
func (in *instance) rssBytes() (int64, error) {
	if in.cmd == nil {
		return 0, errors.New("not running")
	}
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(in.cmd.Process.Pid)).Output()
	if err != nil {
		return 0, err
	}
	kb, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return kb << 10, err
}

func (in *instance) tlsConfig() (*tls.Config, error) {
	pem, err := os.ReadFile(filepath.Join(in.state, "tls", "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA unreadable")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

func (in *instance) httpClient() (*http.Client, error) {
	tc, err := in.tlsConfig()
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 120 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, MaxIdleConnsPerHost: 64},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

var (
	formRe  = regexp.MustCompile(`(?is)<form[^>]*\baction="([^"]*)"`)
	inputRe = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRe  = regexp.MustCompile(`(?is)\b(type|name|value)="([^"]*)"`)
)

// signIn runs the OAuth authorization-code flow with PKCE as the Session
// Approver and returns an access token.
func (in *instance) signIn() (string, error) {
	hc, err := in.httpClient()
	if err != nil {
		return "", err
	}
	base := fmt.Sprintf("https://127.0.0.1:%d", in.port)
	var asm struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	resp, err := hc.Get(base + "/.well-known/oauth-authorization-server")
	if err != nil {
		return "", err
	}
	err = json.NewDecoder(resp.Body).Decode(&asm)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "state": {"perf"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "resource": {base + "/mcp"}}
	au, err := url.Parse(asm.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	au.RawQuery = q.Encode()
	resp, err = hc.Get(au.String())
	if err != nil {
		return "", err
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	m := formRe.FindStringSubmatch(string(page))
	if m == nil {
		return "", fmt.Errorf("no sign-in form (%d)", resp.StatusCode)
	}
	fields := url.Values{}
	for _, inp := range inputRe.FindAllString(string(page), -1) {
		attrs := map[string]string{}
		for _, a := range attrRe.FindAllStringSubmatch(inp, -1) {
			attrs[strings.ToLower(a[1])] = html.UnescapeString(a[2])
		}
		if strings.EqualFold(attrs["type"], "hidden") && attrs["name"] != "" {
			fields.Set(attrs["name"], attrs["value"])
		}
	}
	fields.Set("username", "approver")
	fields.Set("password", approverPassword)
	action, err := au.Parse(html.UnescapeString(m[1]))
	if err != nil {
		return "", err
	}
	resp, err = hc.PostForm(action.String(), fields)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		return "", fmt.Errorf("sign-in: status %d", resp.StatusCode)
	}
	resp, err = hc.PostForm(asm.TokenEndpoint, url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {redirectURI}, "client_id": {clientID}, "code_verifier": {verifier}, "resource": {base + "/mcp"}})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("token: status %d: %w", resp.StatusCode, err)
	}
	return tok.AccessToken, nil
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

// session signs in and opens an MCP client session.
func (in *instance) session(ctx context.Context) (*mcp.ClientSession, error) {
	tok, err := in.signIn()
	if err != nil {
		return nil, err
	}
	tc, err := in.tlsConfig()
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "smcp-workload", Version: "1"}, nil)
	return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: fmt.Sprintf("https://127.0.0.1:%d/mcp", in.port),
		HTTPClient: &http.Client{Transport: bearer{tok, &http.Transport{TLSClientConfig: tc}}}}, nil)
}

// api sends a control API GET with the operator token and returns the
// status and the time it took.
func (in *instance) api(hc *http.Client, path string) (int, time.Duration, error) {
	tok, err := os.ReadFile(filepath.Join(in.state, "keys", "admin.token"))
	if err != nil {
		return 0, 0, err
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%d%s", in.adminPort, path), nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	t0 := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return 0, 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, time.Since(t0), nil
}

// overheads reads the journal and returns, per delivered call, the
// gateway-added overhead P-213 in milliseconds: end-to-end time (P-162,
// from the request's receipt, received_at of the requested event, to the
// delivered event) minus server execution (P-101, from the dispatched
// event to the backend's response, responded_at of the completed event);
// no call here waits for an approval (P-206). The completed event is
// written after response inspection, so its own time is not the end of
// server execution: P-213 measured to it left response inspection out.
func (in *instance) overheads() ([]float64, error) {
	segs, _ := filepath.Glob(filepath.Join(in.state, "journal", "segment-*.jsonl"))
	type marks struct{ recv, disp, resp, del time.Time }
	m := map[string]*marks{}
	for _, s := range segs {
		f, err := os.Open(s)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var e struct {
				Type, Class, Phase, Time string
				Corr                     string `json:"correlation_id"`
				Detail                   struct {
					ReceivedAt  string `json:"received_at"`
					RespondedAt string `json:"responded_at"`
				}
			}
			if json.Unmarshal(sc.Bytes(), &e) != nil || e.Type != "event" || e.Class != "call" || e.Corr == "" {
				continue
			}
			at := e.Time
			switch e.Phase {
			case "requested":
				at = e.Detail.ReceivedAt
			case "completed":
				at = e.Detail.RespondedAt
			}
			t, err := time.Parse(time.RFC3339Nano, at)
			if err != nil {
				continue
			}
			x := m[e.Corr]
			if x == nil {
				x = &marks{}
				m[e.Corr] = x
			}
			switch e.Phase {
			case "requested":
				x.recv = t
			case "dispatched":
				x.disp = t
			case "completed":
				x.resp = t
			case "delivered":
				x.del = t
			}
		}
		f.Close()
	}
	var out []float64
	for _, x := range m {
		if !x.recv.IsZero() && !x.disp.IsZero() && !x.resp.IsZero() && !x.del.IsZero() {
			out = append(out, float64(x.del.Sub(x.recv)-x.resp.Sub(x.disp))/1e6)
		}
	}
	return out, nil
}
