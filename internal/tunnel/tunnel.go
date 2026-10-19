// Package tunnel drives the tunnel connectors that forward a public HTTPS
// name to the Remote Access listener (FR-16.2): Tailscale Funnel through
// the tailscale CLI, and a Cloudflare quick tunnel through cloudflared as a
// fallback. It also checks a public name end to end. The CLIs are located
// through $SMCP_TAILSCALE and $SMCP_CLOUDFLARED or the PATH, which lets
// tests substitute fakes so nothing is ever exposed by a test run.
package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// FunnelPorts are the public ports Tailscale Funnel accepts.
var FunnelPorts = []int{443, 8443, 10000}

// State records what `smcpctl remote enable` started, so that disable can
// undo it. It is kept in <state>/remote/tunnel.json.
type State struct {
	Provider  string `json:"provider"`
	PublicURL string `json:"public_url"`
	Port      int    `json:"port,omitempty"` // Funnel public port
	PID       int    `json:"pid,omitempty"`  // cloudflared process
	Target    string `json:"target"`
	// HostRules is set when enable installed the nftables table
	// HostRulesTable for HostRulePorts (SR-4.14-1); disable removes it.
	HostRules     bool  `json:"host_rules,omitempty"`
	HostRulePorts []int `json:"host_rule_ports,omitempty"`
}

// LoadState reads the tunnel state; a missing file is the zero State.
func LoadState(path string) (State, error) {
	var s State
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// SaveState writes the tunnel state with mode 0600.
func SaveState(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

func bin(env, name string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return name
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Tailscale drives Tailscale Funnel.
type Tailscale struct{ Bin string }

// NewTailscale locates the tailscale CLI.
func NewTailscale() Tailscale { return Tailscale{Bin: bin("SMCP_TAILSCALE", "tailscale")} }

// PublicURL is https://<this node's MagicDNS name>[:port].
func (t Tailscale) PublicURL(ctx context.Context, port int) (string, error) {
	out, err := run(ctx, t.Bin, "status", "--json")
	if err != nil {
		return "", err
	}
	var st struct {
		BackendState string
		Self         struct{ DNSName string }
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return "", fmt.Errorf("tailscale status: %w", err)
	}
	if st.BackendState != "" && st.BackendState != "Running" {
		return "", fmt.Errorf("tailscale is %s; run tailscale up first", st.BackendState)
	}
	name := strings.TrimSuffix(st.Self.DNSName, ".")
	if name == "" {
		return "", errors.New("tailscale status reports no MagicDNS name; enable MagicDNS and HTTPS certificates for the tailnet")
	}
	if port == 443 {
		return "https://" + name, nil
	}
	return "https://" + name + ":" + strconv.Itoa(port), nil
}

func checkFunnelPort(port int) error {
	for _, p := range FunnelPorts {
		if p == port {
			return nil
		}
	}
	return fmt.Errorf("funnel accepts public ports 443, 8443 and 10000, not %d", port)
}

// EnableArgs is the funnel command for port and target.
func EnableArgs(port int, target string) []string {
	return []string{"funnel", "--bg", "--https=" + strconv.Itoa(port), "https+insecure://" + target}
}

// Enable starts Funnel in the background from the public port to the
// remote listener. The listener's certificate is issued by the Gateway's
// own CA, hence https+insecure between tailscaled and the loopback
// listener; the public side has a Let's Encrypt certificate.
func (t Tailscale) Enable(ctx context.Context, port int, target string) error {
	if err := checkFunnelPort(port); err != nil {
		return err
	}
	_, err := run(ctx, t.Bin, EnableArgs(port, target)...)
	return err
}

// Disable turns Funnel off on port.
func (t Tailscale) Disable(ctx context.Context, port int) error {
	_, err := run(ctx, t.Bin, "funnel", "--https="+strconv.Itoa(port), "off")
	return err
}

// Status returns `tailscale funnel status --json`.
func (t Tailscale) Status(ctx context.Context) (json.RawMessage, error) {
	out, err := run(ctx, t.Bin, "funnel", "status", "--json")
	if err != nil {
		return nil, err
	}
	if !json.Valid(out) {
		return nil, errors.New("tailscale funnel status returned non-JSON")
	}
	return out, nil
}

// Cloudflare runs a Cloudflare quick tunnel (trycloudflare.com). Quick
// tunnels get a new random name on every start and have no uptime
// guarantee; they are the fallback when Tailscale is not available.
type Cloudflare struct {
	Bin string
	// Wait bounds how long Start waits for the public name (default 30 s).
	Wait time.Duration
}

// NewCloudflare locates cloudflared.
func NewCloudflare() Cloudflare {
	return Cloudflare{Bin: bin("SMCP_CLOUDFLARED", "cloudflared"), Wait: 30 * time.Second}
}

var quickURL = regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)

// Start launches cloudflared detached, logging to logPath, and returns its
// PID and the public URL it reports.
func (c Cloudflare) Start(target, logPath string) (int, string, error) {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, "", err
	}
	defer logf.Close()
	cmd := exec.Command(c.Bin, "tunnel", "--no-autoupdate", "--url", "https://"+target, "--no-tls-verify")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return 0, "", err
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }()
	wait := c.Wait
	if wait == 0 {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if u := scanFile(logPath); u != "" {
			return pid, u, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = Stop(pid)
	return 0, "", fmt.Errorf("cloudflared reported no trycloudflare.com URL within %s; see %s", wait, logPath)
}

func scanFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for sc.Scan() {
		if m := quickURL.FindString(sc.Text()); m != "" {
			return m
		}
	}
	return ""
}

// Stop terminates a process started by Start.
func Stop(pid int) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// Check is the result of a public-name check (FR-16.2).
type Check struct {
	Provider  string `json:"provider"`
	PublicURL string `json:"public_url"`
	Reachable bool   `json:"reachable"`
	Listener  string `json:"listener"` // remote, local (misconfigured) or unknown
	Resource  string `json:"resource,omitempty"`
	Problem   string `json:"problem,omitempty"`
}

// CheckPublic fetches the protected-resource metadata through the public
// name. The Remote Access listener answers with the public URL as its
// resource; a tunnel pointed at the local harness listener answers with
// the local URL (or 421), which is reported as misconfigured.
func CheckPublic(ctx context.Context, provider, publicURL, localResource, caFile string) Check {
	c := Check{Provider: provider, PublicURL: publicURL, Listener: "unknown"}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			c.Problem = err.Error()
			return c
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tc.RootCAs = pool
	}
	h := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tc},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", publicURL+"/.well-known/oauth-protected-resource/mcp", nil)
	if err != nil {
		c.Problem = err.Error()
		return c
	}
	resp, err := h.Do(req)
	if err != nil {
		c.Problem = "the public name is not reachable: " + err.Error()
		return c
	}
	defer resp.Body.Close()
	c.Reachable = true
	var prm struct {
		Resource string `json:"resource"`
	}
	switch {
	case resp.StatusCode == http.StatusMisdirectedRequest:
		c.Problem = "the Gateway refused the Host header (421): the tunnel rewrites Host or forwards to the local harness listener; configure it to preserve the public host name"
	case resp.StatusCode != http.StatusOK:
		c.Problem = fmt.Sprintf("metadata request answered HTTP %d", resp.StatusCode)
	case json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&prm) != nil:
		c.Problem = "metadata is not JSON; the public name does not reach the Gateway"
	default:
		c.Resource = prm.Resource
		switch prm.Resource {
		case publicURL + "/mcp":
			c.Listener = "remote"
		case localResource:
			c.Listener = "local"
			c.Problem = "misconfigured: the tunnel forwards to the local harness listener, which would erase the remote/local distinction; point it at the remote listener"
		default:
			c.Problem = "the metadata names resource " + prm.Resource + ", not " + publicURL + "/mcp"
		}
	}
	return c
}
