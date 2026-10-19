package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// Policy of the conformance run. One template grants three reference-server
// tools, each exercising one scenario; list_files is deliberately not
// granted so it must never appear in a catalog or in the journal.
const (
	templateID    = "conformance"
	profileID     = "conformance"
	toolAllowed   = "echo"      // allowed scenario
	toolLimited   = "time_now"  // denied scenario (calls_per_minute 1)
	toolApproval  = "read_file" // approval scenario
	toolUngranted = "list_files"
	serverAlias   = "ref"
	approverUser  = "approver"
	helloFile     = "hello.txt"
)

// publicName is the Gateway's public tool name for a reference-server tool.
func publicName(tool string) string { return serverAlias + "_" + tool }

// grantedTools are the public names the conformance template presents.
func grantedTools() []string {
	return []string{publicName(toolAllowed), publicName(toolApproval), publicName(toolLimited)}
}

func conformancePolicy() map[string]any {
	return map[string]any{
		"revision": "agents-r1",
		"framework_profiles": map[string]any{
			// "dev" stays for the bootstrap principal claude-code-local.
			"dev":     map[string]any{"templates": []string{templateID}, "default_template": templateID},
			profileID: map[string]any{"templates": []string{templateID}, "default_template": templateID},
		},
		"templates": map[string]any{
			templateID: map[string]any{
				"description": "Real-agent conformance: one allowed, one rate-limited and one approval-obligated tool",
				"rules": []map[string]any{
					{"id": "conf-allow", "server": serverAlias, "tools": []string{toolAllowed}},
					{"id": "conf-limited", "server": serverAlias, "tools": []string{toolLimited}, "calls_per_minute": 1},
					{"id": "conf-approve", "server": serverAlias, "tools": []string{toolApproval}, "approval": true},
				},
			},
		},
	}
}

// principalID and clientID name the Gateway principal and OAuth client
// registered for one agent, so its evidence is attributable in the journal.
func principalID(c *client) string { return "agents-" + c.ID }
func clientID(c *client) string    { return "smcp-agents-" + c.ID }

// configAppendix is appended to the bootstrap smcp.toml: approvals without
// desktop notifications, and one principal and OAuth client per agent.
func configAppendix(clients []*client) string {
	var b strings.Builder
	b.WriteString("\n# Added by scripts/agents (real-agent conformance suite).\n")
	for _, c := range clients {
		fmt.Fprintf(&b, "\n[[principal]]\nid = %q\nframework = %q\ndisplay_name = %q\nprofile = %q\n",
			principalID(c), c.Framework, c.Name+" (conformance suite)", profileID)
		fmt.Fprintf(&b, "\n[[client]]\nclient_id = %q\nprincipal = %q\nredirect_uris = [\"http://127.0.0.1:*/callback\"]\n",
			clientID(c), principalID(c))
	}
	return b.String()
}

// extraConfig is appended to smcp.toml after configAppendix; the FR-3.25
// approval run sets a short CP-45 hold bound with it.
var extraConfig string

// gateway is a bootstrapped smcpd instance in a temporary directory.
type gateway struct {
	root, work, bin, dir  string
	cfg, ca, journal      string
	url, endpoint         string
	approverPassword      string
	adminURL, adminPWFile string // control API and console (E-24), Administrator password file
	marker                string
	cmd                   *exec.Cmd
	exited                chan error
	log                   *os.File
	hc                    *http.Client
}

// freePort returns a loopback port below the ephemeral range for a
// listener written into the configuration. A port from a "127.0.0.1:0"
// listener is in the ephemeral range, where smcpd's own port-0 listeners
// (the egress proxy) and outgoing connections can take it before the
// configured listener binds it.
func freePort() (int, error) { return testport.Port() }

func newPassword() string { return "agents-" + randomString(18) }

// startGateway builds the binaries, bootstraps an instance with the
// conformance policy and starts smcpd. The caller must call stop.
func startGateway(ctx context.Context, root, work string, clients []*client, dnsOnlyCA, broken bool, logf func(string, ...any)) (*gateway, error) {
	g := &gateway{root: root, work: work, bin: filepath.Join(work, "bin"), dir: filepath.Join(work, "instance")}
	if _, err := os.Stat(g.dir); err == nil {
		return nil, fmt.Errorf("%s already exists; use an empty -work directory", g.dir)
	}
	if err := os.MkdirAll(g.bin, 0o755); err != nil {
		return nil, err
	}
	args := []string{"build", "-trimpath"}
	if broken {
		// FR-15.8 broken-build check: internal/policy compiled with its
		// deliberate defect (no rate limits, no approval obligations).
		logf("BROKEN-BUILD CHECK: building smcpd with -tags smcp_broken")
		args = append(args, "-tags", "smcp_broken")
	}
	logf("building smcpd, smcpctl and smcp-refserver into %s", g.bin)
	build := exec.CommandContext(ctx, "go", append(args, "-o", g.bin+string(os.PathSeparator), "./cmd/smcpd", "./cmd/smcpctl", "./cmd/smcp-refserver")...)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("go build: %w\n%s", err, out)
	}

	port, err := freePort()
	if err != nil {
		return nil, err
	}
	adminPort, err := freePort()
	if err != nil {
		return nil, err
	}
	metricsPort, err := freePort()
	if err != nil {
		return nil, err
	}
	adminPW, approverPW := newPassword(), newPassword()
	g.approverPassword = approverPW
	adminFile, approverFile := filepath.Join(work, "admin.pw"), filepath.Join(work, "approver.pw")
	g.adminURL, g.adminPWFile = fmt.Sprintf("https://127.0.0.1:%d", adminPort), adminFile
	if err := os.WriteFile(adminFile, []byte(adminPW), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(approverFile, []byte(approverPW), 0o600); err != nil {
		return nil, err
	}
	logf("bootstrapping an instance in %s (harness port %d, control port %d)", g.dir, port, adminPort)
	if out, err := g.ctl(ctx, "bootstrap", "--dir", g.dir, "--admin-password-file", adminFile,
		"--approver-password-file", approverFile, "--port", fmt.Sprint(port), "--admin-port", fmt.Sprint(adminPort),
		"--metrics-port", fmt.Sprint(metricsPort), "--notify", "off"); err != nil {
		return nil, fmt.Errorf("smcpctl bootstrap: %w\n%s", err, out)
	}
	g.cfg = filepath.Join(g.dir, "smcp.toml")
	g.ca = filepath.Join(g.dir, "state", "tls", "ca.crt")
	g.journal = filepath.Join(g.dir, "state", "journal")
	g.url = fmt.Sprintf("https://127.0.0.1:%d", port)
	g.endpoint = g.url + "/mcp"

	pol, _ := json.MarshalIndent(conformancePolicy(), "", "  ")
	if err := os.WriteFile(filepath.Join(g.dir, "policy.json"), append(pol, '\n'), 0o600); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(g.cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	_, err = f.WriteString(configAppendix(clients) + extraConfig)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if out, err := g.ctl(ctx, "config", "validate", "--config", g.cfg); err != nil {
		return nil, fmt.Errorf("smcpctl config validate: %w\n%s", err, out)
	}
	g.marker = "smcp-agents-" + randomString(9)
	if err := os.WriteFile(filepath.Join(g.dir, "sandbox", helloFile), []byte(g.marker+"\n"), 0o644); err != nil {
		return nil, err
	}

	if dnsOnlyCA {
		logf("DIAGNOSTIC: replacing the server CA with one that has DNS-only name constraints (deviates from CP-53)")
		if err := reissueDNSOnlyCA(filepath.Join(g.dir, "state")); err != nil {
			return nil, err
		}
	}
	pem, err := os.ReadFile(g.ca)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificates", g.ca)
	}
	g.hc = &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}},
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	if g.log, err = os.Create(filepath.Join(work, "smcpd.log")); err != nil {
		return nil, err
	}
	g.cmd = exec.Command(filepath.Join(g.bin, "smcpd"), "--config", g.cfg)
	g.cmd.Stdout, g.cmd.Stderr = g.log, g.log
	logf("starting smcpd at %s", g.url)
	if err := g.cmd.Start(); err != nil {
		return nil, err
	}
	exited := make(chan error, 1)
	go func() { exited <- g.cmd.Wait() }()
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case err := <-exited:
			g.cmd = nil
			return nil, fmt.Errorf("smcpd exited during startup (%w); log: %s", err, g.log.Name())
		default:
		}
		if _, err := g.ctl(ctx, "health", "--config", g.cfg); err == nil {
			break
		}
		if time.Now().After(deadline) {
			g.stop()
			return nil, fmt.Errorf("smcpd did not become healthy within 60 s; log: %s", g.log.Name())
		}
		time.Sleep(300 * time.Millisecond)
	}
	// Keep the exit channel for stop.
	g.exited = exited
	return g, nil
}

func (g *gateway) ctl(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(g.bin, "smcpctl"), args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

// stop sends SIGTERM and waits for smcpd to exit, so the journal is closed
// cleanly before it is verified.
func (g *gateway) stop() {
	if g.cmd == nil || g.cmd.Process == nil {
		return
	}
	_ = g.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-g.exited:
	case <-time.After(20 * time.Second):
		_ = g.cmd.Process.Kill()
		<-g.exited
	}
	g.cmd = nil
	if g.log != nil {
		_ = g.log.Close()
	}
}

// events reads the journal as written so far.
func (g *gateway) events() ([]audit.Event, error) { return audit.ReadEvents(g.journal) }

// verifyJournal runs `smcpctl journal verify` on the stopped instance.
func (g *gateway) verifyJournal(ctx context.Context) (string, error) {
	out, err := g.ctl(ctx, "journal", "verify", "--config", g.cfg)
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("smcpctl journal verify: %w: %s", err, s)
	}
	return s, nil
}

// pendingApprovals lists pending approvals through `smcpctl approvals list`.
func (g *gateway) pendingApprovals(ctx context.Context) ([]approvalSummary, error) {
	out, err := g.ctl(ctx, "approvals", "list", "--json", "--config", g.cfg)
	if err != nil {
		return nil, fmt.Errorf("smcpctl approvals list: %w: %s", err, out)
	}
	var res struct {
		Approvals []approvalSummary `json:"approvals"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("smcpctl approvals list: %w", err)
	}
	return res.Approvals, nil
}

type approvalSummary struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	PublicName string `json:"public_name"`
	SessionID  string `json:"session_id"`
}

// approvalsAvailable reports whether this build has the Approval Service
// commands (E-07).
func (g *gateway) approvalsAvailable(ctx context.Context) bool {
	out, _ := g.ctl(ctx, "approvals", "help")
	return !strings.HasPrefix(string(out), "usage: smcpctl <command>")
}

// approveFor approves, with smcpctl, every pending approval of sessionID for
// tool until ctx ends, and returns the IDs it approved.
func (g *gateway) approveFor(ctx context.Context, sessionID, tool string, logf func(string, ...any)) []string {
	var approved []string
	seen := map[string]bool{}
	for {
		list, err := g.pendingApprovals(ctx)
		if err == nil {
			for _, a := range list {
				if a.SessionID != sessionID || a.PublicName != tool || seen[a.ID] {
					continue
				}
				seen[a.ID] = true
				// The approval releases the held call, and the caller ends
				// ctx when the agent exits, which can be before smcpctl
				// does: the command runs to its end on its own deadline, so
				// an approval made is never reported as failed.
				actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
				out, err := g.ctl(actx, "approvals", "approve", a.ID, "--yes", "--comment", "real-agent conformance suite", "--config", g.cfg)
				cancel()
				if err != nil {
					logf("smcpctl approvals approve %s: %v: %s", a.ID, err, lastLine(out))
					continue
				}
				logf("approved %s for %s with smcpctl", a.ID, tool)
				approved = append(approved, a.ID)
			}
		}
		select {
		case <-ctx.Done():
			return approved
		case <-time.After(400 * time.Millisecond):
		}
	}
}

func lastLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return s
}
