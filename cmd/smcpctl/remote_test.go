package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const remoteTOML = "[remote]\naddress = \"%REMOTE%\"\ndefault_principal = \"cloud\"\ntemplates = [\"remote\"]\n"

// fakeCLI writes a shell script that records its arguments and prints
// canned output; tests use it instead of the real tailscale or cloudflared
// so that nothing is exposed.
func fakeCLI(t *testing.T, name, script string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls.log")
	bin = filepath.Join(dir, name)
	body := "#!/bin/sh\necho \"$@\" >> " + log + "\n" + script
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil { //nolint:gosec // an executable test fake
		t.Fatal(err)
	}
	return bin, log
}

func rctl(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRemoteEnableDisableTailscaleFake(t *testing.T) {
	reqtest.Partial(t, "FR-16.11", "FR-16.2")
	g := gwtest.Start(t, remoteTOML)
	bin, log := fakeCLI(t, "tailscale", `case "$1 $2" in
"status --json") echo '{"BackendState":"Running","Self":{"DNSName":"gw-test.tail0000.ts.net."}}';;
"funnel status") echo '{"AllowFunnel":{"gw-test.tail0000.ts.net:443":true}}';;
esac
`)
	t.Setenv("SMCP_TAILSCALE", bin)
	code, out, errs := rctl(t, "remote", "enable", "--config", g.CfgPath, "--provider", "tailscale")
	if code != 0 || !strings.Contains(out, "https://gw-test.tail0000.ts.net/mcp") {
		t.Fatalf("enable: %d %s %s", code, out, errs)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "funnel --bg --https=443 https+insecure://"+g.Config.Remote.Address) {
		t.Fatalf("funnel not started: %s", calls)
	}
	if st := g.Remote.Status(); !st.Enabled || st.PublicURL != "https://gw-test.tail0000.ts.net" || st.Provider != "tailscale" {
		t.Fatalf("status %+v", st)
	}
	code, out, _ = rctl(t, "remote", "status", "--config", g.CfgPath)
	if code != 0 || !strings.Contains(out, `"funnel_status"`) || !strings.Contains(out, `"enabled": true`) {
		t.Fatalf("status: %d %s", code, out)
	}
	if code, _, errs := rctl(t, "remote", "enable", "--config", g.CfgPath, "--provider", "tailscale", "--port", "8080"); code == 0 {
		t.Fatalf("port 8080 accepted: %s", errs)
	}
	code, _, errs = rctl(t, "remote", "disable", "--config", g.CfgPath)
	if code != 0 {
		t.Fatalf("disable: %s", errs)
	}
	calls, _ = os.ReadFile(log)
	if !strings.Contains(string(calls), "funnel --https=443 off") {
		t.Fatalf("funnel not stopped: %s", calls)
	}
	if g.Remote.Status().Enabled || g.Remote.Addr() != "" {
		t.Fatal("still enabled")
	}
}

func TestRemoteEnableCloudflareFake(t *testing.T) {
	reqtest.Partial(t, "FR-16.2")
	g := gwtest.Start(t, remoteTOML)
	bin, log := fakeCLI(t, "cloudflared", `echo "INF |  https://quick-test-name.trycloudflare.com  |" >&2
sleep 30
`)
	t.Setenv("SMCP_CLOUDFLARED", bin)
	code, out, errs := rctl(t, "remote", "enable", "--config", g.CfgPath, "--provider", "cloudflare")
	if code != 0 || !strings.Contains(out, "https://quick-test-name.trycloudflare.com/mcp") {
		t.Fatalf("enable: %d %s %s", code, out, errs)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "tunnel --no-autoupdate --url https://"+g.Config.Remote.Address+" --no-tls-verify") {
		t.Fatalf("cloudflared args: %s", calls)
	}
	var st struct{ PID int }
	b, _ := os.ReadFile(filepath.Join(g.Config.State.Dir, "remote", "tunnel.json"))
	_ = json.Unmarshal(b, &st)
	if st.PID == 0 {
		t.Fatalf("no pid recorded: %s", b)
	}
	if code, _, errs := rctl(t, "remote", "disable", "--config", g.CfgPath); code != 0 {
		t.Fatalf("disable: %s", errs)
	}
	p, _ := os.FindProcess(st.PID)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && p.Signal(nilSignal()) == nil {
		time.Sleep(50 * time.Millisecond)
	}
	if p.Signal(nilSignal()) == nil {
		t.Fatal("cloudflared still running")
	}
}

func TestRemoteCheck(t *testing.T) {
	reqtest.Partial(t, "FR-16.2")
	// Partial: Tailscale and Cloudflare tunnels are replaced by a local
	// TLS proxy; the check itself is the same.
	g := gwtest.Start(t, remoteTOML)
	public := g.Tunnel(func() string { return "203.0.113.5" })
	g.EnableRemote(public)
	code, out, errs := rctl(t, "remote", "check", "--config", g.CfgPath, "--public-url", public, "--ca", g.CAFile)
	if code != 0 || !strings.Contains(out, `"listener": "remote"`) || !strings.Contains(out, `"reachable": true`) {
		t.Fatalf("check: %d %s %s", code, out, errs)
	}
	// A tunnel pointed at the local harness listener is misconfigured.
	wrong := g.TunnelTo(g.Config.Listener.Address, func() string { return "203.0.113.5" })
	code, out, _ = rctl(t, "remote", "check", "--config", g.CfgPath, "--public-url", wrong, "--ca", g.CAFile)
	if code == 0 || !strings.Contains(out, "local harness listener") {
		t.Fatalf("misrouted tunnel passed: %d %s", code, out)
	}
	// Unreachable name.
	if code, out, _ := rctl(t, "remote", "check", "--config", g.CfgPath, "--public-url", "https://127.0.0.1:1", "--ca", g.CAFile); code == 0 || !strings.Contains(out, `"reachable": false`) {
		t.Fatalf("unreachable passed: %s", out)
	}
}

func TestClientsApproveCLI(t *testing.T) {
	reqtest.Partial(t, "FR-16.5")
	g := gwtest.Start(t, remoteTOML)
	public := g.Tunnel(func() string { return "203.0.113.5" })
	g.EnableRemote(public)
	req, _ := http.NewRequest("POST", public+"/oauth/register", strings.NewReader(`{"redirect_uris":["https://agent.example/cb"],"client_name":"Cloud Agent","token_endpoint_auth_method":"none"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var reg map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()
	id, _ := reg["client_id"].(string)
	code, out, _ := rctl(t, "clients", "list", "--config", g.CfgPath, "--status", "pending")
	if code != 0 || !strings.Contains(out, id) || !strings.Contains(out, "Cloud Agent") {
		t.Fatalf("list: %s", out)
	}
	code, out, errs := rctl(t, "clients", "approve", id, "--config", g.CfgPath, "--principal", "cloud")
	if code != 0 || !strings.Contains(out, `"status": "approved"`) {
		t.Fatalf("approve: %d %s %s", code, out, errs)
	}
	if code, _, _ := rctl(t, "client", "deny", id, "--config", g.CfgPath); code == 0 {
		t.Fatal("deny of an approved registration accepted")
	}
}

func TestDoctorExitAndJSON(t *testing.T) {
	reqtest.Verifies(t, "FR-15.5")
	g := gwtest.Start(t, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SMCP_CREDENTIALS", filepath.Join(home, "missing", "credentials.toml"))
	t.Setenv("SMCP_HARNESS_ROOT", t.TempDir())
	// No findings: the Gateway paths are not readable by this user.
	for _, d := range []string{g.Config.State.Dir, g.Config.Dir} {
		if err := os.Chmod(d, 0o100); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(d, 0o700)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads every path")
	}
	code, out, errs := rctl(t, "doctor", "--config", g.CfgPath, "--client", "hermes")
	if code != 0 || !strings.Contains(out, "0 findings") {
		t.Fatalf("clean doctor: %d %s %s", code, out, errs)
	}
	// Findings: another MCP server and readable state.
	os.Chmod(g.Config.State.Dir, 0o700)
	if err := os.MkdirAll(filepath.Join(home, ".hermes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".hermes", "config.yaml"), []byte("mcp_servers:\n  other:\n    command: other-mcp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, text, _ := rctl(t, "doctor", "--config", g.CfgPath, "--client", "hermes")
	if code == 0 {
		t.Fatal("findings did not fail")
	}
	code2, js, _ := rctl(t, "doctor", "--config", g.CfgPath, "--client", "hermes", "--json")
	if code2 == 0 {
		t.Fatal("JSON findings did not fail")
	}
	var rep struct {
		Findings []struct {
			Kind, Client, Path, Message string
		}
	}
	if err := json.Unmarshal([]byte(js), &rep); err != nil {
		t.Fatal(err)
	}
	failing := 0
	for _, f := range rep.Findings {
		if !strings.Contains(text, f.Message) {
			t.Errorf("JSON finding missing from text: %s", f.Message)
		}
		if f.Kind != "info" && f.Kind != "warning" {
			failing++
		}
	}
	if failing < 2 || !strings.Contains(text, "readable-path") || !strings.Contains(text, "non-gateway-server") {
		t.Fatalf("findings %d\n%s", failing, text)
	}
}

func TestClientsSetupDryRunAndRemove(t *testing.T) {
	reqtest.Partial(t, "FR-15.7", "FR-15.6")
	g := gwtest.Start(t, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SMCP_HARNESS_ROOT", t.TempDir())
	code, out, errs := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--dry-run", "--system-trust")
	// The system trust command depends on the platform the test runs on.
	trust := map[string]string{"darwin": "run: security add-trusted-cert", "linux": "run: sudo update-ca-certificates"}[runtime.GOOS]
	if code != 0 || !strings.Contains(out, "dry run") || !strings.Contains(out, "NODE_EXTRA_CA_CERTS") || !strings.Contains(out, "allowManagedMcpServersOnly") ||
		!strings.Contains(out, trust) {
		t.Fatalf("dry run: %d %s %s", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); err == nil {
		t.Fatal("dry run wrote files")
	}
	orig := []byte(`{"theme":"dark"}`)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath); code != 0 {
		t.Fatalf("setup: %s %s", out, errs)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	if !strings.Contains(string(b), g.MCPURL()) || !strings.Contains(string(b), "dark") {
		t.Fatalf("claude.json %s", b)
	}
	if code, out, errs := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--remove"); code != 0 {
		t.Fatalf("remove: %s %s", out, errs)
	}
	b, _ = os.ReadFile(filepath.Join(home, ".claude.json"))
	if !bytes.Equal(b, orig) {
		t.Fatalf("not restored: %s", b)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err == nil {
		t.Fatal("created file left after remove")
	}
}

func nilSignal() os.Signal { return syscall.Signal(0) }
