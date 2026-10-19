package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// remoteState asks a running Gateway for GET /api/v1/remote as the
// Administrator.
func remoteState(t *testing.T, cfgPath string) map[string]any {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	body, st, err := c.do("GET", "/api/v1/remote", nil)
	if err != nil || st != 200 {
		t.Fatalf("GET /api/v1/remote: %d %v", st, err)
	}
	return body
}

// TestRemoteAccessDisabledByDefault is FR-16.11: the configurations
// written by `smcpctl bootstrap` and `smcpctl install` start a Gateway
// with the Remote Access Profile off and its listener closed; enabling it
// as an Operator (a [[console.account]] signed in through the control API)
// is refused and records nothing; enabling it as the Administrator
// (`smcpctl remote enable`) succeeds and records remote_access_enabled with
// the Administrator as actor.
func TestRemoteAccessDisabledByDefault(t *testing.T) {
	reqtest.Verifies(t, "FR-16.11")
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 34\n")
	opPW := writeFile(t, secrets, "operator", "operator password 56\n")

	off := func(where string, body map[string]any) {
		t.Helper()
		if body["enabled"] != false || body["listening"] != false {
			t.Fatalf("%s: remote access not off by default: %v", where, body)
		}
	}

	// smcpctl install (Standalone, the service manager faked so that the
	// real smcpd runs from the written configuration).
	home, err := os.MkdirTemp("", "smcp-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	env := map[string]string{"XDG_RUNTIME_DIR": filepath.Join(home, "run")}
	if err := os.MkdirAll(env["XDG_RUNTIME_DIR"], 0o700); err != nil {
		t.Fatal(err)
	}
	f := &fakeManager{t: t}
	in, out := testInstaller(t, "linux", home, env, f)
	l, err := in.layout()
	if err != nil {
		t.Fatal(err)
	}
	installCfg := filepath.Join(l.cfgDir, "smcp.toml")
	f.cfg = func() string { return installCfg }
	if err := in.standalone(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	raw, _ := os.ReadFile(installCfg)
	if strings.Contains(string(raw), "\n[remote]") {
		t.Fatalf("install wrote a [remote] table:\n%s", raw)
	}
	off("install", remoteState(t, installCfg))
	f.stop()

	// smcpctl bootstrap.
	dir := t.TempDir()
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", "0", "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	raw, _ = os.ReadFile(cfgPath)
	if strings.Contains(string(raw), "\n[remote]") {
		t.Fatalf("bootstrap wrote a [remote] table:\n%s", raw)
	}
	d := startDaemon(t, cfgPath)
	off("bootstrap", remoteState(t, cfgPath))
	stopDaemon(t, d)

	// An Operator account and a free port for the remote listener; then
	// the Operator's enable is refused and the Administrator's recorded.
	hash := strings.TrimSpace(mustCtl(t, "hash-password", "--password-file", opPW))
	extra := fmt.Sprintf("\n[remote]\naddress = \"127.0.0.1:%s\"\n\n[[console.account]]\nusername = \"olga\"\npassword_hash = %q\nrole = \"operator\"\n", freePort(t), hash)
	if err := os.WriteFile(cfgPath, append(raw, extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	d = startDaemon(t, cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	op, err := newAdminClient(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	login, st, err := op.do("POST", "/api/v1/console/login", map[string]any{"username": "olga", "password": "operator password 56", "role": "operator"})
	if err != nil || st != 200 || login["role"] != "operator" {
		t.Fatalf("operator sign-in: %d %v %v", st, err, login)
	}
	op.token = login["token"].(string)
	if _, st, _ := op.do("POST", "/api/v1/remote/enable", map[string]any{"public_url": "https://gw.example.test", "provider": "manual"}); st != 403 {
		t.Fatalf("Operator enable: %d, want 403", st)
	}
	off("after the Operator's attempt", remoteState(t, cfgPath))
	if out := mustCtl(t, "remote", "enable", "--config", cfgPath, "--provider", "manual", "--public-url", "https://gw.example.test"); !strings.Contains(out, "remote access enabled") {
		t.Fatalf("Administrator enable: %s", out)
	}
	if body := remoteState(t, cfgPath); body["enabled"] != true {
		t.Fatalf("after the Administrator's enable: %v", body)
	}
	mustCtl(t, "remote", "disable", "--config", cfgPath)
	stopDaemon(t, d)

	segs, _ := filepath.Glob(filepath.Join(cfg.State.Dir, "journal", "segment-*.jsonl"))
	var enabled []string
	for _, s := range segs {
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, `"remote_access_enabled"`) {
				enabled = append(enabled, line)
			}
		}
	}
	if len(enabled) != 1 || strings.Contains(enabled[0], "olga") || !strings.Contains(enabled[0], `"actor":"operator-token"`) {
		t.Fatalf("remote_access_enabled events (want one, by the Administrator): %q", enabled)
	}
}
