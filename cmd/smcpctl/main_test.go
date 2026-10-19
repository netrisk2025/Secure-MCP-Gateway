package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// bins builds smcpctl, smcpd and smcp-refserver once per test binary.
var binDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "smcpctl-test-")
	if err != nil {
		panic(err)
	}
	binDir = dir
	// go test puts its own toolchain first on PATH for the test process.
	goTool, err := exec.LookPath("go")
	if err != nil {
		os.RemoveAll(dir)
		panic("go tool: " + err.Error())
	}
	for _, pkg := range []string{"smcpctl", "smcpd", "smcp-refserver"} {
		cmd := exec.Command(goTool, "build", "-o", filepath.Join(dir, pkg), "../"+pkg)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			os.RemoveAll(dir)
			panic("build " + pkg + ": " + err.Error())
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func freePort(t *testing.T) string {
	t.Helper()
	return strconv.Itoa(testport.Free(t))
}

// ctl runs smcpctl and returns its output and exit error.
func ctl(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "smcpctl"), args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func mustCtl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := ctl(t, "", args...)
	if err != nil {
		t.Fatalf("smcpctl %v: %v\n%s", args, err, out)
	}
	return out
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// startDaemon runs smcpd and waits until the control API answers.
func startDaemon(t *testing.T, cfg string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "smcpd"), "--config", cfg)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := ctl(t, "", "health", "--config", cfg)
		if err == nil {
			return cmd
		}
		if time.Now().After(deadline) {
			t.Fatalf("smcpd did not become healthy: %s\nsmcpd log:\n%s", out, logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func stopDaemon(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("smcpd exit: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("smcpd did not exit on SIGTERM")
	}
}

func TestBootstrapAndControlCommands(t *testing.T) {
	reqtest.Verifies(t, "FR-4.14", "FR-7.5", "FR-12.6")
	reqtest.Partial(t, "SR-3.6-1")
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")

	// Without a terminal and without a password file, bootstrap refuses.
	if out, err := ctl(t, "", "bootstrap", "--dir", dir); err == nil || !strings.Contains(out, "password file") {
		t.Fatalf("bootstrap without a password: %v %s", err, out)
	}
	out := mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	if !strings.Contains(out, "wrote") || strings.Contains(out, "admin password 12") {
		t.Fatalf("%s", out)
	}
	cfgPath := filepath.Join(dir, "smcp.toml")
	raw, _ := os.ReadFile(cfgPath)
	checkPackagedBootstrap(t, dir, string(raw))
	if st, _ := os.Stat(cfgPath); st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %o", st.Mode().Perm())
	}
	if out := mustCtl(t, "config", "validate", "--config", cfgPath); !strings.Contains(out, "configuration OK") || !strings.Contains(out, "1 approvers") {
		t.Fatal(out)
	}
	if out := mustCtl(t, "hash-password", "--password-file", adminPW); !strings.HasPrefix(out, "$argon2id$") {
		t.Fatal(out)
	}
	// Bootstrap is idempotent.
	if out := mustCtl(t, "bootstrap", "--dir", dir); !strings.Contains(out, "kept existing") {
		t.Fatal(out)
	}

	d := startDaemon(t, cfgPath)
	out = mustCtl(t, "health", "--config", cfgPath)
	if !strings.Contains(out, `"release_label": "not enforced"`) || !strings.Contains(out, "unconfined") {
		t.Fatalf("health: %s", out)
	}
	if out := mustCtl(t, "stop", "--config", cfgPath, "--reason", "drill"); !strings.Contains(out, `"stopped"`) {
		t.Fatal(out)
	}
	if out := mustCtl(t, "health", "--config", cfgPath); !strings.Contains(out, "emergency_stop") || !strings.Contains(out, "fail-closed") {
		t.Fatalf("health while stopped: %s", out)
	}
	if out := mustCtl(t, "resume", "--config", cfgPath); !strings.Contains(out, `"running"`) {
		t.Fatal(out)
	}
	pol, _ := os.ReadFile(filepath.Join(dir, "policy.json"))
	os.WriteFile(filepath.Join(dir, "policy.json"), bytes.Replace(pol, []byte(`"revision": "r1"`), []byte(`"revision": "r2"`), 1), 0o644)
	if out := mustCtl(t, "policy", "reload", "--config", cfgPath); !strings.Contains(out, `"revision": "r2"`) {
		t.Fatal(out)
	}
	if out := mustCtl(t, "approvals", "--config", cfgPath); !strings.Contains(out, "no approvals") {
		t.Fatal(out)
	}
	// The Local Server Registry: the reference server runs and the
	// metadata scan suspended none of its tools (SR-5.9-2 listing).
	if out := mustCtl(t, "servers", "list", "--config", cfgPath); !strings.Contains(out, `"alias": "ref"`) || !strings.Contains(out, `"suspended_tools": []`) {
		t.Fatalf("servers list: %s", out)
	}
	if out := mustCtl(t, "servers", "show", "ref", "--config", cfgPath); !strings.Contains(out, `"public_name": "ref_echo"`) {
		t.Fatalf("servers show: %s", out)
	}
	if out := mustCtl(t, "servers", "suspended-tools", "--config", cfgPath); !strings.Contains(out, "0 suspended tools") {
		t.Fatalf("servers suspended-tools: %s", out)
	}
	stopDaemon(t, d)
	out = mustCtl(t, "journal", "verify", "--config", cfgPath, "--strict")
	if !strings.Contains(out, "journal OK") || !strings.Contains(out, "anchored at segment") {
		t.Fatal(out)
	}
	// A deleted trailing segment fails verification.
	segs, _ := filepath.Glob(filepath.Join(dir, "state", "journal", "segment-*.jsonl"))
	os.Remove(segs[len(segs)-1])
	if out, err := ctl(t, "", "journal", "verify", "--config", cfgPath); err == nil || !strings.Contains(out, "FAILED") {
		t.Fatalf("truncated journal verified: %s", out)
	}
}

func TestBootstrapTokenFlow(t *testing.T) {
	reqtest.Verifies(t, "SR-7.5-1")
	dir := t.TempDir()
	secrets := t.TempDir()
	approverPW := writeFile(t, secrets, "approver", "approver password 1")
	out := mustCtl(t, "bootstrap", "--dir", dir, "--bootstrap-token", "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	var token string
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "One-use bootstrap token") && i+2 < len(lines) {
			token = strings.TrimSpace(lines[i+2])
		}
	}
	if len(token) < 43 {
		t.Fatalf("no token printed:\n%s", out)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "smcp.toml"))
	if strings.Contains(string(raw), token) || !strings.Contains(string(raw), "bootstrap_token_sha256") {
		t.Fatal("token stored in clear")
	}
	cfgPath := filepath.Join(dir, "smcp.toml")
	// SR-7.5-1: the credential's hash is stored with mode 0600 and expires
	// 24 hours after bootstrap.
	if st, err := os.Stat(cfgPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("configuration mode: %v", err)
	}
	m := regexp.MustCompile(`bootstrap_token_expires = "([^"]+)"`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("no bootstrap_token_expires")
	}
	exp, err := time.Parse(time.RFC3339, m[1])
	if err != nil || exp.Before(time.Now().Add(23*time.Hour+50*time.Minute)) || exp.After(time.Now().Add(24*time.Hour+time.Minute)) {
		t.Fatalf("expiry %s", m[1])
	}
	tokFile := writeFile(t, secrets, "token", token)
	pwFile := writeFile(t, secrets, "newpw", "a new admin password")
	// An expired credential creates no Administrator.
	expired := strings.Replace(string(raw), m[1], time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), 1)
	if err := os.WriteFile(cfgPath, []byte(expired), 0o600); err != nil {
		t.Fatal(err)
	}
	d := startDaemon(t, cfgPath)
	if out, err := ctl(t, "", "admin", "redeem", "--config", cfgPath, "--token-file", tokFile, "--password-file", pwFile); err == nil {
		t.Fatalf("expired token redeemed: %s", out)
	}
	stopDaemon(t, d)
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	d = startDaemon(t, cfgPath)
	// Without the credential (a wrong token), nothing is created either.
	wrongFile := writeFile(t, secrets, "wrong", strings.Repeat("A", len(token)))
	if out, err := ctl(t, "", "admin", "redeem", "--config", cfgPath, "--token-file", wrongFile, "--password-file", pwFile); err == nil {
		t.Fatalf("wrong token redeemed: %s", out)
	}
	if out := mustCtl(t, "admin", "redeem", "--config", cfgPath, "--token-file", tokFile, "--password-file", pwFile); !strings.Contains(out, "password set") {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "admin", "redeem", "--config", cfgPath, "--token-file", tokFile, "--password-file", pwFile); err == nil {
		t.Fatalf("token redeemed twice: %s", out)
	}
	stopDaemon(t, d)
}

func TestUsage(t *testing.T) {
	if out, err := ctl(t, "", "bogus"); err == nil || !strings.Contains(out, "usage: smcpctl") {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := ctl(t, "", "help"); err != nil || !strings.Contains(out, "policy reload") {
		t.Fatalf("%v %s", err, out)
	}
}
