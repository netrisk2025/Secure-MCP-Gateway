package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// ctlTerminal runs smcpctl with a pseudo-terminal as its standard input
// and output, through script(1) (BSD script on macOS, util-linux script on
// Linux), with env added to its environment, and types input once the
// first prompt (a line ending in "password" or "Password") is shown.
// Standard input stays open until the command exits, as at a terminal. It
// skips when script is not installed.
func ctlTerminal(t *testing.T, env []string, input string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) is not installed; no pseudo-terminal for the prompt")
	}
	bin := filepath.Join(binDir, "smcpctl")
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("script", append([]string{"-q", "/dev/null", bin}, args...)...)
	} else {
		words := []string{shellQuote(bin)}
		for _, a := range args {
			words = append(words, shellQuote(a))
		}
		cmd = exec.Command("script", "-qec", strings.Join(words, " "), "/dev/null")
	}
	cmd.Env = append(os.Environ(), env...)
	pr, pw := ioPipe(t)
	cmd.Stdin = pr
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		deadline := time.Now().Add(30 * time.Second)
		for !strings.Contains(strings.ToLower(out.String()), "password") && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		_, _ = pw.Write([]byte(input))
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		pw.Close()
		return out.String(), err
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		pw.Close()
		t.Fatalf("smcpctl %v under script did not finish:\n%s", args, out.String())
	}
	return "", nil
}

// TestPasswordPromptAndInstallSources is SR-7.5-2: hash-password,
// bootstrap and install each refuse a password given as a command-line
// argument and in a mode 0644 file, and accept one in a mode 0600 file and
// typed at an interactive prompt (a pseudo-terminal through script(1)).
func TestPasswordPromptAndInstallSources(t *testing.T) {
	reqtest.Verifies(t, "SR-7.5-2")
	const admin, approver = "admin password 12", "approver password 34"

	// hash-password: the prompt asks twice and prints a verifier.
	out, err := ctlTerminal(t, nil, admin+"\n"+admin+"\n", "hash-password")
	if err != nil || !strings.Contains(out, "$argon2id$v=19$") || !strings.Contains(out, "Password:") {
		t.Fatalf("hash-password at the prompt: %v\n%s", err, out)
	}

	// bootstrap: both passwords at the prompt; the configuration verifies them.
	dir := t.TempDir()
	out, err = ctlTerminal(t, nil, admin+"\n"+admin+"\n"+approver+"\n"+approver+"\n",
		"bootstrap", "--dir", dir, "--refserver", filepath.Join(binDir, "smcp-refserver"),
		"--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", "0", "--notify", "off")
	if err != nil || !strings.Contains(out, "Administrator password") || !strings.Contains(out, "Session Approver password") {
		t.Fatalf("bootstrap at the prompt: %v\n%s", err, out)
	}
	cfg, err := config.Load(filepath.Join(dir, "smcp.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SessionApprovers()) != 1 || !strings.HasPrefix(cfg.SessionApprovers()[0].PasswordHash, "$argon2id$") {
		t.Fatalf("approvers %+v", cfg.SessionApprovers())
	}

	// install: a home of its own and --no-start (no service manager).
	home := func() (string, []string) {
		h, err := os.MkdirTemp("", "smcp-home-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(h) })
		return h, []string{"HOME=" + h, "XDG_CONFIG_HOME=", "XDG_STATE_HOME=", "XDG_DATA_HOME=", "XDG_RUNTIME_DIR="}
	}
	installArgs := func() []string {
		return []string{"install", "--no-start", "--bin-dir", binDir, "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", "0", "--notify", "off"}
	}
	runInstall := func(env []string, args ...string) (string, error) {
		cmd := exec.Command(filepath.Join(binDir, "smcpctl"), args...)
		cmd.Env = append(os.Environ(), env...)
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	installed := func(h string) bool {
		in := &installer{goos: runtime.GOOS, home: h, getenv: func(string) string { return "" }}
		l, err := in.layout()
		if err != nil {
			t.Fatal(err)
		}
		_, err = os.Stat(filepath.Join(l.cfgDir, "smcp.toml"))
		return err == nil
	}
	secrets := t.TempDir()
	good := writeFile(t, secrets, "admin.pw", admin+"\n")
	goodApprover := writeFile(t, secrets, "approver.pw", approver+"\n")
	loose := writeFile(t, secrets, "loose.pw", admin+"\n")
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}

	// bootstrap and hash-password: an argument and a mode 0644 file are
	// refused, a mode 0600 file is accepted.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"hash-password", admin}, "command-line"},
		{[]string{"hash-password", "--password-file", loose}, "mode 0644"},
		{[]string{"bootstrap", "--dir", t.TempDir(), admin}, "command-line"},
		{[]string{"bootstrap", "--dir", t.TempDir(), "--admin-password-file", loose, "--approver-password-file", goodApprover}, "mode 0644"},
	} {
		if out, err := ctl(t, "", c.args...); err == nil || !strings.Contains(out, c.want) || strings.Contains(out, "$argon2id$") {
			t.Fatalf("%v: %v\n%s", c.args[0], err, out)
		}
	}
	if out := mustCtl(t, "hash-password", "--password-file", good); !strings.HasPrefix(out, "$argon2id$") {
		t.Fatalf("hash-password with a mode 0600 file: %s", out)
	}
	bdir := t.TempDir()
	mustCtl(t, "bootstrap", "--dir", bdir, "--admin-password-file", good, "--approver-password-file", goodApprover,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", "0", "--notify", "off")
	if _, err := os.Stat(filepath.Join(bdir, "smcp.toml")); err != nil {
		t.Fatalf("bootstrap with mode 0600 files: %v", err)
	}

	h, env := home()
	out, err = runInstall(env, append(installArgs(), admin)...)
	if err == nil || !strings.Contains(out, "command-line arguments") || strings.Contains(out, admin) {
		t.Fatalf("install with a password argument: %v\n%s", err, out)
	}
	out, err = runInstall(env, append(installArgs(), "--admin-password-file", loose, "--approver-password-file", goodApprover)...)
	if err == nil || !strings.Contains(out, "mode 0644") {
		t.Fatalf("install with a mode 0644 file: %v\n%s", err, out)
	}
	if installed(h) {
		t.Fatal("a refused install wrote a configuration")
	}
	out, err = runInstall(env, append(installArgs(), "--admin-password-file", good, "--approver-password-file", goodApprover)...)
	if err != nil || !installed(h) {
		t.Fatalf("install with mode 0600 files: %v\n%s", err, out)
	}

	h, env = home()
	out, err = ctlTerminal(t, env, admin+"\n"+admin+"\n"+approver+"\n"+approver+"\n", installArgs()...)
	if err != nil || !strings.Contains(out, "Administrator password") || !installed(h) {
		t.Fatalf("install at the prompt: %v\n%s", err, out)
	}
}
