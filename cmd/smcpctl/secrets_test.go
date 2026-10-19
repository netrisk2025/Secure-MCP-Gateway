package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// startDaemonWithLogs is startDaemon that also returns the diagnostic log.
func startDaemonWithLogs(t *testing.T, cfg string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "smcpd"), "--config", cfg, "--log-level", "debug")
	logs := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
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
		if _, err := ctl(t, "", "health", "--config", cfg); err == nil {
			return cmd, logs
		}
		if cmd.ProcessState != nil || time.Now().After(deadline) {
			t.Fatalf("smcpd did not become healthy:\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestSecretsCommands(t *testing.T) {
	reqtest.Partial(t, "FR-6.2", "FR-6.11", "FR-17.3", "SR-2.13-1")
	dir := t.TempDir()
	priv := t.TempDir()
	adminPW := writeFile(t, priv, "admin", "admin password 12\n")
	approverPW := writeFile(t, priv, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	pp := writeFile(t, priv, "vault-pass", "vault passphrase for tests\n")
	usePath := filepath.Join(dir, "secret-use.json")
	if err := os.WriteFile(usePath, []byte(`{"revision": "u1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\n[secrets]\nkey_source = \"passphrase\"\npassphrase_file = " + quote(pp) + "\nuse_policy_file = \"secret-use.json\"\n")
	f.Close()

	// Before init the daemon refuses to start and names the fix.
	if out, err := exec.Command(filepath.Join(binDir, "smcpd"), "--config", cfgPath).CombinedOutput(); err == nil || !strings.Contains(string(out), "smcpctl secrets init") {
		t.Fatalf("smcpd without a vault: %v %s", err, out)
	}
	if out := mustCtl(t, "secrets", "init", "--config", cfgPath); !strings.Contains(out, "initialized") {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "secrets", "init", "--config", cfgPath); err == nil {
		t.Fatalf("second init: %s", out)
	}

	d, logs := startDaemonWithLogs(t, cfgPath)
	value := "cli-secret-value-0123456789abcdef"
	rotated := "cli-secret-value-rotated-fedcba98"
	// Values are never accepted as arguments.
	for _, args := range [][]string{{"secrets", "set", "k", "--value=" + value}, {"secrets", "set", "k", "--value", value}} {
		if out, err := ctl(t, "", append(args, "--config", cfgPath)...); err == nil || !strings.Contains(out, "never accepted on the command line") {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	if out, err := ctl(t, value+"\n", "secrets", "set", "api-key", "--type", "api_key", "--config", cfgPath); err != nil || strings.Contains(out, value) {
		t.Fatalf("set: %v %s", err, out)
	}
	if out, err := ctl(t, rotated+"\n", "secrets", "rotate", "api-key", "--overlap", "1h", "--config", cfgPath); err != nil || !strings.Contains(out, `"current_version": 2`) {
		t.Fatalf("rotate: %v %s", err, out)
	}
	valFile := writeFile(t, priv, "other", "file-secret-value-12345\n")
	mustCtl(t, "secrets", "set", "other", "--value-file", valFile, "--config", cfgPath)
	out := mustCtl(t, "secrets", "list", "--config", cfgPath)
	if !strings.Contains(out, `"name": "api-key"`) || !strings.Contains(out, `"key_source": "passphrase"`) || strings.Contains(out, value) || strings.Contains(out, "file-secret-value") {
		t.Fatalf("list: %s", out)
	}
	if out := mustCtl(t, "secrets", "show", "api-key", "--config", cfgPath); !strings.Contains(out, `"state": "overlap"`) {
		t.Fatalf("show: %s", out)
	}
	mustCtl(t, "secrets", "rm", "other", "--config", cfgPath)
	// Bind the secret to the reference server as an S3 file and reload.
	os.WriteFile(usePath, []byte(`{"revision": "u2",
	  "slots": [{"server": "ref", "name": "token", "modes": ["S3"], "file_env": "REF_TOKEN_FILE"}],
	  "policies": [{"id": "ref-token", "secret": "api-key", "server": "ref", "slot": "token", "mode": "S3", "tools": ["*"], "purpose": "test"}]}`), 0o600)
	if out := mustCtl(t, "secrets", "reload", "--config", cfgPath); !strings.Contains(out, `"revision": "u2"`) {
		t.Fatalf("reload: %s", out)
	}
	if out := mustCtl(t, "secrets", "impact", "api-key", "--config", cfgPath); !strings.Contains(out, `"use_policy": "ref-token"`) {
		t.Fatalf("impact: %s", out)
	}
	stopDaemon(t, d)

	// On restart the reference server is launched with the S3 file.
	d, logs2 := startDaemonWithLogs(t, cfgPath)
	stopDaemon(t, d)
	if out := mustCtl(t, "journal", "verify", "--config", cfgPath, "--strict"); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
	var journal bytes.Buffer
	segs, _ := filepath.Glob(filepath.Join(dir, "state", "journal", "segment-*.jsonl"))
	for _, s := range segs {
		b, _ := os.ReadFile(s)
		journal.Write(b)
	}
	j := journal.String()
	if !strings.Contains(j, `"class":"secret_use"`) || !strings.Contains(j, `"outcome":"delivered"`) || !strings.Contains(j, `"outcome":"rotated"`) {
		t.Fatal("journal lacks secret events")
	}
	vault, _ := os.ReadFile(filepath.Join(dir, "state", "vault", "secrets.json"))
	for where, text := range map[string]string{"journal": j, "log": logs.String() + logs2.String(), "vault": string(vault)} {
		for _, v := range []string{value, rotated, value[4:16], "file-secret-value"} {
			if strings.Contains(text, v) {
				t.Fatalf("%s contains %q", where, v)
			}
		}
	}
	// The instance files are gone after shutdown.
	left, _ := filepath.Glob(filepath.Join(dir, "state", "run", "secrets", "*", "*"))
	if len(left) != 0 {
		t.Fatalf("secret files left after shutdown: %v", left)
	}
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }
