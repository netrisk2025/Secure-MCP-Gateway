package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestApproversCommands creates, lists and removes a Session Approver with
// smcpctl against a running smcpd (FR-2.23's command-line flow).
func TestApproversCommands(t *testing.T) {
	reqtest.Partial(t, "FR-2.23")
	dir := t.TempDir()
	priv := t.TempDir()
	adminPW := writeFile(t, priv, "admin", "admin password 12\n")
	approverPW := writeFile(t, priv, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	startDaemon(t, cfgPath)

	if out, err := ctl(t, "", "approvers", "add", "desk", "--password=x", "--config", cfgPath); err == nil || !strings.Contains(out, "never accepted on the command line") {
		t.Fatalf("password argument: %v %s", err, out)
	}
	// The Administrator's password is refused.
	if out, err := ctl(t, "", "approvers", "add", "desk", "--password-file", adminPW, "--config", cfgPath); err == nil || !strings.Contains(out, "Administrator") {
		t.Fatalf("admin password accepted: %v %s", err, out)
	}
	deskPW := writeFile(t, priv, "desk", "desk approver pw 1\n")
	if out := mustCtl(t, "approvers", "add", "desk", "--password-file", deskPW, "--config", cfgPath); !strings.Contains(out, `"desk"`) || strings.Contains(out, "argon2") {
		t.Fatal(out)
	}
	out := mustCtl(t, "approvers", "list", "--config", cfgPath)
	if !strings.Contains(out, `"desk"`) || !strings.Contains(out, `"approver"`) || strings.Contains(out, "argon2") {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "approvers", "rm", "approver", "--config", cfgPath); err == nil || !strings.Contains(out, "smcp.toml") {
		t.Fatalf("file approver removed: %v %s", err, out)
	}
	if out := mustCtl(t, "approvers", "rm", "desk", "--reason", "left", "--config", cfgPath); !strings.Contains(out, `"removed": true`) {
		t.Fatal(out)
	}
	if out := mustCtl(t, "approvers", "list", "--config", cfgPath); strings.Contains(out, `"desk"`) {
		t.Fatal(out)
	}
}
