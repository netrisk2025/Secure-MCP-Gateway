package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// bootstrapped writes a bootstrap configuration into a temporary directory
// and returns the directory and the configuration path.
func bootstrapped(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	return dir, filepath.Join(dir, "smcp.toml")
}

func TestPolicyCommands(t *testing.T) {
	reqtest.Verifies(t, "FR-3.9")
	reqtest.Partial(t, "FR-3.5", "FR-3.8", "SR-1.14-1")
	dir, cfg := bootstrapped(t)
	pol, err := os.ReadFile(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	// r2 removes read_file from the read-only template.
	r2 := strings.Replace(strings.Replace(string(pol), `"revision": "r1"`, `"revision": "r2"`, 1), `"list_files", "read_file"] }`, `"list_files"] }`, 1)
	r2File := writeFile(t, t.TempDir(), "r2.json", r2)
	if out := mustCtl(t, "policy", "validate", r2File); !strings.Contains(out, "policy OK: revision r2") || !strings.Contains(out, "2 templates") {
		t.Fatal(out)
	}
	bad := writeFile(t, t.TempDir(), "bad.json", strings.Replace(r2, `"server": "ref"`, `"server": "REF!"`, 1))
	if out, err := ctl(t, "", "policy", "validate", bad); err == nil || !strings.Contains(out, "schema") {
		t.Fatalf("invalid policy validated: %s", out)
	}

	d := startDaemon(t, cfg)
	defer stopDaemon(t, d)
	// The policy file was imported as the first signed revision.
	if out := mustCtl(t, "policy", "history", "--config", cfg); !strings.Contains(out, "r1") || !strings.Contains(out, "import") || !strings.Contains(out, "*") {
		t.Fatal(out)
	}
	if out := mustCtl(t, "policy", "diff", r2File, "--config", cfg); !strings.Contains(out, "from r1 to r2: 1 changes") || !strings.Contains(out, "grant_removed") ||
		!strings.Contains(out, "read-only ref/read_file") {
		t.Fatal(out)
	}
	scenario := writeFile(t, t.TempDir(), "s.jsonl", `{"template": "read-only", "server": "ref", "tool": "read_file"}
{"template": "read-only", "server": "ref", "tool": "echo"}
`)
	out := mustCtl(t, "policy", "simulate", r2File, "--scenario", scenario, "--config", cfg)
	if !strings.Contains(out, "2 fixtures from fixtures, active r1, candidate r2: 1 changed, permit_to_deny 1") {
		t.Fatal(out)
	}
	simID := strings.Fields(out)[1]
	simID = strings.TrimSuffix(simID, ":")
	// Journal replay with no recorded calls yet.
	if out, err := ctl(t, "", "policy", "simulate", r2File, "--config", cfg); err == nil || !strings.Contains(out, "no_fixtures") {
		t.Fatalf("empty journal: %s", out)
	}
	if out, err := ctl(t, "", "policy", "publish", r2File, "--parent", "r0", "--config", cfg); err == nil || !strings.Contains(out, "parent_mismatch") {
		t.Fatalf("stale parent: %s", out)
	}
	if out := mustCtl(t, "policy", "publish", r2File, "--parent", "r1", "--simulation", simID, "--config", cfg); !strings.Contains(out, "published and activated revision r2 (sequence 2, parent r1") {
		t.Fatal(out)
	}
	if out := mustCtl(t, "policy", "publish", r2File, "--config", cfg); !strings.Contains(out, "already active") {
		t.Fatal(out)
	}
	// Published revisions cannot be modified through the API.
	edited := writeFile(t, t.TempDir(), "r2b.json", strings.Replace(r2, `"time_now", `, ``, 1))
	if out, err := ctl(t, "", "policy", "publish", edited, "--config", cfg); err == nil || !strings.Contains(out, "revision_exists") {
		t.Fatalf("modified r2 accepted: %s", out)
	}
	if out := mustCtl(t, "policy", "show", "--config", cfg); !strings.Contains(out, `"revision": "r2"`) || !strings.Contains(out, `"simulation_ref": "`+simID+`"`) ||
		!strings.Contains(out, `"active": true`) {
		t.Fatal(out)
	}
	// Roll back to r1: a new revision with r1's content.
	if out := mustCtl(t, "policy", "rollback", "r1", "--config", cfg); !strings.Contains(out, "published and activated revision r1-rb1 (sequence 3, parent r2") {
		t.Fatal(out)
	}
	doc := mustCtl(t, "policy", "show", "r1-rb1", "--document", "--config", cfg)
	orig := mustCtl(t, "policy", "show", "r1", "--document", "--config", cfg)
	if strings.Replace(doc, `"r1-rb1"`, `"r1"`, 1) != orig {
		t.Fatalf("rollback content differs:\n%s\n%s", doc, orig)
	}
	if out := mustCtl(t, "policy", "diff", "--from", "r1", "--to", "r1-rb1", "--config", cfg); !strings.Contains(out, "0 changes") {
		t.Fatal(out)
	}
	if out := mustCtl(t, "policy", "history", "--config", cfg); !strings.Contains(out, "rollback of r1") || strings.Count(out, "\n") != 4 {
		t.Fatal(out)
	}
	if out := mustCtl(t, "health", "--config", cfg); !strings.Contains(out, `"policy_revision": "r1-rb1"`) {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "policy", "rollback", "nope", "--config", cfg); err == nil || !strings.Contains(out, "not_found") {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "policy", "frobnicate"); err == nil || !strings.Contains(out, "usage: smcpctl policy") {
		t.Fatal(out)
	}
}

func TestTamperedPolicyStartsFailClosed(t *testing.T) {
	reqtest.Verifies(t, "SR-1.1-2")
	dir, cfg := bootstrapped(t)
	d := startDaemon(t, cfg)
	stopDaemon(t, d)
	files, _ := filepath.Glob(filepath.Join(dir, "state", "policy", "revisions", "*.json"))
	if len(files) != 1 {
		t.Fatalf("%d revision files", len(files))
	}
	orig, _ := os.ReadFile(files[0])
	altered := []byte(strings.Replace(string(orig), `"echo"`, `"echx"`, 1))
	if string(altered) == string(orig) {
		t.Fatal("nothing altered")
	}
	os.Chmod(files[0], 0o644)
	if err := os.WriteFile(files[0], altered, 0o644); err != nil {
		t.Fatal(err)
	}
	d = startDaemon(t, cfg)
	out := mustCtl(t, "health", "--config", cfg)
	if !strings.Contains(out, `"fail-closed"`) || !strings.Contains(out, `"policy_signature"`) || strings.Contains(out, `"policy_revision"`) {
		t.Fatalf("tampered revision loaded: %s", out)
	}
	stopDaemon(t, d)
	if err := os.WriteFile(files[0], orig, 0o400); err != nil {
		t.Fatal(err)
	}
	d = startDaemon(t, cfg)
	if out := mustCtl(t, "health", "--config", cfg); strings.Contains(out, "policy_signature") || !strings.Contains(out, `"policy_revision": "r1"`) {
		t.Fatalf("restored revision: %s", out)
	}
	stopDaemon(t, d)
}
