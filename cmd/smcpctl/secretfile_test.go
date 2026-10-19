package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestPasswordSources is SR-7.5-2 in part: bootstrap, hash-password and
// admin redeem refuse a password given as a command-line argument, a
// password file readable by group or others and standard input, and accept
// a mode 0600 file.
//
// Partial on its own: the prompt (on a pseudo-terminal) and the install
// command are TestPasswordPromptAndInstallSources; this test checks the
// refusal without a terminal.
func TestPasswordSources(t *testing.T) {
	reqtest.Partial(t, "SR-7.5-2")
	secrets := t.TempDir()
	good := writeFile(t, secrets, "good", "admin password 12\n")
	loose := writeFile(t, secrets, "loose", "admin password 12\n")
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	groupRead := writeFile(t, secrets, "group", "admin password 12\n")
	if err := os.Chmod(groupRead, 0o640); err != nil {
		t.Fatal(err)
	}

	refused := func(name, stdin, want string, args ...string) {
		t.Helper()
		out, err := ctl(t, stdin, args...)
		if err == nil || !strings.Contains(out, want) {
			t.Fatalf("%s: accepted or wrong reason: %v\n%s", name, err, out)
		}
		if strings.Contains(out, "$argon2id$") {
			t.Fatalf("%s: printed a verifier", name)
		}
	}
	refused("hash-password argument", "", "command-line", "hash-password", "admin password 12")
	refused("hash-password 0644 file", "", "mode 0644", "hash-password", "--password-file", loose)
	refused("hash-password 0640 file", "", "mode 0640", "hash-password", "--password-file", groupRead)
	refused("hash-password stdin", "admin password 12\n", "standard input", "hash-password", "--password-file", "-")
	refused("hash-password no terminal", "", "no terminal", "hash-password")
	if out := mustCtl(t, "hash-password", "--password-file", good); !strings.HasPrefix(out, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatal(out)
	}

	dir := t.TempDir()
	refused("bootstrap argument", "", "command-line", "bootstrap", "--dir", dir, "admin password 12")
	refused("bootstrap 0644 admin file", "", "mode 0644", "bootstrap", "--dir", dir, "--admin-password-file", loose, "--approver-password-file", good)
	refused("bootstrap 0644 approver file", "", "mode 0644", "bootstrap", "--dir", dir, "--admin-password-file", good, "--approver-password-file", loose)
	refused("bootstrap stdin", "admin password 12\n", "standard input", "bootstrap", "--dir", dir, "--admin-password-file", "-", "--approver-password-file", good)
	if _, err := os.Stat(filepath.Join(dir, "smcp.toml")); err == nil {
		t.Fatal("a refused bootstrap wrote a configuration")
	}
	refused("admin redeem argument", "", "command-line", "admin", "redeem", "--config", filepath.Join(dir, "smcp.toml"), "token-value")
}
