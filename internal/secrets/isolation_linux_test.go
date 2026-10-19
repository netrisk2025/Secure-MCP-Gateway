//go:build linux

package secrets

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// cp46Identities are the service identities of CP-46.
var cp46Identities = []string{"smcp-core", "smcp-evidence", "smcp-keys", "smcp-vault", "smcp-data", "smcp-console", "smcp-srv"}

// TestIntegrationVaultIsolation is SR-2.13-3 on an Enforced host (the
// linux-integration CI job runs it after scripts/ci-systemd.sh has
// installed the Enforced profile, started smcpd.service as smcp-core and
// stored a secret): every file of the vault directory and of its key
// source is read as each CP-46 service identity other than the one the
// Secret Broker runs as, and as nobody; every read and every listing of
// the vault directory is denied. The same reads as the Secret Broker's
// identity succeed, so the denials are not an artifact of missing files.
// The vault directory and its files carry no group or other permission,
// so the denial does not rest on the parent directory alone.
//
// Environment (the test is skipped without SMCP_VAULT_IT_DIR):
//
//	SMCP_VAULT_IT_DIR     the vault directory ([secrets] vault_dir)
//	SMCP_VAULT_IT_FILES   further files of the vault's key source,
//	                      separated by ":" (the passphrase file)
//	SMCP_VAULT_IT_BROKER  the identity smcpd, and so the Secret Broker,
//	                      runs as (default smcp-core)
//
// It needs passwordless sudo.
func TestIntegrationVaultIsolation(t *testing.T) {
	dir := os.Getenv("SMCP_VAULT_IT_DIR")
	if dir == "" {
		t.Skip("set SMCP_VAULT_IT_DIR on an Enforced host (scripts/ci-integration.sh)")
	}
	reqtest.Verifies(t, "SR-2.13-3")
	broker := os.Getenv("SMCP_VAULT_IT_BROKER")
	if broker == "" {
		broker = "smcp-core"
	}
	sudo := func(args ...string) (string, error) {
		out, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	for _, id := range append(cp46Identities, "nobody") {
		if _, err := sudo("id", "-u", id); err != nil {
			t.Fatalf("identity %s does not exist: %v", id, err)
		}
	}
	if owner, err := sudo("stat", "-c", "%U %a", dir); err != nil || owner != broker+" 700" {
		t.Fatalf("vault directory %s: %q %v, want owner %s and mode 700", dir, owner, err, broker)
	}
	list, err := sudo("find", dir, "-type", "f")
	if err != nil {
		t.Fatalf("find: %v %s", err, list)
	}
	files := strings.Fields(list)
	secretFiles := len(files)
	if extra := os.Getenv("SMCP_VAULT_IT_FILES"); extra != "" {
		files = append(files, strings.Split(extra, ":")...)
	}
	if secretFiles == 0 {
		t.Fatalf("the vault %s holds no file; store a secret first", dir)
	}
	for _, f := range files {
		mode, err := sudo("stat", "-c", "%U %a", f)
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if parts := strings.Fields(mode); len(parts) != 2 || parts[0] != broker || !strings.HasSuffix(parts[1], "00") {
			t.Errorf("%s: owner and mode %q, want %s with no group or other permission", f, mode, broker)
		}
		if _, err := sudo("-u", broker, "cat", f); err != nil {
			t.Errorf("%s cannot read %s: %v", broker, f, err)
		}
	}
	if _, err := sudo("-u", broker, "ls", dir); err != nil {
		t.Errorf("%s cannot list %s: %v", broker, dir, err)
	}
	reads := 0
	for _, id := range append(cp46Identities, "nobody") {
		if id == broker {
			continue
		}
		if out, err := sudo("-u", id, "ls", dir); err == nil {
			t.Errorf("%s listed the vault directory: %s", id, out)
		}
		for _, f := range files {
			out, err := sudo("-u", id, "cat", f)
			reads++
			if err == nil {
				t.Errorf("%s read %s", id, f)
			} else if !strings.Contains(out, "Permission denied") {
				t.Errorf("%s reading %s: %q, want a permission denial", id, f, out)
			}
		}
	}
	t.Logf("%d vault files, %d denied reads by %d identities other than %s", len(files), reads, len(cp46Identities), broker)
}
