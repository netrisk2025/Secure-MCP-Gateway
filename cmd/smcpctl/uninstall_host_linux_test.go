//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// sudoOut runs a command with sudo -n and returns its combined output.
func sudoOut(t *testing.T, stdin string, argv ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sudo", append([]string{"-n"}, argv...)...)
	cmd.Stdin = strings.NewReader(stdin)
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// TestEnforcedUninstallAndPurgeOnHost runs `smcpctl uninstall` and then
// `smcpctl uninstall --purge` on a host where scripts/ci-systemd.sh
// installed the Enforced profile with `smcpctl install --profile enforced`.
//
// Uninstall (FR-13.11, Enforced profile): the units, binaries, the
// nftables table smcp and the AppArmor profiles are gone, the journal and
// the evidence key are kept, and `smcpctl journal verify` of another
// installation (this test's own build), pointed at the kept journal and
// key, succeeds. The Standalone half is TestInstallStandaloneServiceManager,
// so FR-13.11 is partial here.
//
// Purge (FR-13.12): a wrong installation ID is refused and removes
// nothing; the correct one prints the SHA-256 of the last journal segment
// (checked against the file) and deletes the configuration, the state with
// keys and journal, and the CP-46 service identities.
//
// It changes the host, so it runs only with SMCP_ENFORCED_HOST_TEST=1, at
// the end of scripts/ci-systemd.sh (CI job linux-integration).
func TestEnforcedUninstallAndPurgeOnHost(t *testing.T) {
	if os.Getenv("SMCP_ENFORCED_HOST_TEST") != "1" {
		t.Skip("removes the Enforced installation; set SMCP_ENFORCED_HOST_TEST=1 on a disposable host after scripts/ci-systemd.sh")
	}
	reqtest.Verifies(t, "FR-13.12")
	reqtest.Partial(t, "FR-13.11")
	const (
		cfg      = "/etc/smcp/smcp.toml"
		state    = "/var/lib/smcp/state"
		bin      = "/usr/local/bin"
		unit     = "/etc/systemd/system/smcpd.service"
		profile  = "/etc/apparmor.d/smcpd"
		journal  = state + "/journal"
		evidence = state + "/" + keys.EvidenceGenesisFile
	)
	exists := func(p string) bool {
		_, err := sudoOut(t, "", "test", "-e", p)
		return err == nil
	}
	nftTablePresent := func() bool {
		_, err := sudoOut(t, "", "nft", "list", "table", "inet", "smcp")
		return err == nil
	}
	apparmor := false
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		apparmor = true
	}
	if !nftTablePresent() {
		if out, err := sudoOut(t, "", "systemctl", "start", "smcp-nftables.service"); err != nil || !nftTablePresent() {
			t.Fatalf("the nftables table smcp is not installed: %v\n%s", err, out)
		}
	}
	for _, p := range []string{cfg, unit, journal, evidence, bin + "/smcpd", bin + "/smcpctl"} {
		if !exists(p) {
			t.Fatalf("%s missing: run after scripts/ci-systemd.sh", p)
		}
	}
	if apparmor && !exists(profile) {
		t.Fatalf("%s missing", profile)
	}

	// uninstall removes the binaries it runs from: run a copy.
	ctlCopy := filepath.Join(t.TempDir(), "smcpctl")
	if out, err := sudoOut(t, "", "cp", bin+"/smcpctl", ctlCopy); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err := sudoOut(t, "", ctlCopy, "uninstall", "--config", cfg, "--bin-dir", bin)
	t.Logf("uninstall:\n%s", out)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	for _, p := range []string{unit, bin + "/smcpd", bin + "/smcpctl", bin + "/smcp-refserver"} {
		if exists(p) {
			t.Errorf("uninstall left %s", p)
		}
	}
	if nftTablePresent() {
		t.Error("uninstall left the nftables table inet smcp")
	}
	if apparmor {
		if exists(profile) {
			t.Errorf("uninstall left %s", profile)
		}
		if st, _ := sudoOut(t, "", "aa-status"); regexp.MustCompile(`(?m)^\s+smcpd$`).MatchString(st) {
			t.Error("the AppArmor profile smcpd is still loaded")
		}
	}
	if out, err := sudoOut(t, "", "systemctl", "is-active", "--quiet", "smcpd.service"); err == nil {
		t.Errorf("smcpd.service still active: %s", out)
	}
	for _, p := range []string{cfg, journal, evidence} {
		if !exists(p) {
			t.Fatalf("uninstall removed %s", p)
		}
	}
	// Another installation's smcpctl verifies the kept journal.
	if out, err := sudoOut(t, "", filepath.Join(binDir, "smcpctl"), "journal", "verify", "--dir", journal, "--key", evidence, "--strict"); err != nil || !strings.Contains(out, "journal OK") {
		t.Fatalf("journal verify of the kept journal: %v\n%s", err, out)
	}

	// Purge: a wrong installation ID first.
	idRaw, err := sudoOut(t, "", "cat", filepath.Join(state, keys.InstallationIDFile))
	if err != nil {
		t.Fatalf("installation ID: %v %s", err, idRaw)
	}
	id := strings.TrimSpace(idRaw)
	out, err = sudoOut(t, "not-"+id+"\n", ctlCopy, "uninstall", "--purge", "--config", cfg, "--bin-dir", bin)
	if err == nil || !strings.Contains(out, "does not match") {
		t.Fatalf("purge with a wrong ID: %v\n%s", err, out)
	}
	if !exists(cfg) || !exists(journal) {
		t.Fatal("a refused purge removed files")
	}
	segSums := map[string]string{}
	list, _ := sudoOut(t, "", "sh", "-c", "cd "+journal+" && sha256sum segment-*")
	for _, l := range strings.Split(strings.TrimSpace(list), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			segSums[f[1]] = f[0]
		}
	}
	if len(segSums) == 0 {
		t.Fatalf("no journal segments: %s", list)
	}
	out, err = sudoOut(t, id+"\n", ctlCopy, "uninstall", "--purge", "--config", cfg, "--bin-dir", bin)
	t.Logf("purge:\n%s", out)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	m := regexp.MustCompile(`last journal segment (\S+) sha256 ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil || segSums[filepath.Base(m[1])] != m[2] {
		t.Fatalf("purge printed %v; segment digests %v", m, segSums)
	}
	for _, p := range []string{cfg, state} {
		if exists(p) {
			t.Errorf("purge left %s", p)
		}
	}
	for _, name := range serviceIdentities {
		if err := exec.Command("id", name).Run(); err == nil {
			t.Errorf("purge left the service identity %s", name)
		}
	}
}
