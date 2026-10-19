package acceptance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAT19BackupRestoreRollback is acceptance scenario AT-19 against the
// real binaries:
//
//   - a backup taken under load stops dispatch (emergency stop with reason
//     "backup"), writes and checksums the archive, then resumes; no call is
//     dispatched between the stop and the resume (SR-7.7-1);
//   - an archive with one altered byte fails restore verification;
//   - restoring a backup taken before a principal was suspended re-applies
//     the suspension from the current journal before service starts
//     (SR-7.8-1 as its verification states);
//   - with the reference server's package revision suspended (the
//     console's Suspend action), a policy rollback leaves the principal
//     suspension, a credential revocation and the server suspension in
//     force (SR-7.9-1);
//   - an upgrade to a release whose smcpd never becomes healthy restores
//     the previous binaries, which run with the journal intact, and the
//     journal records upgrade_rolled_back (FR-13.8, unhealthy case); the
//     application rollback leaves the principal suspension, the credential
//     revocation and the server suspension in force (SR-7.9-1).
//
// Partial: SR-7.7-1 does not open the archive to list each component;
// SR-7.8-1 does not rebuild a graph mirror (none configured); FR-13.8
// does not inject a failing migration.
func TestAT19BackupRestoreRollback(t *testing.T) {
	g := newGateway(t, options{limits: "principal_calls_per_minute = 1000000"})
	g.start()
	g.scenario("AT-19")
	reqtest.Verifies(t, "SR-7.9-1")
	reqtest.Partial(t, "SR-7.7-1", "SR-7.8-1", "FR-13.8")
	pass := writeFile(t, t.TempDir(), "backup.pw", "acceptance backup passphrase\n", 0o600)

	// Backup under load.
	var stop atomic.Bool
	var wg sync.WaitGroup
	var released atomic.Int64
	for range 2 {
		cs := g.session(g.freshToken())
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !stop.Load(); n++ {
				if _, isErr, err := call(cs, "ref_echo", map[string]any{"text": fmt.Sprint("load ", n)}); err == nil && !isErr {
					released.Add(1)
				} else {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	g.mustCtl("backup", "--passphrase-file", pass)
	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	archives, _ := filepath.Glob(filepath.Join(g.dir, "backups", "*.age"))
	if len(archives) != 1 {
		t.Fatalf("archives: %v", archives)
	}
	archive := archives[0]
	sumFile, err := os.ReadFile(archive + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(archive)
	sum := sha256.Sum256(raw)
	if !strings.Contains(string(sumFile), hex.EncodeToString(sum[:])) {
		t.Fatalf("checksum file %q does not match the archive", sumFile)
	}

	// Revoke after the backup: suspend the principal.
	if code, out := g.api("POST", "/api/v1/principals/claude-code-local/suspend", map[string]any{"reason": "AT-19"}); code >= 300 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	g.stop()

	evs := g.events()
	stopAt, writtenAt, resumeAt := -1, -1, -1
	for i, e := range evs {
		switch {
		case e.str("reason_code") == "EMERGENCY_STOP" && e.detail()["reason"] == "backup" && stopAt < 0:
			stopAt = i
		case e.str("reason_code") == "BACKUP_WRITTEN" && stopAt >= 0 && writtenAt < 0:
			writtenAt = i
		case e.str("reason_code") == "EMERGENCY_RESUME" && writtenAt >= 0 && resumeAt < 0:
			resumeAt = i
		}
	}
	if stopAt < 0 || writtenAt < stopAt || resumeAt < writtenAt {
		t.Fatalf("backup sequence: stop %d, written %d, resume %d", stopAt, writtenAt, resumeAt)
	}
	dispatchedAfter := 0
	for i, e := range evs {
		if e.str("class") == "call" && e.str("phase") == "dispatched" {
			if i > stopAt && i < resumeAt {
				t.Fatalf("call dispatched during the backup (event %d between %d and %d)", i, stopAt, resumeAt)
			}
			if i > resumeAt {
				dispatchedAfter++
			}
		}
	}
	if released.Load() == 0 || dispatchedAfter == 0 {
		t.Fatalf("load: %d released, %d dispatched after the resume", released.Load(), dispatchedAfter)
	}

	// A tampered archive does not verify.
	bad := filepath.Join(t.TempDir(), filepath.Base(archive))
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)/2] ^= 0xff
	if err := os.WriteFile(bad, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad+".sha256", sumFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := g.ctl("restore", "--archive", bad, "--passphrase-file", pass, "--verify-only"); err == nil {
		t.Fatalf("a tampered archive verified:\n%s", out)
	}

	// Restore the pre-suspension backup; the suspension comes back from
	// the current journal.
	g.mustCtl("restore", "--archive", archive, "--passphrase-file", pass, "--verify-only")
	g.mustCtl("restore", "--archive", archive, "--passphrase-file", pass)
	g.mustCtl("journal", "verify")
	g.start()
	g.expectSuspended("after restore")
	// A second principal's credential is revoked.
	if code, out := g.api("POST", "/api/v1/principals", map[string]any{"id": "at19-second", "framework": "codex", "profile": "dev"}); code != 201 {
		t.Fatalf("create principal: %d %v", code, out)
	}
	code, out := g.api("POST", "/api/v1/principals/at19-second/credentials", map[string]any{"redirect_uris": []string{"http://localhost:51234/callback"}, "confidential": false})
	revoked, _ := out["client_id"].(string)
	if code != 201 || revoked == "" {
		t.Fatalf("issue credential: %d %v", code, out)
	}
	if code, out := g.api("POST", "/api/v1/credentials/"+revoked+"/revoke", map[string]any{"reason": "AT-19"}); code != 200 {
		t.Fatalf("revoke: %d %v", code, out)
	}
	// SR-7.9-1: suspend the reference server's revision. From here on the
	// principal check must not rely on a call (no tool is served), so it
	// requires the sign-in itself to be refused.
	id, rev := g.refRevision()
	if code, out := g.api("POST", "/api/v1/packages/"+id+"/"+rev+"/disable", map[string]any{"reason": "AT-19"}); code != 200 {
		t.Fatalf("suspend server revision: %d %v", code, out)
	}
	g.expectServerSuspended(id, rev, "after the suspension")
	// Roll the policy back; the suspensions and the revocation stay.
	g.mustCtl("policy", "rollback", "r1", "--as", "at19-rollback")
	g.expectSignInRefused("after a policy rollback")
	g.expectRevoked(revoked, "after a policy rollback")
	g.expectServerSuspended(id, rev, "after a policy rollback")
	g.stop()

	// FR-13.8: an upgrade whose new smcpd never becomes healthy rolls back;
	// SR-7.9-1: the previous version keeps all three.
	upgradeRollback(t, g, pass, func() {
		g.expectSignInRefused("after an application rollback")
		g.expectRevoked(revoked, "after an application rollback")
		g.expectServerSuspended(id, rev, "after an application rollback")
	})
}

// refRevision returns the package ID and revision the reference server
// (alias ref) runs.
func (g *gateway) refRevision() (string, string) {
	g.t.Helper()
	code, out := g.api("GET", "/api/v1/packages", nil)
	servers, _ := out["servers"].([]any)
	for _, s := range servers {
		m, _ := s.(map[string]any)
		if m["alias"] == "ref" {
			id, _ := m["package"].(string)
			rev, _ := m["revision"].(string)
			if id != "" && rev != "" {
				return id, rev
			}
		}
	}
	g.t.Fatalf("no package binding for ref: %d %v", code, out)
	return "", ""
}

// expectServerSuspended requires that the reference server does not run
// and that its package revision is still out of the enabled state.
func (g *gateway) expectServerSuspended(id, rev, when string) {
	g.t.Helper()
	code, out := g.api("GET", "/api/v1/servers", nil)
	servers, _ := out["servers"].([]any)
	found := false
	for _, s := range servers {
		m, _ := s.(map[string]any)
		if m["alias"] == "ref" {
			found = true
			if m["state"] == "running" || m["tool_count"] != float64(0) {
				g.t.Fatalf("%s: the suspended server runs: %v", when, m)
			}
		}
	}
	if code != 200 || !found {
		g.t.Fatalf("%s: servers: %d %v", when, code, out)
	}
	code, out = g.api("GET", "/api/v1/packages", nil)
	revs, _ := out["revisions"].([]any)
	for _, r := range revs {
		m, _ := r.(map[string]any)
		if m["server_id"] == id && m["revision"] == rev {
			if m["state"] != "verified-disabled" {
				g.t.Fatalf("%s: revision %s@%s is %v", when, id, rev, m["state"])
			}
			return
		}
	}
	g.t.Fatalf("%s: revision %s@%s not listed: %d %v", when, id, rev, code, out)
}

// expectSignInRefused requires that the suspended principal
// claude-code-local cannot sign in at all.
func (g *gateway) expectSignInRefused(when string) {
	g.t.Helper()
	if _, err := g.signIn("", approverPassword); err == nil {
		g.t.Fatalf("%s: the suspended principal signed in", when)
	}
}

// expectRevoked requires that the control API lists the client credential
// as revoked.
func (g *gateway) expectRevoked(clientID, when string) {
	g.t.Helper()
	code, out := g.api("GET", "/api/v1/principals", nil)
	if code != 200 {
		g.t.Fatalf("%s: principals: %d %v", when, code, out)
	}
	ps, _ := out["principals"].([]any)
	for _, p := range ps {
		creds, _ := p.(map[string]any)["credentials"].([]any)
		for _, c := range creds {
			m, _ := c.(map[string]any)
			if m["client_id"] == clientID {
				if m["revoked_at"] == nil {
					g.t.Fatalf("%s: credential %s is no longer revoked: %v", when, clientID, m)
				}
				return
			}
		}
	}
	g.t.Fatalf("%s: credential %s not listed: %v", when, clientID, out)
}

// upgradeRollback installs the binaries into a directory, then upgrades to
// a release whose smcpd exits at once, and requires the rollback.
func upgradeRollback(t *testing.T, g *gateway, pass string, afterRollback func()) {
	t.Helper()
	work := t.TempDir()
	installed, badrel := filepath.Join(work, "installed"), filepath.Join(work, "bad-release")
	for _, d := range []string{installed, badrel} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{"smcpd": []byte("#!/bin/sh\nexit 1\n")}
	for _, b := range []string{"smcpd", "smcpctl"} {
		raw, err := os.ReadFile(filepath.Join(binDir, b))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, installed, b, string(raw), 0o755)
		if b == "smcpctl" {
			files[b] = raw
		}
	}
	// A release directory as GitHub serves it, signed with a throwaway
	// minisign key (smcpctl upgrade verifies releases as install.sh does).
	pubkey := signedRelease(t, badrel, "9.9.10", files)
	pidfile, logf := filepath.Join(work, "smcpd.pid"), filepath.Join(work, "smcpd.log")
	start := fmt.Sprintf(`nohup %q --config "$SMCP_CONFIG" >>%q 2>&1 & echo $! > %q`, filepath.Join(installed, "smcpd"), logf, pidfile)
	stopCmd := fmt.Sprintf(`p=$(cat %q 2>/dev/null); [ -n "$p" ] && kill "$p" 2>/dev/null; while [ -n "$p" ] && kill -0 "$p" 2>/dev/null; do sleep 0.1; done; true`, pidfile)
	t.Cleanup(func() { _ = exec.Command("sh", "-c", stopCmd).Run() })
	sh := exec.Command("sh", "-c", start)
	sh.Env = append(os.Environ(), "SMCP_CONFIG="+g.cfg)
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("start: %v %s", err, out)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := g.ctl("health"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(logf)
			t.Fatalf("installed smcpd did not start:\n%s", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	cmd := exec.Command(filepath.Join(installed, "smcpctl"), "upgrade", "--config", g.cfg, "--release", badrel, "--pubkey", pubkey, "--bin-dir", installed,
		"--passphrase-file", pass, "--start-cmd", start, "--stop-cmd", stopCmd, "--health-timeout", "10s")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "previous version is running") {
		t.Fatalf("fault-injected upgrade: err %v\n%s", err, out)
	}
	if _, err := g.ctl("health"); err != nil {
		t.Fatalf("the previous version is not serving after the rollback: %v", err)
	}
	afterRollback()
	if err := exec.Command("sh", "-c", stopCmd).Run(); err != nil {
		t.Fatal(err)
	}
	if out := g.mustCtl("journal", "verify"); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
	if !strings.Contains(g.journalText(), "upgrade_rolled_back") {
		t.Fatal("upgrade_rolled_back is not in the journal")
	}
}

// expectSuspended requires that the suspended principal claude-code-local
// is not served: its sign-in is refused, or its calls are.
func (g *gateway) expectSuspended(when string) {
	g.t.Helper()
	tok, err := g.signIn("", approverPassword)
	if err != nil {
		g.t.Logf("%s: sign-in refused: %v", when, err)
		return
	}
	cs := g.session(tok)
	if text, isErr, err := call(cs, "ref_echo", map[string]any{"text": when}); err == nil && !isErr {
		g.t.Fatalf("the suspended principal was served %s: %q", when, text)
	}
}

// signedRelease writes a release directory for this platform: the archive
// holding files, smcp_<version>_checksums.txt and its minisign signature
// with GoReleaser's trusted comment. It returns the public key.
func signedRelease(t *testing.T, dir, version string, files map[string][]byte) string {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(files[n])), Typeflag: tar.TypeReg, ModTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := fmt.Sprintf("smcp_%s_%s_%s.tar.gz", version, runtime.GOOS, runtime.GOARCH)
	writeFile(t, dir, archive, buf.String(), 0o644)
	sum := sha256.Sum256(buf.Bytes())
	sumsName := fmt.Sprintf("smcp_%s_checksums.txt", version)
	sums := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), archive)
	writeFile(t, dir, sumsName, sums, 0o644)
	r := minisign.NewReader(strings.NewReader(sums))
	_, _ = r.Read(make([]byte, len(sums)+1))
	sig := r.SignWithComments(priv, "smcp "+version+" file:"+sumsName, "signature from the acceptance test key")
	writeFile(t, dir, sumsName+".minisig", string(sig), 0o644)
	return pub.String()
}
