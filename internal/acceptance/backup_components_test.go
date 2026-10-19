package acceptance

import (
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/backup"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestBackupUnderLoadComponents is SR-7.7-1's verification against the
// real smcpd: with two sessions calling continuously, `smcpctl backup`
// (with the Observation Store added as an optional part) records, in this
// order, the emergency stop with reason "backup", the archive written with
// its checksum and the resume; no call is dispatched between the stop and
// the resume, calls are dispatched after it; and the decrypted archive's
// manifest lists the configuration, Policy Store, Server Registry, vault,
// Evidence Journal, key material, trust anchors and the optional part, with
// the stop event sealed into the archived journal. AT-19 runs the same
// sequence in the Enforced profile; the drain of a call in flight is
// internal/edge.TestDrainStopReleasesInFlightResults.
func TestBackupUnderLoadComponents(t *testing.T) {
	reqtest.Verifies(t, "SR-7.7-1")
	if requestedProfile() == reqtest.Enforced {
		t.Skip("standalone profile; TestAT19BackupRestoreRollback covers the Enforced profile")
	}
	g := newGateway(t, options{limits: "principal_calls_per_minute = 1000000"})
	priv := t.TempDir()
	vp := writeFile(t, priv, "vault-pass", "vault passphrase "+randomString(12)+"\n", 0o600)
	writeFile(t, g.dir, "secret-use.json", `{"revision": "u0"}`, 0o600)
	g.appendConfig(fmt.Sprintf("\n[secrets]\nkey_source = \"passphrase\"\npassphrase_file = %q\nuse_policy_file = \"secret-use.json\"\n", vp))
	g.mustCtl("secrets", "init")
	g.start()
	g.mustCtl("secrets", "set", "backup-check", "--value-file", writeFile(t, priv, "v", "backup-check-value-"+randomString(8)+"\n", 0o600))
	pass := writeFile(t, priv, "backup.pw", "acceptance backup passphrase\n", 0o600)

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
	g.mustCtl("backup", "--passphrase-file", pass, "--optional", "observation_store="+filepath.Join(g.state, "observation"))
	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	g.stop()

	evs := g.events()
	stopAt, writtenAt, resumeAt := -1, -1, -1
	for i, e := range evs {
		switch {
		case e.str("reason_code") == "EMERGENCY_STOP" && e.detail()["reason"] == "backup" && stopAt < 0:
			stopAt = i
		case e.str("reason_code") == "BACKUP_WRITTEN" && stopAt >= 0 && writtenAt < 0:
			writtenAt = i
			if e.detail()["sha256"] == "" || e.detail()["sha256"] == nil {
				t.Fatalf("BACKUP_WRITTEN without a checksum: %v", e.detail())
			}
		case e.str("reason_code") == "EMERGENCY_RESUME" && writtenAt >= 0 && resumeAt < 0:
			resumeAt = i
		}
	}
	if stopAt < 0 || writtenAt < stopAt || resumeAt < writtenAt {
		t.Fatalf("backup sequence: stop %d, written %d, resume %d", stopAt, writtenAt, resumeAt)
	}
	// A call whose launch was authorized before the stop is in flight: the
	// drain lets it run, so its dispatched event may follow the stop event
	// (the launch recheck and the stop are ordered by the coordinator's
	// gate). No launch may be authorized after the stop, and every drained
	// call must be dispatched before the archive is written.
	authorizedAt := map[string]int{}
	for i, e := range evs {
		if e.str("class") == "decision" && e.str("phase") == "authorized" {
			if _, ok := authorizedAt[e.str("correlation_id")]; !ok {
				authorizedAt[e.str("correlation_id")] = i
			}
		}
	}
	dispatchedBefore, dispatchedAfter := 0, 0
	for i, e := range evs {
		if e.str("class") == "decision" && e.str("phase") == "authorized" && i > stopAt && i < resumeAt {
			t.Fatalf("launch authorized during the backup (event %d between %d and %d)", i, stopAt, resumeAt)
		}
		if e.str("class") == "call" && e.str("phase") == "dispatched" {
			switch {
			case i > stopAt && i < resumeAt:
				a, ok := authorizedAt[e.str("correlation_id")]
				if !ok || a > stopAt || i > writtenAt {
					t.Fatalf("call dispatched during the backup (event %d between %d and %d, authorized at %d, archive written at %d)", i, stopAt, resumeAt, a, writtenAt)
				}
			case i < stopAt:
				dispatchedBefore++
			case i > resumeAt:
				dispatchedAfter++
			}
		}
	}
	if released.Load() == 0 || dispatchedBefore == 0 || dispatchedAfter == 0 {
		t.Fatalf("load: %d released, %d dispatched before the stop, %d after the resume", released.Load(), dispatchedBefore, dispatchedAfter)
	}

	archives, _ := filepath.Glob(filepath.Join(g.dir, "backups", "*.age"))
	if len(archives) != 1 {
		t.Fatalf("archives: %v", archives)
	}
	dest := filepath.Join(t.TempDir(), "x")
	m, err := backup.Extract(archives[0], dest, backup.Decryption{Passphrase: "acceptance backup passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"configuration", "policy_store", "server_registry", "vault", "evidence_journal", "key_material", "trust_anchors", "optional:observation_store"} {
		if !m.Has(c) {
			t.Errorf("the archive lacks %s (components %v)", c, m.Components)
		}
	}
	sealed := false
	for _, e := range journalOf(t, filepath.Join(dest, "state", "journal")) {
		sealed = sealed || (e.str("reason_code") == "EMERGENCY_STOP" && e.detail()["reason"] == "backup")
	}
	if !sealed {
		t.Fatal("the backup's stop event is not sealed into the archived journal")
	}
}

// journalOf reads the events of a journal directory (an extracted archive).
func journalOf(t *testing.T, dir string) []event {
	t.Helper()
	g := &gateway{t: t, state: filepath.Dir(dir)}
	return g.events()
}
