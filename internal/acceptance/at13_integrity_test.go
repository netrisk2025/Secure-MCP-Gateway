package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAT13IntegrityPrivacyRetention is acceptance scenario AT-13 against
// the real binaries:
//
//   - FR-7.5 as its verification states: smcpctl journal verify passes on
//     the intact journal and reports the exact segment and record of a
//     modified byte;
//   - a credential sent in arguments and one returned in a result appear
//     nowhere in the state directory (journal, observation store, logs);
//   - an authorized purge of observation data leaves a deletion receipt in
//     the journal (SR-6.15-1).
//
// Retention conflicts (SR-6.9-1) are deferred from release 1.0 (SRS
// Appendix N): there is one retention setting per store and no
// no-capture classification, so there is nothing to conflict.
//
// Partial: SR-6.7-1 needs a secret delivered by the Secret Broker on every
// captured surface; this run checks credential formats only.
func TestAT13IntegrityPrivacyRetention(t *testing.T) {
	g := newGateway(t, options{})
	if err := os.WriteFile(filepath.Join(g.sandbox, "creds.txt"), []byte("key="+awsKey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.start()
	g.scenario("AT-13")
	reqtest.Verifies(t, "FR-7.5")
	reqtest.Partial(t, "SR-6.7-1", "SR-6.15-1")

	cs := g.session(g.token(""))
	for i := range 5 {
		g.mustCall(cs, "ref_echo", map[string]any{"text": "event " + string(rune('a'+i))}, "event")
	}
	if _, isErr, err := call(cs, "ref_echo", map[string]any{"text": "key " + awsKey}); err == nil && !isErr {
		t.Fatal("credential in arguments not refused")
	}
	if txt := g.mustCall(cs, "ref_read_file", map[string]any{"path": "creds.txt"}, "REDACTED"); strings.Contains(txt, awsKey) {
		t.Fatalf("credential released: %q", txt)
	}

	today := time.Now().UTC().Format("2006-01-02")
	code, receipt := g.api("POST", "/api/v1/observations/purge", map[string]any{"before": today, "reason": "AT-13 purge"})
	if code != 200 || receipt["receipt_id"] == nil {
		t.Fatalf("purge: %d %v", code, receipt)
	}
	g.stop()

	found := false
	for _, e := range g.events() {
		if e.str("reason_code") == "DATA_PURGED" && e.detail()["receipt_id"] == receipt["receipt_id"] && e.detail()["reason"] == "AT-13 purge" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no deletion receipt %v in the journal", receipt["receipt_id"])
	}

	// No raw credential anywhere in the state directory.
	err := filepath.WalkDir(g.state, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Logf("%s: %v", p, rerr) // key material the test user cannot read
			return nil
		}
		if bytes.Contains(b, []byte(awsKey)) {
			t.Errorf("%s holds the raw credential", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// FR-7.5: intact journal passes; one modified byte is reported with
	// its segment and record.
	if out := g.mustCtl("journal", "verify"); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
	copyDir := filepath.Join(t.TempDir(), "journal")
	copyTree(t, filepath.Join(g.state, "journal"), copyDir)
	segs, _ := filepath.Glob(filepath.Join(copyDir, "segment-*.jsonl"))
	if len(segs) == 0 {
		t.Fatal("no journal segment")
	}
	seg := segs[0]
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(raw, []byte(`"outcome":"ok"`))
	if i < 0 {
		t.Fatalf("no completed call in %s", seg)
	}
	raw[i+len(`"outcome":"`)] = 'O'
	line := bytes.Count(raw[:i], []byte("\n")) + 1
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := g.ctl("journal", "verify", "--dir", copyDir, "--key", filepath.Join(g.state, "keys", "evidence-genesis.pub"))
	if err == nil {
		t.Fatalf("a modified journal verified:\n%s", out)
	}
	if !strings.Contains(out, filepath.Base(seg)) {
		t.Fatalf("failure does not name the segment %s (record on line %d):\n%s", filepath.Base(seg), line, out)
	}
	t.Logf("modified line %d; verify reported: %s", line, strings.TrimSpace(out))
}
