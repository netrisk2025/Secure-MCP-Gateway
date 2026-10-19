package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/backup"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestScheduledAndOnDemandBackups is FR-9.16: with [backup] interval set,
// the Gateway writes encrypted backups on schedule; on-demand backups are
// written with and without an optional part. Each backup's result and
// checksum are recorded (the index and a BACKUP_WRITTEN event), the
// recorded checksum matches the archive, and after decryption the archive
// holds the configuration, the Policy Store, the Evidence Journal, the key
// material and the trust anchors, plus the optional part when one was
// asked for.
func TestScheduledAndOnDemandBackups(t *testing.T) {
	reqtest.Verifies(t, "FR-9.16")
	const pass = "scheduled backup pass"
	pf := filepath.Join(t.TempDir(), "backup.pass")
	if err := os.WriteFile(pf, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := startOps(t, fmt.Sprintf("[backup]\ninterval = \"1s\"\npassphrase_file = %q\n", pf), nil)
	// A schedule counts as a configured backup before the first one runs.
	if _, list := f.admin("GET", "/api/v1/backup", f.operator, nil); list["scheduled"] != true || list["configured"] != true {
		t.Fatalf("backup state with a schedule: %v", list)
	}
	access, _, _ := f.oauthLogin("")
	// A backup stops dispatch while it runs (SR-7.7-1), so a call that
	// meets a scheduled backup is refused; between backups calls run.
	served := false
	var lastErr error
	for deadline := time.Now().Add(20 * time.Second); !served && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		hc := &http.Client{Transport: bearerRT{access, f.client.Transport}}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e-harness", Version: "1"}, nil).Connect(context.Background(),
			&mcp.StreamableClientTransport{Endpoint: f.cfg.ResourceURI(), HTTPClient: hc}, nil)
		if err == nil {
			err = f.echo(cs, "x")
			cs.Close()
		}
		served, lastErr = err == nil, err
	}
	if !served {
		t.Fatalf("no call served between scheduled backups: %v", lastErr)
	}
	// A scheduled backup appears in the index.
	var scheduled map[string]any
	for deadline := time.Now().Add(20 * time.Second); scheduled == nil; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no scheduled backup")
		}
		if code, list := f.admin("GET", "/api/v1/backup", f.operator, nil); code == 200 {
			if bs, _ := list["backups"].([]any); len(bs) > 0 {
				scheduled = bs[0].(map[string]any)
			}
		}
	}
	optDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(optDir, "obs.jsonl"), []byte(`{"x":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, plain := f.admin("POST", "/api/v1/backup", f.operator, map[string]any{"passphrase": pass})
	if code != 200 {
		t.Fatalf("on-demand backup %d %v", code, plain)
	}
	code, withOpt := f.admin("POST", "/api/v1/backup", f.operator, map[string]any{"passphrase": pass, "optional": map[string]string{"observation_store": optDir}})
	if code != 200 {
		t.Fatalf("on-demand backup with an optional part %d %v", code, withOpt)
	}
	check := func(name, path, sum string, optional bool) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != sum {
			t.Fatalf("%s: recorded checksum %s does not match the archive", name, sum)
		}
		if ok, err := backup.VerifyChecksum(path); !ok || err != nil {
			t.Fatalf("%s: checksum file: %v %v", name, ok, err)
		}
		m, err := backup.Extract(path, filepath.Join(t.TempDir(), "x"), backup.Decryption{Passphrase: pass})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range []string{"configuration", "policy_store", "evidence_journal", "key_material", "trust_anchors"} {
			if !m.Has(c) {
				t.Errorf("%s lacks %s: %v", name, c, m.Components)
			}
		}
		if m.Has("optional:observation_store") != optional {
			t.Errorf("%s: optional part present %v, want %v", name, m.Has("optional:observation_store"), optional)
		}
	}
	check("scheduled", scheduled["path"].(string), scheduled["sha256"].(string), false)
	check("on demand", plain["path"].(string), plain["sha256"].(string), false)
	check("on demand with the optional part", withOpt["path"].(string), withOpt["sha256"].(string), true)
	f.stopAll()
	byScheduler := 0
	for _, e := range journalEvents(t, f.stateDir) {
		if d, ok := e.Detail.(map[string]any); ok && e.ReasonCode == "BACKUP_WRITTEN" && d["sha256"] != "" {
			if strings.Contains(fmt.Sprint(d["actor"]), "scheduler") {
				byScheduler++
			}
		}
	}
	if byScheduler == 0 {
		t.Fatal("no BACKUP_WRITTEN event of the scheduler")
	}
}
