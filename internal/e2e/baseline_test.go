package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// roleTokens authenticates "role-<role>" as an account of that role.
type roleTokens struct{}

func (roleTokens) Authenticate(tok string) (string, string, bool) {
	role, ok := strings.CutPrefix(tok, "role-")
	if !ok {
		return "", "", false
	}
	return role + ":tester", role, true
}

// TestBaselinePromotionRollbackAndIntegrity covers the baseline lifecycle
// through the control API of a running Gateway:
//
//   - FR-10.20: a candidate snapshot is promoted on an authorized operator
//     action (refused without authentication and for the Operator and
//     Researcher roles; accepted for the Policy Author); with automatic
//     promotion limits configured, a record-triggered snapshot within the
//     limits is promoted automatically and one beyond them is not.
//   - FR-10.21: an earlier snapshot is promoted again on command, and the
//     scores of later calls record its ID.
//   - SR-7-1: a stored snapshot whose content no longer matches its digest
//     is refused, an integrity event is recorded and the loaded snapshot
//     stays.
func TestBaselinePromotionRollbackAndIntegrity(t *testing.T) {
	reqtest.Verifies(t, "FR-10.20", "FR-10.21", "SR-7-1")
	of := startObservation(t, `sampling_rate = 1.0
flush_interval = "20ms"
[observation.baseline]
n_min = 20
snapshot_records = 0
snapshot_interval = "1000h"
auto_promote_max_shift = 0.5
auto_promote_max_sigma_factor = 1.5
[[observation.baseline.feature]]
parameter = "request_bytes"
transform = "log1p"
sigma_floor = 0.05
`)
	of.app.Admin.AddAuthenticator(roleTokens{})
	access, _, _ := of.oauthLogin("smcp:template:ro")
	cs := of.mcpClient(access)
	calls := uint64(0)
	run := func(n int, text func(int) string) {
		t.Helper()
		for i := range n {
			if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": text(i)}}); err != nil {
				t.Fatal(err)
			}
		}
		calls += uint64(n)
		of.waitAssembled(calls)
	}
	normal := func(i int) string { return fmt.Sprintf("hello %03d", i) }
	run(40, normal)

	// A: built on operator command, not promoted without an operator.
	code, built := of.admin("POST", "/api/v1/baselines/snapshots", of.operator, map[string]any{})
	if code != 200 || built["promoted"] == true {
		t.Fatalf("build: %d %v", code, built)
	}
	a := built["snapshot"].(map[string]any)["id"].(string)
	promote := func(token, id string) (int, map[string]any) {
		return of.admin("POST", "/api/v1/baselines/"+id+"/promote", token, map[string]any{})
	}
	for tok, want := range map[string]int{"": 401, "role-" + adminapi.RoleOperator: 403, "role-" + adminapi.RoleResearcher: 403} {
		if code, _ := promote(tok, a); code != want {
			t.Fatalf("promotion with %q: %d, want %d", tok, code, want)
		}
	}
	if of.obs.Scorer.SnapshotID() != "" {
		t.Fatal("a refused promotion loaded the snapshot")
	}
	code, p := promote("role-"+adminapi.RolePolicyAuthor, a)
	if code != 200 || p["loaded_snapshot"] != a {
		t.Fatalf("operator promotion: %d %v", code, p)
	}

	// B: the same distribution, record-triggered: promoted automatically.
	run(40, normal)
	rb, err := of.obs.Baselines.BuildSnapshot("records", "E-30")
	if err != nil {
		t.Fatal(err)
	}
	if !rb.Promoted || of.obs.Scorer.SnapshotID() != rb.Snapshot.ID {
		t.Fatalf("within the limits: promoted %v, loaded %s, drift %+v", rb.Promoted, of.obs.Scorer.SnapshotID(), rb.Drift)
	}
	b := rb.Snapshot.ID
	// C: a shifted distribution: beyond the limits, not promoted. Calls that
	// large would score abnormal against B and be kept out of learning, so
	// the shifted samples are given to the engine as the collector gives
	// them (same context, LearnInfo of a released permit).
	now := time.Now()
	for i := range 300 {
		of.obs.Baselines.Learn(baseline.Sample{Time: now, Session: "shifted", Dims: map[string]string{"principal": "cc", "tool": "echo"},
			Numeric: map[string]float64{"request_bytes": float64(5000 + i%7)}, Categorical: map[string]string{}, Tool: "echo"}, baseline.LearnInfo{})
	}
	rc, err := of.obs.Baselines.BuildSnapshot("records", "E-30")
	if err != nil {
		t.Fatal(err)
	}
	if rc.Promoted || of.obs.Scorer.SnapshotID() != b {
		t.Fatalf("beyond the limits: promoted %v, loaded %s, drift %+v", rc.Promoted, of.obs.Scorer.SnapshotID(), rc.Drift)
	}

	// Rollback to A on command; the next call's score records A.
	code, p = promote(of.operator, a)
	if code != 200 || p["loaded_snapshot"] != a {
		t.Fatalf("rollback: %d %v", code, p)
	}
	if pr, _ := p["promotion"].(map[string]any); pr["mode"] != "rollback" {
		t.Fatalf("promotion record %v", p["promotion"])
	}
	run(1, func(int) string { return "after the rollback" })
	of.obs.Sync()
	code, recs := of.admin("GET", "/api/v1/observations?limit=1000&tool=echo", of.operator, nil)
	if code != 200 {
		t.Fatalf("records %d", code)
	}
	var latest map[string]any
	for _, r := range recs["rows"].([]any) {
		m := r.(map[string]any)
		if ts, _ := m["ts"].(string); latest == nil || ts > latest["ts"].(string) {
			latest = m
		}
	}
	if latest == nil || latest["baseline_snapshot_id"] != a {
		t.Fatalf("score after the rollback recorded %v, want %s", latest["baseline_snapshot_id"], a)
	}

	// Tamper with B's stored snapshot: its promotion is refused with an
	// integrity event, and A stays loaded.
	matches, _ := filepath.Glob(filepath.Join(of.stateDir, "*", "baselines", b+".json"))
	if len(matches) == 0 {
		matches, _ = filepath.Glob(filepath.Join(of.stateDir, "*", "*", "baselines", b+".json"))
	}
	if len(matches) != 1 {
		t.Fatalf("snapshot file of %s: %v", b, matches)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["records"] = 1
	raw, _ = json.Marshal(doc)
	_ = os.Chmod(matches[0], 0o600)
	if err := os.WriteFile(matches[0], raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, body := promote(of.operator, b); code < 400 {
		t.Fatalf("tampered snapshot promoted: %d %v", code, body)
	}
	if of.obs.Scorer.SnapshotID() != a {
		t.Fatalf("loaded %s after the refused load", of.obs.Scorer.SnapshotID())
	}
	// The test observer receives the event from the journal fan-out queue.
	found := func() bool {
		of.mu.Lock()
		defer of.mu.Unlock()
		for _, ev := range of.events {
			if ev.Class == "integrity" && ev.ReasonCode == "BASELINE_DIGEST_MISMATCH" {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(10 * time.Second); !found(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no integrity event for the tampered snapshot")
		}
	}
}
