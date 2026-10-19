package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func startObserveGateway(t *testing.T) (string, *analytics.Service) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	h, _ := keys.HashPassword("admin password 12")
	writeFile(t, dir, "policy.json", `{"revision":"r1","framework_profiles":{"dev":{"templates":["ro"],"default_template":"ro"}},"templates":{"ro":{"rules":[]}}}`)
	cfgPath := writeFile(t, dir, "smcp.toml", fmt.Sprintf(`
[listener]
address = "127.0.0.1:%s"
[admin_listener]
address = "127.0.0.1:%s"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[policy]
file = "policy.json"
[observation]
sampling_rate = 1.0
flush_interval = "10ms"
[observation.baseline]
n_min = 10
snapshot_records = 0
[[observation.baseline.feature]]
parameter = "request_bytes"
sigma_floor = 1
`, freePort(t), freePort(t), state, h))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := analytics.New(analytics.Options{Config: cfg, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	filters := pipeline.NewFilters()
	obs.RegisterFilters(filters)
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), Filters: filters, Observers: map[string]audit.Observer{"observation": obs.Observer()}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	obs.Start(ctx, a.Evidence, a.Admin, nil)
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done; a.Close(); obs.Close() })
	return cfgPath, obs
}

// feed sends the evidence of n synthetic delivered calls to the collector.
func feed(obs *analytics.Service, n int, bytes func(i int) int64) {
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		corr := fmt.Sprintf("c-%d-%d", now.UnixNano(), i)
		at := now.Add(time.Duration(i) * time.Millisecond)
		base := audit.Event{CorrelationID: corr, SessionID: "s1", PrincipalID: "agent-a", ServerRevision: "rev", ToolRevision: "rev/read", PolicyRevision: "r1"}
		for _, st := range []struct {
			class string
			phase audit.Phase
		}{{"call", audit.PhaseRequested}, {"decision", audit.PhaseAuthorized}, {"call", audit.PhaseDispatched}, {"call", audit.PhaseCompleted}, {"call", audit.PhaseDelivered}} {
			e := base
			e.Class, e.Phase, e.Time, e.DecisionID = st.class, st.phase, at.Format(time.RFC3339Nano), "d"
			obs.Collector.Observe(e)
			if st.phase == audit.PhaseRequested {
				obs.Collector.Offer(&observe.Probe{CorrelationID: corr, ServerID: "fs", Values: map[string]any{"request_bytes": bytes(i)}})
			}
		}
	}
	obs.Sync() // assembled, scored, learned and written to the store
}

func runOut(t *testing.T, args ...string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("smcpctl %v: exit %d: %s", args, code, errb.String())
	}
	return out.String()
}

func TestObserveCommands(t *testing.T) {
	reqtest.Partial(t, "FR-10.18", "FR-10.20", "FR-10.21", "FR-10.36")
	cfgPath, obs := startObserveGateway(t)
	feed(obs, 50, func(i int) int64 { return int64(100 + i%5) })

	out := runOut(t, "observe", "status", "--config", cfgPath)
	if !strings.Contains(out, "observation: enabled") || !strings.Contains(out, "assembled 50") {
		t.Fatalf("status: %s", out)
	}
	var built map[string]any
	json.Unmarshal([]byte(runOut(t, "observe", "baseline", "build", "--config", cfgPath)), &built)
	id1 := built["snapshot"].(map[string]any)["id"].(string)
	runOut(t, "observe", "baseline", "promote", id1, "--config", cfgPath)
	if !strings.Contains(runOut(t, "observe", "baseline", "--config", cfgPath), "promoted: "+id1) {
		t.Fatal("baseline list does not show the promoted snapshot")
	}
	feed(obs, 1, func(int) int64 { return 5000 })
	out = runOut(t, "observe", "anomalies", "--config", cfgPath)
	if !strings.Contains(out, "critical") || !strings.Contains(out, "request_bytes") {
		t.Fatalf("anomalies: %s", out)
	}
	json.Unmarshal([]byte(runOut(t, "observe", "baseline", "build", "--config", cfgPath)), &built)
	id2 := built["snapshot"].(map[string]any)["id"].(string)
	runOut(t, "observe", "baseline", "promote", id2, "--config", cfgPath)
	out = runOut(t, "observe", "baseline", "rollback", id1, "--config", cfgPath)
	if !strings.Contains(out, `"rollback"`) || obs.Scorer.SnapshotID() != id1 {
		t.Fatalf("rollback: %s", out)
	}
	runOut(t, "observe", "baseline", "flag", "s1", "--reason", "test", "--config", cfgPath)

	// Campaign and export with download.
	spec := filepath.Join(filepath.Dir(cfgPath), "spec.json")
	os.WriteFile(spec, []byte(fmt.Sprintf(`{"name":"c1","parameters":["P-024"],"start":%q,"end":%q,"quota_bytes":100000}`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))), 0o600)
	var cp map[string]any
	json.Unmarshal([]byte(runOut(t, "observe", "campaign", "create", "--file", spec, "--config", cfgPath)), &cp)
	cid := cp["id"].(string)
	runOut(t, "observe", "campaign", "submit", cid, "--config", cfgPath)
	runOut(t, "observe", "campaign", "approve", cid, "--config", cfgPath)
	if !strings.Contains(runOut(t, "observe", "campaign", "list", "--config", cfgPath), cid) {
		t.Fatal("campaign not listed")
	}
	dl := t.TempDir()
	out = runOut(t, "observe", "export", "--format", "jsonl", "--parameters", "request_bytes", "--download", dl, "--config", cfgPath)
	if !strings.Contains(out, "51 rows") {
		t.Fatalf("export: %s", out)
	}
	m, _ := filepath.Glob(filepath.Join(dl, "*", "*"))
	if len(m) != 4 {
		t.Fatalf("downloaded %v", m)
	}
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir(m[0]), "dataset.jsonl"))
	if strings.Contains(string(raw), "agent-a") {
		t.Fatal("principal in clear in export")
	}
	var errb bytes.Buffer
	if code := run([]string{"observe", "baseline", "promote", "not-an-id", "--config", cfgPath}, &bytes.Buffer{}, &errb); code == 0 {
		t.Fatal("bad ID accepted")
	}
}
