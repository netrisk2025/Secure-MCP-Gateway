package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type obsFixture struct {
	*fixture
	obs    *analytics.Service
	mu     sync.Mutex
	events []audit.Event
}

// startObservation runs a Gateway wired as cmd/smcpd wires analytics, with
// an extra [observation] table body.
func startObservation(t *testing.T, observation string) *obsFixture {
	t.Helper()
	return startObservationOpts(t, observation, nil, nil, false, nil)
}

// startObservationWith is startObservation with extra filters registered
// before the observation probes and a tap on the call-path spans.
func startObservationWith(t *testing.T, observation string, extra func(*pipeline.Filters) error, tap pipeline.SpanSink) *obsFixture {
	t.Helper()
	return startObservationOpts(t, observation, extra, tap, false, nil)
}

// startObservationBuiltins is startObservation with the built-in E-09/E-11
// filters in the inspection chain too, as cmd/smcpd wires it
// (app.Options.ExtraFilters).
func startObservationBuiltins(t *testing.T, observation string) *obsFixture {
	t.Helper()
	return startObservationOpts(t, observation, nil, nil, true, nil)
}

func startObservationOpts(t *testing.T, observation string, extra func(*pipeline.Filters) error, tap pipeline.SpanSink, builtins bool, approver pipeline.Approver) *obsFixture {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	port, adminPort := freePort(t), freePort(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	toml := fmt.Sprintf(`
[listener]
address = "127.0.0.1:%d"
public_url = "https://127.0.0.1:%d"
[admin_listener]
address = "127.0.0.1:%d"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[[approver]]
username = "approver"
password_hash = %q
[policy]
file = %q
[limits]
# No observation test exercises the timeouts. The backend is this test
# binary (built with -race in CI), so a call can stall past a 2 s bound on
# a loaded machine; the bounds are generous.
upstream_timeout = "30s"
client_deadline = "35s"
principal_calls_per_minute = 100000
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = %q
principal = "cc"
redirect_uris = ["http://localhost:*/callback"]
[[server]]
alias = "t"
command = %q
args = ["-test.run=NONE"]
[server.env]
SMCP_E2E_BACKEND = "1"
[observation]
%s
`, port, port, adminPort, stateDir, mustHash(t, "admin password 12"), mustHash(t, approverPassword), filepath.Join(dir, "policy.json"),
		clientID, exe, observation)
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := analytics.New(analytics.Options{Config: cfg, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	register := func(f *pipeline.Filters) error {
		if extra != nil {
			if err := extra(f); err != nil {
				return err
			}
		}
		return obs.RegisterFilters(f)
	}
	ao := app.Options{Log: diag.Discard(), JanitorInterval: 200 * time.Millisecond, Approver: approver}
	if builtins {
		ao.ExtraFilters = register
	} else {
		ao.Filters = pipeline.NewFilters()
		if err := register(ao.Filters); err != nil {
			t.Fatal(err)
		}
	}
	of := &obsFixture{obs: obs}
	spans := obs.SpanSink() // as cmd/smcpd wires it (FR-10.2)
	if tap != nil {
		sink := spans
		spans = func(sp []pipeline.StageSpan) { tap(sp); sink(sp) }
	}
	ctx, cancel := context.WithCancel(context.Background())
	ao.Spans = spans
	ao.Observers = map[string]audit.Observer{"observation": obs.Observer(),
		"test": audit.ObserverFunc(func(e audit.Event) { of.mu.Lock(); of.events = append(of.events, e); of.mu.Unlock() })}
	a, err := app.Start(ctx, cfg, ao)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	obs.Start(ctx, a.Evidence, a.Admin, func() uint64 { return a.Evidence.Dropped()["observation"] })
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	f := &fixture{t: t, cfg: cfg, app: a, base: cfg.Listener.PublicURL, stateDir: stateDir, cancel: cancel, served: make(chan error, 1)}
	go func() { f.served <- a.Serve(ctx) }()
	pool := x509.NewCertPool()
	ca, _ := os.ReadFile(filepath.Join(stateDir, keys.CACertFile))
	pool.AppendCertsFromPEM(ca)
	f.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if f.operator, err = keys.LoadAdminToken(stateDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.stop(); obs.Close() })
	of.fixture = f
	return of
}

func (of *obsFixture) waitAssembled(n uint64) {
	of.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for of.obs.Collector.Stats().Assembled < n {
		if time.Now().After(deadline) {
			of.t.Fatalf("assembled %d records, want %d", of.obs.Collector.Stats().Assembled, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestObservationThroughGateway(t *testing.T) {
	// FR-10.36: the export is written to the configured export directory
	// and downloaded through the control API route the G-09 Research view
	// uses (below).
	reqtest.Verifies(t, "FR-10.36")
	reqtest.Partial(t, "FR-10", "FR-10.3", "FR-10.20", "FR-9.7")
	of := startObservation(t, `sampling_rate = 1.0
flush_interval = "20ms"
[observation.baseline]
n_min = 20
snapshot_records = 0
[[observation.baseline.feature]]
parameter = "request_bytes"
transform = "log1p"
sigma_floor = 0.05
`)
	access, _, _ := of.oauthLogin("smcp:template:ro")
	cs := of.mcpClient(access)
	const n = 120
	for i := 0; i < n; i++ {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": fmt.Sprintf("hello %03d", i)}}); err != nil {
			t.Fatal(err)
		}
	}
	// A call denied by policy is observed too.
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_write", Arguments: map[string]any{}}); err == nil {
		t.Fatal("write was not refused")
	}
	of.waitAssembled(n + 1)
	of.obs.Sync() // rows written to the store, instead of sleeping for the flush interval

	code, st := of.admin("GET", "/api/v1/observations/status", of.operator, nil)
	if code != 200 || st["enabled"] != true {
		t.Fatalf("status %d %v", code, st)
	}
	code, recs := of.admin("GET", "/api/v1/observations?limit=1000&tool=echo", of.operator, nil)
	if code != 200 || int(recs["count"].(float64)) != n {
		t.Fatalf("records %d %v", code, recs["count"])
	}
	r0 := recs["rows"].([]any)[0].(map[string]any)
	for _, k := range []string{"principal_id", "session_id", "server_revision", "tool_name", "decision_outcome", "request_bytes", "response_bytes",
		"end_to_end_latency", "server_execution_time", "gateway_overhead", "argument_entropy", "server_id"} {
		if r0[k] == nil {
			t.Fatalf("record lacks %s: %v", k, r0)
		}
	}
	if r0["principal_id"] != "cc" || r0["decision_outcome"] != "permit" || r0["release_outcome"] != "released" {
		t.Fatalf("record %v", r0)
	}
	code, agg := of.admin("GET", "/api/v1/observations/aggregate?feature=request_bytes&group_by=context&quantiles=0.5&tool=echo", of.operator, nil)
	if code != 200 || len(agg["rows"].([]any)) != 1 {
		t.Fatalf("aggregate %d %v", code, agg)
	}

	// Baseline: build by operator command, refuse unauthenticated
	// promotion, promote with the operator token.
	code, built := of.admin("POST", "/api/v1/baselines/snapshots", of.operator, map[string]any{})
	if code != 200 {
		t.Fatalf("build %d %v", code, built)
	}
	id := built["snapshot"].(map[string]any)["id"].(string)
	if code, _ := of.admin("POST", "/api/v1/baselines/"+id+"/promote", "", map[string]any{}); code != 401 {
		t.Fatalf("unauthenticated promotion: %d", code)
	}
	if code, p := of.admin("POST", "/api/v1/baselines/"+id+"/promote", of.operator, map[string]any{}); code != 200 || p["loaded_snapshot"] != id {
		t.Fatalf("promote %d %v", code, p)
	}
	// An outlier call is scored abnormal or worse and reported.
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": strings.Repeat("A", 20000)}}); err != nil {
		t.Fatal(err)
	}
	of.waitAssembled(n + 2)
	of.obs.Sync()
	code, an := of.admin("GET", "/api/v1/anomalies", of.operator, nil)
	if code != 200 || an["count"].(float64) < 1 {
		t.Fatalf("anomalies %d %v", code, an)
	}
	a0 := an["rows"].([]any)[0].(map[string]any)
	if a0["snapshot_id"] != id || a0["contributing_feature"] != "request_bytes" || (a0["band"] != "abnormal" && a0["band"] != "critical") {
		t.Fatalf("anomaly %v", a0)
	}
	anomalyEvent := false
	for _, ev := range of.journal() {
		if ev.Class == "anomaly" && ev.Origin == "E-31" {
			anomalyEvent = true
		}
	}
	if !anomalyEvent {
		t.Fatal("no anomaly evidence event")
	}

	// Research export and download through the control API.
	code, m := of.admin("POST", "/api/v1/research/exports", of.operator, map[string]any{"format": "csv", "parameters": []string{"request_bytes"}})
	if code != 200 {
		t.Fatalf("export %d %v", code, m)
	}
	ds := m["dataset_id"].(string)
	if _, err := os.Stat(filepath.Join(of.stateDir, "exports", ds, "dataset.csv")); err != nil {
		t.Fatal("export not in the export directory")
	}
	req, _ := http.NewRequest("GET", of.cfg.AdminURL()+"/api/v1/research/exports/"+ds+"/files/dataset.csv", nil)
	req.Header.Set("Authorization", "Bearer "+of.operator)
	resp, err := of.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.Count(string(body), "\n") < n || strings.Contains(string(body), ",cc,") {
		t.Fatalf("download %d: %d lines", resp.StatusCode, strings.Count(string(body), "\n"))
	}
	req, _ = http.NewRequest("GET", of.cfg.AdminURL()+"/api/v1/research/exports/"+ds+"/files/..%2Fkeys", nil)
	req.Header.Set("Authorization", "Bearer "+of.operator)
	if resp, err := of.client.Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("path traversal served a file")
		}
	}
}

func (of *obsFixture) journal() []audit.Event {
	of.t.Helper()
	// The anomaly event is recorded on the collector goroutine; give it a moment.
	for i := 0; i < 100; i++ {
		of.mu.Lock()
		out := append([]audit.Event(nil), of.events...)
		of.mu.Unlock()
		for _, e := range out {
			if e.Class == "anomaly" {
				return out
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	of.mu.Lock()
	defer of.mu.Unlock()
	return append([]audit.Event(nil), of.events...)
}

func TestSynchronousAnomalyObligation(t *testing.T) {
	// SR-1.12-2: a normal permitted call stays a plain permit, an abnormal
	// permitted call gains the approval obligation (the only action the
	// scorer can add before dispatch), and denied calls with a normal and
	// with an abnormal band stay denied.
	reqtest.Partial(t, "FR-4.15", "FR-10.28")
	reqtest.Verifies(t, "SR-1.19-1", "SR-1.12-3", "SR-1.12-2")
	of := startObservation(t, `sampling_rate = 1.0
scoring = "sync"
require_approval_band = "abnormal"
[observation.baseline]
n_min = 20
snapshot_records = 0
[[observation.baseline.feature]]
parameter = "request_bytes"
transform = "log1p"
sigma_floor = 0.05
`)
	if _, err := consoleapi.Attach(of.app, diag.Discard()); err != nil { // the explanation route (SR-1.19-1)
		t.Fatal(err)
	}
	access, _, _ := of.oauthLogin("smcp:template:ro")
	cs := of.mcpClient(access)
	for i := 0; i < 40; i++ {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": fmt.Sprintf("v%03d", i)}}); err != nil {
			t.Fatal(err)
		}
	}
	of.waitAssembled(40)
	res, err := of.obs.Baselines.BuildSnapshot("operator", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := of.obs.Baselines.Promote(res.Snapshot.ID, "test"); err != nil {
		t.Fatal(err)
	}
	// Normal call: permitted.
	normal, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "v999"}})
	if err != nil {
		t.Fatalf("normal call: %v", err)
	}
	prov, _ := normal.Meta["local.smcpgw/provenance"].(map[string]any)
	normalID, _ := prov["decisionId"].(string)
	// Abnormal call: the scorer adds the approval obligation before
	// dispatch; with no approval service the call is refused as approval
	// required and never reaches the backend.
	jerr, data := callErr(t, cs, "t_echo", map[string]any{"text": strings.Repeat("B", 50000)})
	if jerr == nil || jerr.Code != edge.CodeApprovalRequired {
		t.Fatalf("abnormal call: %v %v", jerr, data)
	}
	dispatched := false
	for _, ev := range of.journal() {
		if ev.Phase == audit.PhaseDispatched && ev.CorrelationID == data["correlationId"] {
			dispatched = true
		}
	}
	if dispatched {
		t.Fatal("abnormal call was dispatched")
	}
	// A denied call stays denied whatever its band (restrict-only).
	jerr, _ = callErr(t, cs, "t_secret", map[string]any{})
	if jerr == nil {
		t.Fatal("denied call permitted")
	}
	// A decision that denies: a revision with a per-session quota of one
	// call, spent by the next call.
	of.publish(strings.Replace(strings.Replace(testPolicy, `"r1"`, `"r2"`, 1), `"ro": {"rules"`, `"ro": {"calls_per_session": 1, "rules"`, 1))
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "v997"}}); err != nil {
		t.Fatalf("first call under the quota: %v", err)
	}
	jerr, denied := callErr(t, cs, "t_echo", map[string]any{"text": "v998"})
	if jerr == nil || denied["reasonCode"] != "QUOTA_EXHAUSTED" {
		t.Fatalf("quota: %v %v", jerr, denied)
	}
	// SR-1.12-2: the denial stands for a call whose band would be
	// abnormal too; a band never turns it into a permit or an approval.
	jerr, deniedAbnormal := callErr(t, cs, "t_echo", map[string]any{"text": strings.Repeat("B", 50000)})
	if jerr == nil || jerr.Code == edge.CodeApprovalRequired || deniedAbnormal["reasonCode"] != "QUOTA_EXHAUSTED" {
		t.Fatalf("denied abnormal call: %v %v", jerr, deniedAbnormal)
	}
	checkExplanations(t, of, res.Snapshot.ID, normalID, data["decisionId"].(string), denied["decisionId"].(string))
}

// checkExplanations reads GET /api/v1/decisions/{id}/explanation for a
// permitted, an anomaly-restricted and a denied decision (SR-1.19-1); the
// anomaly-restricted one records the baseline snapshot of its obligation
// (SR-1.12-3).
func checkExplanations(t *testing.T, of *obsFixture, snapshot, permitID, anomalyID, denyID string) {
	t.Helper()
	get := func(id string) map[string]any {
		t.Helper()
		status, body := of.admin("GET", "/api/v1/decisions/"+id+"/explanation", of.operator, nil)
		if status != 200 {
			t.Fatalf("explanation of %s: %d %v", id, status, body)
		}
		return body
	}
	p := get(permitID)
	if p["outcome"] != "permit" || p["phase"] != "authorized" || p["route"] != "t" || fmt.Sprint(p["decisive_rules"]) != "[r1/ro/ro-t]" ||
		len(p["considered_rules"].([]any)) != 2 || p["obligations"] == nil {
		t.Fatalf("permit explanation %v", p)
	}
	d := get(denyID)
	if d["outcome"] != "deny" || d["phase"] != "denied" || d["reason_code"] != "QUOTA_EXHAUSTED" || d["policy_revision"] != "r2" ||
		fmt.Sprint(d["decisive_rules"]) != "[r2/ro/ro-t]" || len(d["considered_rules"].([]any)) != 2 {
		t.Fatalf("deny explanation %v", d)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		a := get(anomalyID)
		ob, _ := a["anomaly_obligation"].(map[string]any)
		obl, _ := a["obligations"].(map[string]any)
		if ob == nil || ob["snapshot_id"] != snapshot || a["baseline_snapshot_id"] != snapshot || obl["approval"] != true || a["reason_code"] != "APPROVAL_REQUIRED" {
			t.Fatalf("anomaly explanation %v", a)
		}
		if ev, _ := a["anomaly"].([]any); len(ev) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no anomaly evidence in %v", a)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status, _ := of.admin("GET", "/api/v1/decisions/no-such-decision/explanation", of.operator, nil); status != 404 {
		t.Fatalf("unknown decision: %d", status)
	}
}
