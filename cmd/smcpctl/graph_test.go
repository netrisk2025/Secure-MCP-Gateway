package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// startGraphGateway runs a Gateway in process with the graph mirror on an
// in-memory fake database.
func startGraphGateway(t *testing.T) (string, *graph.Mirror, *audit.Fanout) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	h, err := keys.HashPassword("admin password 12")
	if err != nil {
		t.Fatal(err)
	}
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
`, freePort(t), freePort(t), state, h))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	mirror, err := graph.New(graph.Options{Config: cfg, Log: diag.Discard(), Backend: graph.NewFake()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), Observers: map[string]audit.Observer{"graph": mirror}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	mirror.Register(a.Admin)
	mirror.Start(ctx, a.Evidence)
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done; mirror.Close(); a.Close() })
	return cfgPath, mirror, a.Evidence
}

func TestGraphCLI(t *testing.T) {
	reqtest.Partial(t, "FR-12.7")
	cfgPath, mirror, ev := startGraphGateway(t)
	for _, e := range []audit.Event{
		{Class: "session", Origin: "E-04", SessionID: "s1", PrincipalID: "cc", Outcome: "active"},
		{Class: "call", Phase: audit.PhaseRequested, Origin: "E-02", CorrelationID: "c1", SessionID: "s1", PrincipalID: "cc", ToolRevision: "live-1/echo", ServerRevision: "live-1"},
		{Class: "decision", Phase: audit.PhaseDenied, Origin: "E-06", CorrelationID: "c1", SessionID: "s1", PrincipalID: "cc", DecisionID: "d1", PolicyRevision: "r1", Outcome: "deny", ReasonCode: "NO_MATCHING_RULE"},
	} {
		if err := ev.Commit(e); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := mirror.DAS(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mirror not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := mirror.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	cli := func(stdin string, args ...string) (string, error) {
		var out bytes.Buffer
		err := graphCmd(append(args, "--config", cfgPath), strings.NewReader(stdin), &out)
		return out.String(), err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := cli("", args...)
		if err != nil {
			t.Fatalf("graph %v: %v\n%s", args, err, out)
		}
		return out
	}
	if out := must("status"); !strings.Contains(out, "state:     ready") || !strings.Contains(out, "schema:    2") || !strings.Contains(out, "sessions=1") {
		t.Fatalf("%s", out)
	}
	if out := must("status", "--json"); !strings.Contains(out, `"template_digest"`) {
		t.Fatal(out)
	}
	if out := must("query"); !strings.Contains(out, "call_timeline") || !strings.Contains(out, "correlationId,limit") {
		t.Fatal(out)
	}
	if out := must("query", "recent_denials"); !strings.Contains(out, "NO_MATCHING_RULE") || !strings.Contains(out, "DECISION") {
		t.Fatal(out)
	}
	if out := must("query", "call_timeline", "--param", "correlationId=c1", "--limit", "5"); strings.Count(out, "\n") != 3 {
		t.Fatalf("timeline: %q", out)
	}
	if out := must("neighborhood", "Session", "s1"); !strings.Contains(out, "OF_PRINCIPAL") {
		t.Fatal(out)
	}
	if out, err := cli("", "query", "nope"); err == nil || !strings.Contains(err.Error(), "unknown_query") {
		t.Fatalf("%v %s", err, out)
	}
	if _, err := cli("", "query", "call_timeline", "--param", "bad name=x"); err == nil {
		t.Fatal("bad param accepted")
	}
	if _, err := cli("", "neighborhood", "Session"); err == nil {
		t.Fatal("missing id accepted")
	}
	if _, err := cli("n\n", "rebuild"); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatal(err)
	}
	if out := must("rebuild", "--yes"); !strings.Contains(out, "rebuild queued") {
		t.Fatal(out)
	}
	if out := must("config"); !strings.Contains(out, "server.memory.heap.max_size=1g") || !strings.Contains(out, "server.http.enabled=false") {
		t.Fatal(out)
	}
	if _, err := cli("", "frobnicate"); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
}

func TestSmcpdServesWithGraphConfigured(t *testing.T) {
	// FR-9.17 third case through the real daemon: with [graph] enabled and
	// the database unreachable, smcpd serves and reports the mirror as
	// unavailable. With SMCP_NEO4J_URL set the same daemon mirrors into
	// Neo4j and answers canned queries.
	reqtest.Partial(t, "FR-9.17")
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	uri, user, pw := os.Getenv("SMCP_NEO4J_URL"), os.Getenv("SMCP_NEO4J_USER"), os.Getenv("SMCP_NEO4J_PASSWORD")
	real := uri != ""
	if !real {
		uri, user, pw = "bolt://127.0.0.1:"+freePort(t), "smcp_graph", "unused"
	}
	if user == "" {
		user = "neo4j"
	}
	pwFile := writeFile(t, secrets, "graph.pw", pw+"\n")
	cfgPath := filepath.Join(dir, "smcp.toml")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "\n[graph]\nenabled = true\nuri = %q\nusername = %q\npassword_file = %q\n", uri, user, pwFile)
	f.Close()
	if out := mustCtl(t, "config", "validate", "--config", cfgPath); !strings.Contains(out, "configuration OK") {
		t.Fatal(out)
	}
	d := startDaemon(t, cfgPath)
	defer stopDaemon(t, d)
	want := "unavailable"
	if real {
		want = "ready"
	}
	deadline := time.Now().Add(30 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		out = mustCtl(t, "graph", "status", "--config", cfgPath)
		if strings.Contains(out, "state:     "+want) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(out, "state:     "+want) {
		t.Fatalf("graph status: %s", out)
	}
	mustCtl(t, "health", "--config", cfgPath)
	if !real {
		if out, err := ctl(t, "", "graph", "query", "tool_usage", "--config", cfgPath); err == nil || !strings.Contains(out, "graph_unavailable") {
			t.Fatalf("%v %s", err, out)
		}
		return
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out = mustCtl(t, "graph", "query", "policy_revisions", "--config", cfgPath)
		if strings.Contains(out, "r1") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(out, "r1") {
		t.Fatalf("policy revision not mirrored: %s", out)
	}
}
