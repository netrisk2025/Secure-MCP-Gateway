package graph

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type nopCtl struct{}

func (nopCtl) Health() edge.Health                                   { return edge.Health{State: "ok"} }
func (nopCtl) Stop(string, string) error                             { return nil }
func (nopCtl) Resume(string) error                                   { return nil }
func (nopCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

type apiFixture struct {
	t        *testing.T
	srv      *adminapi.Server
	operator string
	env      *testEnv
	fake     *Fake
}

func newAPI(t *testing.T, enabled bool) *apiFixture {
	t.Helper()
	f := NewFake()
	var b Backend
	if enabled {
		b = f
	}
	e := newEnv(t, b, 1000, nil, nil)
	if err := keys.Ensure(e.dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("[admin_listener]\naddress = \"127.0.0.1:8444\"\n[state]\ndir = \"" + e.dir + "\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := adminapi.New(adminapi.Options{Config: cfg, Controller: nopCtl{}, Evidence: e.fanout, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	e.mirror.Register(srv)
	op, _ := keys.LoadAdminToken(e.dir)
	return &apiFixture{t: t, srv: srv, operator: op, env: e, fake: f}
}

func (a *apiFixture) do(method, path, tok string) (int, map[string]any) {
	a.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Host = "127.0.0.1:8444"
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	a.srv.Handler().ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func TestGraphControlAPI(t *testing.T) {
	// G-14 backend (FR-8.22, partial: the console view is the console
	// agent's): bounded neighborhood and event path queries, canned
	// queries, status and rebuild behind control API authentication.
	reqtest.Partial(t, "FR-8.22")
	a := newAPI(t, true)
	a.env.workload(3)
	syncMirror(t, a.env.mirror)

	if c, _ := a.do("GET", "/api/v1/graph/status", ""); c != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status: %d", c)
	}
	c, st := a.do("GET", "/api/v1/graph/status", a.operator)
	if c != 200 || st["state"] != "ready" || st["schema_version"] != float64(2) {
		t.Fatalf("%d %v", c, st)
	}
	counts, _ := st["counts"].(map[string]any)
	if counts["invocations"] != float64(4) || counts["sessions"] != float64(1) {
		t.Fatalf("counts %v", counts)
	}

	c, nb := a.do("GET", "/api/v1/graph/neighborhood?label=Session&id=s1&limit=3", a.operator)
	if c != 200 || nb["truncated"] != true || len(nb["edges"].([]any)) != 3 {
		t.Fatalf("%d %v", c, nb)
	}
	node, _ := nb["node"].(map[string]any)
	if node["id"] != "s1" {
		t.Fatalf("%v", node)
	}
	for path, want := range map[string]string{
		"/api/v1/graph/neighborhood?label=Checkpoint&id=schema":                "invalid_label",
		"/api/v1/graph/neighborhood?label=Session&id=":                         "invalid_parameter",
		"/api/v1/graph/neighborhood?label=Session&id=s1&limit=9999":            "invalid_parameter",
		"/api/v1/graph/neighborhood?label=Session&id=nope":                     "not_found",
		"/api/v1/graph/queries/drop_everything":                                "unknown_query",
		"/api/v1/graph/queries/call_timeline":                                  "invalid_parameter",
		"/api/v1/graph/queries/recent_sessions?cypher=" + url.QueryEscape("x"): "invalid_parameter",
		"/api/v1/graph/events/nope/path":                                       "not_found",
	} {
		if _, out := a.do("GET", path, a.operator); errCode(out) != want {
			t.Errorf("%s: %v, want %s", path, out, want)
		}
	}

	ids := journalIDs(t, a.env.dir)
	var delivered string
	for _, id := range ids {
		if n := a.fake.Node("AuditEvent", id); n["phase"] == "delivered" && n["correlationId"] == "corr-1" {
			delivered = id
		}
	}
	c, p := a.do("GET", "/api/v1/graph/events/"+delivered+"/path", a.operator)
	if c != 200 {
		t.Fatalf("%d %v", c, p)
	}
	if d, _ := p["decision"].(map[string]any); d["id"] != "dec-1" {
		t.Fatalf("decision %v", p["decision"])
	}
	if pr, _ := p["principal"].(map[string]any); pr["id"] != "cc" {
		t.Fatalf("principal %v", p["principal"])
	}
	if tr, _ := p["toolRevision"].(map[string]any); tr["id"] != "live-abc/echo" {
		t.Fatalf("tool %v", p["toolRevision"])
	}
	if ph, _ := p["phases"].([]any); len(ph) != 5 {
		t.Fatalf("phases %v", p["phases"])
	}
	if dr, _ := p["decisiveRules"].([]any); len(dr) != 1 || dr[0].(map[string]any)["id"] != "r1/dev/allow-echo" {
		t.Fatalf("decisive rules %v", p["decisiveRules"])
	}
	if ap, _ := p["auditProfile"].(map[string]any); ap["id"] != "audit_profile@file" {
		t.Fatalf("audit profile %v", p["auditProfile"])
	}

	c, ql := a.do("GET", "/api/v1/graph/queries", a.operator)
	if c != 200 || len(ql["queries"].([]any)) != len(CannedQueries) {
		t.Fatalf("%v", ql)
	}
	c, q := a.do("GET", "/api/v1/graph/queries/recent_denials", a.operator)
	if rows, _ := q["rows"].([]any); c != 200 || len(rows) != 1 {
		t.Fatalf("%d %v", c, q)
	}
	c, q = a.do("GET", "/api/v1/graph/queries/call_timeline?correlationId=corr-2&limit=10", a.operator)
	if rows, _ := q["rows"].([]any); c != 200 || len(rows) != 5 {
		t.Fatalf("%d %v", c, q)
	}

	c, rb := a.do("POST", "/api/v1/graph/rebuild", a.operator)
	if c != http.StatusAccepted || rb["status"] != "queued" {
		t.Fatalf("%d %v", c, rb)
	}
	deadline := time.Now().Add(10 * time.Second)
	for a.env.mirror.Status(t.Context(), false).LastRebuild == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := a.env.mirror.Status(t.Context(), false); st.LastRebuild == "" || st.RebuildError != "" {
		t.Fatalf("%+v", st)
	}
	evs, err := audit.ReadEvents(a.env.journal.Dir())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range evs {
		found = found || (ev.ReasonCode == "GRAPH_REBUILD" && ev.Origin == "E-26")
	}
	if !found {
		t.Fatal("rebuild request not in the journal")
	}
}

func TestGraphControlAPIWhenDisabledOrDown(t *testing.T) {
	a := newAPI(t, false)
	c, st := a.do("GET", "/api/v1/graph/status", a.operator)
	if c != 200 || st["enabled"] != false || st["state"] != "disabled" {
		t.Fatalf("%d %v", c, st)
	}
	for _, p := range []string{"/api/v1/graph/neighborhood?label=Session&id=s1", "/api/v1/graph/queries/tool_usage"} {
		if c, out := a.do("GET", p, a.operator); c != 503 || errCode(out) != "graph_disabled" {
			t.Fatalf("%s: %d %v", p, c, out)
		}
	}
	if c, out := a.do("POST", "/api/v1/graph/rebuild", a.operator); c != 503 || errCode(out) != "graph_disabled" {
		t.Fatalf("%d %v", c, out)
	}

	b := newAPI(t, true)
	waitReady(t, b.env.mirror)
	b.fake.Fail(ErrUnavailable)
	b.env.workload(1)
	deadline := time.Now().Add(5 * time.Second)
	for b.env.mirror.Status(t.Context(), false).State == StateReady && time.Now().Before(deadline) {
		b.env.workload(1)
		time.Sleep(20 * time.Millisecond)
	}
	if c, out := b.do("GET", "/api/v1/graph/queries/tool_usage", b.operator); c != 503 || errCode(out) != "graph_unavailable" {
		t.Fatalf("%d %v", c, out)
	}
	if c, st := b.do("GET", "/api/v1/graph/status", b.operator); c != 200 || st["state"] == "ready" || st["error"] == "" {
		t.Fatalf("%d %v", c, st)
	}
}
