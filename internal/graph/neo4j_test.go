package graph

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Integration tests against a real Neo4j Community Edition. They run when
// SMCP_NEO4J_URL is set (for example bolt://127.0.0.1:7687), with
// SMCP_NEO4J_USER (default neo4j) and SMCP_NEO4J_PASSWORD. They wipe the
// database: never point them at a database holding data you need.

func neo4jEnv(t *testing.T) *Neo4j {
	t.Helper()
	uri := os.Getenv("SMCP_NEO4J_URL")
	if uri == "" {
		t.Skip("SMCP_NEO4J_URL not set")
	}
	user := os.Getenv("SMCP_NEO4J_USER")
	if user == "" {
		user = "neo4j"
	}
	b, err := NewNeo4j(uri, user, os.Getenv("SMCP_NEO4J_PASSWORD"), "neo4j")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close(context.Background()) })
	resetNeo4j(t, b)
	return b
}

// resetNeo4j empties the database, including constraints and indexes, with
// the driver directly (test setup only; the service has no such operation).
func resetNeo4j(t *testing.T, b *Neo4j) {
	t.Helper()
	ctx := context.Background()
	s := b.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer s.Close(ctx)
	run := func(q string) []*neo4j.Record {
		res, err := s.Run(ctx, q, nil) // auto-commit: CALL IN TRANSACTIONS needs it
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return recs
	}
	run("MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS")
	for _, r := range run("SHOW CONSTRAINTS YIELD name RETURN name") {
		n, _ := r.Get("name")
		run("DROP CONSTRAINT `" + n.(string) + "`")
	}
	for _, r := range run("SHOW INDEXES YIELD name, type WHERE type IN ['RANGE','TEXT','POINT'] RETURN name") {
		n, _ := r.Get("name")
		run("DROP INDEX `" + n.(string) + "` IF EXISTS")
	}
}

func TestNeo4jEveryTemplateCompiles(t *testing.T) {
	b := neo4jEnv(t)
	das := NewDAS(b, nil, nil)
	if _, _, err := das.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range DefaultCatalog().Ops() {
		op, _ := DefaultCatalog().Op(id)
		if strings.HasPrefix(id, "migration.") || strings.HasPrefix(op.Text(), "SHOW") || strings.HasPrefix(op.Text(), "CALL dbms") {
			continue
		}
		explain := &Op{id: op.id, mode: ModeRead, params: op.params, text: "EXPLAIN " + op.Text()}
		params := map[string]any{}
		for name, typ := range op.params {
			switch typ {
			case TypeRows:
				params[name] = []map[string]any{{"id": "x", "ts": int64(1), "props": map[string]any{}, "from": "a", "to": "b"}}
			case TypeString:
				params[name] = "x"
			case TypeInt:
				params[name] = int64(1)
			case TypeStrings:
				params[name] = []string{"x"}
			}
		}
		if _, err := b.Read(ctx, Statement{Op: explain, Params: params}); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}

// TestNeo4jMigrationAfterInterruptedConstraint is FR-9.2 after a first
// start that was stopped while the engine built a constraint's backing
// index: the database holds an index with the constraint's name and no
// constraint. The next migration drops that index, creates the constraint
// and completes.
func TestNeo4jMigrationAfterInterruptedConstraint(t *testing.T) {
	reqtest.Partial(t, "FR-9.2")
	b := neo4jEnv(t)
	ctx := context.Background()
	orphan := &Op{id: "test.orphan", mode: ModeWrite, params: map[string]ParamType{}, text: "CREATE INDEX smcp_approval_id FOR (n:Approval) ON (n.id)"}
	if _, err := b.Write(ctx, []Statement{{Op: orphan, Params: map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	das := NewDAS(b, nil, nil)
	if from, to, err := das.Migrate(ctx); err != nil || from != 0 || to != 2 {
		t.Fatalf("migration over an orphaned index: %d %d %v", from, to, err)
	}
	show := &Op{id: "test.show", mode: ModeRead, params: map[string]ParamType{}, text: "SHOW CONSTRAINTS YIELD name, type WHERE name = 'smcp_approval_id' RETURN name, type"}
	rows, err := b.Read(ctx, Statement{Op: show, Params: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	// UNIQUENESS, or NODE_PROPERTY_UNIQUENESS on newer engines.
	typ := ""
	if len(rows) == 1 {
		typ, _ = rows[0]["type"].(string)
	}
	if !strings.HasSuffix(typ, "UNIQUENESS") {
		t.Fatalf("smcp_approval_id is not a uniqueness constraint after the migration: %v", rows)
	}
}

func TestNeo4jSchemaMigrationAndIndexes(t *testing.T) {
	// FR-9.2 on Neo4j: an empty database migrates; one at version 1
	// migrates to 2; one newer than the release is refused. FR-9.18: the
	// decision timestamp, event timestamp, event correlation ID, session ID
	// and server revision ID indexes exist and are online.
	reqtest.Verifies(t, "FR-9.2", "FR-9.18")
	reqtest.Partial(t, "FR-9.1")
	b := neo4jEnv(t)
	ctx := context.Background()
	das := NewDAS(b, nil, nil)
	if from, to, err := das.Migrate(ctx); err != nil || from != 0 || to != 2 {
		t.Fatalf("%d %d %v", from, to, err)
	}
	objs, err := das.SchemaObjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]SchemaObject{}
	constraints := 0
	for _, o := range objs {
		byName[o.Name] = o
		if o.Kind == "constraint" && strings.HasPrefix(o.Name, "smcp_") {
			constraints++
		}
	}
	if constraints != 30 {
		t.Fatalf("%d constraints: %+v", constraints, objs)
	}
	for _, ix := range []string{"smcp_decision_ts", "smcp_audit_event_ts", "smcp_audit_event_correlation", "smcp_audit_event_session",
		"smcp_audit_event_server_revision"} {
		if byName[ix].State != "ONLINE" {
			t.Errorf("index %s: %+v", ix, byName[ix])
		}
	}
	for _, c := range []string{"smcp_session_id", "smcp_server_revision_id"} {
		if byName[c].Kind != "constraint" {
			t.Errorf("constraint %s missing", c)
		}
	}
	// Older schema: pretend only migration 1 ran.
	st, _ := das.stmt("schema.set", map[string]any{"version": int64(1), "updated": int64(0)})
	if _, err := b.Write(ctx, []Statement{st}); err != nil {
		t.Fatal(err)
	}
	if from, to, err := das.Migrate(ctx); err != nil || from != 1 || to != 2 {
		t.Fatalf("%d %d %v", from, to, err)
	}
	st, _ = das.stmt("schema.set", map[string]any{"version": int64(7), "updated": int64(0)})
	if _, err := b.Write(ctx, []Statement{st}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := das.Migrate(ctx); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("newer schema accepted: %v", err)
	}
	// Uniqueness is enforced by the engine.
	dup := &Op{id: "test.dup", mode: ModeWrite, params: map[string]ParamType{}, text: "CREATE (:AuditEvent {id: 'same'}), (:AuditEvent {id: 'same'})"}
	if _, err := b.Write(ctx, []Statement{{Op: dup, Params: map[string]any{}}}); err == nil {
		t.Fatal("duplicate id accepted")
	}
}

func TestNeo4jInjectedTextIsNeverExecuted(t *testing.T) {
	// SR-1.13-1 on Neo4j: query text placed in every caller-controlled
	// value (node id, canned query parameter) is bound as a value and not
	// executed; labels and query names outside the catalog are refused.
	reqtest.Verifies(t, "SR-1.13-1")
	b := neo4jEnv(t)
	e := newEnv(t, b, 1000, nil, nil)
	e.workload(2)
	syncMirror(t, e.mirror)
	das, _ := e.mirror.DAS()
	ctx := context.Background()
	before, err := das.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"x'}) MATCH (n) DETACH DELETE n //", "s1\"}) DETACH DELETE n RETURN 1 AS x //", "`) CALL dbms.killQueries([]) //"} {
		if _, err := das.Neighborhood(ctx, "Session", id, 10); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%q: %v", id, err)
		}
		if _, err := das.EventPath(ctx, id, 10); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%q: %v", id, err)
		}
	}
	if _, err := das.Neighborhood(ctx, "Session) DETACH DELETE (n", "s1", 10); !errors.Is(err, ErrBadParameter) {
		t.Fatal(err)
	}
	if _, err := das.Query(ctx, "call_timeline", map[string]string{"correlationId": "x' OR 1=1"}, 10); !errors.Is(err, ErrBadParameter) {
		t.Fatal(err)
	}
	if _, err := das.Query(ctx, "MATCH (n) DETACH DELETE n", nil, 10); !errors.Is(err, ErrUnknownOp) {
		t.Fatal(err)
	}
	after, _ := das.Counts(ctx)
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("%s changed %d -> %d", k, v, after[k])
		}
	}
}

// flakyNeo4j fails writes after a budget, like a database that crashes.
type flakyNeo4j struct {
	*Neo4j
	left atomic.Int64
}

func (f *flakyNeo4j) Write(ctx context.Context, s []Statement) ([][]Row, error) {
	if f.left.Add(-1) < 0 {
		return nil, ErrUnavailable
	}
	return f.Neo4j.Write(ctx, s)
}

func TestNeo4jMirrorExactlyOnceAfterCrash(t *testing.T) {
	// SR-6.10-1 (graph mirror half) on Neo4j: crash the feed mid-batch,
	// restart, and the graph holds each journal event once.
	reqtest.Partial(t, "SR-6.10-1")
	b := neo4jEnv(t)
	fb := &flakyNeo4j{Neo4j: b}
	fb.left.Store(1 << 40)
	e := newEnv(t, fb, 100, func(c *config.Config) { c.Graph.BatchSize = 50 }, nil)
	waitReady(t, e.mirror)
	fb.left.Store(5)
	e.workload(300)
	deadline := time.Now().Add(20 * time.Second)
	for e.mirror.Status(context.Background(), false).State == StateReady && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	e.mirror.Close()
	fb.left.Store(1 << 40)
	m2 := e.startMirror(fb, nil)
	defer m2.Close()
	syncMirror(t, m2)
	das, _ := m2.DAS()
	ctx := context.Background()
	counts, err := das.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := journalIDs(t, e.dir)
	if counts["auditEvents"] != int64(len(ids)) {
		t.Fatalf("%d audit events, journal has %d", counts["auditEvents"], len(ids))
	}
	if counts["invocations"] != 301 || counts["decisions"] != 301 || counts["sessions"] != 1 {
		t.Fatalf("%v", counts)
	}
	if err := m2.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	again, _ := das.Counts(ctx)
	if again["auditEvents"] != int64(len(ids)) {
		t.Fatalf("rebuild: %v", again)
	}
}

func TestNeo4jQueriesRetentionAndEngineStatus(t *testing.T) {
	// The read templates return the same shapes as the fake on Neo4j, the
	// retention templates delete in bounded batches, and the engine
	// settings and heap can be read for the hardening and memory checks.
	reqtest.Partial(t, "FR-8.22", "SR-7.4-1", "FR-9.11")
	b := neo4jEnv(t)
	now := time.Now()
	clock := func() time.Time { return now }
	e := newEnv(t, b, 1000, func(c *config.Config) { c.Graph.Retention = config.Duration{Duration: time.Hour} }, clock)
	e.workload(3)
	syncMirror(t, e.mirror)
	das, _ := e.mirror.DAS()
	ctx := context.Background()
	nb, err := das.Neighborhood(ctx, "Session", "s1", 3)
	if err != nil || nb.Node.ID != "s1" || len(nb.Edges) != 3 || !nb.Truncated || nb.Degree < 10 {
		t.Fatalf("%+v %v", nb, err)
	}
	inv, err := das.Neighborhood(ctx, "Invocation", "corr-1", 50)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, ed := range inv.Edges {
		types[ed.Type] = true
	}
	for _, ty := range []string{"FOR_INVOCATION", "IN_SESSION", "INVOKED", "AUTHORIZED_BY"} {
		if !types[ty] {
			t.Errorf("invocation lacks %s: %+v", ty, inv.Edges)
		}
	}
	rows, err := das.Query(ctx, "call_timeline", map[string]string{"correlationId": "corr-1"}, 10)
	if err != nil || len(rows) != 5 || rows[0]["phase"] != "requested" || rows[4]["phase"] != "delivered" {
		t.Fatalf("%v %v", rows, err)
	}
	var delivered string
	if ev, ok := rows[4]["event"].(string); ok {
		delivered = ev
	}
	p, err := das.EventPath(ctx, delivered, 10)
	if err != nil || p.Decision["id"] != "dec-1" || p.Principal["id"] != "cc" || p.ToolRevision["id"] != "live-abc/echo" || len(p.Phases) != 5 {
		t.Fatalf("%+v %v", p, err)
	}
	// SR-6.4-1: the path reaches the decisive rule revisions and the
	// Audit Profile revision through the decision.
	if len(p.DecisiveRules) != 1 || p.DecisiveRules[0]["id"] != "r1/dev/allow-echo" || p.DecisiveRules[0]["parentId"] != "r1" ||
		p.AuditProfile["id"] != "audit_profile@file" || p.PolicyRevision["id"] != "r1" {
		t.Fatalf("decision links: %+v %+v %+v", p.DecisiveRules, p.AuditProfile, p.PolicyRevision)
	}
	for _, q := range CannedQueries {
		params := map[string]string{}
		if q.Name == "approvals" {
			continue // the workload has none
		}
		if q.Name == "call_timeline" {
			params["correlationId"] = "corr-0"
		}
		rows, err := das.Query(ctx, q.Name, params, 5)
		if err != nil || len(rows) == 0 {
			t.Errorf("%s: %v %v", q.Name, rows, err)
		}
	}
	if rows, _ := das.Query(ctx, "recent_denials", nil, 5); len(rows) != 1 || rows[0]["reasonCode"] != "NO_MATCHING_RULE" {
		t.Fatalf("%v", rows)
	}
	if rows, _ := das.Query(ctx, "tool_usage", nil, 5); rows[0]["toolRevision"] != "live-abc/echo" || rows[0]["calls"] != int64(3) {
		t.Fatalf("%v", rows)
	}
	settings, err := das.Settings(ctx, checkedSettings)
	if err != nil || settings["server.http.enabled"] == "" {
		t.Fatalf("%v %v", settings, err)
	}
	if h, err := das.HeapUse(ctx); err != nil || h.Used <= 0 || h.Max <= 0 {
		t.Fatalf("%+v %v", h, err)
	}
	deleted, err := das.Retain(ctx, now.Add(time.Hour), 7)
	if err != nil {
		t.Fatal(err)
	}
	if deleted["AuditEvent"] != int64(len(journalIDs(t, e.dir))) || deleted["Invocation"] != 4 || deleted["Session"] != 1 {
		t.Fatalf("%v", deleted)
	}
	counts, _ := das.Counts(ctx)
	if counts["auditEvents"] != 0 || counts["policyRevisions"] == 0 || counts["toolRevisions"] == 0 {
		t.Fatalf("%v", counts)
	}
}
