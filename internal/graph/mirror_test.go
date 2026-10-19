package graph

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestMigrationsApplyInOrderAndRefuseNewer(t *testing.T) {
	// FR-9.2 with the fake: an empty database migrates to the release
	// version, a current one is left alone, a newer one is refused and
	// the mirror reports "refused". The integration test repeats this on
	// Neo4j.
	reqtest.Partial(t, "FR-9.2")
	f := NewFake()
	das := NewDAS(f, nil, nil)
	ctx := context.Background()
	from, to, err := das.Migrate(ctx)
	if err != nil || from != 0 || to != 2 {
		t.Fatalf("%d %d %v", from, to, err)
	}
	n := len(f.Schema())
	if from, to, err = das.Migrate(ctx); err != nil || from != 2 || to != 2 || len(f.Schema()) != n {
		t.Fatalf("second migrate: %d %d %v", from, to, err)
	}
	// Older schema: version 1 only migration 2 runs.
	f2 := NewFake()
	d2 := NewDAS(f2, nil, nil)
	st, _ := d2.stmt("schema.set", map[string]any{"version": int64(1), "updated": int64(0)})
	if _, err := f2.Write(ctx, []Statement{st}); err != nil {
		t.Fatal(err)
	}
	if from, to, err := d2.Migrate(ctx); err != nil || from != 1 || to != 2 {
		t.Fatalf("%d %d %v", from, to, err)
	}
	for _, s := range f2.Schema() {
		if strings.Contains(s, "CONSTRAINT") {
			t.Fatalf("migration 1 re-ran: %s", s)
		}
	}
	// Newer schema.
	st, _ = das.stmt("schema.set", map[string]any{"version": int64(99), "updated": int64(0)})
	if _, err := f.Write(ctx, []Statement{st}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := das.Migrate(ctx); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("newer schema accepted: %v", err)
	}
	e := newEnv(t, f, 1000, nil, nil)
	deadline := time.Now().Add(5 * time.Second)
	for e.mirror.Status(ctx, false).State != StateRefused && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := e.mirror.Status(ctx, false); st.State != StateRefused || !strings.Contains(st.Error, "newer") {
		t.Fatalf("%+v", st)
	}
	e.workload(3) // evidence still commits
}

func TestSchemaHasConstraintForEveryAppendixDLabel(t *testing.T) {
	// FR-9.1: migration 1 creates a uniqueness constraint on id for every
	// Appendix D label. Relationship types exist in Neo4j only once used;
	// the mirror creates the audit, session and decision ones, while the
	// behavior model, registry and secret relationships belong to E-13,
	// E-14, E-19 and E-30, so this is partial.
	reqtest.Partial(t, "FR-9.1")
	labels := []string{"Principal", "CredentialRef", "Session", "Server", "ServerRevision", "ToolRevision", "ImportReceipt", "TrustAnchor",
		"PolicyControl", "PolicyRevision", "PolicyObject", "RuleRevision", "RouteRevision", "Approval", "Decision", "Invocation", "AuditEvent",
		"PayloadRef", "OutboxRecord", "Checkpoint", "SecretRef", "SecretUse", "BaselineContext", "FeatureStat", "BaselineSnapshot",
		"AbnormalEvent", "Parameter", "CatalogVersion", "Campaign", "Dataset"}
	m := DefaultCatalog().Migrations()[0]
	for _, l := range labels {
		found := false
		for _, op := range m.Ops {
			found = found || strings.Contains(op.Text(), "FOR (n:"+l+") REQUIRE n.id IS UNIQUE")
		}
		if !found {
			t.Errorf("no uniqueness constraint for %s", l)
		}
	}
	if len(m.Ops) != len(labels) {
		t.Fatalf("%d constraints for %d labels", len(m.Ops), len(labels))
	}
}

func TestMirrorProjectsCallsSessionsDecisionsAndApprovals(t *testing.T) {
	// The projection links each event to its session, call, decision,
	// server, tool and policy revisions (Appendix D relationships).
	reqtest.Partial(t, "FR-9.1", "SR-6.10-1")
	f := NewFake()
	e := newEnv(t, f, 1000, nil, nil)
	e.workload(2)
	e.commit(audit.Event{Class: "approval", Origin: "E-07", CorrelationID: "corr-1", SessionID: "s1", PrincipalID: "cc", DecisionID: "dec-1",
		Outcome: "approved", ReasonCode: "APPROVED", Detail: map[string]any{"approval_id": "ap-1", "public_name": "t_echo", "approver": "approver:alice"}})
	e.commit(audit.Event{Class: "admin", Origin: "E-05", Outcome: "activated", ReasonCode: "POLICY_ACTIVATED", PolicyRevision: "r2"})
	syncMirror(t, e.mirror)
	ids := journalIDs(t, e.dir)
	if got := f.Count("AuditEvent"); got != len(ids) {
		t.Fatalf("%d audit events for %d journal events", got, len(ids))
	}
	for _, c := range []struct{ fl, f, typ, tl, to string }{
		{"Session", "s1", "OF_PRINCIPAL", "Principal", "cc"},
		{"Invocation", "corr-0", "IN_SESSION", "Session", "s1"},
		{"Invocation", "corr-0", "INVOKED", "ToolRevision", "live-abc/echo"},
		{"Invocation", "corr-0", "AUTHORIZED_BY", "Decision", "dec-0"},
		{"Decision", "dec-0", "EVALUATED_UNDER", "PolicyRevision", "r1"},
		{"Decision", "dec-0", "TARGETED", "ServerRevision", "live-abc"},
		{"Decision", "dec-0", "IN_SESSION", "Session", "s1"},
		{"ToolRevision", "live-abc/echo", "BELONGS_TO", "ServerRevision", "live-abc"},
		{"Approval", "ap-1", "FOR_INVOCATION", "Invocation", "corr-1"},
		{"Approval", "ap-1", "IN_SESSION", "Session", "s1"},
	} {
		if !f.HasRel(c.fl, c.f, c.typ, c.tl, c.to) {
			t.Errorf("missing %s %s -%s-> %s %s", c.fl, c.f, c.typ, c.tl, c.to)
		}
	}
	if d := f.Node("Decision", "ddec-0"); d["outcome"] != "deny" || d["reasonCode"] != "NO_MATCHING_RULE" {
		t.Fatalf("denial %v", d)
	}
	if s := f.Node("Session", "s1"); s["state"] != "active" {
		t.Fatalf("session %v", s)
	}
	if a := f.Node("Approval", "ap-1"); a["state"] != "approved" || a["approver"] != "approver:alice" || a["publicName"] != "t_echo" {
		t.Fatalf("approval %v", a)
	}
	if pc := f.Node("PolicyControl", "control"); pc["activeRevisionId"] != "r2" {
		t.Fatalf("policy control %v", pc)
	}
	if r := f.Node("PolicyRevision", "r2"); r["activatedAt"] == nil {
		t.Fatalf("revision %v", r)
	}
	if i := f.Node("Invocation", "corr-0"); i["phase"] != "delivered" {
		t.Fatalf("invocation keeps the latest phase: %v", i)
	}
}

// crashingBackend fails every write after the first n.
type crashingBackend struct {
	*Fake
	left atomic.Int64
}

func (c *crashingBackend) Write(ctx context.Context, s []Statement) ([][]Row, error) {
	if c.left.Add(-1) < 0 {
		return nil, ErrUnavailable
	}
	return c.Fake.Write(ctx, s)
}

func TestMirrorExactlyOncePerEventAcrossCrashAndRestart(t *testing.T) {
	// SR-6.10-1 for the graph mirror: the feed crashes mid-batch, the
	// mirror restarts on the same database, catches up from the journal
	// and holds every journal event exactly once (no gaps, no duplicates:
	// one AuditEvent per event ID, and re-applying changes nothing).
	// The evidence export (X-09) half of SR-6.10-1 is not built here.
	reqtest.Partial(t, "SR-6.10-1")
	reqtest.Scenario(t, reqtest.Standalone, "AT-12") // mirror replay and duplicate event IDs
	f := NewFake()
	cb := &crashingBackend{Fake: f}
	cb.left.Store(1 << 40)
	e := newEnv(t, cb, 50, func(c *config.Config) { c.Graph.BatchSize = 40 }, nil)
	waitReady(t, e.mirror)
	cb.left.Store(6) // migrations are done; allow a few batches then crash
	e.workload(120)  // 603 events, 13 segments
	deadline := time.Now().Add(10 * time.Second)
	for e.mirror.Status(context.Background(), false).State == StateReady && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	e.mirror.Close()
	before := f.Count("AuditEvent")
	ids := journalIDs(t, e.dir)
	if before >= len(ids) {
		t.Fatalf("crash did not interrupt the feed (%d of %d)", before, len(ids))
	}
	cb.left.Store(1 << 40)
	m2 := e.startMirror(cb, nil)
	defer m2.Close()
	syncMirror(t, m2)
	if got := f.Count("AuditEvent"); got != len(ids) {
		t.Fatalf("after restart %d audit events, journal has %d", got, len(ids))
	}
	for _, id := range ids {
		if f.Node("AuditEvent", id) == nil {
			t.Fatalf("gap: %s", id)
		}
	}
	rels := f.RelCount()
	cp := m2.Status(context.Background(), false).Checkpoint
	if cp.Segment < 12 || cp.Events < 550 {
		t.Fatalf("checkpoint %+v", cp)
	}
	// Re-applying the whole journal (rebuild) yields the same graph.
	if err := m2.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.Count("AuditEvent") != len(ids) || f.RelCount() != rels {
		t.Fatalf("rebuild changed the graph: %d events %d rels (was %d)", f.Count("AuditEvent"), f.RelCount(), rels)
	}
}

func TestUnavailableGraphNeverBlocksOrFailsEvidence(t *testing.T) {
	// FR-9 and FR-9.17 (graph part): with the database hung, then failing,
	// every journal commit returns at once and without error; the mirror
	// reports unavailable and, once the database is back, catches up from
	// the journal. The end-to-end variant with tool calls is in
	// internal/e2e (TestGraphMirrorDownDoesNotAffectCalls).
	reqtest.Partial(t, "FR-9", "FR-9.17")
	f := NewFake()
	e := newEnv(t, f, 200, func(c *config.Config) { c.Graph.Queue = 16; c.Graph.BatchSize = 8 }, nil)
	waitReady(t, e.mirror)
	f.Block()
	start := time.Now()
	var slowest time.Duration
	for i := 0; i < 150; i++ {
		t0 := time.Now()
		e.commit(callEvents(i, "s1", "cc")...)
		slowest = max(slowest, time.Since(t0))
	}
	if total := time.Since(start); total > 20*time.Second || slowest > 2*time.Second {
		t.Fatalf("commits slowed by the graph: total %v, slowest call %v", total, slowest)
	}
	f.Unblock()
	f.Fail(ErrUnavailable)
	e.commit(callEvents(1000, "s1", "cc")...)
	deadline := time.Now().Add(5 * time.Second)
	for e.mirror.Status(context.Background(), false).State == StateReady && time.Now().Before(deadline) {
		e.commit(callEvents(1001, "s1", "cc")...)
		time.Sleep(20 * time.Millisecond)
	}
	if st := e.mirror.Status(context.Background(), false); st.State == StateReady {
		t.Fatalf("mirror still ready: %+v", st)
	}
	f.Fail(nil)
	syncMirror(t, e.mirror)
	if got, want := f.Count("AuditEvent"), len(journalIDs(t, e.dir)); got != want {
		t.Fatalf("after recovery %d of %d events", got, want)
	}
	if e.mirror.Status(context.Background(), false).LiveDropped == 0 && e.fanout.Dropped()["graph"] == 0 {
		t.Log("no drops observed (queue kept up)")
	}
}

func TestRetentionDeletesExpiredMirrorRecordsOnly(t *testing.T) {
	// FR-9.14 asks for observation and research data, which live in E-27;
	// this is the graph mirror's retention: expired events and the calls,
	// decisions and sessions only they referenced go, revisions and
	// principals stay (SR-6.14-1), and a rebuild does not bring them back.
	reqtest.Partial(t, "FR-9.14", "SR-6.14-1")
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	f := NewFake()
	e := newEnv(t, f, 1000, func(c *config.Config) { c.Graph.Retention = config.Duration{Duration: 48 * time.Hour} }, clock)
	old := now.Add(-72 * time.Hour).UTC().Format(time.RFC3339Nano)
	for _, ev := range callEvents(1, "old-session", "cc") {
		ev.Time = old
		e.commit(ev)
	}
	e.commit(callEvents(2, "s1", "cc")...)
	syncMirror(t, e.mirror)
	if f.Count("Invocation") != 1 || f.Node("Invocation", "corr-2") == nil {
		t.Fatalf("expired events were mirrored: %d invocations", f.Count("Invocation"))
	}
	// Age the mirror: move the clock so that call 2 expires too.
	mu.Lock()
	now = now.Add(72 * time.Hour)
	mu.Unlock()
	if err := e.mirror.RunRetention(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"AuditEvent", "Invocation", "Decision", "Session"} {
		if n := f.Count(l); n != 0 {
			t.Errorf("%s: %d left after retention", l, n)
		}
	}
	for _, l := range []string{"PolicyRevision", "ServerRevision", "ToolRevision", "Principal"} {
		if f.Count(l) == 0 {
			t.Errorf("%s deleted by retention", l)
		}
	}
	st := e.mirror.Status(context.Background(), false)
	if st.LastRetention == "" || st.RetentionDeleted["AuditEvent"] != 5 {
		t.Fatalf("%+v", st)
	}
	if err := e.mirror.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.Count("AuditEvent") != 0 {
		t.Fatal("rebuild resurrected expired events")
	}
}

func TestEngineCheckAndMemorySampling(t *testing.T) {
	// SR-7.4-1, SR-4.2-1, FR-9.10, FR-9.11 (graph engine part): the
	// effective settings are checked at connect, findings are reported and
	// refuse the mirror when require_hardening is set; the heap is sampled
	// on the memory interval and pressure is flagged above 90% of the
	// CP-33 heap budget. The firewall rules, the page-cache measurement
	// and the other budgeted components are not covered.
	reqtest.Partial(t, "SR-7.4-1", "SR-4.2-1", "FR-9.10", "FR-9.11")
	good := NewFake().Settings
	if f := CheckSettings(good, Budget{HeapBytes: 1 << 30, PageCacheBytes: 1 << 30}); len(f) != 0 {
		t.Fatalf("%+v", f)
	}
	bad := map[string]string{"server.http.enabled": "true", "server.https.enabled": "false", "dbms.usage_report.enabled": "true",
		"dbms.security.allow_csv_import_from_file_urls": "true", "dbms.security.procedures.unrestricted": "apoc.*",
		"server.bolt.listen_address": "0.0.0.0:7687", "server.default_listen_address": "0.0.0.0",
		"server.memory.heap.max_size": "4.00GiB", "server.memory.pagecache.size": "2g"}
	got := map[string]bool{}
	for _, f := range CheckSettings(bad, Budget{HeapBytes: 1 << 30, PageCacheBytes: 1 << 30}) {
		got[f.Setting] = true
	}
	for name := range bad {
		if name != "server.https.enabled" && !got[name] {
			t.Errorf("%s not reported", name)
		}
	}
	for v, want := range map[string]int64{"512.00MiB": 512 << 20, "1g": 1 << 30, "1073741824": 1 << 30, "": 0, "2.5k": 2560} {
		if n, err := ParseSize(v); err != nil || n != want {
			t.Errorf("ParseSize(%q) = %d, %v", v, n, err)
		}
	}
	if _, err := ParseSize("12 parsecs"); err == nil {
		t.Error("bad unit accepted")
	}
	conf := EngineConfig(Budget{HeapBytes: 1 << 30, PageCacheBytes: 512 << 20}, 0)
	for _, l := range []string{"server.http.enabled=false", "server.memory.heap.max_size=1g", "server.memory.pagecache.size=512m",
		"server.bolt.listen_address=127.0.0.1:7687", "dbms.usage_report.enabled=false"} {
		if !strings.Contains(conf, l+"\n") {
			t.Errorf("engine config lacks %s", l)
		}
	}

	f := NewFake()
	f.Settings["server.http.enabled"] = "true"
	e := newEnv(t, f, 1000, func(c *config.Config) { c.Graph.RequireHardening = true }, nil)
	deadline := time.Now().Add(5 * time.Second)
	for e.mirror.Status(context.Background(), false).State != StateRefused && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := e.mirror.Status(context.Background(), false); st.State != StateRefused || len(st.Hardening) != 1 {
		t.Fatalf("%+v", st)
	}

	f2 := NewFake()
	f2.Heap["used"] = 980 << 20
	e2 := newEnv(t, f2, 1000, func(c *config.Config) { c.Graph.MemoryInterval = config.Duration{Duration: 100 * time.Millisecond} }, nil)
	waitReady(t, e2.mirror)
	deadline = time.Now().Add(5 * time.Second)
	for !e2.mirror.Status(context.Background(), false).Memory.Pressure && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	st := e2.mirror.Status(context.Background(), false)
	if !st.Memory.Pressure || st.Memory.HeapUsed != 980<<20 || st.Memory.Budget.HeapBytes != DefaultHeapBytes || st.Memory.PageCacheConfigured != 512<<20 {
		t.Fatalf("%+v", st.Memory)
	}
}

func TestResolveDefaultsAndBounds(t *testing.T) {
	cfg := &config.Config{State: config.State{Dir: "/var/lib/smcp"}}
	s, err := Resolve(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled || s.URI != DefaultURI || s.PasswordFile != "/var/lib/smcp/graph/password" || s.Retention != DefaultRetention ||
		s.RetentionInterval != 24*time.Hour || s.MemoryInterval != 5*time.Second || s.Budget.HeapBytes != 1<<30 {
		t.Fatalf("%+v", s)
	}
	cfg.Graph.RetentionInterval = config.Duration{Duration: 48 * time.Hour}
	if _, err := Resolve(cfg); err == nil {
		t.Fatal("retention interval above one day accepted")
	}
	// A disabled mirror ignores events and answers ErrDisabled.
	m, err := New(Options{Config: &config.Config{State: config.State{Dir: t.TempDir()}}, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	m.Start(context.Background(), nil)
	m.Observe(audit.Event{EventID: "x"})
	if _, err := m.DAS(); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if err := m.Sync(context.Background()); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	m.Close()
}

func TestPasswordFileMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/pw"
	if err := os.WriteFile(p, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassword(p); err == nil {
		t.Fatal("world-readable password file accepted")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if pw, err := readPassword(p); err != nil || pw != "secret" {
		t.Fatalf("%q %v", pw, err)
	}
}
