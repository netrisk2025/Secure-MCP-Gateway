package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type fakeNotifier struct {
	mu    sync.Mutex
	texts []string
	at    []time.Time
}

func (f *fakeNotifier) Notify(_ context.Context, title, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.texts = append(f.texts, title+"\n"+body)
	f.at = append(f.at, time.Now())
	return nil
}

func (f *fakeNotifier) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.texts...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fixture struct {
	svc   *Service
	mem   *audit.Memory
	notes *fakeNotifier
	dir   string
	cfg   *config.Config
}

func newFixture(t *testing.T, mut func(*config.Config, *Options)) *fixture {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{State: config.State{Dir: dir}, AdminListener: config.AdminListener{Address: "127.0.0.1:8444"}}
	cfg.Approvals.KeepAlive.Duration = 20 * time.Millisecond
	f := &fixture{mem: &audit.Memory{}, notes: &fakeNotifier{}, dir: dir, cfg: cfg}
	o := Options{Config: cfg, Log: diag.Discard(), Notifier: f.notes, JanitorInterval: 10 * time.Millisecond}
	if mut != nil {
		mut(cfg, &o)
	}
	svc, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); svc.Close() })
	svc.Start(ctx, f.mem, nil, nil)
	f.svc = svc
	return f
}

func call(session, corr string) pipeline.Call {
	return pipeline.Call{CorrelationID: corr, SessionID: session, PrincipalID: "cc", Template: "ap", Server: "fs", Tool: "write_file",
		PublicName: "fs_write_file", ServerRevision: "sr1", ToolRevision: "tr1", PolicyRevision: "r1", DecisionID: "d-" + corr,
		DecisiveRules: []string{"ap-write"}, ManifestSource: "live"}
}

func args(s string) json.RawMessage { return json.RawMessage(s) }

// waitPending waits until n approvals are pending and returns the newest.
func (f *fixture) waitPending(t *testing.T, n int) Summary {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if l := f.svc.List(StatePending); len(l) >= n {
			return l[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pending approval: %+v", f.svc.List("all"))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fixture) outcomes(id string) []string {
	var out []string
	for _, e := range f.mem.Events() {
		if d, ok := e.Detail.(map[string]any); ok && e.Class == "approval" && d["approval_id"] == id {
			out = append(out, e.Outcome)
		}
	}
	return out
}

type result struct {
	res pipeline.ApprovalResult
	err error
}

func (f *fixture) request(c pipeline.Call, a json.RawMessage, hold time.Duration, progress func(string)) <-chan result {
	ch := make(chan result, 1)
	go func() {
		r, err := f.svc.Request(context.Background(), pipeline.ApprovalRequest{Call: c, Arguments: a, Hold: hold, Progress: progress})
		ch <- result{r, err}
	}()
	return ch
}

func TestCanonicalDigest(t *testing.T) {
	reqtest.Partial(t, "SR-1.18-2")
	a, da, err := Canonical(args(`{ "b": [1, 2.50, {"y": true, "x": null}], "a": "<p>" }`))
	if err != nil {
		t.Fatal(err)
	}
	_, db, _ := Canonical(args(`{"a":"<p>","b":[1,2.50,{"x":null,"y":true}]}`))
	if string(a) != `{"a":"<p>","b":[1,2.50,{"x":null,"y":true}]}` || da != db || !strings.HasPrefix(da, "sha256:") {
		t.Fatalf("%s %s %s", a, da, db)
	}
	if _, dc, _ := Canonical(args(`{"a":"<p>","b":[1,2.5,{"x":null,"y":true}]}`)); dc == da {
		t.Fatal("a different number literal produced the same digest")
	}
	e1, d1, _ := Canonical(nil)
	_, d2, _ := Canonical(args(`null`))
	if string(e1) != "{}" || d1 != d2 {
		t.Fatalf("%s %s %s", e1, d1, d2)
	}
	if _, _, err := Canonical(args(`{"a":1} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestHoldApprovedContinuesAndConsumes(t *testing.T) {
	// FR-3.14 needs G-13 (console) visibility, which another element
	// provides; FR-3.19 needs the edge's wire form (e2e test).
	reqtest.Partial(t, "FR-3.14", "FR-3.17", "FR-3.19", "FR-3.20")
	f := newFixture(t, nil)
	var keepalives atomic.Int32
	ch := f.request(call("s1", "c1"), args(`{"path":"/tmp/x","data":"secret-value-123"}`), 5*time.Second, func(string) { keepalives.Add(1) })
	p := f.waitPending(t, 1)
	time.Sleep(80 * time.Millisecond) // several keep-alive intervals
	select {
	case r := <-ch:
		t.Fatalf("held call answered before a decision: %+v", r)
	default:
	}
	rec, _ := f.svc.Get(p.ID)
	if rec.State != StatePending || rec.PublicName != "fs_write_file" || rec.ArgumentsDigest == "" || string(rec.Arguments) != `{"data":"secret-value-123","path":"/tmp/x"}` ||
		rec.URL != "https://127.0.0.1:8444/approvals/"+p.ID || rec.ExpiresAt.Sub(rec.CreatedAt) != DefaultLifetime || rec.DecisiveRules[0] != "ap-write" {
		t.Fatalf("%+v", rec)
	}
	if err := f.svc.Decide(context.Background(), p.ID, true, "admin:admin", "looks fine"); err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil || r.res.Outcome != pipeline.Approved || r.res.ApprovalID != p.ID || r.res.Approver != "admin:admin" {
		t.Fatalf("%+v", r)
	}
	if n := keepalives.Load(); n < 3 {
		t.Fatalf("%d keep-alives", n)
	}
	rec, _ = f.svc.Get(p.ID)
	if rec.State != StateConsumed || rec.DecidedBy != "admin:admin" || rec.Comment != "looks fine" || rec.DecidedAt == nil || rec.ConsumedCorrelation != "c1" {
		t.Fatalf("%+v", rec)
	}
	if got := strings.Join(f.outcomes(p.ID), ","); got != "requested,approved,consumed" {
		t.Fatalf("evidence %s", got)
	}
	for _, e := range f.mem.Events() {
		if b, _ := json.Marshal(e); bytes.Contains(b, []byte("secret-value-123")) {
			t.Fatalf("argument value in evidence: %s", b)
		}
	}
	// A second identical call needs a new approval.
	r2 := <-f.request(call("s1", "c2"), args(`{"path":"/tmp/x","data":"secret-value-123"}`), 0, nil)
	if r2.res.Outcome != pipeline.Pending || r2.res.ApprovalID == p.ID || r2.res.ApprovalID == "" {
		t.Fatalf("%+v", r2)
	}
}

func TestDenyDuringHold(t *testing.T) {
	reqtest.Partial(t, "FR-3.21", "FR-3.17")
	f := newFixture(t, nil)
	ch := f.request(call("s1", "c1"), args(`{}`), 5*time.Second, nil)
	p := f.waitPending(t, 1)
	if err := f.svc.Decide(context.Background(), p.ID, false, "approver:alice", "no"); err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.res.Outcome != pipeline.Denied || r.res.ReasonCode != ReasonDenied || r.res.Approver != "approver:alice" {
		t.Fatalf("%+v", r)
	}
	if err := f.svc.Decide(context.Background(), p.ID, true, "approver:alice", ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("decided twice: %v", err)
	}
	if err := f.svc.Decide(context.Background(), "nope", true, "x", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if got := strings.Join(f.outcomes(p.ID), ","); got != "requested,denied" {
		t.Fatalf("evidence %s", got)
	}
}

func TestHoldBoundFallbackAndRetry(t *testing.T) {
	reqtest.Partial(t, "FR-3.15", "FR-3.22", "SR-1.18-2")
	f := newFixture(t, nil)
	a := args(`{"path":"/a"}`)
	r := <-f.request(call("s1", "c1"), a, 60*time.Millisecond, nil)
	if r.err != nil || r.res.Outcome != pipeline.Pending || r.res.ReasonCode != ReasonRequired || r.res.ApprovalID == "" ||
		r.res.ConsoleURL != f.svc.URL(r.res.ApprovalID) || r.res.ExpiresAt.IsZero() || !strings.Contains(r.res.RetryText, r.res.ConsoleURL) {
		t.Fatalf("%+v", r)
	}
	id := r.res.ApprovalID
	if rec, _ := f.svc.Get(id); rec.State != StatePending {
		t.Fatalf("approval not kept pending after the bound: %+v", rec)
	}
	// A retry while still pending attaches to the same approval.
	if r := <-f.request(call("s1", "c1b"), a, 0, nil); r.res.ApprovalID != id {
		t.Fatalf("retry while pending made a new approval: %+v", r)
	}
	if err := f.svc.Decide(context.Background(), id, true, "operator-token", ""); err != nil {
		t.Fatal(err)
	}
	// Binding: another session, other arguments or another policy revision
	// do not consume the approval.
	other := call("s2", "c2")
	if r := <-f.request(other, a, 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id {
		t.Fatalf("other session consumed: %+v", r)
	}
	if r := <-f.request(call("s1", "c3"), args(`{"path":"/b"}`), 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id {
		t.Fatalf("other arguments consumed: %+v", r)
	}
	rev := call("s1", "c4")
	rev.PolicyRevision = "r2"
	if r := <-f.request(rev, a, 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id {
		t.Fatalf("other policy revision consumed: %+v", r)
	}
	rev = call("s1", "c4b")
	rev.ToolRevision = "tr2"
	if r := <-f.request(rev, a, 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id {
		t.Fatalf("other tool revision consumed: %+v", r)
	}
	// The identical retry consumes it (whitespace and key order do not
	// matter), once.
	if r := <-f.request(call("s1", "c5"), args(` { "path" : "/a" } `), 0, nil); r.res.Outcome != pipeline.Approved || r.res.ApprovalID != id {
		t.Fatalf("retry not approved: %+v", r)
	}
	if r := <-f.request(call("s1", "c6"), a, 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id {
		t.Fatalf("replay consumed the approval again: %+v", r)
	}
}

func TestExpiry(t *testing.T) {
	reqtest.Partial(t, "SR-1.18-2", "FR-3.16")
	c := &clock{t: time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC)}
	f := newFixture(t, func(_ *config.Config, o *Options) { o.Now = c.now })
	r := <-f.request(call("s1", "c1"), nil, 0, nil)
	id := r.res.ApprovalID
	if !r.res.ExpiresAt.Equal(c.now().Add(5 * time.Minute)) {
		t.Fatalf("expiry %v", r.res.ExpiresAt)
	}
	c.add(5*time.Minute + time.Second)
	f.svc.Expire()
	if rec, _ := f.svc.Get(id); rec.State != StateExpired {
		t.Fatalf("%+v", rec)
	}
	if err := f.svc.Decide(context.Background(), id, true, "admin:admin", ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("expired approval decided: %v", err)
	}
	// An approved but unused approval expires too.
	r = <-f.request(call("s1", "c2"), nil, 0, nil)
	if r.res.ApprovalID == id {
		t.Fatal("expired approval reused")
	}
	id2 := r.res.ApprovalID
	if err := f.svc.Decide(context.Background(), id2, true, "admin:admin", ""); err != nil {
		t.Fatal(err)
	}
	c.add(6 * time.Minute)
	if r := <-f.request(call("s1", "c3"), nil, 0, nil); r.res.Outcome != pipeline.Pending || r.res.ApprovalID == id2 {
		t.Fatalf("expired approval consumed: %+v", r)
	}
	if got := strings.Join(f.outcomes(id2), ","); got != "requested,approved,expired" {
		t.Fatalf("evidence %s", got)
	}
	// Records past retention are pruned from memory and disk.
	c.add(Retention + time.Hour)
	f.svc.Expire()
	if _, ok := f.svc.Get(id); ok {
		t.Fatal("not pruned")
	}
	if _, err := os.Stat(filepath.Join(f.dir, StoreDir, id+".json")); !os.IsNotExist(err) {
		t.Fatalf("record file not pruned: %v", err)
	}
}

func TestExpiryDuringHold(t *testing.T) {
	f := newFixture(t, func(cfg *config.Config, _ *Options) { cfg.Approvals.Lifetime.Duration = time.Second })
	r := <-f.request(call("s1", "c1"), nil, 10*time.Second, nil)
	if r.res.Outcome != pipeline.Pending || r.res.ReasonCode != ReasonExpired {
		t.Fatalf("%+v", r)
	}
}

func TestRecordsSurviveRestart(t *testing.T) {
	reqtest.Partial(t, "FR-3.22")
	f := newFixture(t, nil)
	r := <-f.request(call("s1", "c1"), args(`{"k":1}`), 0, nil)
	id := r.res.ApprovalID
	if err := f.svc.Decide(context.Background(), id, true, "admin:admin", ""); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(f.dir, StoreDir, id+".json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("record file %v %v", st, err)
	}
	// A second service over the same state directory.
	svc2, err := New(Options{Config: f.cfg, Log: diag.Discard(), Notifier: Off{}})
	if err != nil {
		t.Fatal(err)
	}
	svc2.Start(t.Context(), f.mem, nil, nil)
	r2, err := svc2.Request(context.Background(), pipeline.ApprovalRequest{Call: call("s1", "c2"), Arguments: args(`{"k":1}`)})
	if err != nil || r2.Outcome != pipeline.Approved || r2.ApprovalID != id {
		t.Fatalf("%+v %v", r2, err)
	}
	// A corrupt record file is skipped.
	if err := os.WriteFile(filepath.Join(f.dir, StoreDir, "00000000-0000-0000-0000-000000000000.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Config: f.cfg, Log: diag.Discard(), Notifier: Off{}}); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopNotification(t *testing.T) {
	// G-13 (console) delivery is another element's; this covers the
	// watch stream and the desktop notifier.
	reqtest.Partial(t, "FR-3.23")
	f := newFixture(t, nil)
	ch, cancel := f.svc.Watch()
	defer cancel()
	start := time.Now()
	r := <-f.request(call("s1", "c1"), args(`{"path":"/etc/passwd","token":"hunter2-value"}`), 0, nil)
	select {
	case n := <-ch:
		if n.Type != "requested" || n.Approval.ID != r.res.ApprovalID {
			t.Fatalf("%+v", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no watch notice within 2 s")
	}
	f.svc.Close() // wait for the notifier goroutine
	texts := f.notes.all()
	if len(texts) != 1 || f.notes.at[0].Sub(start) > 2*time.Second {
		t.Fatalf("%v", texts)
	}
	txt := texts[0]
	for _, want := range []string{"fs_write_file", "fs", r.res.ApprovalID, f.svc.URL(r.res.ApprovalID)} {
		if !strings.Contains(txt, want) {
			t.Fatalf("notification %q lacks %q", txt, want)
		}
	}
	for _, leak := range []string{"/etc/passwd", "hunter2", "path", "token"} {
		if strings.Contains(txt, leak) {
			t.Fatalf("notification %q contains argument content %q", txt, leak)
		}
	}
}

func TestMissingNotifierBinary(t *testing.T) {
	reqtest.Partial(t, "FR-3.23")
	dir := t.TempDir()
	out := filepath.Join(dir, "notified.txt")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(notifierOutEnv, out)
	var logs bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(lockedWriter{&logs, &logMu}, nil))
	f := newFixture(t, func(cfg *config.Config, o *Options) {
		cfg.Approvals.Notify, cfg.Approvals.NotifyCommand = "command", exe
		o.Notifier, o.Log = nil, log
	})
	r := <-f.request(call("s1", "c1"), args(`{"v":"argument-value"}`), 0, nil)
	f.svc.Close() // waits for the notifier process
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), r.res.ApprovalID) || strings.Contains(string(b), "argument-value") {
		t.Fatalf("command notifier output %q %v", b, err)
	}
	// A notifier program that does not exist: approvals still work and a
	// warning is logged.
	f2 := newFixture(t, func(cfg *config.Config, o *Options) {
		cfg.Approvals.Notify, cfg.Approvals.NotifyCommand = "command", filepath.Join(dir, "no-such-notifier")
		o.Notifier, o.Log = nil, log
	})
	r = <-f2.request(call("s1", "c2"), args(`{"v":2}`), 0, nil)
	if r.err != nil || r.res.Outcome != pipeline.Pending {
		t.Fatalf("%+v", r)
	}
	if err := f2.svc.Decide(context.Background(), r.res.ApprovalID, true, "admin:admin", ""); err != nil {
		t.Fatal(err)
	}
	f2.svc.Close()
	logMu.Lock()
	defer logMu.Unlock()
	if !strings.Contains(logs.String(), "desktop notification failed") {
		t.Fatalf("no warning: %s", logs.String())
	}
}

type lockedWriter struct {
	b  *bytes.Buffer
	mu *sync.Mutex
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func TestFailClosed(t *testing.T) {
	cfg := &config.Config{State: config.State{Dir: t.TempDir()}}
	svc, err := New(Options{Config: cfg, Notifier: Off{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Request(context.Background(), pipeline.ApprovalRequest{Call: call("s", "c")}); !errors.Is(err, ErrNotAttached) {
		t.Fatalf("request before Start: %v", err)
	}
	f := newFixture(t, nil)
	r := <-f.request(call("s1", "c1"), nil, 0, nil)
	f.mem.Fail(errors.New("disk full"))
	if err := f.svc.Decide(context.Background(), r.res.ApprovalID, true, "admin:admin", ""); !errors.Is(err, ErrAudit) {
		t.Fatalf("decision without evidence: %v", err)
	}
	if rec, _ := f.svc.Get(r.res.ApprovalID); rec.State != StatePending {
		t.Fatalf("state changed without evidence: %+v", rec)
	}
	if r := <-f.request(call("s1", "c2"), args(`{"x":1}`), 0, nil); !errors.Is(r.err, ErrAudit) {
		t.Fatalf("approval created without evidence: %+v", r)
	}
	if _, _, err := Canonical(args(`{`)); err == nil {
		t.Fatal("bad JSON")
	}
}

func TestOptionsValidation(t *testing.T) {
	cfg := &config.Config{State: config.State{Dir: t.TempDir()}}
	cfg.Approvals.Lifetime.Duration = 6 * time.Minute
	if _, err := New(Options{Config: cfg, Notifier: Off{}}); err == nil {
		t.Fatal("lifetime above CP-17 accepted")
	}
	cfg.Approvals.Lifetime.Duration = 0
	cfg.Approvals.Notify = "command"
	if _, err := New(Options{Config: cfg}); err == nil {
		t.Fatal("command notifier without a command accepted")
	}
	cfg.Approvals.Notify = "bogus"
	if _, err := New(Options{Config: cfg}); err == nil {
		t.Fatal("unknown notifier accepted")
	}
	for _, m := range []string{"auto", "off", "osascript", "terminal-notifier", "notify-send"} {
		if n, err := NewNotifier(m, ""); err != nil || n == nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	if got := appleScriptString(`a"b\c`); got != `"a\"b\\c"` {
		t.Fatal(got)
	}
	cfg.Approvals.Notify = ""
	cfg.Approvals.Accounts = []config.ApproverAccount{{Username: "a"}, {Username: "a"}}
	if _, err := New(Options{Config: cfg, Notifier: Off{}}); err == nil {
		t.Fatal("duplicate account accepted")
	}
}
