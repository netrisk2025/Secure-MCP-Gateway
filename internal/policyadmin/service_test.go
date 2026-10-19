package policyadmin

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const doc1 = `{"revision": "r1", "framework_profiles": {"dev": {"templates": ["ro"], "default_template": "ro"}},
  "templates": {"ro": {"rules": [{"id": "ro-fs", "server": "fs", "tools": ["read_file", "list"]}, {"id": "no", "effect": "deny", "server": "fs", "tools": ["list"]}]}}}`

func rev(id string) []byte { return []byte(strings.Replace(doc1, `"r1"`, `"`+id+`"`, 1)) }

// fakeGW stands in for the Gateway: it keeps the active snapshot like the
// decider and can be told to fail activation.
type fakeGW struct {
	mu   sync.Mutex
	d    *policy.Decider
	fail error
	acts int
}

func (f *fakeGW) Health() edge.Health        { return edge.Health{State: "healthy"} }
func (f *fakeGW) Stop(string, string) error  { return nil }
func (f *fakeGW) Resume(string) error        { return nil }
func (f *fakeGW) snapshot() *policy.Snapshot { return f.d.Snapshot() }
func (f *fakeGW) setFail(err error)          { f.mu.Lock(); f.fail = err; f.mu.Unlock() }
func (f *fakeGW) activations() int           { f.mu.Lock(); defer f.mu.Unlock(); return f.acts }
func (f *fakeGW) ActivatePolicy(_ string, s *policy.Snapshot) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return false, f.fail
	}
	f.acts++
	return f.d.Replace(s)
}

type fixture struct {
	dir   string
	store *policystore.Store
	gw    *fakeGW
	ev    *audit.Memory
	svc   *Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	pf := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pf, rev("r1"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := policystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap, imported, fault, err := Load(st, pf)
	if err != nil || fault != "" || imported == nil || imported.Origin != "import" || snap.Revision != "r1" {
		t.Fatalf("first load: %v %q %+v", err, fault, imported)
	}
	gw := &fakeGW{d: policy.NewDecider(snap, 60)}
	ev := &audit.Memory{}
	svc := New(Options{Store: st, Evidence: ev, Active: gw.snapshot, DefaultRate: 60})
	svc.Bind(gw)
	svc.Started(imported, nil)
	return &fixture{dir: dir, store: st, gw: gw, ev: ev, svc: svc}
}

func (f *fixture) reasons() []string {
	var out []string
	for _, e := range f.ev.Events() {
		out = append(out, e.ReasonCode)
	}
	return out
}

func TestLoadImportsOnceThenUsesTheStore(t *testing.T) {
	reqtest.Partial(t, "SR-1.1-1")
	f := newFixture(t)
	// The file changes on disk; the store, not the file, is the authority.
	pf := filepath.Join(f.dir, "policy.json")
	if err := os.WriteFile(pf, rev("r9"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, _ := policystore.Open(f.dir)
	snap, imported, fault, err := Load(st, pf)
	if err != nil || imported != nil || fault != "" || snap.Revision != "r1" {
		t.Fatalf("second load: %v %+v %q", err, imported, fault)
	}
	// An invalid file is refused at first start.
	empty := t.TempDir()
	bad := filepath.Join(empty, "p.json")
	os.WriteFile(bad, []byte(`{"revision": "x"}`), 0o644)
	st2, _ := policystore.Open(empty)
	if _, _, fault, err := Load(st2, bad); err == nil || fault != "" {
		t.Fatalf("invalid first policy: %v %q", err, fault)
	}
	// A tampered active revision: no snapshot, fault policy_signature.
	files, _ := filepath.Glob(filepath.Join(f.dir, policystore.RevisionsDir, "*.json"))
	os.Chmod(files[0], 0o644)
	raw, _ := os.ReadFile(files[0])
	os.WriteFile(files[0], []byte(strings.Replace(string(raw), "read_file", "write_file", 1)), 0o644)
	st3, _ := policystore.Open(f.dir)
	snap, _, fault, err = Load(st3, pf)
	if snap != nil || fault != FaultSignature || !errors.Is(err, policystore.ErrIntegrity) {
		t.Fatalf("tampered: %v %q %v", snap, fault, err)
	}
	svc := New(Options{Store: st3, Evidence: f.ev, Active: func() *policy.Snapshot { return nil }, Fault: fault})
	svc.Started(nil, err)
	if svc.Fault() != FaultSignature || f.reasons()[len(f.reasons())-1] != ReasonIntegrity {
		t.Fatalf("%q %v", svc.Fault(), f.reasons())
	}
}

func TestPublishOrderAndFailures(t *testing.T) {
	reqtest.Partial(t, "SR-1.15-1", "SR-1.14-1")
	f := newFixture(t)
	if _, err := f.svc.Publish([]byte(`{"revision": "x"}`), PublishOptions{Actor: "a"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	res, err := f.svc.Publish(rev("r2"), PublishOptions{Actor: "admin:alice", Parent: "r1"})
	if err != nil || !res.Created || !res.Changed || res.Record.Parent != "r1" || f.gw.snapshot().Revision != "r2" {
		t.Fatalf("%+v %v", res, err)
	}
	if _, ctl, _ := f.store.Active(); ctl.Revision != "r2" {
		t.Fatalf("control record: %+v", ctl)
	}
	want := []string{ReasonImported, ReasonInvalid, ReasonPublished}
	if got := f.reasons(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("evidence: %v", got)
	}
	// Stale parent.
	if _, err := f.svc.Publish(rev("r3"), PublishOptions{Actor: "a", Parent: "r1"}); !errors.Is(err, ErrParentMismatch) {
		t.Fatalf("stale parent: %v", err)
	}
	// Activation fails after the pointer moved: the pointer is restored and
	// the decider keeps r2.
	f.gw.setFail(errors.New("barrier says no"))
	if _, err := f.svc.Publish(rev("r3"), PublishOptions{Actor: "a"}); !errors.Is(err, ErrActivation) {
		t.Fatalf("activation failure: %v", err)
	}
	if act, _, _ := f.store.Active(); act.Record.Revision != "r2" || f.gw.snapshot().Revision != "r2" {
		t.Fatalf("after failed activation: %s %s", act.Record.Revision, f.gw.snapshot().Revision)
	}
	f.gw.setFail(nil)
	// r3 is now published but not active; republishing it is refused.
	if _, err := f.svc.Publish(rev("r3"), PublishOptions{Actor: "a"}); !errors.Is(err, ErrPublished) {
		t.Fatalf("republish inactive: %v", err)
	}
	// Reload maps the conflict to ErrRevisionReused (409 on the reload route).
	r3, _ := policy.Compile(rev("r3"))
	if _, err := f.svc.ActivatePolicy("a", r3); !errors.Is(err, policy.ErrRevisionReused) {
		t.Fatalf("reload conflict: %v", err)
	}
	// Reloading the active content is a no-op.
	r2, _ := policy.Compile(rev("r2"))
	if changed, err := f.svc.ActivatePolicy("a", r2); err != nil || changed {
		t.Fatalf("reload same: %v %v", changed, err)
	}
	// The evidence journal failing stops a publication before activation.
	n := f.gw.activations()
	f.ev.Fail(errors.New("disk full"))
	if _, err := f.svc.Publish(rev("r4"), PublishOptions{Actor: "a"}); !errors.Is(err, ErrAudit) {
		t.Fatalf("audit failure: %v", err)
	}
	if f.gw.activations() != n || f.gw.snapshot().Revision != "r2" {
		t.Fatal("activated without evidence")
	}
}

func TestRollback(t *testing.T) {
	reqtest.Verifies(t, "FR-3.9")
	f := newFixture(t)
	if _, err := f.svc.Publish(rev("r2"), PublishOptions{Actor: "a"}); err != nil {
		t.Fatal(err)
	}
	if id := f.svc.RollbackID("r1"); id != "r1-rb1" {
		t.Fatal(id)
	}
	res, err := f.svc.Rollback("r1", "", "admin:bob")
	if err != nil || res.Record.Revision != "r1-rb1" || res.Record.RollbackOf != "r1" || res.Record.Origin != "rollback" || res.Record.Parent != "r2" {
		t.Fatalf("%+v %v", res, err)
	}
	old, _ := f.store.Get("r1")
	nw, _ := f.store.Get("r1-rb1")
	if strings.Replace(string(nw.Snapshot.Raw), `"r1-rb1"`, `"r1"`, 1) != string(old.Snapshot.Raw) {
		t.Fatalf("content differs:\n%s\n%s", nw.Snapshot.Raw, old.Snapshot.Raw)
	}
	if f.gw.snapshot().Revision != "r1-rb1" || f.svc.RollbackID("r1") != "r1-rb2" {
		t.Fatal("not active")
	}
	if f.reasons()[len(f.reasons())-1] != ReasonRolledBack {
		t.Fatal(f.reasons())
	}
	long := strings.Repeat("a", 63)
	if id := f.svc.RollbackID(long); len(id) != 64 || !strings.HasSuffix(id, "-rb1") {
		t.Fatal(id)
	}
	if _, err := f.svc.Rollback("r1", "bad id!", "a"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := f.svc.Rollback("zz", "", "a"); !errors.Is(err, policystore.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestJournalFixturesAndSimulation(t *testing.T) {
	reqtest.Partial(t, "FR-3.5")
	f := newFixture(t)
	jdir := filepath.Join(t.TempDir(), "journal")
	key, err := keys.LoadEvidenceKey(func() string { d := t.TempDir(); keys.Ensure(d, "127.0.0.1"); return d }())
	if err != nil {
		t.Fatal(err)
	}
	j, err := audit.Open(jdir, key, audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"read_file", "list", "write_file"} {
		j.Record(audit.Event{Class: "call", Phase: audit.PhaseRequested, Origin: "E-02", SessionID: "s", PrincipalID: "p",
			Detail: map[string]any{"server": "fs", "tool": tool, "template": "ro", "profile": "dev"}})
	}
	j.Record(audit.Event{Class: "call", Phase: audit.PhaseRequested, Origin: "E-02"}) // no detail: skipped
	j.Record(audit.Event{Class: "admin", Origin: "E-24"})
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	fx, err := JournalFixtures(jdir, 0)
	if err != nil || len(fx) != 3 || fx[0].Tool != "read_file" || fx[0].Time.IsZero() || fx[0].Profile != "dev" {
		t.Fatalf("%+v %v", fx, err)
	}
	if fx, _ := JournalFixtures(jdir, 2); len(fx) != 2 || fx[0].Tool != "list" {
		t.Fatalf("limit keeps the most recent: %+v", fx)
	}
	f.svc.o.JournalDir = jdir
	// The candidate drops the deny rule: list becomes permitted.
	cand := strings.Replace(strings.Replace(doc1, `"r1"`, `"r2"`, 1), `, {"id": "no", "effect": "deny", "server": "fs", "tools": ["list"]}`, ``, 1)
	res, err := f.svc.Simulate([]byte(cand), nil, 0, false, "a")
	if err != nil || res.Source != "journal" || res.Fixtures != 3 || res.Changed != 1 || res.Counts[policy.SimDenyToPermit] != 1 || res.SimulationID == "" {
		t.Fatalf("%+v %v", res, err)
	}
	if f.reasons()[len(f.reasons())-1] != ReasonSimulated {
		t.Fatal(f.reasons())
	}
	if _, err := f.svc.Simulate([]byte(`{}`), nil, 0, false, "a"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := JournalFixtures("", 0); err == nil {
		t.Fatal("no journal")
	}
}

func TestPermissionsAndErrorMapping(t *testing.T) {
	reqtest.Partial(t, "FR-3.6")
	f := newFixture(t)
	r, _ := f.store.Get("r1")
	perms := Permissions(r.Snapshot, "ro")
	if len(perms) != 1 || perms[0].Tool != "read_file" || perms[0].Rule != "ro-fs" {
		t.Fatalf("deny rules must be applied: %+v", perms)
	}
	for err, code := range map[error]int{
		ErrInvalid: 422, policystore.ErrRevisionExists: 409, ErrPublished: 409, ErrParentMismatch: 409, policystore.ErrNotFound: 404,
		policystore.ErrIntegrity: 422, policy.ErrNoFixtures: 422, ErrAudit: 503, ErrActivation: 503, errors.New("x"): 500,
	} {
		w := httptest.NewRecorder()
		writeErr(w, err)
		if w.Code != code {
			t.Errorf("%v: %d want %d", err, w.Code, code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policy/revisions/active/permissions?template=ro", nil)
	req.SetPathValue("id", "active")
	w := httptest.NewRecorder()
	f.svc.httpPermissions(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"read_file"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/policy/revisions/r1/permissions?template=zz", nil)
	req.SetPathValue("id", "r1")
	w = httptest.NewRecorder()
	f.svc.httpPermissions(w, req)
	if w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}

// TestCheckCurrency (FR-7.11): the snapshot in force is current after
// load and after each publication, also while publications run
// concurrently with the check; an altered control record or a control
// record naming another revision is reported.
func TestCheckCurrency(t *testing.T) {
	reqtest.Partial(t, "FR-7.11")
	f := newFixture(t)
	if c := f.svc.CheckCurrency(); c.Detail != "" {
		t.Fatalf("after load: %+v", c)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 2; i < 30; i++ {
			if _, err := f.svc.Publish(rev(fmt.Sprintf("r%d", i)), PublishOptions{Actor: "admin"}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		if c := f.svc.CheckCurrency(); c.Detail != "" {
			t.Fatalf("during publications: %+v", c)
		}
	}
	ctl := filepath.Join(f.dir, policystore.ControlFile)
	raw, _ := os.ReadFile(ctl)
	_ = os.WriteFile(ctl, []byte(strings.Replace(string(raw), "admin", "intruder", 1)), 0o600)
	if c := f.svc.CheckCurrency(); c.Detail == "" || !c.Integrity {
		t.Fatalf("altered control record: %+v", c)
	}
	_ = os.WriteFile(ctl, raw, 0o600)
	r1, err := f.store.Get("r1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Activate(r1, "intruder"); err != nil { // the store moved, the Gateway did not
		t.Fatal(err)
	}
	if c := f.svc.CheckCurrency(); !strings.Contains(c.Detail, "r1") || c.Integrity {
		t.Fatalf("control record naming another revision: %+v", c)
	}
}
