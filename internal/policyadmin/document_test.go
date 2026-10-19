package policyadmin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// docGrants is a revision with two templates and grants on two servers,
// used by the simulation and export tests.
const docGrants = `{"revision": "g1",
  "framework_profiles": {"dev": {"templates": ["ro", "ops"], "default_template": "ro"}},
  "templates": {
    "ro": {"rules": [{"id": "ro-fs", "server": "fs", "tools": ["read_file", "list_directory", "stat"]},
                     {"id": "ro-git", "server": "git", "tools": ["log", "diff"]}]},
    "ops": {"calls_per_minute": 600, "rules": [{"id": "ops-fs", "server": "fs", "tools": ["read_file", "write_file"], "approval": true}]}
  }}`

// scenario50 writes a 50-fixture JSON Lines scenario over both templates
// and every granted and some ungranted tools, two seconds apart.
func scenario50(t *testing.T) string {
	t.Helper()
	calls := []struct{ tmpl, server, tool string }{
		{"ro", "fs", "read_file"}, {"ro", "fs", "list_directory"}, {"ro", "fs", "stat"}, {"ro", "git", "log"},
		{"ro", "git", "diff"}, {"ro", "fs", "write_file"}, {"ops", "fs", "read_file"}, {"ops", "fs", "write_file"},
		{"ops", "fs", "stat"}, {"ro", "git", "push"},
	}
	var b bytes.Buffer
	base := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	for i := range 50 {
		c := calls[i%len(calls)]
		line, _ := json.Marshal(map[string]any{"time": base.Add(time.Duration(i) * 2 * time.Second), "principal": fmt.Sprintf("p%d", i%3),
			"session": fmt.Sprintf("s%d", i%5), "profile": "dev", "template": c.tmpl, "server": c.server, "tool": c.tool})
		b.Write(line)
		b.WriteByte('\n')
	}
	p := filepath.Join(t.TempDir(), "scenario.jsonl")
	if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadScenario(t *testing.T, path string) []policy.Fixture {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	fx, err := policy.ParseFixtures(fh)
	if err != nil || len(fx) != 50 {
		t.Fatalf("%d fixtures, %v", len(fx), err)
	}
	return fx
}

// grantsFixture is a service whose active revision is docGrants.
func grantsFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	if _, err := f.svc.Publish([]byte(docGrants), PublishOptions{Actor: "a"}); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestSchemaRejectsWithFieldMessages is FR-3.2: a document submitted for
// publication is validated against the versioned policy schema
// (policy.schema.json, SchemaVersion, recorded on every revision) before
// anything is stored. A missing field, a wrong type and an unknown
// enumeration value are each rejected with a message naming the field,
// and nothing reaches the store. The policy object types of release 1.0
// are the Framework Profiles and Session Allow Policy Templates of the
// document (the other FR-3.1 object types are listed in the gap list).
func TestSchemaRejectsWithFieldMessages(t *testing.T) {
	reqtest.Verifies(t, "FR-3.2")
	f := newFixture(t)
	stored := len(f.store.List())
	for _, c := range []struct{ name, doc, field, msg string }{
		{"missing field", strings.Replace(docGrants, `"id": "ro-git", "server": "git",`, `"id": "ro-git",`, 1), "/templates/ro/rules/1", "missing property 'server'"},
		{"wrong type", strings.Replace(docGrants, `"calls_per_minute": 600`, `"calls_per_minute": "600"`, 1), "/templates/ops/calls_per_minute", "want integer"},
		{"unknown enumeration value", strings.Replace(docGrants, `"default_template": "ro"`, `"default_template": "ro", "high_risk": ["quantum"]`, 1), "/framework_profiles/dev/high_risk/0", "must be one of"},
	} {
		_, err := f.svc.Publish([]byte(c.doc), PublishOptions{Actor: "a"})
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "at '"+c.field+"'") || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, verr := policy.Compile([]byte(c.doc)); verr == nil {
			t.Errorf("%s: compiles", c.name)
		}
	}
	if n := len(f.store.List()); n != stored {
		t.Fatalf("rejected documents reached the store: %d revisions, want %d", n, stored)
	}
	for _, r := range f.store.List() {
		if r.SchemaVersion != policy.SchemaVersion {
			t.Fatalf("revision %s records schema version %q", r.Revision, r.SchemaVersion)
		}
	}
}

// TestSimulationFiftyFixtures is FR-3.5: a stored 50-fixture scenario is
// replayed against a draft that removes one grant (stat from the ro
// template); the report gives each fixture's decision under the draft and
// under the active revision, and exactly the fixtures that call the
// removed grant report a changed decision.
func TestSimulationFiftyFixtures(t *testing.T) {
	reqtest.Verifies(t, "FR-3.5")
	f := grantsFixture(t)
	fx := loadScenario(t, scenario50(t))
	draft := strings.Replace(strings.Replace(docGrants, `"g1"`, `"g2"`, 1), `"list_directory", "stat"]`, `"list_directory"]`, 1)
	res, err := f.svc.Simulate([]byte(draft), fx, 0, true, "a")
	if err != nil {
		t.Fatal(err)
	}
	if res.ActiveRevision != "g1" || res.CandidateRevision != "g2" || res.Fixtures != 50 || len(res.Results) != 50 || res.Source != "fixtures" {
		t.Fatalf("%+v", res.SimReport)
	}
	affected := 0
	for _, r := range res.Results {
		removed := r.Fixture.Template == "ro" && r.Fixture.Tool == "stat"
		if removed {
			affected++
		}
		switch {
		case removed && (r.Change != policy.SimPermitToDeny || r.Active.Outcome != policy.Permit || r.Candidate.Outcome != policy.Deny ||
			r.Active.DecisiveRules[0] != "ro-fs" || r.Candidate.ReasonCode != policy.ReasonNoPermit):
			t.Errorf("fixture %d (%+v): %+v", r.Index, r.Fixture, r)
		case !removed && (r.Change != policy.SimUnchanged || r.Active.Outcome != r.Candidate.Outcome || r.Active.ReasonCode != r.Candidate.ReasonCode):
			t.Errorf("fixture %d (%+v) changed: %+v", r.Index, r.Fixture, r)
		}
		if r.Active.Outcome == "" || r.Candidate.Outcome == "" || r.Active.ReasonCode == "" || r.Candidate.ReasonCode == "" {
			t.Errorf("fixture %d lacks a decision: %+v", r.Index, r)
		}
	}
	if affected != 5 || res.Changed != affected || res.Counts[policy.SimPermitToDeny] != affected {
		t.Fatalf("affected %d, changed %d, counts %v", affected, res.Changed, res.Counts)
	}
	// The unchanged results include permits and denials on both sides.
	if res.Counts[policy.SimUnchanged] != 45 {
		t.Fatalf("counts %v", res.Counts)
	}
}

// TestExportImportIdenticalDecisions is FR-3.8: a revision is exported as
// its canonical JSON document, imported into a clean instance as a new
// draft (the document a publication takes), published there, and both
// instances decide the 50-fixture scenario identically.
func TestExportImportIdenticalDecisions(t *testing.T) {
	reqtest.Verifies(t, "FR-3.8")
	a := grantsFixture(t)
	exported, err := a.store.Export("g1")
	if err != nil {
		t.Fatal(err)
	}
	canon, err := policy.Canonical(exported)
	if err != nil || !bytes.Equal(canon, exported) {
		t.Fatalf("export is not canonical: %v", err)
	}
	// Clean instance: a new state directory with no revisions.
	dir := t.TempDir()
	st, err := policystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.List()) != 0 {
		t.Fatal("instance not clean")
	}
	gw := &fakeGW{d: policy.NewDecider(nil, 60)}
	b := New(Options{Store: st, Evidence: &audit.Memory{}, Active: gw.snapshot, DefaultRate: 60})
	b.Bind(gw)
	// Import as a draft: compiled and simulated without being stored.
	fx := loadScenario(t, scenario50(t))
	if sim, err := b.Simulate(exported, fx, 0, false, "importer"); err != nil || sim.CandidateRevision != "g1" || sim.ActiveRevision != "" {
		t.Fatalf("%+v %v", sim, err)
	}
	if len(st.List()) != 0 {
		t.Fatal("the draft was stored before publication")
	}
	res, err := b.Publish(exported, PublishOptions{Actor: "importer", Origin: "import"})
	if err != nil || !res.Created || res.Record.Revision != "g1" {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Record.Digest != mustRecord(t, a.store, "g1").Digest {
		t.Fatalf("digest differs: %s", res.Record.Digest)
	}
	da, db := policy.NewDecider(a.gw.snapshot(), 60), policy.NewDecider(gw.snapshot(), 60)
	permits := 0
	for i, x := range fx {
		now := x.Time
		da.SetNow(func() time.Time { return now })
		db.SetNow(func() time.Time { return now })
		req := policy.Request{PrincipalID: x.PrincipalID, SessionID: x.SessionID, Profile: x.Profile, Template: x.Template, Server: x.Server, Tool: x.Tool}
		ra, rb := da.Decide(req), db.Decide(req)
		if ra.Outcome != rb.Outcome || ra.ReasonCode != rb.ReasonCode || strings.Join(ra.DecisiveRules, ",") != strings.Join(rb.DecisiveRules, ",") ||
			ra.Obligations.Approval != rb.Obligations.Approval || ra.Obligations.CallsPerMinute != rb.Obligations.CallsPerMinute || ra.Route != rb.Route {
			t.Fatalf("fixture %d: %+v\n%+v", i, ra, rb)
		}
		if ra.Outcome == policy.Permit {
			permits++
		}
	}
	if permits == 0 || permits == len(fx) {
		t.Fatalf("%d permits: the fixture set does not exercise both outcomes", permits)
	}
}

func mustRecord(t *testing.T, st *policystore.Store, id string) policystore.Record {
	t.Helper()
	r, err := st.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return r.Record
}
