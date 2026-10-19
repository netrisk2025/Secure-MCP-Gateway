package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// graphOptions returns the [graph] table that connects an instance to the
// Neo4j database named by SMCP_NEO4J_URL (SMCP_NEO4J_USER, default neo4j,
// and SMCP_NEO4J_PASSWORD), or skips the test when it is unset. The CI job
// acceptance-enforced runs Neo4j Community Edition in a service container.
func graphOptions(t *testing.T) string {
	t.Helper()
	needBinaries(t)
	uri := os.Getenv("SMCP_NEO4J_URL")
	if uri == "" {
		t.Skip("needs a Neo4j database: set SMCP_NEO4J_URL (and SMCP_NEO4J_USER, SMCP_NEO4J_PASSWORD)")
	}
	user := os.Getenv("SMCP_NEO4J_USER")
	if user == "" {
		user = "neo4j"
	}
	pw := writeFile(t, t.TempDir(), "neo4j.password", os.Getenv("SMCP_NEO4J_PASSWORD")+"\n", 0o600)
	return fmt.Sprintf("\n[graph]\nenabled = true\nuri = %q\nusername = %q\npassword_file = %q\ncatchup_interval = \"1s\"\n", uri, user, pw)
}

// graphReset wipes the mirror and rebuilds it from this instance's journal:
// the database is shared by the tests of a run.
func (g *gateway) graphReset() {
	g.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		out, err := g.ctl("graph", "rebuild", "--yes")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("graph rebuild: %v\n%s\n%s", err, out, g.logs.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
	g.waitGraph(func(st map[string]any) bool { return st["last_rebuild"] != nil && st["last_rebuild"] != "" }, "the rebuild")
}

// graphStatus is GET /api/v1/graph/status.
func (g *gateway) graphStatus() map[string]any {
	g.t.Helper()
	_, st := g.api("GET", "/api/v1/graph/status", nil)
	return st
}

// waitGraph polls the mirror status until ok holds.
func (g *gateway) waitGraph(ok func(map[string]any) bool, what string) map[string]any {
	g.t.Helper()
	var st map[string]any
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		if st = g.graphStatus(); ok(st) {
			return st
		}
	}
	g.t.Fatalf("graph mirror: %s did not happen: %v", what, st)
	return nil
}

// eventPath returns the investigation path of a mirrored event, waiting
// until the event is in the mirror.
func (g *gateway) eventPath(id string) map[string]any {
	g.t.Helper()
	var code int
	var p map[string]any
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if code, p = g.api("GET", "/api/v1/graph/events/"+url.PathEscape(id)+"/path?limit=50", nil); code == 200 {
			return p
		}
	}
	g.t.Fatalf("event %s never reached the graph mirror: %d %v", id, code, p)
	return nil
}

// mirroredAll waits until the mirror holds exactly the journal's events:
// the AuditEvent count equals the number of distinct event IDs of the
// journal, read before and after the count without change. With the
// mirror's unique constraint on the event ID, equal counts mean every
// event once, with no duplicates and no gaps.
func (g *gateway) mirroredAll() int {
	g.t.Helper()
	var last string
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		ids := map[string]bool{}
		for _, e := range g.events() {
			ids[e.str("event_id")] = true
		}
		counts, _ := g.graphStatus()["counts"].(map[string]any)
		n, _ := counts["auditEvents"].(float64)
		after := len(g.events())
		last = fmt.Sprintf("journal %d distinct IDs (%d events after), mirror %v", len(ids), after, counts["auditEvents"])
		if int(n) == len(ids) && after == len(ids) {
			return len(ids)
		}
	}
	g.t.Fatalf("the mirror does not hold the journal's events exactly once: %s\n%s", last, g.logs.String())
	return 0
}

func nodeID(v any) string {
	m, _ := v.(map[string]any)
	s, _ := m["id"].(string)
	return s
}

const at11Policy = `{
  "revision": "at11-r1",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [{"id": "echo-ok", "server": "%s", "tools": ["echo"], "when": [{"op": "in", "arg": "text", "value": ["allowed"]}]}]},
    "approval-demo": {"rules": [{"id": "demo", "server": "%s", "tools": ["echo"]}]}
  }
}`

// TestAT11AuditLinkage is acceptance scenario AT-11 against the real
// binaries and a real Neo4j graph mirror, in the profile the run asks for
// (the CI job acceptance-enforced runs it in the Enforced profile):
//
//   - a permitted call and a call denied before dispatch (a policy
//     predicate that does not hold) are made through the reference server;
//   - the server is renamed (a new alias in the configuration and a new
//     policy revision naming it), updated (a new signed package revision
//     of the same artifact, enabled) and its old revision removed
//     (retired), with a call after each change;
//   - afterwards every evaluated event of the first call still resolves,
//     through the mirror's investigation path, to the same decision, policy
//     revision, decisive rule, server revision and tool revision as before
//     the changes, and every one of those events has a direct link to its
//     decision (SR-6.20-1);
//   - no event of the denied call is linked as observed from (executing
//     on) a server revision (SR-6.5-1), and the mirror holds every journal
//     event exactly once.
//
// Partial claims: the requirements are verified by their unit tests
// (internal/graph, internal/edge).
func TestAT11AuditLinkage(t *testing.T) {
	gopts := graphOptions(t)
	g := newGateway(t, options{extra: gopts})
	g.writePolicy(fmt.Sprintf(at11Policy, "ref", "ref"))
	g.start()
	g.graphReset()
	g.scenario("AT-11")
	reqtest.Partial(t, "SR-6.4-1", "SR-6.5-1", "SR-6.20-1")

	cs := g.session(g.token(""))
	g.mustCall(cs, "ref_echo", map[string]any{"text": "allowed"}, "allowed")
	if text, isErr, err := call(cs, "ref_echo", map[string]any{"text": "denied text"}); err == nil && !isErr {
		t.Fatalf("the call outside the predicate was not refused: %q", text)
	}

	// The two calls by correlation ID: the permitted one has a dispatched
	// event, the denied one a denied event and no dispatch.
	var permitted, denied string
	for _, e := range g.events() {
		switch {
		case e.str("class") == "call" && e.str("phase") == "dispatched":
			permitted = e.str("correlation_id")
		case e.str("phase") == "denied" && e.str("correlation_id") != "":
			denied = e.str("correlation_id") // a decision denied before dispatch
		}
	}
	if permitted == "" || denied == "" {
		t.Fatalf("calls not found in the journal: permitted %q denied %q", permitted, denied)
	}
	evaluated := func(corr string) []event {
		var out []event
		for _, e := range g.events() {
			if e.str("correlation_id") == corr && e.str("decision_id") != "" {
				out = append(out, e)
			}
		}
		return out
	}
	type links struct{ decision, policy, server, tool, rule string }
	snapshot := func(corr string) map[string]links {
		out := map[string]links{}
		for _, e := range evaluated(corr) {
			p := g.eventPath(e.str("event_id"))
			l := links{decision: nodeID(p["decision"]), policy: nodeID(p["policyRevision"]), server: nodeID(p["serverRevision"]), tool: nodeID(p["toolRevision"])}
			if rules, _ := p["decisiveRules"].([]any); len(rules) > 0 {
				l.rule = nodeID(rules[0])
			}
			if l.decision != e.str("decision_id") || l.policy != e.str("policy_revision") {
				t.Fatalf("%s/%s event %s: path decision %q policy %q, journal %q %q", e.str("class"), e.str("phase"), e.str("event_id"),
					l.decision, l.policy, e.str("decision_id"), e.str("policy_revision"))
			}
			out[e.str("event_id")] = l
		}
		return out
	}
	before := snapshot(permitted)
	if len(before) < 3 {
		t.Fatalf("only %d evaluated events of the permitted call: %v", len(before), before)
	}
	// Every evaluated event links its tool revision and decisive rule; the
	// path names the server revision for the events that carry one (as in
	// internal/graph's TestAT11AuditLinkageSurvivesChanges).
	withServer := 0
	for id, l := range before {
		if l.tool == "" || l.rule == "" {
			t.Fatalf("event %s of the permitted call lacks a link: %+v", id, l)
		}
		if l.server != "" {
			withServer++
		}
	}
	if withServer == 0 {
		t.Fatalf("no event of the permitted call links its server revision: %v", before)
	}

	// Rename: the same package under a new alias, with a new policy
	// revision that names it.
	g.stop()
	raw, err := os.ReadFile(g.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "alias = \"ref\"\n") < 1 {
		t.Fatalf("configuration has no ref alias:\n%s", raw)
	}
	if err := os.WriteFile(g.cfg, []byte(strings.ReplaceAll(string(raw), "alias = \"ref\"\n", "alias = \"renamed\"\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	g.start()
	pol := writeFile(t, t.TempDir(), "at11-r2.json", strings.Replace(fmt.Sprintf(at11Policy, "renamed", "renamed"), "at11-r1", "at11-r2", 1), 0o644)
	g.mustCtl("policy", "publish", pol)
	cs = g.session(g.freshToken())
	g.mustCall(cs, "renamed_echo", map[string]any{"text": "allowed"}, "allowed")

	// Update: a new revision of the signed package (same artifact), signed
	// by a newly enrolled key and enabled.
	g.stop()
	oldRev := at11NewRevision(t, g, "0.0.1-at11")
	g.start()
	cs = g.session(g.freshToken())
	g.mustCall(cs, "renamed_echo", map[string]any{"text": "allowed"}, "allowed")

	// Removal: the old revision is retired.
	g.stop()
	g.mustCtl("package", "retire", oldRev)
	g.start()
	cs = g.session(g.freshToken())
	g.mustCall(cs, "renamed_echo", map[string]any{"text": "allowed"}, "allowed")

	g.mirroredAll()
	after := snapshot(permitted)
	for id, l := range before {
		if after[id] != l {
			t.Fatalf("event %s of the first call: links %+v after the changes, %+v before", id, after[id], l)
		}
	}
	// The later calls ran on another server revision: the old links were
	// not moved to it.
	var first, newer string
	for _, e := range g.events() {
		if e.str("class") == "call" && e.str("phase") == "dispatched" {
			if e.str("correlation_id") == permitted {
				first = e.str("server_revision")
			} else {
				newer = e.str("server_revision")
			}
		}
	}
	if first == "" || newer == "" || newer == first {
		t.Fatalf("the last call ran on server revision %q, the first on %q: the update did not change the revision", newer, first)
	}
	for id, l := range before {
		if l.server != "" && l.server != first {
			t.Fatalf("event %s links server revision %q, the call ran on %q", id, l.server, first)
		}
	}

	// SR-6.20-1 and SR-6.5-1 on the mirror: every evaluated event of both
	// calls links to its decision; no event of the denied call is linked
	// as observed from a server revision.
	for _, corr := range []string{permitted, denied} {
		for _, e := range evaluated(corr) {
			code, nb := g.api("GET", "/api/v1/graph/neighborhood?"+url.Values{"label": {"AuditEvent"}, "id": {e.str("event_id")}, "limit": {"100"}}.Encode(), nil)
			if code != 200 {
				t.Fatalf("neighborhood of %s: %d %v", e.str("event_id"), code, nb)
			}
			forDecision := false
			edges, _ := nb["edges"].([]any)
			for _, x := range edges {
				ed, _ := x.(map[string]any)
				switch ed["type"] {
				case "FOR_DECISION":
					forDecision = forDecision || ed["to"] == e.str("decision_id")
				case "OBSERVED_FROM":
					if corr == denied {
						t.Fatalf("denied call event %s/%s is linked as observed from %v", e.str("class"), e.str("phase"), ed["to"])
					}
				}
			}
			if !forDecision {
				t.Fatalf("event %s/%s has no FOR_DECISION link to %s: %v", e.str("class"), e.str("phase"), e.str("decision_id"), edges)
			}
		}
	}
}

// at11NewRevision builds a new revision of the reference package from the
// imported one (same artifact, revision rev), signs it with a newly
// enrolled key and installs and enables it. It returns the reference of the
// revision it replaces (<id>@<rev>).
func at11NewRevision(t *testing.T, g *gateway, rev string) string {
	t.Helper()
	pkgs := filepath.Join(g.state, "packages")
	reg := readJSON(t, filepath.Join(pkgs, "registry.json"))
	revs, _ := reg["revisions"].([]any)
	if len(revs) != 1 {
		t.Fatalf("registry: %v", reg)
	}
	cur := revs[0].(map[string]any)
	id, old := cur["server_id"].(string), cur["revision"].(string)
	sha := cur["artifact_sha256"].(string)
	work := t.TempDir()
	pkg := filepath.Join(work, "pkg")
	copyTree(t, filepath.Join(pkgs, "revisions", id, old), pkg)
	artifact, err := os.ReadFile(filepath.Join(pkgs, "artifacts", "sha256", sha))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, pkg, filepath.Join("artifact", "smcp-refserver"), string(artifact), 0o755)
	os.Remove(filepath.Join(pkg, "index.json.minisig"))
	// The provenance statement first: the manifest names its digest.
	for _, member := range []string{"provenance", "manifest"} {
		m := readJSON(t, filepath.Join(pkg, member+".json"))
		if !strings.Contains(fmt.Sprint(m), old) {
			t.Fatalf("%s does not name revision %s", member, old)
		}
		m = replaceString(m, old, rev).(map[string]any)
		if member == "manifest" {
			b, err := os.ReadFile(filepath.Join(pkg, "provenance.json"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			prov, _ := m["provenance"].(map[string]any)
			if prov == nil {
				t.Fatal("manifest has no provenance member")
			}
			prov["statement_sha256"] = hex.EncodeToString(sum[:])
		}
		writeJSON(t, filepath.Join(pkg, member+".json"), m)
		refreshIndex(t, pkg, member)
	}
	idx := readJSON(t, filepath.Join(pkg, "index.json"))
	idx["revision"] = rev
	writeJSON(t, filepath.Join(pkg, "index.json"), idx)
	key := filepath.Join(work, "at11")
	g.mustCtl("package", "keygen", "--out", key, "--unencrypted")
	g.mustCtl("package", "sign", pkg, "--key", key+".key")
	g.trustAdd(key+".pub", "at11", "--classes", "low")
	g.mustCtl("package", "install", pkg, "--enable", "--alias", "renamed")
	return id + "@" + old
}

// replaceString replaces old with new in every string of a decoded JSON
// value.
func replaceString(v any, old, new string) any {
	switch x := v.(type) {
	case string:
		if x == old {
			return new
		}
		return x
	case map[string]any:
		for k, e := range x {
			x[k] = replaceString(e, old, new)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = replaceString(e, old, new)
		}
		return x
	}
	return v
}
