package acceptance

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

const at03Policy = `{
  "revision": "at03-r2",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [{"id": "echo", "server": "ref", "tools": ["echo"]}]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// expect31004 sends one tools/call and requires Gateway error -31004.
func (g *gateway) expect31004(tok string) string {
	g.t.Helper()
	resp, body := g.mcpPost(tok, wireCall(9, "ref_echo", `{"text":"x"}`, ""), wireHeaders("tools/call", "ref_echo"))
	if !strings.Contains(body, "-31004") {
		g.t.Fatalf("want -31004, got %d %s\n%s", resp.StatusCode, body, g.logs.String())
	}
	return body
}

// TestAT03PolicyAuthorityAndOutage is acceptance scenario AT-03 against
// the real smcpd:
//
//   - the signed Policy Store is the only policy source: editing the
//     configured policy file changes no decision until it is published;
//   - SR-1.1-2 exactly as its verification states: a published revision
//     with one altered byte is refused at restart, the Gateway is
//     fail-closed with cause policy_signature and answers -31004, and
//     restoring the file restores normal start;
//   - FR-9.17: -31004 with an altered revision, -31004 with a read-only
//     journal directory and normal service once it is writable again, and
//     normal service with health degraded when the graph database is down;
//   - the journal keeps recording permits and denials while the graph
//     mirror is unreachable.
//
// FR-9.17 is verified when the read-only journal case runs (not as root,
// where the directory mode does not stop writes); SR-1.1-1 shows one alternative source (the
// configured policy file) is ignored, while its verification is an
// Inspection of every rule source; SR-1.2-1 checks the altered-revision
// case only; SR-1.2-2 covers the graph outage, not an injected flush
// failure during traffic (internal/e2e covers that in process); SR-6.13-1
// checks journal recording during the outage, not the mirror backfill
// (graph job with Neo4j).
func TestAT03PolicyAuthorityAndOutage(t *testing.T) {
	g := newGateway(t, options{})
	g.start()
	g.scenario("AT-03")
	reqtest.Verifies(t, "SR-1.1-2")
	reqtest.Partial(t, "SR-1.1-1", "SR-1.2-1", "SR-1.2-2", "SR-6.13-1", "FR-9.17")

	pol := writeFile(t, t.TempDir(), "at03.json", at03Policy, 0o644)
	g.mustCtl("policy", "publish", pol)
	tok := g.token("")
	cs := g.session(tok)
	g.mustCall(cs, "ref_echo", map[string]any{"text": "signed"}, "signed")

	// The configured policy file is not a policy source: granting
	// time_now in it changes nothing until it is published.
	g.writePolicy(strings.Replace(at03Policy, `"tools": ["echo"]}]},`, `"tools": ["echo", "time_now"]}]},`, 1))
	if text, isErr, err := call(cs, "ref_time_now", map[string]any{}); err == nil && !isErr {
		t.Fatalf("an unpublished policy file granted time_now: %q", text)
	}
	g.stop()

	// Alter one byte of the stored active revision.
	revs, _ := filepath.Glob(filepath.Join(g.state, "policy", "revisions", "*.json"))
	var active string
	var orig []byte
	for _, r := range revs {
		b, err := os.ReadFile(r)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("at03-r2")) {
			active, orig = r, b
		}
	}
	if active == "" {
		t.Fatalf("no stored revision at03-r2 among %v", revs)
	}
	altered := bytes.Replace(orig, []byte(`echo`), []byte(`ech0`), 1)
	if bytes.Equal(altered, orig) {
		t.Fatal("revision file not altered")
	}
	st, err := os.Stat(active)
	if err != nil {
		t.Fatal(err)
	}
	overwrite := func(b []byte) {
		t.Helper()
		if err := os.Chmod(active, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(active, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(active, st.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	overwrite(altered)
	g.start()
	causes := fmt.Sprint(g.health())
	if !strings.Contains(causes, "policy_signature") {
		t.Fatalf("health after an altered revision lacks policy_signature: %s", causes)
	}
	// Sign-in is refused without a snapshot; the token issued before the
	// restart and an unauthenticated request both get -31004.
	g.expect31004(tok)
	g.expect31004("")
	g.stop()
	overwrite(orig)
	g.start()
	if causes := fmt.Sprint(g.health()); strings.Contains(causes, "policy_signature") {
		t.Fatalf("restored revision still refused: %s", causes)
	}
	cs = g.session(g.token(""))
	g.mustCall(cs, "ref_echo", map[string]any{"text": "restored"}, "restored")
	g.stop()

	// A read-only journal directory: smcpd does not start the Gateway; it
	// answers every harness request with -31004 (JOURNAL_UNAVAILABLE) until
	// the directory is writable, and then starts and serves normally.
	if os.Geteuid() != 0 {
		jdir := filepath.Join(g.state, "journal")
		if err := os.Chmod(jdir, 0o500); err != nil {
			t.Fatal(err)
		}
		if err := g.launch(); err != nil {
			t.Fatal(err)
		}
		refused := false
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && !refused; {
			select {
			case <-g.exited:
				t.Fatalf("smcpd exited with a read-only journal directory\n%s", g.logs.String())
			case <-time.After(200 * time.Millisecond):
			}
			resp, body, err := g.tryMCPPost("", wireCall(9, "ref_echo", `{"text":"x"}`, ""), wireHeaders("tools/call", "ref_echo"))
			if err != nil {
				continue // not listening yet
			}
			if resp.StatusCode == http.StatusOK || strings.Contains(body, "echo:") {
				t.Fatalf("served with a read-only journal: %d %s", resp.StatusCode, body)
			}
			refused = resp.StatusCode == http.StatusServiceUnavailable && strings.Contains(body, "-31004") && strings.Contains(body, "JOURNAL_UNAVAILABLE")
		}
		if !refused {
			t.Fatalf("no -31004 with a read-only journal directory\n%s", g.logs.String())
		}
		if err := os.Chmod(jdir, 0o700); err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(60 * time.Second); ; {
			if _, err := g.ctl("health"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("smcpd did not start after the journal became writable\n%s", g.logs.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
		cs = g.session(g.token(""))
		g.mustCall(cs, "ref_echo", map[string]any{"text": "journal back"}, "journal back")
		g.stop()
		// All three cases of the verification ran: an altered revision, a
		// read-only journal directory, and the graph outage below.
		reqtest.Verifies(t, "FR-9.17")
	}

	// The graph database is down: requests are served, health is
	// degraded, and the journal records the permit and the denial.
	pw := writeFile(t, t.TempDir(), "neo4j.pw", "unused-password\n", 0o600)
	g.appendConfig(fmt.Sprintf("\n[graph]\nenabled = true\nuri = \"bolt://127.0.0.1:%d\"\npassword_file = %q\n", testport.Free(t), pw))
	g.start()
	// Requests are served at once, while the mirror is still connecting.
	cs = g.session(g.token(""))
	g.mustCall(cs, "ref_echo", map[string]any{"text": "mirror-connecting"}, "mirror-connecting")
	// Health becomes degraded for the unavailable graph mirror (not only
	// for the Standalone profile's unconfined servers).
	waitHealth(t, g, func(st map[string]any) bool {
		return st["state"] == "degraded" && strings.Contains(fmt.Sprint(st["causes"]), "graph_mirror_unavailable")
	}, "degraded with graph_mirror_unavailable")
	g.mustCall(cs, "ref_echo", map[string]any{"text": "graph-down"}, "graph-down")
	if _, isErr, err := call(cs, "ref_echo", map[string]any{"text": strings.Repeat("x", 10) + " AKIAIOSFODNN7EXAMPLE"}); err == nil && !isErr {
		t.Fatal("a credential in the arguments was not refused")
	}
	g.stop()
	var permits, refusals int
	for _, e := range g.events() {
		if e.str("class") == "call" && e.str("phase") == "delivered" {
			permits++
		}
		if e.str("phase") == "filtered" {
			refusals++
		}
	}
	if permits < 4 || refusals < 1 {
		t.Fatalf("journal during the outage: %d delivered, %d refused", permits, refusals)
	}
	if out := g.mustCtl("journal", "verify"); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
}
