//go:build hostile

package hostile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// rowCheck runs one fixture against a fresh Gateway and returns what was
// observed and whether it matches the row's expected outcome.
type rowCheck func(t *testing.T) (observed string, pass bool)

var checks = map[string]rowCheck{
	"HF-01": func(t *testing.T) (string, bool) { return metadataRow(t, "HF-01", "lookup", nil) },
	"HF-02": func(t *testing.T) (string, bool) { return metadataRow(t, "HF-02", "lookup", nil) },
	"HF-03": rugPull,
	"HF-04": func(t *testing.T) (string, bool) { return injectionRow(t, "HF-04", "fetch_page") },
	"HF-05": func(t *testing.T) (string, bool) { return injectionRow(t, "HF-05", "fetch_record") },
	"HF-06": func(t *testing.T) (string, bool) { return injectionRow(t, "HF-06", "fail") },
	"HF-07": progressRow,
	"HF-08": secretInResult,
	"HF-09": secretInArguments,
	"HF-10": remoteRef,
	"HF-11": func(t *testing.T) (string, bool) { return metadataRow(t, "HF-11", "deep_tool", nil) },
	"HF-12": func(t *testing.T) (string, bool) { return metadataRow(t, "HF-12", "enum_tool", nil) },
	"HF-13": schemaDrift,
	"HF-14": collision,
	"HF-15": func(t *testing.T) (string, bool) {
		return metadataRow(t, "HF-15", "mailer", []serverSpec{{alias: "good", fixture: "BENIGN"}})
	},
	"HF-16": oversized,
	"HF-17": func(t *testing.T) (string, bool) { return stalled(t, "HF-17", "slow") },
	"HF-18": invalidStdout,
	"HF-19": func(t *testing.T) (string, bool) { return stalled(t, "HF-19", "hang") },
	"HF-20": forkBomb,
	"HF-21": memoryBlowUp,
	"HF-22": pathEscape,
	"HF-23": networkEscape,
	"HF-24": dnsEscape,
	"HF-25": inputRequired,
	"HF-26": serverRequests,
	"HF-27": unicodeControl,
}

// TestHostileFixtures runs every Appendix L row (FR-19.1) and writes the
// results (FR-19.2). A row whose defense is missing is reported with
// pass=false; it does not fail the test. Harness errors do.
//
// With SMCP_HOSTILE_REQUIRE_ENFORCED=1 (the CI hostile job) the enforced
// profile must be available and every Enforced row must pass in it; the
// test fails otherwise.
func TestHostileFixtures(t *testing.T) {
	profile := suiteProfile()
	requireEnforced := profile == "enforced" && os.Getenv("SMCP_HOSTILE_REQUIRE_ENFORCED") == "1"
	if profile == "enforced" {
		if why := enforcedUnavailable(); why != "" {
			if requireEnforced {
				t.Fatal("enforced profile required but unavailable: " + why)
			}
			t.Skip("enforced profile unavailable: " + why)
		}
	}
	var mu sync.Mutex
	var results []Result
	for _, row := range Rows {
		t.Run(row.ID, func(t *testing.T) {
			check := checks[row.ID]
			if check == nil {
				t.Fatalf("no check for %s", row.ID)
			}
			res := Result{Fixture: row.ID, Attack: row.Attack, Expected: row.Expected, Profile: profile, Requirements: row.Requirements,
				Observed: HarnessError}
			defer func() {
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}()
			observed, pass := check(t)
			if row.EnforcedOnly() && profile != "enforced" {
				observed = "not asserted (Enforced row, Standalone profile; see docs/security-limitations.md). Observed: " + observed
				pass = false
			}
			res.Observed, res.Pass = observed, pass
			t.Logf("%s pass=%v: %s", row.ID, pass, observed)
			if requireEnforced && row.EnforcedOnly() && !pass {
				t.Errorf("%s is an Enforced row and did not behave as expected in the enforced profile", row.ID)
			}
			if pass {
				// A passing row exercises its requirements against one hostile
				// behavior; none of them is proven in full by one row.
				reqtest.Partial(t, row.Requirements...)
			}
		})
	}
	// Acceptance scenarios realized by Appendix L rows (SRS Appendix M,
	// FR-19.4): AT-08 by HF-20 to HF-24, asserted in the Enforced profile
	// only, and AT-09's binary, injection, secret and oversize cases by
	// HF-04 to HF-09 and HF-16 in either profile. Each scenario subtest
	// fails when one of its rows did not behave as expected in this run.
	passed := map[string]bool{}
	for _, r := range results {
		passed[r.Fixture] = r.Pass
	}
	for _, sc := range []struct {
		id           string
		rows         []string
		enforcedOnly bool
	}{
		{"AT-08", []string{"HF-20", "HF-21", "HF-22", "HF-23", "HF-24"}, true},
		{"AT-09", []string{"HF-04", "HF-05", "HF-06", "HF-07", "HF-08", "HF-09", "HF-16"}, false},
	} {
		t.Run(sc.id, func(t *testing.T) {
			if sc.enforcedOnly && profile != reqtest.Enforced {
				t.Skipf("%s is asserted in the Enforced profile only", sc.id)
			}
			reqtest.Scenario(t, profile, sc.id)
			for _, id := range sc.rows {
				if !passed[id] {
					t.Errorf("%s: %s did not behave as expected in the %s profile", sc.id, id, profile)
				}
			}
		})
	}
	merged, err := WriteResults(outDir(), profile, results)
	if err != nil {
		t.Fatal(err)
	}
	nPassed := 0
	for _, r := range merged {
		if r.Pass {
			nPassed++
		}
	}
	reqtest.Partial(t, "FR-19.2") // the CI job publishes what this writes
	// FR-19.1 is verified only when every row passed in the profiles it
	// names (merged over the profile runs present in the output directory).
	if nPassed == len(Rows) {
		reqtest.Verifies(t, "FR-19.1")
	} else {
		reqtest.Partial(t, "FR-19.1")
	}
	t.Logf("hostile fixtures (%s run; merged %s): %d of %d rows behaved as expected", profile, merged[0].Profile, nPassed, len(Rows))
}

// outDir is where results are written: SMCP_HOSTILE_OUT or <repo>/build.
func outDir() string {
	if d := os.Getenv("SMCP_HOSTILE_OUT"); d != "" {
		return d
	}
	return filepath.Join("..", "..", "build")
}

// note collects observation fragments.
type note []string

func (n *note) add(format string, a ...any) { *n = append(*n, fmt.Sprintf(format, a...)) }
func (n note) String() string               { return strings.Join(n, "; ") }

func mustStart(t *testing.T, sp gwSpec) *gw {
	t.Helper()
	g, err := startGateway(t, sp)
	if err != nil {
		t.Fatalf("gateway start: %v", err)
	}
	return g
}

func hostileServer(fixture string, args ...string) serverSpec {
	return serverSpec{alias: "h", fixture: fixture, args: args}
}

// metadataRow covers rows whose defense is the import-time metadata scan:
// the tool must be absent from the catalog, suspended at import with a
// metadata_blocked event, while the server's benign echo tool stays.
func metadataRow(t *testing.T, fixture, tool string, before []serverSpec, args ...string) (string, bool) {
	g := mustStart(t, gwSpec{servers: append(before, hostileServer(fixture, args...))})
	return metadataVerdict(g, tool)
}

func metadataVerdict(g *gw, tool string) (string, bool) {
	cs, _ := g.client(nil)
	cat := g.catalog(cs)
	_, listed := cat["h_"+tool]
	_, echo := cat["h_echo"]
	var rules []string
	suspended := false
	for _, s := range g.app.Inspector.Suspended() {
		if s.Server == "h" && s.Tool == tool && s.Stage == "import" {
			suspended = true
			for _, f := range s.Findings {
				if !slices.Contains(rules, f.RuleSet+"/"+f.Rule) {
					rules = append(rules, f.RuleSet+"/"+f.Rule)
				}
			}
		}
	}
	_, event := g.waitEvent(2*time.Second, func(e audit.Event) bool {
		d, _ := e.Detail.(map[string]any)
		return e.Outcome == "metadata_blocked" && d["tool"] == tool
	})
	o := g.call(cs, "h_"+tool, map[string]any{}, nil)
	var n note
	n.add("h_%s in catalog: %v", tool, listed)
	n.add("suspended at import: %v (%s)", suspended, strings.Join(rules, ", "))
	n.add("metadata_blocked event: %v", event)
	n.add("call to h_%s: %s", tool, o)
	n.add("benign h_echo presented: %v", echo)
	return n.String(), !listed && suspended && event && echo && o.code == -32602
}

func remoteRef(t *testing.T) (string, bool) {
	c := newHTTPCanary(t)
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-10", "-canary-url", c.url())}})
	obs, pass := metadataVerdict(g, "ref_tool")
	time.Sleep(200 * time.Millisecond)
	hits := c.count()
	return fmt.Sprintf("%s; requests to the $ref canary: %d", obs, hits), pass && hits == 0
}

// rugPull: a signed package whose running server sends list_changed with a
// changed description and an added tool (HF-03).
func rugPull(t *testing.T) (string, bool) {
	s := hostileServer("HF-03")
	s.pkg = mcpTools(t, Tools("HF-03", Config{}))
	g := mustStart(t, gwSpec{servers: []serverSpec{s}})
	cs, _ := g.client(nil)
	before := g.catalog(cs)
	first := g.call(cs, "h_echo", map[string]any{"text": "trigger"}, nil)
	suspended := waitFor(10*time.Second, func() bool { return g.app.Registry.Servers()["h"] == nil })
	_, drift := g.waitEvent(2*time.Second, func(e audit.Event) bool { return e.ReasonCode == library.ReasonDrift })
	after := g.catalog(cs)
	cs2, _ := g.client(nil)
	fresh := g.catalog(cs2)
	leaked := false
	for _, cat := range []map[string]string{before, after, fresh} {
		if _, ok := cat["h_exfiltrate"]; ok {
			leaked = true
		}
		if d, ok := cat["h_echo"]; ok && strings.Contains(d, CanaryMarker) {
			leaked = true
		}
	}
	var n note
	n.add("first call: %s", first)
	n.add("server suspended after list_changed: %v", suspended)
	n.add("%s evidence: %v", library.ReasonDrift, drift)
	n.add("changed or added tool in any catalog: %v", leaked)
	n.add("catalog afterwards: %v", sortedKeys(fresh))
	return n.String(), first.code == 0 && suspended && drift && !leaked
}

// schemaDrift: the live schema loosens additionalProperties and adds
// patternProperties compared with the signed manifest (HF-13).
func schemaDrift(t *testing.T) (string, bool) {
	s := hostileServer("HF-13")
	tools := mcpTools(t, Tools("HF-13", Config{}))
	for _, tl := range tools {
		if tl.Name == "lookup" {
			tl.InputSchema = StrictLookupSchema()
		}
	}
	s.pkg = tools
	g := mustStart(t, gwSpec{servers: []serverSpec{s}})
	enabled := g.app.Registry.Servers()["h"] != nil
	_, drift := g.waitEvent(2*time.Second, func(e audit.Event) bool { return e.ReasonCode == library.ReasonDrift })
	cs, _ := g.client(nil)
	cat := g.catalog(cs)
	o := g.call(cs, "h_lookup", map[string]any{"key": "k", "x-extra": "smuggled"}, nil)
	var n note
	n.add("server enabled: %v", enabled)
	n.add("%s evidence: %v", library.ReasonDrift, drift)
	n.add("catalog: %v", sortedKeys(cat))
	n.add("call with an extra property: %s", o)
	return n.String(), !enabled && drift && o.code != 0
}

func collision(t *testing.T) (string, bool) {
	var n note
	// Cross-server form: needs an alias containing "_", which CP-42 forbids.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "smcp.toml")
	_ = os.WriteFile(cfgPath, []byte("[state]\ndir = \"s\"\n[policy]\nfile = \"p.json\"\n[[server]]\nalias = \"a_b\"\ncommand = \"/bin/true\"\n"), 0o600)
	_, cfgErr := config.Load(cfgPath)
	n.add("alias containing \"_\" refused by configuration validation: %v", cfgErr != nil)
	// In-server form: "send.email" and "send_email" share a public name.
	// FR-1.49 refuses to enable that revision; the Gateway itself runs.
	g, err := startGateway(t, gwSpec{servers: []serverSpec{hostileServer("HF-14")}})
	if err != nil {
		n.add("in-server collision: Gateway start failed: %v", err)
		return n.String(), false
	}
	reason := g.app.Registry.Disabled()["h"]
	enabled := g.app.Registry.Servers()["h"] != nil
	namesBoth := strings.Contains(reason, "send.email") && strings.Contains(reason, "send_email") && strings.Contains(reason, "FR-1.49")
	ev, recorded := g.waitEvent(time.Second, func(e audit.Event) bool { return e.Outcome == "not_enabled" && e.ReasonCode == "SERVER_NOT_ENABLED" })
	if recorded {
		d, _ := ev.Detail.(map[string]any)
		recorded = d["alias"] == "h"
	}
	cs, _ := g.client(nil)
	cat := g.catalog(cs)
	n.add("in-server collision: revision enabled: %v; reason names both tools: %v; not_enabled event: %v; Gateway serves sessions: %v (catalog %v)",
		enabled, namesBoth, recorded, cs != nil, sortedKeys(cat))
	return n.String(), cfgErr != nil && !enabled && namesBoth && recorded && len(cat) == 0
}

// injectionRow covers HF-04 to HF-06: the result is released with an
// injection tag, P-143 is recorded and the session is tainted (the policy
// rule declares source_trust untrusted).
func injectionRow(t *testing.T, fixture, tool string) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer(fixture)}})
	cs, sid := g.client(nil)
	o := g.call(cs, "h_"+tool, map[string]any{}, nil)
	prov := provenance(o.res)
	tags, _ := prov["tags"].([]any)
	_, params := g.filterFindings("response", correlation(o))
	p143, _ := params["P-143"].(float64)
	tainted := g.app.Decider.Tainted(sid)
	released := o.code == 0 && o.err == nil && o.res != nil
	var n note
	n.add("call: %s", o)
	var tagNames []string
	for _, tg := range tags {
		m, _ := tg.(map[string]any)
		tagNames = append(tagNames, fmt.Sprintf("%v/%v@%v at %v", m["ruleSet"], m["rule"], m["ruleSetVersion"], m["location"]))
	}
	n.add("provenance tags: %v", tagNames)
	n.add("P-143: %v", params["P-143"])
	n.add("session tainted: %v", tainted)
	if fixture == "HF-06" {
		n.add("isError released: %v", o.res != nil && o.res.IsError)
		released = released && o.res.IsError
	}
	return n.String(), released && len(tags) > 0 && p143 > 0 && tainted
}

func progressRow(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-07")}})
	var mu sync.Mutex
	var msgs []string
	var metas []mcp.Meta
	cs, _ := g.client(&mcp.ClientOptions{ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
		mu.Lock()
		msgs = append(msgs, r.Params.Message)
		metas = append(metas, r.Params.Meta)
		mu.Unlock()
	}})
	o := g.call(cs, "h_long_task", map[string]any{}, mcp.Meta{"progressToken": "hostile-07"})
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	raw, tagged := 0, 0
	for i, m := range msgs {
		if strings.Contains(m, CanaryMarker) {
			raw++
		}
		if metas[i] != nil && metas[i]["local.smcpgw/provenance"] != nil {
			tagged++
		}
	}
	var n note
	n.add("call: %s", o)
	n.add("progress notifications relayed: %d", len(msgs))
	n.add("relayed with the canary text unchanged: %d", raw)
	n.add("tagged: %d", tagged)
	return n.String(), o.code == 0 && len(msgs) > 0 && tagged == len(msgs)
}

func secretInResult(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-08", "-secret-env", secretEnv)}, secrets: true})
	cs, _ := g.client(nil)
	o := g.call(cs, "h_whoami", map[string]any{}, nil)
	susp := g.sec.Broker.Suspended()
	leaked := strings.Contains(o.text, g.secret)
	var n note
	n.add("call: %s", o)
	n.add("secret value reached the client: %v", leaked)
	n.add("secret grants suspended: %d", len(susp))
	// The broker keys suspensions by secret reference; the vault holds one.
	return n.String(), o.code == -31003 && o.reason() == "SECRET_LEAK" && !leaked && len(susp) == 1
}

func secretInArguments(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-09")}, secrets: true})
	cs, _ := g.client(nil)
	reg := g.call(cs, "h_send_note", map[string]any{"text": "please store " + g.secret}, nil)
	// The documented AWS example access key ID, assembled at run time.
	aws := g.call(cs, "h_send_note", map[string]any{"text": "key " + "AKIA" + "IOSFODNN7EXAMPLE"}, nil)
	ok := g.call(cs, "h_send_note", map[string]any{"text": "an ordinary note"}, nil)
	var n note
	pass := true
	for _, c := range []struct {
		name string
		o    callOutcome
	}{{"registered secret", reg}, {"AWS-format key", aws}} {
		d := g.dispatched(correlation(c.o))
		n.add("%s: %s, dispatched: %v", c.name, c.o, d)
		pass = pass && c.o.code == -31001 && c.o.reason() == "SECRET_IN_ARGUMENTS" && !d
	}
	n.add("ordinary note: %s", ok)
	return n.String(), pass && ok.code == 0
}

func oversized(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-16", "-oversize-mib", "1")}})
	cs, _ := g.client(nil)
	o := g.call(cs, "h_big", map[string]any{}, nil)
	partial := strings.Contains(o.text, "SMCP-CANARY-OVERSIZE")
	after := g.call(cs, "h_echo", map[string]any{"text": "x"}, nil)
	var n note
	n.add("call (1 MiB result, result_bytes 64 KiB): %s", o)
	n.add("partial content released: %v", partial)
	n.add("next call: %s", after)
	return n.String(), o.code == -31003 && o.reason() == "RESULT_TOO_LARGE" && !partial
}

// stalled covers HF-17 and HF-19: the call ends at the upstream deadline
// with -31009 UPSTREAM_TIMEOUT and the instance is restarted.
func stalled(t *testing.T, fixture, tool string) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer(fixture, "-drip-every", "1s")}})
	cs, _ := g.client(nil)
	before := g.instance(cs, "h")
	o := g.call(cs, "h_"+tool, map[string]any{}, nil)
	after := g.instance(cs, "h")
	restarted := before != "" && after != "" && before != after
	var n note
	n.add("call: %s after %s (upstream_timeout 2s)", o, o.elapsed.Round(100*time.Millisecond))
	n.add("instance restarted: %v (next echo %s)", restarted, map[bool]string{true: "answered", false: "failed"}[after != ""])
	return n.String(), o.code == -31009 && o.reason() == "UPSTREAM_TIMEOUT" && o.elapsed < 8*time.Second && restarted
}

func invalidStdout(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-18")}})
	cs, _ := g.client(nil)
	pidBefore, before := g.pidAndNonce(cs)
	o := g.call(cs, "h_garble", map[string]any{}, nil)
	gone := false
	if pidBefore > 0 && suiteProfile() == "standalone" {
		gone = waitFor(5*time.Second, func() bool { return syscall.Kill(pidBefore, 0) != nil })
	}
	after := g.instance(cs, "h")
	if suiteProfile() != "standalone" {
		gone = after != before
	}
	_, event := g.waitEvent(time.Second, func(e audit.Event) bool {
		return e.CorrelationID == correlation(o) && e.Class != "filter" && (e.ReasonCode != "" || e.Outcome == "terminated")
	})
	var n note
	n.add("call: %s after %s", o, o.elapsed.Round(100*time.Millisecond))
	n.add("instance terminated: %v", gone)
	n.add("refusal event recorded: %v", event)
	return n.String(), o.code == -31007 && gone && event
}

func (g *gw) pidAndNonce(cs *mcp.ClientSession) (int, string) {
	o := g.call(cs, "h_echo", map[string]any{"text": "probe"}, nil)
	var pid int
	var nonce string
	if _, rest, ok := strings.Cut(o.text, "pid="); ok {
		_, _ = fmt.Sscanf(rest, "%d nonce=%s", &pid, &nonce)
	}
	return pid, nonce
}

func forkBomb(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-20", "-children", "64")}, upstream: "60s"})
	cs, _ := g.client(nil)
	before := g.instance(cs, "h")
	o := g.call(cs, "h_spawn", map[string]any{}, nil)
	time.Sleep(time.Second) // the Runtime Monitor samples every 200 ms in the enforced profile
	after := g.instance(cs, "h")
	killed := before != "" && after != before
	healthy := g.call(cs, "h_echo", map[string]any{"text": "host"}, nil).err == nil
	var n note
	n.add("spawn call: %s %q", o, o.text)
	n.add("instance killed: %v", killed)
	n.add("Gateway still answers: %v", healthy)
	stopped := o.code != 0 || !strings.HasPrefix(o.text, fmt.Sprintf("spawned %d of", MaxChildren))
	return n.String(), stopped && killed && healthy
}

func memoryBlowUp(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-21", "-alloc-mib", "256")}, upstream: "60s"})
	cs, _ := g.client(nil)
	before := g.instance(cs, "h")
	o := g.call(cs, "h_alloc", map[string]any{}, nil)
	time.Sleep(time.Second)
	after := g.instance(cs, "h")
	killed := before != "" && after != before
	healthy := g.call(cs, "h_echo", map[string]any{"text": "host"}, nil).err == nil
	var n note
	n.add("alloc call: %s %q", o, o.text)
	n.add("instance killed: %v", killed)
	n.add("Gateway still answers: %v", healthy)
	return n.String(), o.text != fmt.Sprintf("allocated %d MiB", MaxAllocMiB) && killed && healthy
}

func pathEscape(t *testing.T) (string, bool) {
	base := mountBase(t)
	root, outside := filepath.Join(base, "allowed"), filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SMCP-CANARY-PATH-22"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "inside.txt"), []byte("inside"), 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	toml := fmt.Sprintf("\n[filters.paths]\nroots = [%q]\n", root)
	if suiteProfile() == "enforced" {
		toml += fmt.Sprintf("\n[[runtime.server]]\nalias = \"h\"\n[[runtime.server.mount]]\nsource = %q\ntarget = %q\n", root, root)
	}
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-22")}, toml: toml})
	cs, _ := g.client(nil)
	var n note
	argCheck := true
	for _, c := range []struct{ name, path string }{
		{"../ traversal", root + "/../outside/secret.txt"},
		{"symlink to a directory outside the root", root + "/escape/secret.txt"},
	} {
		o := g.call(cs, "h_read_file", map[string]any{"path": c.path}, nil)
		d := g.dispatched(correlation(o))
		n.add("%s: %s, dispatched: %v", c.name, o, d)
		argCheck = argCheck && o.code == -31001 && o.reason() == "PATH_OUTSIDE_ROOTS" && !d && !strings.Contains(o.text, "SMCP-CANARY-PATH")
	}
	in := g.call(cs, "h_read_file", map[string]any{"path": root + "/inside.txt"}, nil)
	n.add("path inside the root: %s", in)
	argCheck = argCheck && in.code == 0
	// The mount part: the server follows the symlink inside its mount with a
	// value no argument check applies to (x-smcp-type text).
	raw := g.call(cs, "h_read_raw", map[string]any{"blob": root + "/escape/secret.txt"}, nil)
	mount := raw.code == 0 && !strings.Contains(raw.text, "SMCP-CANARY-PATH")
	n.add("server-side read through the symlink: %s, outside file read: %v", raw, !mount)
	if suiteProfile() == "enforced" {
		return n.String(), argCheck && mount
	}
	n.add("mount confinement is the Enforced part of this row")
	return n.String(), argCheck
}

// mountBase returns a new directory for files a fixture mounts into its
// sandbox at their own path. The sandbox reserves /tmp inside the
// container, so in the enforced profile the directory is created below
// SMCP_HOSTILE_MOUNT_DIR (default <repo>/build/hostile-mounts) instead of
// the test's temporary directory.
func mountBase(t *testing.T) string {
	t.Helper()
	if suiteProfile() != "enforced" {
		return t.TempDir()
	}
	parent := os.Getenv("SMCP_HOSTILE_MOUNT_DIR")
	if parent == "" {
		parent = filepath.Join(outDir(), "hostile-mounts")
	}
	parent, err := filepath.Abs(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(parent, 0o755); err != nil { // #nosec G301 -- test fixture directory
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(parent, "hf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

func networkEscape(t *testing.T) (string, bool) {
	c := newTCPCanary(t)
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-23", "-canary-addr", c.addr())}})
	cs, _ := g.client(nil)
	o := g.call(cs, "h_connect", map[string]any{}, nil)
	time.Sleep(200 * time.Millisecond)
	var n note
	n.add("connect to the loopback canary: %s %q", o, o.text)
	n.add("canary connections: %d", c.count())
	return n.String(), c.count() == 0 && strings.HasPrefix(o.text, "blocked")
}

func dnsEscape(t *testing.T) (string, bool) {
	dns, tcp := newUDPCanary(t), newTCPCanary(t)
	_, port, _ := strings.Cut(tcp.addr(), ":")
	toml := fmt.Sprintf("\n[egress]\nenabled = true\n[[egress.grant]]\nserver = \"h\"\nhost = \"localhost\"\nports = [%s]\nmethods = [\"CONNECT-TLS\"]\n", port)
	if suiteProfile() == "enforced" {
		// The sandboxed instance is attached to the Egress Broker on a
		// confined network; without this it has network "none".
		toml += "\n[[runtime.server]]\nalias = \"h\"\nnetwork = \"egress\"\n"
	}
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-24", "-canary-dns", dns.addr(), "-canary-addr", tcp.addr())}, toml: toml, upstream: "20s"})
	cs, _ := g.client(nil)
	o := g.call(cs, "h_resolve", map[string]any{}, nil)
	time.Sleep(200 * time.Millisecond)
	// The fixture presents the call's egress capability (SR-5.16-1), so the
	// refusal must be the broker's address check (SR-5.15-2).
	_, brokerRefusal := g.waitEvent(time.Second, func(e audit.Event) bool {
		return e.Class == "egress" && e.Outcome == "deny" && e.ReasonCode == "EGRESS_ADDRESS_REFUSED"
	})
	var n note
	n.add("fixture report: %s %q", o, o.text)
	n.add("direct DNS queries reaching the loopback DNS canary: %d", dns.count())
	n.add("broker deny event: %v; connections reaching the TCP canary: %d", brokerRefusal, tcp.count())
	return n.String(), dns.count() == 0 && tcp.count() == 0 && brokerRefusal
}

func inputRequired(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-25")}})
	var mu sync.Mutex
	elicited := 0
	cs, _ := g.client(&mcp.ClientOptions{ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		mu.Lock()
		elicited++
		mu.Unlock()
		return &mcp.ElicitResult{Action: "decline"}, nil
	}})
	o := g.call(cs, "h_ask", map[string]any{}, nil)
	ev, recorded := g.waitEvent(2*time.Second, func(e audit.Event) bool {
		return e.Phase == audit.PhaseFailed && e.ReasonCode == "INPUT_REQUIRED_UNSUPPORTED"
	})
	mu.Lock()
	defer mu.Unlock()
	var n note
	n.add("call: %s", o)
	n.add("elicitation requests relayed to the client: %d", elicited)
	n.add("audit event: %v (%s %s %s)", recorded, ev.Class, ev.Phase, ev.ReasonCode)
	pass := o.code == -31010 && elicited == 0 && recorded
	if pass {
		// The row performs the whole FR-5.24 verification: -31010 to the
		// harness and an audit event, with nothing relayed northbound.
		reqtest.Verifies(t, "FR-5.24")
	}
	return n.String(), pass
}

func serverRequests(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-26")}})
	var mu sync.Mutex
	north := 0
	// Sampling is deprecated (SEP-2577); the handler only detects a relay.
	cs, _ := g.client(&mcp.ClientOptions{CreateMessageHandler: func(context.Context, *mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) { //nolint:staticcheck // HF-26
		mu.Lock()
		north++
		mu.Unlock()
		return &mcp.CreateMessageResult{Content: &mcp.TextContent{Text: "no"}, Model: "none", Role: "assistant"}, nil //nolint:staticcheck // HF-26
	}})
	o := g.call(cs, "h_legacy", map[string]any{}, nil)
	// The same requests plus ping and elicitation/create inside one
	// JSON-RPC batch line: each member is screened (FR-5.20).
	b := g.call(cs, "h_legacy_batch", map[string]any{}, nil)
	mu.Lock()
	defer mu.Unlock()
	answered := strings.Contains(o.text, "=answered") || strings.Contains(b.text, "=answered")
	const batchWant = "ping=empty-result roots/list=error(-32601) sampling/createMessage=error(-32601) elicitation/create=error(-32601)"
	var n note
	n.add("fixture saw: %q (%s)", o.text, o)
	n.add("batch line: %q (%s)", b.text, b)
	n.add("sampling requests relayed to the client: %d", north)
	return n.String(), o.code == 0 && b.code == 0 && b.text == batchWant && !answered && strings.Contains(o.text, "roots/list=") && north == 0
}

func unicodeControl(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-27")}})
	cs, _ := g.client(nil)
	o := g.call(cs, "h_statement", map[string]any{}, nil)
	stripped := o.code == 0 && !strings.ContainsAny(o.text, "\u202E\u202C\u200B")
	fs, _ := g.filterFindings("response", correlation(o))
	var versions []string
	for _, f := range fs {
		if f["filter_id"] == "unicode-control" {
			v := fmt.Sprintf("%v@%v", f["ruleSet"], f["ruleSetVersion"])
			if !slices.Contains(versions, v) {
				versions = append(versions, v)
			}
		}
	}
	var n note
	n.add("call: %s", o)
	n.add("control characters removed: %v", stripped)
	n.add("unicode-control findings: %v", versions)
	return n.String(), stripped && len(versions) > 0
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
