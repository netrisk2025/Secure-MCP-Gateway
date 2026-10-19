// Command evidence-fixture writes hostile fixture content into a stopped
// Gateway instance for the console's inert-rendering and export tests
// (SR-6.17-1, console/e2e/exports.spec.ts): journal events signed with the
// instance's evidence key, and observation records in its Observation
// Store, whose text fields begin with spreadsheet formula characters or
// carry HTML, script and remote-media markup. No call through the Gateway
// can put such text at the start of an exported field, so the test writes
// it here, through the same journal and store code smcpd uses.
//
// Run it only while smcpd is stopped: smcpd holds the journal and the
// store while it runs.
//
//	evidence-fixture -config smcp.toml -marker <text>
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
)

// Payloads: a formula behind each of the four characters, HTML with a
// script handler, a script element and remote media.
func payloads(marker string) map[string]string {
	return map[string]string{
		"eq":     `=HYPERLINK("https://evil.example/` + marker + `","open")`,
		"plus":   `+cmd|' /C calc'!A0 ` + marker,
		"minus":  `-2+3+cmd|' /C calc'!A0 ` + marker,
		"at":     `@SUM(1+1)*cmd|' /C calc'!A0 ` + marker,
		"html":   `<img src="https://evil.example/pixel.png" onerror="window.__smcpXSS=1">` + marker,
		"script": `<script>window.__smcpXSS=1</script>` + marker,
	}
}

func main() {
	cfgPath := flag.String("config", "", "the instance's smcp.toml")
	marker := flag.String("marker", "smcp-fixture", "text appended to every payload, to find them")
	flag.Parse()
	if err := run(*cfgPath, *marker); err != nil {
		fmt.Fprintln(os.Stderr, "evidence-fixture:", err)
		os.Exit(1)
	}
}

func run(cfgPath, marker string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	p := payloads(marker)
	now := time.Now().UTC()

	key, err := keys.LoadEvidenceKey(cfg.State.Dir)
	if err != nil {
		return err
	}
	j, err := audit.Open(filepath.Join(cfg.State.Dir, "journal"), key, audit.Options{})
	if err != nil {
		return err
	}
	events := []audit.Event{
		{Class: "fixture", Origin: "E-21", Outcome: p["plus"], ReasonCode: p["eq"], CorrelationID: p["minus"], SessionID: p["at"], PrincipalID: p["html"],
			ServerRevision: p["script"], ToolRevision: p["eq"], PolicyStatus: "not_evaluated", Detail: map[string]any{"note": p["html"], "formula": p["eq"]}},
		{Class: "fixture", Origin: "E-21", Outcome: p["at"], ReasonCode: p["minus"], PrincipalID: p["eq"], SessionID: p["script"], PolicyStatus: "not_evaluated",
			Detail: map[string]any{"script": p["script"]}},
	}
	for _, ev := range events {
		if err := j.Commit(ev); err != nil {
			j.Close()
			return err
		}
	}
	if err := j.Close(); err != nil {
		return err
	}

	cat := observe.DefaultCatalog()
	st, err := analytics.Resolve(cfg, cat)
	if err != nil {
		return err
	}
	store, err := obsstore.Open(obsstore.Options{Dir: filepath.Join(st.Dir, "store"), Backend: st.Store, Tables: analytics.Tables(cat)})
	if err != nil {
		return err
	}
	rows := []obsstore.Row{}
	for i, k := range []string{"eq", "plus", "minus", "at", "html", "script"} {
		rows = append(rows, obsstore.Row{
			"ts": now.Add(time.Duration(i) * time.Millisecond), "correlation_id": fmt.Sprintf("fixture-%d", i), "server_id": "ref",
			"policy_revision": "r1", "capture": "fixture", "catalog_version": cat.Version,
			"tool_name": p[k], "principal_id": "claude-code-local", "framework_type": p[k], "mcp_method": "tools/call",
			"decision_outcome": "permit", "request_bytes": int64(10 + i),
		})
	}
	if err := store.Append("records", rows); err != nil {
		store.Close()
		return err
	}
	if err := store.Close(); err != nil {
		return err
	}
	fmt.Printf("wrote %d journal events and %d observation records\n", len(events), len(rows))
	return nil
}
