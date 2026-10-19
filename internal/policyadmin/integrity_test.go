package policyadmin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestStartupIntegrityFailsClosed: at each start the active revision is
// verified; a corrupted rule, a removed signature, a broken cross-reference
// and a schema violation each leave the Gateway without a snapshot, and the
// Health & Safety Monitor enters fail-closed with the matching cause:
// policy_signature for integrity failures, policy_invalid for a verified
// document that fails the schema or cross-reference checks (SR-7.3-1).
func TestStartupIntegrityFailsClosed(t *testing.T) {
	reqtest.Verifies(t, "SR-7.3-1")
	for _, tc := range []struct {
		name   string
		change func(env map[string]any)
		fault  string
		detail string
	}{
		{"corrupted rule", func(env map[string]any) {
			d := env["document"].(map[string]any)
			d["templates"].(map[string]any)["ro"].(map[string]any)["rules"].([]any)[0].(map[string]any)["tools"] = []any{"read_file", "write_file"}
		}, FaultSignature, "does not match its record"},
		{"signature removed", func(env map[string]any) { env["signature"] = "" }, FaultSignature, "signature does not verify"},
		{"broken cross-reference", func(env map[string]any) {
			d := env["document"].(map[string]any)
			d["framework_profiles"].(map[string]any)["dev"].(map[string]any)["templates"] = []any{"ro", "gone"}
		}, FaultInvalid, `unknown template "gone"`},
		{"schema violation", func(env map[string]any) {
			d := env["document"].(map[string]any)
			d["templates"].(map[string]any)["ro"].(map[string]any)["rules"].([]any)[0].(map[string]any)["effect"] = "maybe"
		}, FaultInvalid, "schema"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			files, _ := filepath.Glob(filepath.Join(f.dir, policystore.RevisionsDir, "*.json"))
			if len(files) != 1 {
				t.Fatalf("revision files %v", files)
			}
			raw, _ := os.ReadFile(files[0])
			var env map[string]any
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatal(err)
			}
			tc.change(env)
			out, _ := json.Marshal(env)
			os.Chmod(files[0], 0o600)
			if err := os.WriteFile(files[0], out, 0o600); err != nil {
				t.Fatal(err)
			}
			// Restart: open the store and load again.
			st, _ := policystore.Open(f.dir)
			snap, _, fault, err := Load(st, filepath.Join(f.dir, "policy.json"))
			if snap != nil || fault != tc.fault || err == nil || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("load: snapshot %v fault %q err %v", snap != nil, fault, err)
			}
			svc := New(Options{Store: st, Evidence: f.ev, Active: func() *policy.Snapshot { return nil }, Fault: fault})
			svc.Started(nil, err)
			mon := health.New(health.Options{})
			mon.Register("policy_store", health.PolicyFault(svc.Fault))
			mon.Evaluate()
			if mon.State() != health.FailClosed || len(mon.Gate()) != 1 || mon.Gate()[0] != tc.fault {
				t.Fatalf("health %s gate %v", mon.State(), mon.Gate())
			}
			last := f.ev.Events()[len(f.ev.Events())-1]
			if last.ReasonCode != ReasonIntegrity || last.Detail.(map[string]any)["cause"] != tc.fault {
				t.Fatalf("evidence %+v", last)
			}
		})
	}
}
