package acceptance

import (
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

const rolePassword = "acceptance role password 1"

// consoleToken signs in a console account of another Appendix C role and
// returns its bearer token.
func (g *gateway) consoleToken(user, role string) string {
	g.t.Helper()
	code, out := g.apiAs("", "POST", "/api/v1/console/login", map[string]any{"username": user, "password": rolePassword, "role": role})
	tok, _ := out["token"].(string)
	if code != 200 || tok == "" || out["role"] != role {
		g.t.Fatalf("console sign-in %s as %s: %d %v", user, role, code, out)
	}
	return tok
}

// TestResearcherRoleLimits is SR-2-2 against the real smcpd with every
// element that owns one of the excluded operations configured (policy,
// approvals, the Secret Vault, the principal directory, remote
// registrations, observation and research). A Researcher signed in to the
// console is refused:
//
//   - policy publication: a new policy revision, a rollback, a policy
//     reload, and the observation objects (Audit Profile, Observation
//     Policy, Anomaly Response Policy) and baseline promotion;
//   - approval decisions: approving or denying a real pending tool-call
//     approval on every decision route, and client registration decisions;
//     the approval stays pending until an Approver decides it;
//   - secret operations: listing, reading, creating, rotating, resuming,
//     revoking and reloading secrets;
//   - credential operations: creating, suspending and enabling principals,
//     issuing and revoking credentials, Session Approver accounts and key
//     rotation;
//   - S3 payload access without a campaign grant: raw observation records,
//     a dataset export without a campaign, a campaign that asks for an S3
//     parameter without raw_export_grant, and an S3 parameter in the export
//     of an approved campaign that has no raw_export_grant.
//
// The same Researcher can export the approved campaign's S0/S1 dataset, so
// the refusals are the role limits and not a broken research service, and
// nothing the Researcher sent changed the state behind the routes.
func TestResearcherRoleLimits(t *testing.T) {
	needBinaries(t)
	reqtest.Verifies(t, "SR-2-2")
	priv := t.TempDir()
	pw := writeFile(t, priv, "role.pw", rolePassword+"\n", 0o600)
	hashOut, err := (&gateway{t: t}).ctlRaw("hash-password", "--password-file", pw)
	if err != nil {
		t.Fatalf("hash-password: %v %s", err, hashOut)
	}
	hash := strings.TrimSpace(hashOut[strings.LastIndex(hashOut, "$argon2id"):])
	vaultPW := writeFile(t, priv, "vault.pw", "acceptance vault passphrase 1\n", 0o600)
	g := newGateway(t, options{extra: fmt.Sprintf(`
[secrets]
key_source = "passphrase"
passphrase_file = %q

[remote]
address = "127.0.0.1:%d"

[[console.account]]
username = "rita"
password_hash = %q
role = "researcher"

[[console.account]]
username = "pat"
password_hash = %q
role = "policy_author"
`, vaultPW, testport.Free(t), hash, hash)})
	g.mustCtl("secrets", "init", "--passphrase-file", vaultPW)
	if err := os.WriteFile(filepath.Join(g.sandbox, "held.txt"), []byte("held-marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.start()
	researcher := g.consoleToken("rita", "researcher")
	author := g.consoleToken("pat", "policy_author")

	// A secret to act on, created by the Administrator.
	if code, out := g.api("POST", "/api/v1/secrets", map[string]any{"name": "svc-token", "value": "s3cr3t-value-1", "type": "token"}); code >= 300 {
		t.Fatalf("create secret: %d %v", code, out)
	}
	// A pending tool-call approval.
	cs := g.session(g.token("smcp:template:approval-demo"))
	done := make(chan error, 1)
	go func() {
		_, isErr, err := call(cs, "ref_read_file", map[string]any{"path": "held.txt"})
		if err == nil && !isErr {
			err = fmt.Errorf("the held call was released")
		} else {
			err = nil
		}
		done <- err
	}()
	approvalID := ""
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && approvalID == ""; time.Sleep(100 * time.Millisecond) {
		_, list := g.api("GET", "/api/v1/approvals?state=pending", nil)
		if items, _ := list["approvals"].([]any); len(items) > 0 {
			approvalID, _ = items[0].(map[string]any)["id"].(string)
		}
	}
	if approvalID == "" {
		t.Fatalf("no pending approval\n%s", g.logs.String())
	}

	refused := []struct{ group, method, path string }{
		{"policy publication", "POST", "/api/v1/policy/revisions"},
		{"policy publication", "POST", "/api/v1/policy/validate"},
		{"policy publication", "POST", "/api/v1/policy/rollback"},
		{"policy publication", "POST", "/admin/v1/policy/reload"},
		{"policy publication", "POST", "/api/v1/observations/audit-profile"},
		{"policy publication", "POST", "/api/v1/observations/observation-policy"},
		{"policy publication", "POST", "/api/v1/observations/anomaly-response"},
		{"policy publication", "POST", "/api/v1/baselines/snapshots"},
		{"policy publication", "POST", "/api/v1/baselines/b1/promote"},
		{"approval decision", "POST", "/api/v1/approvals/" + approvalID + "/approve"},
		{"approval decision", "POST", "/api/v1/approvals/" + approvalID + "/deny"},
		{"approval decision", "POST", "/admin/v1/approvals/" + approvalID},
		{"approval decision", "POST", "/api/v1/clients/c1/approve"},
		{"approval decision", "POST", "/api/v1/clients/c1/deny"},
		{"approval decision", "POST", "/api/v1/research/campaigns/c1/approve"},
		{"secret operation", "GET", "/api/v1/secrets"},
		{"secret operation", "GET", "/api/v1/secrets/svc-token"},
		{"secret operation", "GET", "/api/v1/secrets/svc-token/impact"},
		{"secret operation", "POST", "/api/v1/secrets"},
		{"secret operation", "POST", "/api/v1/secrets/svc-token/rotate"},
		{"secret operation", "POST", "/api/v1/secrets/svc-token/resume"},
		{"secret operation", "DELETE", "/api/v1/secrets/svc-token"},
		{"secret operation", "POST", "/api/v1/secrets/reload"},
		{"credential operation", "POST", "/api/v1/principals"},
		{"credential operation", "POST", "/api/v1/principals/claude-code-local/suspend"},
		{"credential operation", "POST", "/api/v1/principals/claude-code-local/enable"},
		{"credential operation", "POST", "/api/v1/principals/claude-code-local/credentials"},
		{"credential operation", "POST", "/api/v1/credentials/smcp-local-claude-code/revoke"},
		{"credential operation", "POST", "/api/v1/clients/c1/revoke"},
		{"credential operation", "POST", "/api/v1/approvers"},
		{"credential operation", "POST", "/api/v1/approvers/approver/remove"},
		{"credential operation", "POST", "/api/v1/keys/rotate"},
		{"S3 payload access", "GET", "/api/v1/observations"},
	}
	for _, r := range refused {
		var body any
		if r.method == "POST" {
			body = map[string]any{"reason": "researcher", "name": "x", "value": "y", "id": "p-new", "kind": "evidence", "comment": "researcher", "decision": "approve"}
		}
		if code, out := g.apiAs(researcher, r.method, r.path, body); code != http.StatusForbidden {
			t.Errorf("%s: researcher %s %s: %d %v, want 403", r.group, r.method, r.path, code, out)
		}
	}

	// Nothing the Researcher sent took effect.
	if _, a := g.api("GET", "/api/v1/approvals/"+approvalID, nil); a["state"] != "pending" {
		t.Fatalf("approval after the researcher's decisions: %v", a)
	}
	if code, s := g.api("GET", "/api/v1/secrets/svc-token", nil); code != 200 || strings.Contains(fmt.Sprint(s), "revoked") {
		t.Fatalf("secret after the researcher's operations: %d %v", code, s)
	}
	if _, p := g.api("GET", "/api/v1/principals", nil); strings.Contains(fmt.Sprint(p), "p-new") || !strings.Contains(fmt.Sprint(p), "enabled:true") || strings.Contains(fmt.Sprint(p), "enabled:false") {
		t.Fatalf("principals after the researcher's operations: %v", p)
	}
	if code, out := g.api("POST", "/api/v1/approvals/"+approvalID+"/deny", map[string]any{"comment": "SR-2-2"}); code != 200 {
		t.Fatalf("administrator deny: %d %v", code, out)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// S3 payload access without a campaign grant.
	if code, out := g.apiAs(researcher, "POST", "/api/v1/research/exports", map[string]any{"format": "csv", "parameters": []string{"raw_arguments"}}); code != http.StatusForbidden {
		t.Errorf("researcher export of raw_arguments without a campaign: %d %v", code, out)
	}
	start := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	end := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	spec := func(params ...string) map[string]any {
		return map[string]any{"name": "SR-2-2 study", "purpose": "role limits", "parameters": params, "start": start, "end": end, "quota_bytes": 1 << 20}
	}
	if code, out := g.apiAs(researcher, "POST", "/api/v1/research/campaigns", spec("tool_name", "raw_arguments")); code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out), "raw_export_grant") {
		t.Errorf("researcher campaign with raw_arguments and no grant: %d %v", code, out)
	}
	code, cp := g.apiAs(researcher, "POST", "/api/v1/research/campaigns", spec("tool_name", "request_bytes"))
	id, _ := cp["id"].(string)
	if code != http.StatusCreated || id == "" {
		t.Fatalf("researcher campaign: %d %v", code, cp)
	}
	if code, out := g.apiAs(researcher, "POST", "/api/v1/research/campaigns/"+id+"/submit", map[string]any{}); code != 200 {
		t.Fatalf("submit: %d %v", code, out)
	}
	if code, out := g.apiAs(researcher, "POST", "/api/v1/research/campaigns/"+id+"/approve", map[string]any{}); code != http.StatusForbidden {
		t.Errorf("researcher approving its own campaign: %d %v", code, out)
	}
	if code, out := g.apiAs(author, "POST", "/api/v1/research/campaigns/"+id+"/approve", map[string]any{}); code != 200 {
		t.Fatalf("policy author approval: %d %v", code, out)
	}
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		_, c := g.apiAs(researcher, "GET", "/api/v1/research/campaigns/"+id, nil)
		if c["state"] == "active" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("campaign not active: %v", c)
		}
	}
	if code, out := g.apiAs(researcher, "POST", "/api/v1/research/exports", map[string]any{"campaign_id": id, "format": "csv", "parameters": []string{"raw_arguments"}}); code != http.StatusForbidden || out["error"].(map[string]any)["code"] != "raw_export_not_granted" {
		t.Errorf("researcher export of raw_arguments from a campaign without the grant: %d %v", code, out)
	}
	if code, out := g.apiAs(researcher, "POST", "/api/v1/research/exports", map[string]any{"campaign_id": id, "format": "csv"}); code != 200 {
		t.Fatalf("researcher export of the campaign's own parameters: %d %v", code, out)
	}
	g.stop()
}
