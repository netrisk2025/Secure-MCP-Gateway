package secrets

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func usePolicyDoc(rev, purpose string) map[string]any {
	return map[string]any{
		"revision": rev,
		"slots":    []any{map[string]any{"server": "t", "name": "k", "modes": []string{"S3"}, "file_env": "K_FILE"}},
		"policies": []any{map[string]any{"id": "k", "secret": "api-key", "server": "t", "slot": "k", "mode": "S3", "tools": []string{"*"}, "purpose": purpose}},
	}
}

// TestUsePolicyAuthoring covers the Secret Use Policy routes of the G-02
// editor: read, validate, publish (file, archive, evidence, activation),
// rollback and the refusals.
func TestUsePolicyAuthoring(t *testing.T) {
	reqtest.Partial(t, "FR-8.4", "FR-3.1")
	h := newAPIHarness(t)
	var got struct {
		File      string              `json:"file"`
		Active    map[string]any      `json:"active"`
		Document  json.RawMessage     `json:"document"`
		Revisions []UsePolicyRevision `json:"revisions"`
	}
	read := func() {
		t.Helper()
		code, body := h.do("GET", "/api/v1/secret-use-policy", nil)
		if code != http.StatusOK {
			t.Fatalf("get: %d %s", code, body)
		}
		got.Document = nil
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if got.Active["revision"] != "u1" || got.File != h.svc.Settings.UsePolicyFile || len(got.Document) != 0 || len(got.Revisions) != 0 {
		t.Fatalf("initial: %+v", got)
	}

	// Validation compiles the draft like a reloaded file.
	bad := usePolicyDoc("u2", "p")
	bad["slots"].([]any)[0].(map[string]any)["server"] = "nosuch"
	if code, body := h.do("POST", "/api/v1/secret-use-policy/validate", map[string]any{"document": bad}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "unknown server") {
		t.Fatalf("validate bad: %d %s", code, body)
	}
	if code, body := h.do("POST", "/api/v1/secret-use-policy/validate", map[string]any{"document": usePolicyDoc("u2", "p")}); code != http.StatusOK || !strings.Contains(body, `"bindings":1`) {
		t.Fatalf("validate: %d %s", code, body)
	}
	if code, _ := h.do("POST", "/api/v1/secret-use-policy", map[string]any{"document": bad, "reason": "x"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("publish bad: %d", code)
	}
	// The active revision ID cannot be reused.
	if code, body := h.do("POST", "/api/v1/secret-use-policy", map[string]any{"document": usePolicyDoc("u1", "p"), "reason": "x"}); code != http.StatusConflict || !strings.Contains(body, "revision_exists") {
		t.Fatalf("reuse active: %d %s", code, body)
	}

	// Publish u2: the file, the archive, the evidence and the broker.
	if code, body := h.do("POST", "/api/v1/secret-use-policy", map[string]any{"document": usePolicyDoc("u2", "second"), "reason": "console draft"}); code != http.StatusOK || !strings.Contains(body, `"revision":"u2"`) {
		t.Fatalf("publish: %d %s", code, body)
	}
	fi, err := os.Stat(h.svc.Settings.UsePolicyFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", fi, err)
	}
	if h.svc.Broker.UsePolicy().Revision != "u2" {
		t.Fatalf("active: %s", h.svc.Broker.UsePolicy().Revision)
	}
	read()
	if got.Active["revision"] != "u2" || !strings.Contains(string(got.Document), `"second"`) || len(got.Revisions) != 1 || got.Revisions[0].Revision != "u2" {
		t.Fatalf("after publish: %+v %s", got, got.Document)
	}
	// A reloaded file gives the same policy (it survives a restart).
	if code, body := h.do("POST", "/api/v1/secrets/reload", map[string]any{}); code != http.StatusOK || !strings.Contains(body, `"revision":"u2"`) {
		t.Fatalf("reload: %d %s", code, body)
	}

	// Publish u3, then roll back to u2.
	if code, body := h.do("POST", "/api/v1/secret-use-policy", map[string]any{"document": usePolicyDoc("u3", "third"), "reason": "next"}); code != http.StatusOK {
		t.Fatalf("publish u3: %d %s", code, body)
	}
	if code, body := h.do("POST", "/api/v1/secret-use-policy", map[string]any{"document": usePolicyDoc("u2", "changed"), "reason": "x"}); code != http.StatusConflict || !strings.Contains(body, "revision_exists") {
		t.Fatalf("u2 with other content: %d %s", code, body)
	}
	if code, body := h.do("POST", "/api/v1/secret-use-policy/rollback", map[string]any{"revision": "u2", "reason": "back"}); code != http.StatusOK || !strings.Contains(body, `"action":"rolled_back"`) {
		t.Fatalf("rollback: %d %s", code, body)
	}
	read()
	if got.Active["revision"] != "u2" || !strings.Contains(string(got.Document), `"second"`) || len(got.Revisions) != 2 {
		t.Fatalf("after rollback: %+v", got)
	}
	if code, _ := h.do("POST", "/api/v1/secret-use-policy/rollback", map[string]any{"revision": "u9", "reason": ""}); code != http.StatusNotFound {
		t.Fatalf("rollback unknown: %d", code)
	}

	// Evidence of each activation, before it took effect.
	var actions []string
	for _, e := range h.tv.mem.Events() {
		if e.ReasonCode == "SECRET_USE_POLICY_ACTIVATED" {
			d, _ := e.Detail.(map[string]any)
			if a, ok := d["action"].(string); ok {
				actions = append(actions, e.PolicyRevision+":"+a)
				if d["actor"] != "operator-token" {
					t.Fatalf("actor: %v", d)
				}
			}
		}
	}
	if strings.Join(actions, ",") != "u2:published,u3:published,u2:rolled_back" {
		t.Fatalf("evidence: %v", actions)
	}

	// Without a configured file there is nowhere to publish to.
	h.svc.Settings.UsePolicyFile = ""
	if code, body := h.do("POST", "/api/v1/secret-use-policy", map[string]any{"document": usePolicyDoc("u4", "p"), "reason": "x"}); code != http.StatusConflict || !strings.Contains(body, "use_policy_file_unset") {
		t.Fatalf("no file: %d %s", code, body)
	}
}
