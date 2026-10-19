package session

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSessionContextKey: a session records, at creation, the Observation
// Policy in force and its baseline context key from that policy's context
// dimensions (the session-scoped ones, in the policy's order); sessions
// created under policies with different dimensions store different keys,
// and an existing session keeps its key when the policy changes (FR-2.13).
// Every create response, through the token endpoint and through the session
// API, carries the session ID, token, expiry, template ID, policy revision
// ID and Observation Policy ID, and the creation event records the key
// (FR-2.4).
func TestSessionContextKey(t *testing.T) {
	reqtest.Verifies(t, "FR-2.13", "FR-2.4")
	f := newOAuthFixture(t, authguard.Config{})
	policyID, dims := "obs-a", []string{"principal", "tool"}
	f.store.SetObservationContext(func() (string, []string) { return policyID, dims })

	st, body := f.redeem(f.code(), verifier, redirect)
	if st != 200 {
		t.Fatalf("redeem: %d %v", st, body)
	}
	for _, k := range []string{"session_id", "access_token", "expires_at", "template_id", "policy_revision_id"} {
		if s, _ := body[k].(string); s == "" {
			t.Fatalf("token response lacks %s: %v", k, body)
		}
	}
	if body["observation_policy_id"] != "obs-a" {
		t.Fatalf("token response observation policy %v", body["observation_policy_id"])
	}
	first := f.store.Get(body["session_id"].(string))
	if first == nil {
		t.Fatal("first session not stored")
	}
	if first.ObservationPolicy != "obs-a" || first.ContextKey != "principal=cc" {
		t.Fatalf("first session: policy %q key %q", first.ObservationPolicy, first.ContextKey)
	}

	// A policy with other dimensions: new sessions store its key.
	policyID, dims = "obs-b", []string{"hour", "session_template", "framework_type", "principal", "end_user"}
	req, _ := http.NewRequest("POST", f.srv.URL+pathSessions, strings.NewReader(`{"template":"rw","end_user":"ethan","harness_version":"1"}`))
	req.SetBasicAuth("helper", "helper-secret-123")
	req.Header.Set("Content-Type", "application/json")
	r, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var api map[string]any
	_ = json.NewDecoder(r.Body).Decode(&api)
	if r.StatusCode != 200 && r.StatusCode != 201 {
		t.Fatalf("session API: %d %v", r.StatusCode, api)
	}
	for _, k := range []string{"session_id", "access_token", "expires_at", "template_id", "policy_revision_id"} {
		if s, _ := api[k].(string); s == "" {
			t.Fatalf("session API response lacks %s: %v", k, api)
		}
	}
	if api["observation_policy_id"] != "obs-b" {
		t.Fatalf("session API observation policy %v", api["observation_policy_id"])
	}
	second := f.store.Get(api["session_id"].(string))
	if second == nil {
		t.Fatal("second session not stored")
	}
	want := "session_template=" + second.Template + "|framework_type=claude-code|principal=cc|end_user=" + second.EndUser
	if second.ObservationPolicy != "obs-b" || second.ContextKey != want {
		t.Fatalf("second session: policy %q key %q, want %q", second.ObservationPolicy, second.ContextKey, want)
	}
	if again := f.store.Get(first.ID); again.ContextKey != "principal=cc" || again.ObservationPolicy != "obs-a" {
		t.Fatalf("first session's key changed: %+v", again)
	}

	// The creation events record the policy and key.
	keys := map[string]string{}
	for _, e := range f.rec.Events() {
		if e.Class == "session" && e.Outcome == "created" {
			d, _ := e.Detail.(map[string]string)
			keys[e.SessionID] = d["observation_policy"] + " " + d["context_key"]
		}
	}
	if keys[first.ID] != "obs-a principal=cc" || keys[second.ID] != "obs-b "+want {
		t.Fatalf("creation events: %v", keys)
	}
}
