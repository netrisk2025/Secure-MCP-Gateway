package principals

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

const testPolicy = `{"revision":"r1","framework_profiles":{"dev":{"templates":["ro"],"default_template":"ro"}},
"templates":{"ro":{"rules":[{"id":"ro-fs","server":"fs","tools":["read"]}]}}}`

func testConfig(t *testing.T, addr string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(`[admin_listener]
address = %q
[state]
dir = %q
[policy]
file = %q
[admin]
username = "admin"
password_hash = "$argon2id$x"
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = "c1"
principal = "cc"
redirect_uris = ["http://localhost/cb"]
`, addr, dir, filepath.Join(dir, "policy.json"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Policy.File, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDirectory(t *testing.T) {
	reqtest.Partial(t, "FR-8.19", "FR-2.18")
	cfg := testConfig(t, "127.0.0.1:0")
	d, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetDirectory(d)
	profiles := []string{"dev"}
	for _, bad := range []Principal{
		{ID: "Bad ID", Framework: "codex", Profile: "dev"},
		{ID: "ok", Framework: "unknown", Profile: "dev"},
		{ID: "ok", Framework: "codex", Profile: "nope"},
		{ID: "cc", Framework: "codex", Profile: "dev"}, // in the file
	} {
		if _, err := d.AddPrincipal(bad, profiles, "admin:admin"); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := d.AddPrincipal(Principal{ID: "agent", Framework: "codex", DisplayName: "Agent", Profile: "dev"}, profiles, "admin:admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddPrincipal(Principal{ID: "agent", Framework: "codex", Profile: "dev"}, profiles, "admin:admin"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if p := cfg.FindPrincipal("agent"); p == nil || p.Enabled == nil || !*p.Enabled || p.Profile != "dev" {
		t.Fatalf("FindPrincipal agent: %+v", p)
	}
	// Suspending a file principal shows through FindPrincipal.
	if err := d.SetSuspended("cc", true, "admin:admin", "test"); err != nil {
		t.Fatal(err)
	}
	if p := cfg.FindPrincipal("cc"); p == nil || *p.Enabled {
		t.Fatal("suspended file principal still enabled")
	}
	if err := d.SetSuspended("cc", false, "admin:admin", ""); err != nil || !*cfg.FindPrincipal("cc").Enabled {
		t.Fatalf("enable: %v", err)
	}
	if err := d.SetSuspended("ghost", true, "a", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown principal: %v", err)
	}
	// Credentials.
	if _, _, err := d.Issue("agent", []string{"http://evil.example/cb"}, false, "a"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-loopback http redirect: %v", err)
	}
	c, secret, err := d.Issue("agent", []string{"https://agent.example/cb"}, true, "admin:admin")
	if err != nil || secret == "" || !strings.HasPrefix(c.SecretHash, "$argon2id$") || !keys.VerifyPassword(c.SecretHash, secret) {
		t.Fatalf("issue: %v %+v", err, c)
	}
	if cl := cfg.FindClient(c.ClientID); cl == nil || cl.Principal != "agent" || cl.ClientSecretHash != c.SecretHash {
		t.Fatalf("FindClient: %+v", cl)
	}
	pub, secret2, err := d.Issue("cc", []string{"http://127.0.0.1:51234/callback"}, false, "admin:admin")
	if err != nil || secret2 != "" || pub.SecretHash != "" {
		t.Fatalf("public credential: %v %q", err, secret2)
	}
	// Persisted, and readable again; the file holds no secret.
	raw, _ := os.ReadFile(filepath.Join(cfg.State.Dir, File))
	if strings.Contains(string(raw), secret) {
		t.Fatal("secret stored in clear")
	}
	if st, _ := os.Stat(filepath.Join(cfg.State.Dir, File)); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	d2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d2.Client(c.ClientID); !ok {
		t.Fatal("credential not persisted")
	}
	if _, err := d.Revoke(c.ClientID, "admin:admin"); err != nil || cfg.FindClient(c.ClientID) != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := d.Revoke(c.ClientID, "a"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := d.Revoke("c1", "a"); !errors.Is(err, ErrFromFile) {
		t.Fatalf("file client: %v", err)
	}
	list := d.List()
	if len(list) != 2 || list[0].ID != "agent" || list[0].Source != "console" || list[1].Source != "file" || len(list[1].Credentials) != 2 {
		t.Fatalf("list: %+v", list)
	}
}

type fakeCtl struct{}

func (fakeCtl) Health() edge.Health                                   { return edge.Health{State: "healthy", Causes: []string{}} }
func (fakeCtl) Stop(string, string) error                             { return nil }
func (fakeCtl) Resume(string) error                                   { return nil }
func (fakeCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

// TestRoutes creates a principal, issues a credential, opens a session for
// it, suspends the principal (which suspends the session and refuses new
// ones) and revokes the credential (which terminates the session).
func TestRoutes(t *testing.T) {
	reqtest.Partial(t, "FR-8.19")
	srv := httptest.NewUnstartedServer(nil)
	cfg := testConfig(t, srv.Listener.Addr().String())
	snap, err := policy.Load(cfg.Policy.File)
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	admin, err := adminapi.New(adminapi.Options{Config: cfg, Controller: fakeCtl{}, Evidence: mem})
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewStore(cfg, func() *policy.Snapshot { return snap })
	d, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetDirectory(d)
	// Gate stands for edge.Gateway.Serialize: it records which directory
	// changes ran inside it (SR-1.16-1).
	var gated []string
	gate := func(fn func()) {
		before := fmt.Sprint(d.List())
		fn()
		gated = append(gated, before+" -> "+fmt.Sprint(d.List()))
	}
	(&Service{Dir: d, Sessions: store, Snapshot: func() *policy.Snapshot { return snap }, Evidence: mem, Gate: gate}).Register(admin)
	srv.Config.Handler = admin.Handler()
	srv.StartTLS()
	defer srv.Close()
	op, _ := keys.LoadAdminToken(cfg.State.Dir)
	do := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+op)
		r, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode, out
	}
	if code, out := do("POST", "/api/v1/principals", map[string]any{"id": "agent", "framework": "codex", "display_name": "Agent", "profile": "missing"}); code != 400 {
		t.Fatalf("bad profile: %d %v", code, out)
	}
	if code, out := do("POST", "/api/v1/principals", map[string]any{"id": "agent", "framework": "codex", "display_name": "Agent", "profile": "dev"}); code != 201 || out["id"] != "agent" {
		t.Fatalf("create: %d %v", code, out)
	}
	code, out := do("POST", "/api/v1/principals/agent/credentials", map[string]any{"redirect_uris": []string{"http://127.0.0.1:5000/cb"}, "confidential": true})
	clientID, _ := out["client_id"].(string)
	if code != 201 || clientID == "" || out["client_secret"] == nil {
		t.Fatalf("issue: %d %v", code, out)
	}
	sess, _, err := store.Create(session.CreateParams{PrincipalID: "agent", ClientID: clientID, Listener: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	code, out = do("GET", "/api/v1/principals", nil)
	if code != 200 || strings.Contains(fmt.Sprint(out), "argon2") || !strings.Contains(fmt.Sprint(out), clientID) {
		t.Fatalf("list: %d %v", code, out)
	}
	code, out = do("POST", "/api/v1/principals/agent/suspend", map[string]any{"reason": "investigating"})
	if code != 200 || len(out["suspended_sessions"].([]any)) != 1 || store.Get(sess.ID).State != session.StateSuspended {
		t.Fatalf("suspend principal: %d %v", code, out)
	}
	if _, _, err := store.Create(session.CreateParams{PrincipalID: "agent", ClientID: clientID, Listener: "tls"}); !errors.Is(err, session.ErrUnknownPrincipal) {
		t.Fatalf("suspended principal opened a session: %v", err)
	}
	if code, _ := do("POST", "/api/v1/principals/agent/enable", map[string]any{}); code != 200 {
		t.Fatalf("enable: %d", code)
	}
	if code, out := do("POST", "/api/v1/credentials/c1/revoke", map[string]any{}); code != 409 || out["error"].(map[string]any)["code"] != "defined_in_file" {
		t.Fatalf("revoke file client: %d %v", code, out)
	}
	code, out = do("POST", "/api/v1/credentials/"+clientID+"/revoke", map[string]any{"reason": "rotated"})
	if code != 200 || len(out["terminated_sessions"].([]any)) != 1 || store.Get(sess.ID).State != session.StateTerminated || cfg.FindClient(clientID) != nil {
		t.Fatalf("revoke: %d %v", code, out)
	}
	// Suspend, enable and revoke each changed the directory inside the
	// gate, and the revoked credential is reported to the launch recheck
	// (SR-1.17-1).
	if len(gated) != 3 {
		t.Fatalf("%d revocations through the gate: %v", len(gated), gated)
	}
	for _, g := range gated {
		if before, after, _ := strings.Cut(g, " -> "); before == after {
			t.Fatalf("a gated revocation changed nothing inside the gate: %s", g)
		}
	}
	if !cfg.CredentialRevoked(clientID) || cfg.CredentialRevoked("c1") {
		t.Fatal("credential revocation state")
	}
	seen := map[string]bool{}
	for _, e := range mem.Events() {
		seen[e.ReasonCode] = true
	}
	for _, rc := range []string{"PRINCIPAL_CREATED", "CREDENTIAL_ISSUED", "PRINCIPAL_SUSPENDED", "PRINCIPAL_ENABLED", "CREDENTIAL_REVOKED"} {
		if !seen[rc] {
			t.Errorf("%s not recorded", rc)
		}
	}
	// A journal failure refuses the change.
	mem.Fail(errors.New("disk full"))
	if code, _ := do("POST", "/api/v1/principals", map[string]any{"id": "other", "framework": "codex", "profile": "dev"}); code != 503 || cfg.FindPrincipal("other") != nil {
		t.Fatalf("create without evidence: %d", code)
	}
}
