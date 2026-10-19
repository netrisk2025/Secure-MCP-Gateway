package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type fakeController struct{}

func (fakeController) Health() edge.Health                                   { return edge.Health{State: "healthy"} }
func (fakeController) Stop(string, string) error                             { return nil }
func (fakeController) Resume(string) error                                   { return nil }
func (fakeController) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

type apiHarness struct {
	t     *testing.T
	srv   *httptest.Server
	token string
	tv    *testVault
	svc   *Service
}

func newAPIHarness(t *testing.T) *apiHarness {
	t.Helper()
	h := &apiHarness{t: t, tv: newTestVault(t)}
	state := filepath.Join(t.TempDir(), "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	h.srv = httptest.NewUnstartedServer(nil)
	addr := h.srv.Listener.Addr().String()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
[admin_listener]
address = %q
[state]
dir = %q
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[server]]
alias = "t"
command = "/inproc/t"
[secrets]
use_policy_file = %q
`, addr, state, filepath.Join(t.TempDir(), "missing.json"))))
	if err != nil {
		t.Fatal(err)
	}
	use, err := CompileUsePolicy([]byte(`{"revision": "u1", "slots": [{"server": "t", "name": "k", "modes": ["S3"], "file_env": "K_FILE"}],
	  "policies": [{"id": "k", "secret": "api-key", "server": "t", "slot": "k", "mode": "S3", "tools": ["*"], "purpose": "p"}]}`), cfg.Servers)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBroker(BrokerOptions{Vault: h.tv.v, Use: use, Servers: cfg.Servers, RuntimeDir: filepath.Join(t.TempDir(), "run"), Evidence: h.tv.mem, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := SettingsFrom(cfg)
	h.svc = &Service{Settings: st, Vault: h.tv.v, Broker: b, cfg: cfg, log: diag.Discard()}
	admin, err := adminapi.New(adminapi.Options{Config: cfg, Controller: fakeController{}, Evidence: h.tv.mem, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.Attach(admin, nil)
	h.srv.Config.Handler = admin.Handler()
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
	if h.token, err = keys.LoadAdminToken(state); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *apiHarness) do(method, path string, body any) (int, string) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	req.Host = h.srv.Listener.Addr().String()
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestControlAPIReadsNeverReturnValues(t *testing.T) {
	reqtest.Verifies(t, "FR-6.2")
	reqtest.Partial(t, "FR-6.1", "FR-6.12")
	h := newAPIHarness(t)
	v1, v2 := "api-key-value-0123456789", "api-key-value-rotated-9876"
	code, body := h.do("POST", "/api/v1/secrets", map[string]any{"name": "api-key", "type": "api_key", "description": "vendor", "value": v1})
	if code != http.StatusCreated || !strings.Contains(body, `"current_version":1`) {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, body := h.do("POST", "/api/v1/secrets/api-key/rotate", map[string]any{"value": v2, "overlap": "1h"}); code != http.StatusOK || !strings.Contains(body, `"current_version":2`) {
		t.Fatalf("rotate: %d %s", code, body)
	}
	// The impact report names the binding.
	if code, body := h.do("GET", "/api/v1/secrets/api-key/impact", nil); code != http.StatusOK || !strings.Contains(body, `"use_policy":"k"`) {
		t.Fatalf("impact: %d %s", code, body)
	}
	// Every read operation: metadata only, no value and no ciphertext.
	var reads []string
	for _, p := range []string{"/api/v1/secrets", "/api/v1/secrets/api-key", "/api/v1/secrets/api-key/impact"} {
		code, body := h.do("GET", p, nil)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", p, code, body)
		}
		reads = append(reads, body)
	}
	_, created := h.do("POST", "/api/v1/secrets", map[string]any{"name": "other", "value": "another-value-123456"})
	reads = append(reads, created)
	for _, body := range reads {
		for _, needle := range []string{v1, v2, v1[4:16], base64.StdEncoding.EncodeToString([]byte(v1)), "age-encryption", "YWdlLWVuY3J5cHRpb24", "ciphertext", "another-value"} {
			if strings.Contains(body, needle) {
				t.Fatalf("read returned %q: %s", needle, body)
			}
		}
	}
	// Errors.
	for _, c := range []struct {
		method, path string
		body         any
		code         int
	}{
		{"POST", "/api/v1/secrets", map[string]any{"name": "api-key", "value": "duplicate-value-1"}, http.StatusConflict},
		{"POST", "/api/v1/secrets", map[string]any{"name": "Bad Name", "value": "valid-value-1234"}, http.StatusBadRequest},
		{"POST", "/api/v1/secrets", map[string]any{"name": "nov"}, http.StatusBadRequest},
		{"POST", "/api/v1/secrets/api-key/rotate", map[string]any{"value": "x"}, http.StatusBadRequest},
		{"POST", "/api/v1/secrets/api-key/rotate", map[string]any{"value": "long-enough-value", "overlap": "48h"}, http.StatusBadRequest},
		{"GET", "/api/v1/secrets/nope", nil, http.StatusNotFound},
		{"POST", "/api/v1/secrets/reload", map[string]any{}, http.StatusUnprocessableEntity},
	} {
		if code, body := h.do(c.method, c.path, c.body); code != c.code {
			t.Errorf("%s %s: %d %s", c.method, c.path, code, body)
		}
	}
	if code, body := h.do("POST", "/api/v1/secrets/api-key/resume", map[string]any{}); code != http.StatusOK || !strings.Contains(body, `"resumed":false`) {
		t.Fatalf("resume: %d %s", code, body)
	}
	if code, _ := h.do("DELETE", "/api/v1/secrets/api-key", nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := h.do("GET", "/api/v1/secrets/api-key", nil); code != http.StatusNotFound {
		t.Fatal("deleted secret still readable")
	}
	// Unauthenticated requests are refused by the control API.
	h.token = ""
	if code, _ := h.do("GET", "/api/v1/secrets", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", code)
	}
	// Evidence names the actor and never the value.
	ev, _ := json.Marshal(h.tv.mem.Events())
	if strings.Contains(string(ev), v1) || strings.Contains(string(ev), v2) || !strings.Contains(string(ev), "operator-token") {
		t.Fatal("evidence of control API changes")
	}
}
