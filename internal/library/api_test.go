package library

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type nopCtl struct{}

func (nopCtl) Health() edge.Health                                   { return edge.Health{State: "healthy"} }
func (nopCtl) Stop(string, string) error                             { return nil }
func (nopCtl) Resume(string) error                                   { return nil }
func (nopCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

type apiFixture struct {
	t     *testing.T
	srv   *httptest.Server
	api   *adminapi.Server
	token string
}

func newAPI(t *testing.T, r *rtEnv) *apiFixture {
	t.Helper()
	if err := keys.Ensure(r.state); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	toml := fmt.Sprintf("[admin_listener]\naddress = %q\n[state]\ndir = %q\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g\"\n",
		srv.Listener.Addr().String(), r.state)
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	s, err := adminapi.New(adminapi.Options{Config: cfg, Controller: nopCtl{}, Evidence: r.rec})
	if err != nil {
		t.Fatal(err)
	}
	r.rt.RegisterRoutes(s)
	srv.Config.Handler = s.Handler()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tok, err := keys.LoadAdminToken(r.state)
	if err != nil {
		t.Fatal(err)
	}
	return &apiFixture{t: t, srv: srv, api: s, token: tok}
}

func (f *apiFixture) do(method, path, token string, body any) (int, map[string]any) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestPackagesControlAPI(t *testing.T) {
	reqtest.Partial(t, "SR-3.9-1") // FR-5.7: TestEnablementStatesAndCatalog
	r := newRuntime(t, fixtureDesc)
	if _, err := r.lib.Import(r.pkg(pkgtest.Spec{ID: "api-pkg", Revision: "2.0.0", Alias: "ap"}), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	reg := r.start(t, []config.Server{{Alias: "fx", Package: "fx-id"}})
	f := newAPI(t, r)

	// Unauthenticated callers, including harness session tokens, are refused.
	for _, tok := range []string{"", "not-a-token"} {
		if st, _ := f.do("POST", "/api/v1/packages/api-pkg/2.0.0/enable", tok, map[string]any{}); st != http.StatusUnauthorized {
			t.Fatalf("enable with token %q: %d", tok, st)
		}
	}
	if rev, _ := r.lib.Get("api-pkg", "2.0.0"); rev.State != StateVerifiedDisabled {
		t.Fatal("enabled without authentication")
	}
	st, out := f.do("GET", "/api/v1/packages", f.token, nil)
	if st != 200 || len(out["revisions"].([]any)) != 2 || len(out["servers"].([]any)) != 1 || len(out["trust_anchors"].([]any)) != 1 {
		t.Fatalf("list: %d %v", st, out)
	}
	st, out = f.do("GET", "/api/v1/packages/api-pkg/2.0.0", f.token, nil)
	if st != 200 || out["manifest"] == nil || out["provenance"] == nil {
		t.Fatalf("detail: %d %v", st, out)
	}
	if st, _ = f.do("GET", "/api/v1/packages/nope/1", f.token, nil); st != http.StatusNotFound {
		t.Fatalf("unknown: %d", st)
	}
	st, out = f.do("POST", "/api/v1/packages/api-pkg/2.0.0/enable", f.token, map[string]any{"alias": "ap2"})
	if st != 200 || out["restart_required"] != true || out["revision"].(map[string]any)["state"] != StateEnabled || out["revision"].(map[string]any)["state_actor"] != "operator-token" {
		t.Fatalf("enable: %d %v", st, out)
	}
	if st, out = f.do("POST", "/api/v1/packages/api-pkg/2.0.0/enable", f.token, map[string]any{"bogus": 1}); st != http.StatusBadRequest {
		t.Fatalf("bad body: %d %v", st, out)
	}
	// Disabling the running server tears its instance down.
	st, out = f.do("POST", "/api/v1/packages/fx-id/1/disable", f.token, map[string]any{"reason": "maintenance"})
	if st != 200 || reg.Resolve("fx_echo") != nil {
		t.Fatalf("disable: %d %v", st, out)
	}
	if st, out = f.do("POST", "/api/v1/packages/fx-id/1/retire", f.token, map[string]any{}); st != 200 {
		t.Fatalf("retire: %d %v", st, out)
	}
	st, out = f.do("POST", "/api/v1/packages/fx-id/1/enable", f.token, map[string]any{})
	if st != http.StatusConflict || !strings.Contains(fmt.Sprint(out["error"]), ReasonState) {
		t.Fatalf("enable retired: %d %v", st, out)
	}
	if st, out = f.do("POST", "/api/v1/packages/scan", f.token, map[string]any{}); st != 200 || out["imported"] == nil {
		t.Fatalf("scan: %d %v", st, out)
	}
	if st, out = f.do("GET", "/api/v1/packages/receipts", f.token, nil); st != 200 || len(out["receipts"].([]any)) < 2 {
		t.Fatalf("receipts: %d %v", st, out)
	}
}
