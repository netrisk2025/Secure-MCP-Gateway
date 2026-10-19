package filterapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type nopCtl struct{}

func (nopCtl) Health() edge.Health                                   { return edge.Health{} }
func (nopCtl) Stop(string, string) error                             { return nil }
func (nopCtl) Resume(string) error                                   { return nil }
func (nopCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

func TestScanRoutes(t *testing.T) {
	reqtest.Partial(t, "FR-8.27")
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("[admin_listener]\naddress = \"127.0.0.1:8444\"\n[state]\ndir = \"" + dir + "\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := adminapi.New(adminapi.Options{Config: cfg, Controller: nopCtl{}, Evidence: &audit.Memory{}})
	if err != nil {
		t.Fatal(err)
	}
	RegisterRoutes(s, cfg)
	tok, _ := keys.LoadAdminToken(dir)
	do := func(method, path, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Host = "127.0.0.1:8444"
		req.Header.Set("Authorization", "Bearer "+tok)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, list := do("GET", "/api/v1/filters", "")
	if code != 200 || len(list["request"].([]any)) == 0 || len(list["rule_sets"].([]any)) == 0 || len(list["mandatory_response"].([]any)) == 0 {
		t.Fatalf("list: %d %v", code, list)
	}
	code, rep := do("POST", "/api/v1/filters/scan", `{"stage":"response","filters":["pii-detect"],"input":"mail jane@example.com"}`)
	if code != 200 || rep["disposition"] != "redact" {
		t.Fatalf("scan: %d %v", code, rep)
	}
	if code, _ := do("POST", "/api/v1/filters/scan", `{"stage":"nope"}`); code != 400 {
		t.Fatalf("bad stage: %d", code)
	}
	if code, _ := do("POST", "/api/v1/filters/scan", `{"unknown":1}`); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}
}
