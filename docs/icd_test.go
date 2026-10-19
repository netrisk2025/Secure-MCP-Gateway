package docs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestInterfaceControlDocuments is FR-1.48: the release archive includes
// the X-01 and X-12 interface control documents (.goreleaser.yaml), X-01
// covers the OAuth endpoints and scopes, the session API, the required
// headers, the error codes, both protocol eras and the conformance
// fixtures, and X-12 gives the adapter hooks of every framework in the
// client matrix.
func TestInterfaceControlDocuments(t *testing.T) {
	reqtest.Verifies(t, "FR-1.48")
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	x01 := read("icd/x-01-harness-interface.md")
	for topic, needles := range map[string][]string{
		"OAuth endpoints":     {"/oauth/authorize", "/oauth/token", "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource"},
		"scopes":              {"smcp:template:", "smcp:purpose:", "smcp:project:", "smcp:user:"},
		"session API":         {"/smcp/v1/sessions", "local.smcpgw/authenticate"},
		"required headers":    {"MCP-Protocol-Version", "Mcp-Method", "Mcp-Name", "Authorization: Bearer"},
		"error codes":         {"-31001", "-31002", "-31003", "-31004", "-31005", "-31006", "-31007", "-31008", "-31009", "-31010", "-32020", "-32601", "-32602"},
		"both eras":           {"2026-07-28", "2025-11-25", "initialize", "server/discover"},
		"conformance fixture": {"mcp-spec/2026-07-28/schema/examples", "internal/conformance"},
	} {
		for _, n := range needles {
			if !strings.Contains(x01, n) {
				t.Errorf("X-01 ICD: %s: %q not covered", topic, n)
			}
		}
	}
	x12 := read("icd/x-12-adapter-hooks.md")
	var matrix struct {
		Clients []struct {
			Client string `json:"client"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(read("clients/matrix.json")), &matrix); err != nil {
		t.Fatal(err)
	}
	if len(matrix.Clients) == 0 {
		t.Fatal("empty client matrix")
	}
	for _, c := range matrix.Clients {
		name := strings.Split(c.Client, " (")[0]
		if !strings.Contains(x12, name) {
			t.Errorf("X-12 ICD: no hooks for %s", c.Client)
		}
	}
	for _, n := range []string{"headersHelper", "http_headers_helper", "smcp-session", "smcp-stdio", "smcp-connect", "credentials.toml", "0600"} {
		if !strings.Contains(x12, n) {
			t.Errorf("X-12 ICD: %q not covered", n)
		}
	}
	if !strings.Contains(read("../.goreleaser.yaml"), "src: docs/icd/*.md") {
		t.Error(".goreleaser.yaml does not put docs/icd into the release archives")
	}
}
