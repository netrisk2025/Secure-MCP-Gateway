package remote_test

import (
	"encoding/json"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAuthorizationMetadataTruthful: registration_endpoint is advertised
// only by the Remote Access listener, and only once remote access is
// enabled; client_id_metadata_document_supported is never advertised,
// because metadata documents are not fetched (SR-2.11-5; SR-2.11-3 is in
// Appendix N).
func TestAuthorizationMetadataTruthful(t *testing.T) {
	reqtest.Verifies(t, "SR-2.11-5")
	e := newEnv(t, "")
	meta := func(u string) (int, map[string]any) {
		resp, b := e.get(u + "/.well-known/oauth-authorization-server")
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return resp.StatusCode, m
	}
	local := e.Config.Listener.PublicURL
	check := func(when string) {
		t.Helper()
		st, m := meta(local)
		if st != 200 || m["issuer"] != local {
			t.Fatalf("%s: local metadata %d %v", when, st, m)
		}
		if _, ok := m["registration_endpoint"]; ok {
			t.Fatalf("%s: the local listener advertises registration", when)
		}
		if _, ok := m["client_id_metadata_document_supported"]; ok {
			t.Fatalf("%s: metadata documents advertised", when)
		}
	}
	check("remote off")
	if resp, _ := e.get(e.public + "/.well-known/oauth-authorization-server"); resp.StatusCode == 200 {
		t.Fatal("remote metadata served while remote access is off")
	}
	e.enable()
	check("remote on")
	st, m := meta(e.public)
	if st != 200 || m["registration_endpoint"] != e.public+"/oauth/register" {
		t.Fatalf("remote metadata %d %v", st, m)
	}
	if _, ok := m["client_id_metadata_document_supported"]; ok {
		t.Fatal("remote metadata advertises metadata documents")
	}
}
