package e2e

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAuthorizationMetadataDocuments is FR-2.17: the harness listener
// publishes RFC 9728 protected-resource metadata and RFC 8414
// authorization-server metadata, both valid against their RFCs' rules and
// naming the CP-41 values.
//
// RFC 9728: served at /.well-known/oauth-protected-resource and at the
// path-suffixed form for the /mcp resource (section 3.1); resource is
// present and equals the CP-41 resource URI (section 3.3); every
// authorization server is an issuer URL; bearer_methods_supported holds
// only defined values; scopes_supported is a JSON array.
//
// RFC 8414: issuer is present, an https URL without query or fragment, and
// the metadata URL is issuer + /.well-known/oauth-authorization-server
// (section 3.3); authorization_endpoint, token_endpoint and
// response_types_supported are present (section 2); the Gateway's own
// endpoints are named; S256 is the only code-challenge method; the scopes
// are the CP-41 smcp: scopes (one template scope per template a Framework
// Profile offers, and the template, purpose, project and user patterns).
// The local listener advertises no registration endpoint.
func TestAuthorizationMetadataDocuments(t *testing.T) {
	reqtest.Verifies(t, "FR-2.17")
	f := start(t, "")
	resource := f.cfg.ResourceURI()
	if u, err := url.Parse(resource); err != nil || u.Scheme != "https" || u.Path != "/mcp" {
		t.Fatalf("CP-41 resource URI %q", resource)
	}
	strs := func(v any) []string {
		var out []string
		arr, ok := v.([]any)
		if !ok {
			t.Fatalf("not a JSON array: %#v", v)
		}
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				t.Fatalf("not a string: %#v", e)
			}
			out = append(out, s)
		}
		return out
	}
	wantScopes := []string{"smcp:template:ro", "smcp:template:rw"}

	var issuers []string
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		r, b := f.get(f.base + path)
		var prm map[string]any
		if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || json.Unmarshal(b, &prm) != nil {
			t.Fatalf("%s: %d %s %s", path, r.StatusCode, r.Header.Get("Content-Type"), b)
		}
		if prm["resource"] != resource {
			t.Fatalf("%s: resource %v, want %s", path, prm["resource"], resource)
		}
		issuers = strs(prm["authorization_servers"])
		if len(issuers) != 1 || issuers[0] != f.base {
			t.Fatalf("%s: authorization_servers %v", path, issuers)
		}
		for _, m := range strs(prm["bearer_methods_supported"]) {
			if !slices.Contains([]string{"header", "body", "query"}, m) {
				t.Fatalf("%s: bearer method %q", path, m)
			}
		}
		if got := strs(prm["scopes_supported"]); !slices.Equal(got, wantScopes) {
			t.Fatalf("%s: scopes_supported %v", path, got)
		}
	}

	r, b := f.get(issuers[0] + "/.well-known/oauth-authorization-server")
	var asm map[string]any
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || json.Unmarshal(b, &asm) != nil {
		t.Fatalf("ASM: %d %s", r.StatusCode, b)
	}
	iss, _ := asm["issuer"].(string)
	u, err := url.Parse(iss)
	if err != nil || iss != issuers[0] || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatalf("issuer %q", iss)
	}
	for k, want := range map[string]string{"authorization_endpoint": iss + "/oauth/authorize", "token_endpoint": iss + "/oauth/token"} {
		if asm[k] != want {
			t.Fatalf("%s %v, want %s", k, asm[k], want)
		}
	}
	if rt := strs(asm["response_types_supported"]); !slices.Equal(rt, []string{"code"}) {
		t.Fatalf("response_types_supported %v", rt)
	}
	if m := strs(asm["code_challenge_methods_supported"]); !slices.Equal(m, []string{"S256"}) {
		t.Fatalf("code_challenge_methods_supported %v", m)
	}
	if g := strs(asm["grant_types_supported"]); !slices.Contains(g, "authorization_code") || slices.Contains(g, "implicit") || slices.Contains(g, "password") {
		t.Fatalf("grant_types_supported %v", g)
	}
	if s := strs(asm["scopes_supported"]); !slices.Equal(s, wantScopes) {
		t.Fatalf("scopes_supported %v", s)
	}
	patterns := strings.Join(strs(asm["smcp_scope_patterns"]), " ")
	for _, p := range []string{"smcp:template:", "smcp:purpose:", "smcp:project:", "smcp:user:"} {
		if !strings.Contains(patterns, p) {
			t.Fatalf("scope patterns %q lack %s", patterns, p)
		}
	}
	if asm["authorization_response_iss_parameter_supported"] != true {
		t.Fatal("iss parameter not advertised (RFC 9207)")
	}
	if _, ok := asm["registration_endpoint"]; ok {
		t.Fatal("the local listener advertises a registration endpoint")
	}
}
