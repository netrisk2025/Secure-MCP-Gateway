package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/openapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

const root = "../.."

type nopCtl struct{}

func (nopCtl) Health() edge.Health                                   { return edge.Health{} }
func (nopCtl) Stop(string, string) error                             { return nil }
func (nopCtl) Resume(string) error                                   { return nil }
func (nopCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

// TestSourceRoutesMatchRegistration registers the base control API, the
// approval routes (Handle, HandleRoles and HandlePublic all occur) and the
// OpenAPI route on a real adminapi.Server, and checks that the routes found
// in the sources describe each of them exactly as the server recorded it.
func TestSourceRoutesMatchRegistration(t *testing.T) {
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
	(&approval.Service{}).Register(s)
	openapi.Register(s)

	src, err := SourceRoutes(root)
	if err != nil {
		t.Fatal(err)
	}
	byPattern := map[string]adminapi.RouteInfo{}
	for _, r := range src {
		byPattern[r.Pattern] = r
	}
	served := s.Routes()
	if len(served) < 15 {
		t.Fatalf("only %d routes registered", len(served))
	}
	for _, want := range served {
		got, ok := byPattern[want.Pattern]
		if !ok {
			t.Errorf("%s: registered but not found in the sources", want.Pattern)
			continue
		}
		if got.Public != want.Public || got.Refined != want.Refined || !slices.Equal(got.Roles, want.Roles) {
			t.Errorf("%s: sources %+v, registered %+v", want.Pattern, got, want)
		}
	}
	if r := byPattern["GET /api/v1/approvals"]; !slices.Contains(r.Roles, adminapi.RoleApprover) {
		t.Errorf("approvals list roles %v", r.Roles)
	}
}

// TestEveryOperationHasRoles checks that every operation of the generated
// document carries either x-smcp-public or x-smcp-roles, so no route is
// described without its permissions.
func TestEveryOperationHasRoles(t *testing.T) {
	b, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for path, item := range doc.Paths {
		for method, op := range item {
			n++
			_, public := op["x-smcp-public"]
			roles, _ := op["x-smcp-roles"].([]any)
			if !public && (len(roles) == 0 || roles[0] != adminapi.RoleAdministrator) {
				t.Errorf("%s %s: no roles (%v)", strings.ToUpper(method), path, op["x-smcp-roles"])
			}
		}
	}
	if n < 60 {
		t.Fatalf("only %d operations", n)
	}
}

// TestCommittedDocumentIsCurrent fails when site/data/openapi.json differs
// from what the sources produce. Fix: `make openapi` and commit the file
// (the regenerate workflow does this on pull requests).
func TestCommittedDocumentIsCurrent(t *testing.T) {
	if err := run(root, DefaultOut, true); err != nil {
		t.Fatal(err)
	}
}

func TestRunWritesAndChecks(t *testing.T) {
	out := filepath.Join(t.TempDir(), "openapi.json")
	if err := run(root, out, true); err == nil {
		t.Fatal("check of a missing file passed")
	}
	if err := run(root, out, false); err != nil {
		t.Fatal(err)
	}
	if err := run(root, out, true); err != nil {
		t.Fatalf("check after write: %v", err)
	}
	if err := os.WriteFile(out, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(root, out, true); err == nil || !strings.Contains(err.Error(), "make openapi") {
		t.Fatalf("stale file: %v", err)
	}
}
