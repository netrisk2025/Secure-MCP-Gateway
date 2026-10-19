package library

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestManifestEgressLimits: the egress limits a signed manifest declares
// per destination (FR-5.38) survive import and are served for the packaged
// server's alias once it is resolved, for the Egress Broker's manifest
// source; an alias without a packaged revision has none.
func TestManifestEgressLimits(t *testing.T) {
	reqtest.Partial(t, "FR-5.38")
	e := newEnv(t)
	rules := []packaging.EgressRule{
		{Host: "api.example.com", Ports: []int{443}, Methods: []string{"GET"}, RequestBytes: 1000, ResponseBytes: 2000, TimeoutMS: 300},
		{Host: "*.cdn.example.com", Ports: []int{443}, Methods: []string{"GET"}},
	}
	dir := e.pkg(pkgtest.Spec{ID: "lim-id", Revision: "1", Edit: func(m *packaging.Manifest, _ *packaging.Provenance) {
		m.Capabilities.Egress = rules
	}})
	if _, err := e.lib.Import(dir, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.lib.Enable("lim-id", "1", EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	rt := NewRuntime(e.lib, RuntimeOptions{EgressGrants: []config.EgressGrant{{Server: "lim", Host: "api.example.com", Ports: []int{443}, Methods: []string{"GET"}}}})
	t.Cleanup(func() { rt.Close() })
	if got := rt.EgressRules("lim"); got != nil {
		t.Fatalf("rules before resolution: %+v", got)
	}
	out, _, err := rt.Prepare(&audit.Memory{}, []config.Server{{Alias: "lim", Package: "lim-id"}}, pipeline.SubprocessLauncher{}, true)
	if err != nil || len(out) != 1 {
		t.Fatalf("prepare: %v %v", out, err)
	}
	got := rt.EgressRules("lim")
	if len(got) != 2 || got[0].RequestBytes != 1000 || got[0].ResponseBytes != 2000 || got[0].TimeoutMS != 300 || got[1].RequestBytes != 0 {
		t.Fatalf("rules %+v", got)
	}
	got[0].RequestBytes = 1 // a copy
	if rt.EgressRules("lim")[0].RequestBytes != 1000 {
		t.Fatal("EgressRules returned the manifest's own slice")
	}
	if rt.EgressRules("other") != nil {
		t.Fatal("rules for an unknown alias")
	}
}
