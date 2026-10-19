package library

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestClassificationOverridesOnlyTighten: an operator may make a tool's
// side-effect class, source trust and risk class more restrictive, never
// less; refused attempts leave evidence; the signed manifest keeps its own
// classification, and the presented tool carries the tightened one
// (SR-3.11-1).
func TestClassificationOverridesOnlyTighten(t *testing.T) {
	reqtest.Verifies(t, "SR-3.11-1")
	e := newEnv(t)
	dir := e.pkg(pkgtest.Spec{ID: "fx-id", Revision: "1", Tools: []*mcp.Tool{pkgtest.EchoTool(fixtureDesc)},
		Edit: func(m *packaging.Manifest, _ *packaging.Provenance) {
			m.Tools[0].SideEffect, m.Tools[0].SourceTrust = "write", "trusted"
		}})
	rc, err := e.lib.Import(dir, ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.lib.Enable("fx-id", "1", EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		ov   ToolOverride
		ok   bool
	}{
		{"loosen side effect", ToolOverride{SideEffect: "read"}, false},
		{"unknown side effect", ToolOverride{SideEffect: "none"}, false},
		{"loosen risk", ToolOverride{RiskClass: "low"}, true}, // equal to the manifest: allowed, not looser
		{"tighten all", ToolOverride{SideEffect: "execute", SourceTrust: "untrusted", RiskClass: "moderate"}, true},
	} {
		_, err := e.lib.SetOverride("fx-id", "1", "echo", c.ov)
		if (err == nil) != c.ok {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !c.ok && reason(err) != ReasonLoosening {
			t.Fatalf("%s: reason %s", c.name, reason(err))
		}
	}
	// Once untrusted, trusted is a loosening relative to an untrusted
	// manifest only; check that direction on a manifest marked untrusted.
	dir2 := e.pkg(pkgtest.Spec{ID: "un-id", Revision: "1", Edit: func(m *packaging.Manifest, _ *packaging.Provenance) {
		m.Tools[0].SourceTrust = "untrusted"
		m.RiskClass = "moderate"
	}})
	if _, err := e.lib.Import(dir2, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, ov := range []ToolOverride{{SourceTrust: "trusted"}, {RiskClass: "low"}} {
		if _, err := e.lib.SetOverride("un-id", "1", "echo", ov); reason(err) != ReasonLoosening {
			t.Fatalf("loosening %+v: %v", ov, err)
		}
	}
	if _, err := e.lib.SetOverride("fx-id", "1", "nope", ToolOverride{SideEffect: "execute"}); reason(err) != ReasonOverrideTool {
		t.Fatalf("unknown tool: %v", err)
	}
	refused, overridden := 0, 0
	for _, ev := range e.rec.Events() {
		switch ev.ReasonCode {
		case ReasonLoosening:
			refused++
		case ReasonOverridden:
			overridden++
		}
	}
	if refused != 4 || overridden != 2 {
		t.Fatalf("evidence: %d refused, %d overridden", refused, overridden)
	}
	// The signed manifest keeps its classification.
	m, _, err := e.lib.Manifest("fx-id", "1")
	if err != nil || m.Find("echo").SideEffect != "write" || m.Find("echo").SourceTrust != "trusted" {
		t.Fatalf("manifest changed: %+v %v", m.Find("echo"), err)
	}
	// The presented tool carries the tightened classification.
	r := &rtEnv{env: e, rt: NewRuntime(e.lib, RuntimeOptions{}), fx: &fixtureServer{desc: fixtureDesc}, sha: rc.ArtifactSHA256}
	reg := r.start(t, []config.Server{{Alias: "fx", Package: "fx-id"}})
	ref := reg.Resolve("fx_echo")
	if ref == nil || ref.Tool.Meta["local.smcpgw/sideEffect"] != "execute" || ref.Tool.Meta["local.smcpgw/sourceTrust"] != "untrusted" {
		t.Fatalf("presented tool %+v", ref)
	}
}
