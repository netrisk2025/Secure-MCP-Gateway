package e2e

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestEvaluatedEventLinks: every evaluated-request event of a tool call
// links, in the evidence mirror, to its decision, the policy revision, the
// decisive rule revisions, the target server and tool revisions and the
// effective Audit Profile revision, and the event path query returns each
// of them (SR-6.4-1).
func TestEvaluatedEventLinks(t *testing.T) {
	reqtest.Verifies(t, "SR-6.4-1")
	f := start(t, "")
	fake := graph.NewFake()
	mirror, err := graph.New(graph.Options{Config: f.cfg, Log: diag.Discard(), Backend: fake})
	if err != nil {
		t.Fatal(err)
	}
	f.app.Evidence.AddObserver("graph", mirror, 0)
	mirror.Start(context.Background(), f.app.Evidence)
	t.Cleanup(func() { mirror.Close() })

	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil || res.IsError {
		t.Fatalf("call: %v %+v", err, res)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		if _, err := mirror.DAS(); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("mirror not ready: %+v", mirror.Status(ctx, false))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := mirror.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	das, err := mirror.DAS()
	if err != nil {
		t.Fatal(err)
	}

	evs, err := audit.ReadEvents(filepath.Join(f.stateDir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	var decision *audit.Event
	for i, e := range evs {
		if e.Class == "decision" && e.Phase == audit.PhaseAuthorized {
			decision = &evs[i]
		}
	}
	if decision == nil {
		t.Fatal("no committed decision")
	}
	detail, _ := decision.Detail.(map[string]any)
	decisive := strs(detail["decisive_rules"])
	if len(decisive) == 0 {
		t.Fatalf("decision record has no decisive rules: %v", detail)
	}
	ob, _ := detail["obligations"].(map[string]any)
	profile, _ := ob["audit_profile"].(string)
	if profile == "" {
		t.Fatalf("decision record has no audit profile: %v", ob)
	}

	checked := 0
	for _, e := range evs {
		if e.CorrelationID != decision.CorrelationID || e.PolicyStatus != "evaluated" {
			continue
		}
		checked++
		if e.DecisionID != decision.DecisionID || e.PolicyRevision != decision.PolicyRevision {
			t.Fatalf("%s/%s carries decision %q revision %q", e.Class, e.Phase, e.DecisionID, e.PolicyRevision)
		}
		p, err := das.EventPath(ctx, e.EventID, 20)
		if err != nil {
			t.Fatalf("%s/%s: %v", e.Class, e.Phase, err)
		}
		if pathID(p.Decision) != e.DecisionID || pathID(p.PolicyRevision) != e.PolicyRevision {
			t.Fatalf("%s/%s path decision %v revision %v", e.Class, e.Phase, p.Decision, p.PolicyRevision)
		}
		var got []string
		for _, r := range p.DecisiveRules {
			got = append(got, pathID(r))
		}
		slices.Sort(got)
		want := slices.Clone(decisive)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("%s/%s decisive rules %v, want %v", e.Class, e.Phase, got, want)
		}
		if pathID(p.AuditProfile) != profile {
			t.Fatalf("%s/%s audit profile %v, want %s", e.Class, e.Phase, p.AuditProfile, profile)
		}
		if pathID(p.ToolRevision) != e.ToolRevision || e.ToolRevision == "" {
			t.Fatalf("%s/%s tool revision %v, want %s", e.Class, e.Phase, p.ToolRevision, e.ToolRevision)
		}
		if !fake.HasRel("Decision", e.DecisionID, "TARGETED", "ServerRevision", e.ServerRevision) || e.ServerRevision == "" {
			t.Fatalf("decision %s does not target server revision %q", e.DecisionID, e.ServerRevision)
		}
		if !fake.HasRel("ToolRevision", e.ToolRevision, "BELONGS_TO", "ServerRevision", e.ServerRevision) {
			t.Fatalf("tool revision %s does not belong to %s", e.ToolRevision, e.ServerRevision)
		}
	}
	if checked < 3 {
		t.Fatalf("only %d evaluated events in the call", checked)
	}
	for _, r := range decisive {
		if !fake.HasRel("PolicyRevision", decision.PolicyRevision, "CONTAINS", "RuleRevision", r) {
			t.Fatalf("policy revision %s does not contain %s", decision.PolicyRevision, r)
		}
	}
	if !fake.HasRel("AuditEvent", decision.EventID, "RECORDED_UNDER", "PolicyObject", profile) {
		t.Fatalf("decision event not recorded under %s", profile)
	}
}

func pathID(m map[string]any) string { s, _ := m["id"].(string); return s }

func strs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
