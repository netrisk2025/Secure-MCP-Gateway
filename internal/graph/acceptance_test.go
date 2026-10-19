package graph

import (
	"context"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// revised returns the events of callEvents(n) moved to another server
// revision, tool revision and policy revision, as after an update of the
// server package and a policy publication.
func revised(n int, server, policy string) []audit.Event {
	evs := callEvents(n, "s1", "cc")
	for i := range evs {
		evs[i].ServerRevision, evs[i].ToolRevision = server, server+"/echo"
		if evs[i].DecisionID != "" {
			evs[i].PolicyRevision = policy
		}
		if evs[i].Class == "decision" {
			evs[i].Detail = map[string]any{"decisive_rules": []any{policy + "/dev/allow-echo"}, "applicable_rules": []any{policy + "/dev/allow-echo"},
				"considered_rules": []any{policy + "/dev/allow-echo"}, "obligations": map[string]any{"audit_profile": "audit_profile@file"}}
		}
	}
	return evs
}

// TestAT11AuditLinkageSurvivesChanges is acceptance scenario AT-11 on the
// graph mirror: the links of a call's events name exact revisions, so they
// still resolve to the same decision, policy revision, decisive rule
// revisions, server revision and tool revision after the server is
// renamed (same revision under a new alias), updated (a new server
// revision), its old revision removed, and a new policy revision
// published; and a call denied before dispatch is never linked as
// observed from (executing on) its target.
//
// The scenario runs against the mirror's fake backend in the Standalone
// profile; the same projection runs on Neo4j in the graph job. Partial
// claims: the requirements are verified by their own tests.
func TestAT11AuditLinkageSurvivesChanges(t *testing.T) {
	reqtest.Scenario(t, reqtest.Standalone, "AT-11")
	reqtest.Partial(t, "SR-6.4-1", "SR-6.5-1", "SR-6.20-1")
	f := NewFake()
	e := newEnv(t, f, 1000, nil, nil)
	e.commit(callEvents(0, "s1", "cc")...)
	e.commit(deniedEvents(0, "s1", "cc")...)
	syncMirror(t, e.mirror)
	before, err := audit.ReadEvents(e.dir + "/journal")
	if err != nil {
		t.Fatal(err)
	}

	// Rename: the same server revision under a new alias.
	renamed := callEvents(1, "s1", "cc")
	renamed[0].Detail = map[string]any{"server": "renamed-alias", "tool": "echo"}
	e.commit(renamed...)
	// Update: a new server revision and a new policy revision.
	e.commit(audit.Event{Class: "admin", Origin: "E-05", Outcome: "activated", ReasonCode: "POLICY_ACTIVATED", PolicyRevision: "r2", PolicyStatus: "not_evaluated"})
	e.commit(revised(2, "live-def", "r2")...)
	// Removal: the old revision is retired.
	e.commit(audit.Event{Class: "admin", Origin: "E-14", Outcome: "retired", ReasonCode: "REVISION_RETIRED", ServerRevision: "live-abc", PolicyStatus: "not_evaluated"})
	syncMirror(t, e.mirror)

	das, err := e.mirror.DAS()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checked := 0
	for _, ev := range before {
		if ev.CorrelationID != "corr-0" || ev.DecisionID == "" {
			continue
		}
		p, err := das.EventPath(ctx, ev.EventID, 20)
		if err != nil {
			t.Fatal(err)
		}
		id := func(m map[string]any) string { s, _ := m["id"].(string); return s }
		if id(p.Decision) != "dec-0" || id(p.PolicyRevision) != "r1" || id(p.ToolRevision) != "live-abc/echo" {
			t.Fatalf("%s/%s after the changes: decision %v policy %v tool %v", ev.Class, ev.Phase, p.Decision, p.PolicyRevision, p.ToolRevision)
		}
		if len(p.DecisiveRules) != 1 || id(p.DecisiveRules[0]) != "r1/dev/allow-echo" {
			t.Fatalf("%s/%s decisive rules %v", ev.Class, ev.Phase, p.DecisiveRules)
		}
		if p.ServerRevision != nil && id(p.ServerRevision) != "live-abc" {
			t.Fatalf("%s/%s server revision %v", ev.Class, ev.Phase, p.ServerRevision)
		}
		checked++
	}
	if checked < 3 {
		t.Fatalf("only %d evaluated events of the first call checked", checked)
	}
	if !f.HasRel("Decision", "dec-0", "TARGETED", "ServerRevision", "live-abc") || !f.HasRel("Decision", "dec-2", "TARGETED", "ServerRevision", "live-def") {
		t.Fatal("decisions do not target their exact server revisions")
	}
	if f.HasRel("Decision", "dec-0", "TARGETED", "ServerRevision", "live-def") {
		t.Fatal("the old decision was relinked to the new server revision")
	}
	for _, ev := range before {
		if ev.CorrelationID == "dcorr-0" && f.HasRel("AuditEvent", ev.EventID, "OBSERVED_FROM", "ServerRevision", "live-abc") {
			t.Fatalf("denied call %s/%s is shown as executing on its target", ev.Class, ev.Phase)
		}
	}
	after, err := audit.ReadEvents(e.dir + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range after {
		if f.Node("AuditEvent", ev.EventID) == nil {
			t.Fatalf("%s %s event %s not mirrored", ev.Class, ev.Phase, ev.EventID)
		}
	}
}
