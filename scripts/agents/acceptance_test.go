package main

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

func TestParseHarnessView(t *testing.T) {
	out := strings.Join([]string{
		`{"type":"system","subtype":"init"}`,
		`{"type":"assistant","message":{"content":[{"type":"text","text":"calling"},{"type":"tool_use","name":"mcp__smcp__ref_read_file","input":{"path":"a.txt"}}]}}`,
		`{"type":"control_request","request_id":"1","request":{"subtype":"can_use_tool","tool_name":"mcp__smcp__ref_read_file"}}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","content":[{"type":"text","text":"approval required: Open https://x/approvals/1"}],"is_error":true}]}}`,
		`not json`,
		`{"type":"result","result":"The call failed."}`,
	}, "\n")
	v := parseHarnessView([]byte(out), "mcp__smcp__ref_read_file")
	if v.ToolUse != `mcp__smcp__ref_read_file {"path":"a.txt"}` {
		t.Errorf("tool use %q", v.ToolUse)
	}
	if v.ToolResult != "approval required: Open https://x/approvals/1" || !v.ResultError {
		t.Errorf("tool result %q error %v", v.ToolResult, v.ResultError)
	}
	if v.Reply != "The call failed." {
		t.Errorf("reply %q", v.Reply)
	}
	// A string tool_result content.
	v = parseHarnessView([]byte(`{"type":"user","message":{"content":[{"type":"tool_result","content":"marker\n"}]}}`), "x")
	if v.ToolResult != "marker\n" || v.ResultError {
		t.Errorf("string content: %q %v", v.ToolResult, v.ResultError)
	}
}

func approvalEv(outcome, approver string) audit.Event {
	d := map[string]any{"tool": toolApproval}
	if approver != "" {
		d["approver"] = approver
	}
	return audit.Event{Class: "approval", Outcome: outcome, Detail: d}
}

func callEv(phase audit.Phase, outcome string) audit.Event {
	return audit.Event{Class: "call", Phase: phase, Outcome: outcome, CorrelationID: "c1", ToolRevision: "ref@1/" + toolApproval}
}

func TestAcceptanceChecks(t *testing.T) {
	approved := func(who string) []audit.Event {
		return []audit.Event{callEv(audit.PhaseRequested, ""), approvalEv("requested", ""), approvalEv("approved", who),
			approvalEv("consumed", who), callEv(audit.PhaseDispatched, ""), callEv(audit.PhaseDelivered, "release")}
	}
	if err := checkApprovedCase(true)(approved("admin:admin"), "m1\n", false, "m1"); err != nil {
		t.Errorf("console approval: %v", err)
	}
	if err := checkApprovedCase(true)(approved("operator-token"), "m1", false, "m1"); err == nil {
		t.Error("console case accepted a non-console approver")
	}
	if err := checkApprovedCase(false)(approved("operator-token"), "m1", false, "m1"); err != nil {
		t.Errorf("smcpctl approval: %v", err)
	}
	if err := checkApprovedCase(false)(approved("operator-token"), "other", false, "m1"); err == nil {
		t.Error("approval case accepted a result without the marker")
	}

	denied := []audit.Event{callEv(audit.PhaseRequested, ""), approvalEv("requested", ""), approvalEv("denied", "admin:admin")}
	if err := checkDeniedCase(denied, "approval denied: A person reviewing this call denied it.", true, ""); err != nil {
		t.Errorf("denied: %v", err)
	}
	if err := checkDeniedCase(append(denied, callEv(audit.PhaseDispatched, "")), "approval denied", true, ""); err == nil {
		t.Error("denied case accepted a dispatched call")
	}
	if err := checkDeniedCase(denied, "ok", false, ""); err == nil {
		t.Error("denied case accepted a successful result")
	}

	held := []audit.Event{callEv(audit.PhaseRequested, ""), approvalEv("requested", "")}
	text := "approval required: This call needs approval. Open https://127.0.0.1:1/approvals/x to approve it, then run the same request again."
	if err := checkHoldCase(held, text, true, ""); err != nil {
		t.Errorf("hold: %v", err)
	}
	if err := checkHoldCase(held, "approval required", true, ""); err == nil {
		t.Error("hold case accepted a message without the link")
	}
	if err := checkHoldCase(append(held, approvalEv("approved", "x")), text, true, ""); err == nil {
		t.Error("hold case accepted a decided approval")
	}
}
