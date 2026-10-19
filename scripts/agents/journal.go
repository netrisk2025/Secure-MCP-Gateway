package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// The functions here make every scenario's pass/fail decision from the
// Gateway's evidence journal, never from the model's text. Each takes the
// events of one session written after a scenario started (sinceIndex) and
// returns nil or the reason the scenario failed.

// errNoCall: the agent made no call to the scenario's tool at all; the
// journal holds no call event for it in this session since the scenario
// started. It is the one failure runChecked retries (see there).
var errNoCall = errors.New("the agent made no call")

// backendTool returns the backend tool name of a call event: the Gateway
// writes tool_revision as "<server revision>/<tool>".
func backendTool(e audit.Event) string {
	if i := strings.LastIndexByte(e.ToolRevision, '/'); i >= 0 {
		return e.ToolRevision[i+1:]
	}
	return ""
}

// sessionEvents returns the events of sessionID from index since on.
func sessionEvents(evs []audit.Event, since int, sessionID string) []audit.Event {
	if since > len(evs) {
		since = len(evs)
	}
	var out []audit.Event
	for _, e := range evs[since:] {
		if e.SessionID == sessionID {
			out = append(out, e)
		}
	}
	return out
}

// callsTo groups the call-pipeline events (classes call and decision) for a
// backend tool by correlation ID, in journal order.
func callsTo(evs []audit.Event, tool string) (order []string, by map[string][]audit.Event) {
	by = map[string][]audit.Event{}
	for _, e := range evs {
		if (e.Class != "call" && e.Class != "decision") || backendTool(e) != tool || e.CorrelationID == "" {
			continue
		}
		if _, ok := by[e.CorrelationID]; !ok {
			order = append(order, e.CorrelationID)
		}
		by[e.CorrelationID] = append(by[e.CorrelationID], e)
	}
	return order, by
}

func hasPhase(evs []audit.Event, phase audit.Phase, outcome string) bool {
	for _, e := range evs {
		if e.Phase == phase && (outcome == "" || e.Outcome == outcome) {
			return true
		}
	}
	return false
}

// checkSignIn: the session was created by the OAuth authorization-code flow
// for the agent's principal and the conformance template.
func checkSignIn(evs []audit.Event, sessionID, principal string) error {
	for _, e := range evs {
		if e.Class == "session" && e.SessionID == sessionID && e.Outcome == "created" {
			if e.ReasonCode != "OAUTH_CODE" {
				return fmt.Errorf("session created with reason %s, want OAUTH_CODE", e.ReasonCode)
			}
			if e.PrincipalID != principal {
				return fmt.Errorf("session principal %s, want %s", e.PrincipalID, principal)
			}
			if d, ok := e.Detail.(map[string]any); ok && d["template"] != templateID {
				return fmt.Errorf("session template %v, want %s", d["template"], templateID)
			}
			return nil
		}
	}
	return fmt.Errorf("no session created event for %s", sessionID)
}

// checkCatalog: the session is presented exactly the granted tools.
func checkCatalog(got []string) error {
	want := grantedTools()
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("catalog %v, want %v", got, want)
	}
	return nil
}

// checkUngranted: no call to the ungranted tool reached the pipeline for
// this session, at any time.
func checkUngranted(evs []audit.Event) error {
	if order, _ := callsTo(evs, toolUngranted); len(order) > 0 {
		return fmt.Errorf("%d call(s) to ungranted %s reached the call pipeline", len(order), toolUngranted)
	}
	return nil
}

// checkAllowed: at least one call to the allowed tool was requested,
// authorized with PERMIT and delivered.
func checkAllowed(evs []audit.Event) error {
	order, by := callsTo(evs, toolAllowed)
	if len(order) == 0 {
		return fmt.Errorf("%w to %s", errNoCall, publicName(toolAllowed))
	}
	for _, c := range order {
		ce := by[c]
		if hasPhase(ce, audit.PhaseRequested, "") && hasPhase(ce, audit.PhaseAuthorized, "permit") && hasPhase(ce, audit.PhaseDelivered, "release") {
			return nil
		}
	}
	return fmt.Errorf("%d call(s) to %s but none requested, authorized and delivered", len(order), publicName(toolAllowed))
}

// checkDenied: the agent's call to the rate-limited tool was refused by the
// decision with RATE_LIMITED and never dispatched.
func checkDenied(evs []audit.Event) error {
	order, by := callsTo(evs, toolLimited)
	if len(order) == 0 {
		return fmt.Errorf("%w to %s", errNoCall, publicName(toolLimited))
	}
	for _, c := range order {
		ce := by[c]
		if hasPhase(ce, audit.PhaseDispatched, "") {
			return fmt.Errorf("call %s to %s was dispatched; want a refusal", c, publicName(toolLimited))
		}
	}
	for _, c := range order {
		for _, e := range by[c] {
			if e.Phase == audit.PhaseDenied && e.Outcome == "deny" && e.ReasonCode == "RATE_LIMITED" {
				return nil
			}
		}
	}
	return fmt.Errorf("no denied event with RATE_LIMITED for %s", publicName(toolLimited))
}

// checkApproval: the approval-obligated call was held (approval requested),
// approved by smcpctl, consumed, and the call delivered. When the build has
// no Approval Service the call must instead be refused with
// APPROVAL_REQUIRED and never dispatched.
func checkApproval(evs []audit.Event, serviceAvailable bool) error {
	order, by := callsTo(evs, toolApproval)
	if len(order) == 0 {
		return fmt.Errorf("%w to %s", errNoCall, publicName(toolApproval))
	}
	if !serviceAvailable {
		for _, c := range order {
			if hasPhase(by[c], audit.PhaseDispatched, "") {
				return fmt.Errorf("call %s was dispatched without an approval service", c)
			}
		}
		return nil
	}
	outcomes := map[string]bool{}
	for _, e := range evs {
		if e.Class == "approval" {
			if d, ok := e.Detail.(map[string]any); ok && d["tool"] == toolApproval {
				outcomes[e.Outcome] = true
			}
		}
	}
	for _, o := range []string{"requested", "approved", "consumed"} {
		if !outcomes[o] {
			return fmt.Errorf("no approval %s event for %s", o, publicName(toolApproval))
		}
	}
	for _, c := range order {
		if hasPhase(by[c], audit.PhaseDelivered, "release") {
			return nil
		}
	}
	return fmt.Errorf("approval granted but no call to %s was delivered", publicName(toolApproval))
}

// checkLocalRefusal: the client refused the approval-obligated call itself,
// so no call to that tool may have reached the Gateway.
func checkLocalRefusal(evs []audit.Event) error {
	if order, _ := callsTo(evs, toolApproval); len(order) > 0 {
		return fmt.Errorf("client reported a local refusal but %d call(s) to %s reached the Gateway", len(order), publicName(toolApproval))
	}
	return nil
}
