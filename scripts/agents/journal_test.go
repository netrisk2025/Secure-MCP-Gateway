package main

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func callEvents(corr, tool string, steps ...[3]string) []audit.Event {
	var evs []audit.Event
	for _, s := range steps {
		class := "call"
		if s[0] == string(audit.PhaseAuthorized) || s[0] == string(audit.PhaseDenied) {
			class = "decision"
		}
		evs = append(evs, audit.Event{Class: class, Phase: audit.Phase(s[0]), Outcome: s[1], ReasonCode: s[2],
			CorrelationID: corr, SessionID: "s1", ToolRevision: "live-abc/" + tool})
	}
	return evs
}

var delivered = [][3]string{{"requested", "", ""}, {"authorized", "permit", "PERMIT"}, {"dispatched", "", ""}, {"completed", "ok", ""}, {"delivered", "release", ""}}

func TestJournalAssertions(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")

	t.Run("allowed", func(t *testing.T) {
		if err := checkAllowed(callEvents("c1", toolAllowed, delivered...)); err != nil {
			t.Fatal(err)
		}
		if err := checkAllowed(nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("no events: %v", err)
		}
		// Requested but never delivered.
		if err := checkAllowed(callEvents("c1", toolAllowed, delivered[:3]...)); err == nil {
			t.Fatal("undelivered call accepted")
		}
		// A delivered call to another tool does not count.
		if err := checkAllowed(callEvents("c1", toolApproval, delivered...)); err == nil {
			t.Fatal("call to another tool accepted")
		}
	})

	t.Run("denied", func(t *testing.T) {
		refused := callEvents("c2", toolLimited, [3]string{"requested", "", ""}, [3]string{"denied", "deny", "RATE_LIMITED"})
		if err := checkDenied(refused); err != nil {
			t.Fatal(err)
		}
		if err := checkDenied(callEvents("c2", toolLimited, delivered...)); err == nil {
			t.Fatal("dispatched call accepted as a denial")
		}
		other := callEvents("c2", toolLimited, [3]string{"requested", "", ""}, [3]string{"denied", "deny", "NO_PERMIT"})
		if err := checkDenied(other); err == nil {
			t.Fatal("wrong reason code accepted")
		}
	})

	t.Run("approval", func(t *testing.T) {
		appr := func(outcome string) audit.Event {
			return audit.Event{Class: "approval", Outcome: outcome, SessionID: "s1", Detail: map[string]any{"tool": toolApproval}}
		}
		evs := append([]audit.Event{appr("requested"), appr("approved"), appr("consumed")}, callEvents("c3", toolApproval, delivered...)...)
		if err := checkApproval(evs, true); err != nil {
			t.Fatal(err)
		}
		if err := checkApproval(append([]audit.Event{appr("requested")}, callEvents("c3", toolApproval, delivered...)...), true); err == nil {
			t.Fatal("delivery without an approved event accepted")
		}
		held := callEvents("c3", toolApproval, [3]string{"requested", "", ""}, [3]string{"denied", "deny", "APPROVAL_REQUIRED"})
		if err := checkApproval(held, false); err != nil {
			t.Fatalf("refusal without an approval service: %v", err)
		}
		if err := checkApproval(callEvents("c3", toolApproval, delivered...), false); err == nil {
			t.Fatal("dispatch without an approval service accepted")
		}
		if err := checkLocalRefusal(nil); err != nil {
			t.Fatal(err)
		}
		if err := checkLocalRefusal(held); err == nil {
			t.Fatal("local refusal accepted although the call reached the Gateway")
		}
	})

	t.Run("ungranted", func(t *testing.T) {
		if err := checkUngranted(callEvents("c4", toolAllowed, delivered...)); err != nil {
			t.Fatal(err)
		}
		if err := checkUngranted(callEvents("c4", toolUngranted, delivered...)); err == nil {
			t.Fatal("call to the ungranted tool accepted")
		}
	})

	t.Run("signin", func(t *testing.T) {
		ok := audit.Event{Class: "session", SessionID: "s1", Outcome: "created", ReasonCode: "OAUTH_CODE", PrincipalID: "agents-x",
			Detail: map[string]any{"template": templateID}}
		if err := checkSignIn([]audit.Event{ok}, "s1", "agents-x"); err != nil {
			t.Fatal(err)
		}
		bad := ok
		bad.ReasonCode = "SESSION_API"
		if err := checkSignIn([]audit.Event{bad}, "s1", "agents-x"); err == nil {
			t.Fatal("non-OAuth session accepted")
		}
		if err := checkSignIn([]audit.Event{ok}, "s1", "agents-y"); err == nil {
			t.Fatal("wrong principal accepted")
		}
		if err := checkSignIn(nil, "s1", "agents-x"); err == nil {
			t.Fatal("missing session accepted")
		}
	})

	t.Run("catalog", func(t *testing.T) {
		if err := checkCatalog([]string{"ref_echo", "ref_read_file", "ref_time_now"}); err != nil {
			t.Fatal(err)
		}
		if err := checkCatalog([]string{"ref_echo", "ref_list_files", "ref_read_file", "ref_time_now"}); err == nil {
			t.Fatal("ungranted tool in the catalog accepted")
		}
	})
}

func TestSessionEventsWindow(t *testing.T) {
	evs := []audit.Event{{SessionID: "a"}, {SessionID: "b"}, {SessionID: "a", Class: "x"}}
	got := sessionEvents(evs, 1, "a")
	if len(got) != 1 || got[0].Class != "x" {
		t.Fatalf("got %+v", got)
	}
	if got := sessionEvents(evs, 10, "a"); len(got) != 0 {
		t.Fatalf("index past the end: %+v", got)
	}
	if backendTool(audit.Event{ToolRevision: "live-1/read_file"}) != "read_file" || backendTool(audit.Event{}) != "" {
		t.Fatal("backendTool")
	}
}
