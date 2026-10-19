package reqtest

import (
	"strings"
	"testing"
)

type recorder struct {
	testing.TB
	logs  []string
	fatal string
}

func (r *recorder) Helper()                           {}
func (r *recorder) Log(args ...any)                   { r.logs = append(r.logs, args[0].(string)) }
func (r *recorder) Fatalf(format string, args ...any) { r.fatal = format }

func TestMarkers(t *testing.T) {
	r := &recorder{TB: t}
	Verifies(r, "FR-1.2", "SR-2.9-1")
	Partial(r, "FR-4.5")
	if len(r.logs) != 2 || r.logs[0] != "VERIFIES: FR-1.2 SR-2.9-1" || r.logs[1] != "PARTIAL: FR-4.5" {
		t.Fatalf("%q", r.logs)
	}
	Partial(r, "FR4.5")
	if !strings.Contains(r.fatal, "not a requirement ID") {
		t.Fatalf("bad ID accepted: %q", r.fatal)
	}
}

func TestScenarioMarker(t *testing.T) {
	reqtest := &recorder{TB: t}
	Scenario(reqtest, Standalone, "AT-01", "AT-21")
	if len(reqtest.logs) != 1 || reqtest.logs[0] != "SCENARIO: AT-01 AT-21 profile=standalone" {
		t.Fatalf("%q", reqtest.logs)
	}
	for _, c := range []struct{ profile, id string }{{"lab", "AT-01"}, {Enforced, "AT-22"}, {Enforced, "AT-1"}, {Enforced, "FR-1.1"}} {
		r := &recorder{TB: t}
		Scenario(r, c.profile, c.id)
		if r.fatal == "" {
			t.Fatalf("Scenario(%q, %q) accepted", c.profile, c.id)
		}
	}
}
