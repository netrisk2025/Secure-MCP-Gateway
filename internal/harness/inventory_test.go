package harness

import (
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestDoctorInventoryEveryRecordedClient is FR-15.3: with fixture
// configurations holding one Gateway entry and one other server in each
// scope a client has (user, project, managed), doctor lists every server
// of every Appendix K client whose configuration location is recorded,
// flags exactly the servers that are not the Gateway, and states for Grok
// Build, whose location is to be confirmed at pinning, that its servers
// are not listed.
func TestDoctorInventoryEveryRecordedClient(t *testing.T) {
	reqtest.Verifies(t, "FR-15.3")
	e := testEnv(t)
	want := fixtures(t, e)
	r := Doctor(e, IDs(), nil)
	listed := map[string][]string{}
	scopes := map[string]map[string]bool{}
	for _, s := range r.Servers {
		if !s.Gateway {
			listed[s.Client] = append(listed[s.Client], s.Name)
		}
		if scopes[s.Client] == nil {
			scopes[s.Client] = map[string]bool{}
		}
		scopes[s.Client][s.Scope] = true
	}
	flagged := map[string][]string{}
	grokNote := false
	for _, f := range r.Findings {
		switch {
		case f.Kind == KindServer:
			for _, s := range r.Servers {
				if s.Client == f.Client && !s.Gateway && strings.Contains(f.Message, `"`+s.Name+`"`) {
					flagged[f.Client] = append(flagged[f.Client], s.Name)
				}
			}
		case f.Client == "grok-build" && strings.Contains(f.Message, "servers are not listed"):
			grokNote = true
		}
	}
	for _, id := range IDs() {
		if id == "grok-build" {
			continue
		}
		names, ok := want[id]
		if !ok {
			t.Errorf("no fixture for Appendix K client %s", id)
			continue
		}
		got, fl := listed[id], flagged[id]
		slices.Sort(got)
		slices.Sort(fl)
		slices.Sort(names)
		if !slices.Equal(got, names) || !slices.Equal(fl, names) {
			t.Errorf("%s: listed %v, flagged %v, want %v", id, got, fl, names)
		}
	}
	// The scopes each client has are read (managed included where the
	// client has one).
	for id, sc := range map[string][]string{"claude-code": {"user", "project", "managed"}, "codex": {"user", "project"},
		"gemini-cli": {"user", "project"}, "opencode": {"user", "project"}} {
		for _, s := range sc {
			if !scopes[id][s] {
				t.Errorf("%s: %s scope not read (%v)", id, s, scopes[id])
			}
		}
	}
	if len(scopes["gemini-cli"]) < 3 {
		t.Errorf("gemini-cli system settings not read: %v", scopes["gemini-cli"])
	}
	if !grokNote {
		t.Error("doctor does not say that Grok Build's servers are not listed")
	}
}
