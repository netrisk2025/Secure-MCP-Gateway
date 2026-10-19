package policy

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestRemoteAllowedProfile: remote_allowed (FR-16.12) names templates of
// the profile only, is kept in the snapshot, and marking another template
// remote-allowed is a widening change in the diff.
func TestRemoteAllowedProfile(t *testing.T) {
	reqtest.Partial(t, "FR-16.12")
	a := mustCompile(t, doc)
	marked := strings.Replace(doc, `"default_template": "ro"}`, `"default_template": "ro", "remote_allowed": ["ro"]}`, 1)
	b := mustCompile(t, marked)
	if got := b.Profiles["dev"].RemoteAllowed; len(got) != 1 || got[0] != "ro" {
		t.Fatalf("remote_allowed %v", got)
	}
	if rep := Diff(a, b); !rep.Widening || len(rep.Changes) != 1 || rep.Changes[0].Kind != "profile_changed" || !strings.Contains(rep.Changes[0].After, "remote_allowed=ro") {
		t.Fatalf("marking a template remote-allowed: %+v", rep)
	}
	if rep := Diff(b, a); rep.Widening {
		t.Fatalf("removing the mark widened: %+v", rep)
	}
	if _, err := Compile([]byte(strings.Replace(doc, `"default_template": "ro"}`, `"default_template": "ro", "remote_allowed": ["admin"]}`, 1))); err == nil || !strings.Contains(err.Error(), "remote_allowed") {
		t.Fatalf("remote_allowed outside the profile's templates: %v", err)
	}
}
