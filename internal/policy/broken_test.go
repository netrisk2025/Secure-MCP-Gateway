package policy

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestBrokenBuildTag checks the FR-15.8 deliberate defect in both builds:
// a normal build enforces the rate limit and the approval obligation, and
// only a build with -tags smcp_broken skips them.
//
//	go test ./internal/policy -run TestBrokenBuildTag
//	go test -tags smcp_broken ./internal/policy -run TestBrokenBuildTag
func TestBrokenBuildTag(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")
	d := NewDecider(mustCompile(t, `{
  "revision": "b1",
  "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}},
  "templates": {"t": {"rules": [
    {"id": "lim", "server": "ref", "tools": ["time_now"], "calls_per_minute": 1},
    {"id": "appr", "server": "ref", "tools": ["read_file"], "approval": true}
  ]}}
}`), 60)
	req := func(tool string) Request {
		return Request{PrincipalID: "p", SessionID: "s", Profile: "dev", Template: "t", Server: "ref", Tool: tool}
	}
	d.Decide(req("time_now"))
	second := d.Decide(req("time_now"))
	appr := d.Decide(req("read_file"))
	unknown := d.Decide(req("list_files"))
	if unknown.Outcome != Deny || unknown.ReasonCode != ReasonNoPermit {
		t.Fatalf("ungranted tool must stay denied in every build: %+v", unknown)
	}
	if BrokenBuild {
		if second.Outcome != Permit || appr.Obligations.Approval {
			t.Fatalf("smcp_broken build must skip the rate limit and the approval obligation: %+v %+v", second, appr)
		}
		return
	}
	if second.Outcome != Deny || second.ReasonCode != ReasonRateLimited {
		t.Fatalf("second call within the minute: %+v", second)
	}
	if appr.Outcome != Permit || !appr.Obligations.Approval {
		t.Fatalf("approval obligation missing: %+v", appr)
	}
}
