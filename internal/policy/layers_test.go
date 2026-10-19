package policy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const layersDoc = `{"revision": "l1",
  "framework_profiles": {
    "dev":   {"templates": ["ro", "rw"], "default_template": "ro"},
    "fsonly": {"templates": ["ro", "rw"], "default_template": "ro", "servers": ["fs"]},
    "other": {"templates": ["rw"], "default_template": "rw"}
  },
  "templates": {
    "ro": {"rules": [
      {"id": "ro-read", "server": "fs", "tools": ["read_file"], "when": [{"arg": "path", "op": "path_within", "value": ["/data"]}]},
      {"id": "ro-git", "server": "git", "tools": ["log"]}]},
    "rw": {"calls_per_minute": 2, "rules": [
      {"id": "rw-read", "server": "fs", "tools": ["read_file"]},
      {"id": "rw-write", "server": "fs", "tools": ["write_file"]},
      {"id": "rw-git", "server": "git", "tools": ["log"]}]}
  }}`

// TestLayerIntersection is SR-1-2: a call is permitted only when the
// Framework Profile, the Session Allow Policy Template the session was
// created with (the session claim that narrows the principal's templates
// to one) and the request-time conditions all permit it. Each fixture
// below is permitted by every layer but one and is denied:
//
//   - profile: the template grants git/log and the predicate holds, but the
//     principal's profile has a server ceiling without git, or no longer
//     lists the session's template;
//   - session template: the profile and another of its templates grant
//     fs/write_file, but the session's template does not;
//   - request time: profile and template grant the call, but the argument
//     predicate fails, or the rate bound of the template is spent.
func TestLayerIntersection(t *testing.T) {
	reqtest.Verifies(t, "SR-1-2")
	d := NewDecider(mustCompile(t, layersDoc), 1000)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	d.SetNow(func() time.Time { return now })
	req := func(session, profile, tmpl, server, tool, args string) Request {
		r := Request{PrincipalID: "p-" + session, SessionID: session, Profile: profile, Template: tmpl, Server: server, Tool: tool}
		if args != "" {
			r.Arguments = json.RawMessage(args)
		}
		return r
	}
	// Permitted by all three layers.
	for _, r := range []Request{
		req("a", "dev", "ro", "fs", "read_file", `{"path":"/data/x"}`),
		req("b", "dev", "ro", "git", "log", ""),
		req("c", "dev", "rw", "fs", "write_file", ""),
	} {
		if dec := d.Decide(r); dec.Outcome != Permit {
			t.Fatalf("all layers permit %s/%s: %+v", r.Server, r.Tool, dec)
		}
	}
	for _, c := range []struct {
		layer, reason string
		r             Request
	}{
		{"profile server ceiling", ReasonNoPermit, req("d", "fsonly", "ro", "git", "log", "")},
		{"profile does not list the template", ReasonNoTemplate, req("e", "other", "ro", "git", "log", "")},
		{"session template", ReasonNoPermit, req("f", "dev", "ro", "fs", "write_file", "")},
		{"request-time predicate", ReasonNoPermit, req("g", "dev", "ro", "fs", "read_file", `{"path":"/etc/passwd"}`)},
	} {
		if dec := d.Decide(c.r); dec.Outcome != Deny || dec.ReasonCode != c.reason {
			t.Errorf("%s: %+v", c.layer, dec)
		}
	}
	// Request-time rate bound: the template allows two calls a minute.
	rate := req("h", "dev", "rw", "git", "log", "")
	for i := range 2 {
		if dec := d.Decide(rate); dec.Outcome != Permit {
			t.Fatalf("call %d: %+v", i, dec)
		}
	}
	if dec := d.Decide(rate); dec.Outcome != Deny || dec.ReasonCode != ReasonRateLimited {
		t.Fatalf("rate layer: %+v", dec)
	}
	// The same layers for the profile with the ceiling: fs is within it.
	if dec := d.Decide(req("i", "fsonly", "rw", "fs", "write_file", "")); dec.Outcome != Permit {
		t.Fatalf("ceiling permits fs: %+v", dec)
	}
}
