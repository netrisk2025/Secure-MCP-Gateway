package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const doc = `{
  "revision": "r1",
  "framework_profiles": {"dev": {"templates": ["ro", "rw"], "default_template": "ro"}},
  "templates": {
    "ro": {"rules": [{"id": "ro-fs", "server": "fs", "tools": ["read_file", "list_directory"]}]},
    "rw": {"calls_per_minute": 2, "rules": [
      {"id": "rw-fs", "server": "fs", "tools": ["read_file", "write_file"], "approval": true}
    ]}
  }
}`

func TestCompileAndDecide(t *testing.T) {
	// FR-3.11 is verified by TestDecisionRecordFields and FR-3.2 by
	// internal/policyadmin TestSchemaRejectsWithFieldMessages.
	reqtest.Verifies(t, "SR-1.3-1")
	reqtest.Partial(t, "FR-3.2", "FR-3.11")
	s, err := Compile([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecider(s, 60)
	dec := d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "read_file"})
	if dec.Outcome != Permit || dec.ReasonCode != ReasonPermit || dec.Route != "fs" || dec.PolicyRevision != "r1" || dec.ID == "" {
		t.Fatalf("%+v", dec)
	}
	if len(dec.DecisiveRules) != 1 || dec.DecisiveRules[0] != "ro-fs" || len(dec.ConsideredRules) != 1 {
		t.Fatalf("%+v", dec)
	}
	dec = d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "write_file"})
	if dec.Outcome != Deny || dec.ReasonCode != ReasonNoPermit {
		t.Fatalf("expected default deny, got %+v", dec)
	}
	dec = d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "nope", Server: "fs", Tool: "read_file"})
	if dec.Outcome != Deny || dec.ReasonCode != ReasonNoTemplate {
		t.Fatalf("%+v", dec)
	}
	dec = d.Decide(Request{PrincipalID: "p", SessionID: "s", Template: "rw", Server: "fs", Tool: "write_file"})
	if !dec.Obligations.Approval {
		t.Fatalf("approval obligation missing: %+v", dec)
	}
}

func TestNoSnapshotDenies(t *testing.T) {
	// The Gateway half (-31004) is verified in the edge tests.
	reqtest.Partial(t, "SR-1.2-1")
	d := NewDecider(nil, 60)
	dec := d.Decide(Request{Template: "ro", Server: "fs", Tool: "read_file"})
	if dec.Outcome != Deny || dec.ReasonCode != ReasonNoSnapshot {
		t.Fatalf("%+v", dec)
	}
}

func TestRateLimit(t *testing.T) {
	reqtest.Verifies(t, "FR-3.13")
	s, _ := Compile([]byte(doc))
	d := NewDecider(s, 60)
	now := time.Now()
	d.SetNow(func() time.Time { return now })
	req := Request{PrincipalID: "p", SessionID: "s", Template: "rw", Server: "fs", Tool: "read_file"}
	for i := 0; i < 2; i++ {
		if dec := d.Decide(req); dec.Outcome != Permit {
			t.Fatalf("call %d: %+v", i, dec)
		}
	}
	if dec := d.Decide(req); dec.ReasonCode != ReasonRateLimited || dec.Obligations.CallsPerMinute != 2 {
		t.Fatalf("%+v", dec)
	}
	now = now.Add(61 * time.Second)
	if dec := d.Decide(req); dec.Outcome != Permit {
		t.Fatalf("window did not slide: %+v", dec)
	}
}

func TestPublicationInvariants(t *testing.T) {
	reqtest.Partial(t, "FR-3.2")
	cases := map[string]string{
		"overlap":        strings.Replace(doc, `"tools": ["read_file", "list_directory"]}`, `"tools": ["read_file"]}, {"id": "dup", "server": "fs", "tools": ["read_file"]}`, 1),
		"unknown tmpl":   strings.Replace(doc, `"templates": ["ro", "rw"]`, `"templates": ["ro", "zz"]`, 1),
		"bad default":    strings.Replace(doc, `"default_template": "ro"`, `"default_template": "rw2"`, 1),
		"schema (alias)": strings.Replace(doc, `"server": "fs"`, `"server": "FS!"`, 1),
		"unknown field":  strings.Replace(doc, `"revision": "r1",`, `"revision": "r1", "extra": 1,`, 1),
	}
	for name, c := range cases {
		if _, err := Compile([]byte(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
