package policy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestReplaceHotSwap(t *testing.T) {
	reqtest.Verifies(t, "FR-3.10")
	s1, _ := Compile([]byte(doc))
	d := NewDecider(s1, 60)
	req := Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "list_directory"}
	if dec := d.Decide(req); dec.Outcome != Permit {
		t.Fatalf("%+v", dec)
	}
	// Same content again: unchanged.
	again, _ := Compile([]byte(doc))
	if changed, err := d.Replace(again); changed || err != nil {
		t.Fatalf("reload of identical policy: %v %v", changed, err)
	}
	// Changed content under the same revision ID is refused.
	edited := strings.Replace(doc, `"read_file", "list_directory"]`, `"read_file"]`, 1)
	s2, err := Compile([]byte(edited))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Replace(s2); !errors.Is(err, ErrRevisionReused) {
		t.Fatalf("got %v", err)
	}
	// With a new revision the swap takes effect for the next decision.
	s3, _ := Compile([]byte(strings.Replace(edited, `"revision": "r1"`, `"revision": "r2"`, 1)))
	if changed, err := d.Replace(s3); !changed || err != nil {
		t.Fatalf("%v %v", changed, err)
	}
	dec := d.Decide(req)
	if dec.Outcome != Deny || dec.PolicyRevision != "r2" || dec.ReasonCode != ReasonNoPermit {
		t.Fatalf("after swap: %+v", dec)
	}
	if _, err := d.Replace(nil); err == nil {
		t.Fatal("nil snapshot accepted")
	}
}

func TestProfileRateAndRefusalConsumesNothing(t *testing.T) {
	reqtest.Verifies(t, "FR-3.13")
	src := strings.Replace(doc, `"default_template": "ro"}`, `"default_template": "ro", "calls_per_minute": 3}`, 1)
	s, err := Compile([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecider(s, 60)
	now := time.Now()
	d.SetNow(func() time.Time { return now })
	a := Request{PrincipalID: "p", SessionID: "s1", Profile: "dev", Template: "ro", Server: "fs", Tool: "read_file"}
	for i := 0; i < 3; i++ {
		if dec := d.Decide(a); dec.Outcome != Permit {
			t.Fatalf("call %d: %+v", i, dec)
		}
	}
	dec := d.Decide(a)
	if dec.ReasonCode != ReasonRateLimited || dec.Obligations.CallsPerMinute != 3 {
		t.Fatalf("profile bound not applied: %+v", dec)
	}
	// Per-principal window: another session of the same principal is also
	// limited, and the refused calls above did not extend any window.
	b := a
	b.SessionID = "s2"
	if dec := d.Decide(b); dec.ReasonCode != ReasonRateLimited {
		t.Fatalf("principal window: %+v", dec)
	}
	now = now.Add(61 * time.Second)
	if dec := d.Decide(b); dec.Outcome != Permit {
		t.Fatalf("refused calls consumed window: %+v", dec)
	}
	// Idle windows are pruned eventually.
	now = now.Add(2 * time.Minute)
	for i := 0; i < 1100; i++ {
		d.Decide(Request{PrincipalID: "p", SessionID: "x", Profile: "dev", Template: "nope"})
		d.Decide(Request{PrincipalID: "q", SessionID: "y", Template: "ro", Server: "fs", Tool: "read_file"})
		now = now.Add(time.Minute)
	}
	if n := d.Counters(); n > 3 {
		t.Fatalf("%d windows held", n)
	}
}

func TestFilterObligations(t *testing.T) {
	src := strings.Replace(doc, `"tools": ["read_file", "list_directory"]}`, `"tools": ["read_file", "list_directory"], "filters": ["path-canonicalize"]}`, 1)
	s, err := Compile([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	dec := NewDecider(s, 60).Decide(Request{PrincipalID: "p", SessionID: "s", Template: "ro", Server: "fs", Tool: "read_file"})
	if len(dec.Obligations.Filters) != 1 || dec.Obligations.Filters[0] != "path-canonicalize" {
		t.Fatalf("%+v", dec.Obligations)
	}
	bad := strings.Replace(src, `"path-canonicalize"`, `"Path Canon"`, 1)
	if _, err := Compile([]byte(bad)); err == nil {
		t.Fatal("bad filter ID accepted")
	}
}
