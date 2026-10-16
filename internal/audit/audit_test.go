package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestJournalChainAndVerify(t *testing.T) {
	reqtest.Verifies(t, "FR-7.1", "FR-7.4", "FR-7.5")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	j, err := Open(dir, priv, Options{MaxEvents: 3, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err := j.Record(Event{Class: "decision", Phase: PhaseAuthorized, Origin: "E-06", CorrelationID: "c", SessionID: "s", PrincipalID: "p", DecisionID: "d", PolicyRevision: "r1", Outcome: "permit", ReasonCode: "PERMIT", PolicyStatus: "evaluated"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(dir, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Segments != 3 || rep.Events != 7 {
		t.Fatalf("got %+v", rep)
	}
	// FR-7.1 fields present on the wire.
	b, _ := os.ReadFile(filepath.Join(dir, "segment-000001.jsonl"))
	for _, f := range []string{`"event_id"`, `"time"`, `"class"`, `"phase"`, `"origin"`, `"correlation_id"`, `"session_id"`, `"principal_id"`, `"decision_id"`, `"policy_revision"`, `"outcome"`, `"reason_code"`, `"policy_status"`} {
		if !strings.Contains(string(b), f) {
			t.Errorf("segment lacks %s", f)
		}
	}
	// Tamper with an event in segment 2: verification must name it.
	p2 := filepath.Join(dir, "segment-000002.jsonl")
	b2, _ := os.ReadFile(p2)
	os.WriteFile(p2, []byte(strings.Replace(string(b2), `"outcome":"permit"`, `"outcome":"deny"`, 1)), 0o600)
	if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), "segment-000002") {
		t.Fatalf("tamper undetected: %v", err)
	}
	// Restore and remove a middle segment: chain gap detected.
	os.WriteFile(p2, b2, 0o600)
	os.Remove(p2)
	if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("gap undetected: %v", err)
	}
}

func TestJournalContinuesChainAcrossOpen(t *testing.T) {
	reqtest.Verifies(t, "FR-7.4")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	j, _ := Open(dir, priv, Options{})
	j.Record(Event{Class: "x", Origin: "E-21"})
	j.Close()
	j2, err := Open(dir, priv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	j2.Record(Event{Class: "y", Origin: "E-21"})
	j2.Close()
	rep, err := Verify(dir, pub)
	if err != nil || rep.Segments != 2 {
		t.Fatalf("%v %+v", err, rep)
	}
}

func TestJournalRotatesByAge(t *testing.T) {
	reqtest.Verifies(t, "FR-7.4")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	j, _ := Open(dir, priv, Options{MaxAge: 100 * time.Millisecond})
	j.Record(Event{Class: "x", Origin: "E-21"})
	time.Sleep(300 * time.Millisecond)
	j.Record(Event{Class: "y", Origin: "E-21"})
	j.Close()
	rep, err := Verify(dir, pub)
	if err != nil || rep.Segments < 2 {
		t.Fatalf("%v %+v", err, rep)
	}
}
