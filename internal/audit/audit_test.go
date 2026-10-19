package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func decisionEvent() Event {
	return Event{Class: "decision", Phase: PhaseAuthorized, Origin: "E-06", CorrelationID: "c", SessionID: "s", PrincipalID: "p", DecisionID: "d", PolicyRevision: "r1", Outcome: "permit", ReasonCode: "PERMIT", PolicyStatus: "evaluated"}
}

func TestJournalChainAndVerify(t *testing.T) {
	reqtest.Verifies(t, "FR-7.1", "FR-7.4", "FR-7.5")
	pub, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := Open(dir, priv, Options{MaxEvents: 3, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err := j.Record(decisionEvent()); err != nil {
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
	if rep.Segments != 3 || rep.Events != 7 || rep.AnchorSegment != 3 || len(rep.Findings()) != 0 {
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
	// Tamper with a footer field: the signature covers the whole footer.
	os.WriteFile(p2, []byte(strings.Replace(string(b2), `"type":"footer"`, `"type":"footer","recovered":true`, 1)), 0o600)
	if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("footer tamper undetected: %v", err)
	}
	// Restore and remove a middle segment: chain gap detected.
	os.WriteFile(p2, b2, 0o600)
	os.Remove(p2)
	if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("gap undetected: %v", err)
	}
}

func TestAnchorDetectsTrailingDeletion(t *testing.T) {
	reqtest.Verifies(t, "FR-7.5")
	pub, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, _ := Open(dir, priv, Options{MaxEvents: 2, MaxAge: time.Hour})
	for i := 0; i < 6; i++ {
		j.Record(decisionEvent())
	}
	j.Close()
	if _, err := Verify(dir, pub); err != nil {
		t.Fatal(err)
	}
	// Deleting the last closed segment(s) leaves a valid chain; the anchor
	// catches it.
	os.Remove(filepath.Join(dir, "segment-000004.jsonl"))
	if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("trailing deletion undetected: %v", err)
	}
	// Open refuses to continue a journal the anchor says is short.
	if _, err := Open(dir, priv, Options{}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("open continued a truncated journal: %v", err)
	}
	// A missing anchor is a failure once segments have closed.
	os.Remove(DefaultAnchorPath(dir))
	if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), "anchor") {
		t.Fatalf("missing anchor undetected: %v", err)
	}
	// A forged anchor fails its signature.
	_, other := newKey(t)
	j2, _ := Open(filepath.Join(t.TempDir(), "j2"), other, Options{AnchorPath: DefaultAnchorPath(dir)})
	j2.Close()
	if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("forged anchor accepted: %v", err)
	}
}

func TestJournalContinuesChainAcrossOpen(t *testing.T) {
	reqtest.Verifies(t, "FR-7.4")
	pub, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
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
	if err != nil || rep.Segments != 2 || rep.Events != 2 {
		t.Fatalf("%v %+v", err, rep)
	}
}

func TestCrashRecoveryTruncatedTail(t *testing.T) {
	reqtest.Verifies(t, "FR-7.4", "FR-7.5")
	pub, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, _ := Open(dir, priv, Options{MaxEvents: 100, MaxAge: time.Hour})
	for i := 0; i < 3; i++ {
		if err := j.Commit(decisionEvent()); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate a crash: stop the journal without sealing, then append half a
	// line as a torn write would.
	j.mu.Lock()
	j.closed = true
	close(j.stopTick)
	j.file.Write([]byte(`{"type":"event","event_id":"torn`))
	j.file.Close()
	j.mu.Unlock()

	rep, err := Verify(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Open != "segment-000001.jsonl" || !rep.TruncatedTail || rep.Events != 3 {
		t.Fatalf("open segment report %+v", rep)
	}
	j2, err := Open(dir, priv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rec := j2.Recovered(); len(rec) != 1 || rec[0].Segment != 1 || rec[0].Events != 3 || rec[0].TruncatedBytes == 0 {
		t.Fatalf("recovery %+v", rec)
	}
	j2.Close()
	rep, err = Verify(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Recovered) != 1 || rep.Recovered[0] != "segment-000001.jsonl" || rep.Events != 4 || len(rep.Findings()) != 1 {
		t.Fatalf("recovered report %+v", rep)
	}
	evs, _ := ReadEvents(dir)
	if last := evs[len(evs)-1]; last.ReasonCode != "JOURNAL_RECOVERED" {
		t.Fatalf("no recovery event: %+v", last)
	}
}

func TestUnclosedMiddleSegmentRefused(t *testing.T) {
	reqtest.Verifies(t, "FR-7.5")
	pub, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, _ := Open(dir, priv, Options{MaxEvents: 1, MaxAge: time.Hour})
	j.Record(decisionEvent())
	j.Record(decisionEvent())
	j.Close()
	p1 := filepath.Join(dir, "segment-000001.jsonl")
	b, _ := os.ReadFile(p1)
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(p1, []byte(strings.Join(lines[:len(lines)-2], "")), 0o600) // drop the footer
	if _, err := Verify(dir, pub); err == nil || !strings.Contains(err.Error(), "not closed") {
		t.Fatalf("verify: %v", err)
	}
	if _, err := Open(dir, priv, Options{}); err == nil {
		t.Fatal("open continued past an unclosed middle segment")
	}
}

func TestJournalRotatesByAge(t *testing.T) {
	reqtest.Verifies(t, "FR-7.4")
	pub, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
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

func TestGroupCommitConcurrent(t *testing.T) {
	reqtest.Verifies(t, "FR-7.4")
	pub, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, _ := Open(dir, priv, Options{MaxEvents: 7, MaxAge: time.Hour})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				var err error
				if i%2 == 0 {
					err = j.Commit(decisionEvent())
				} else {
					err = j.Record(decisionEvent())
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := j.Sync(); err != nil {
		t.Fatal(err)
	}
	j.Close()
	rep, err := Verify(dir, pub)
	if err != nil || rep.Events != 200 {
		t.Fatalf("%v %+v", err, rep)
	}
}

func TestWriteFailureIsSticky(t *testing.T) {
	reqtest.Partial(t, "SR-6.1-1")
	_, priv := newKey(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, _ := Open(dir, priv, Options{MaxAge: time.Hour})
	j.mu.Lock()
	j.file.Close() // the next write fails as a full or failed disk would
	j.mu.Unlock()
	if err := j.Record(decisionEvent()); err == nil {
		t.Fatal("write to a failed journal succeeded")
	}
	if err := j.Commit(decisionEvent()); err == nil || j.Err() == nil {
		t.Fatal("failure was not sticky")
	}
}

func TestFanoutObserversCannotBlockOrFail(t *testing.T) {
	m := &Memory{}
	f := NewFanout(m, nil)
	block := make(chan struct{})
	var got []Event
	var mu sync.Mutex
	f.AddObserver("slow", ObserverFunc(func(Event) { <-block }), 1)
	f.AddObserver("panics", ObserverFunc(func(Event) { panic("observer bug") }), 4)
	f.AddObserver("ok", ObserverFunc(func(e Event) { mu.Lock(); got = append(got, e); mu.Unlock() }), 16)
	for i := 0; i < 5; i++ {
		if err := f.Commit(Event{Class: "x", Origin: "E-21"}); err != nil {
			t.Fatal(err)
		}
	}
	if f.Dropped()["slow"] == 0 {
		t.Fatal("a blocked observer did not drop events")
	}
	close(block)
	f.Close()
	if len(got) != 5 || got[0].EventID == "" {
		t.Fatalf("observer saw %d events", len(got))
	}
	// The authoritative store's failure is returned; observers see nothing.
	m.Fail(errors.New("disk full"))
	if err := f.Record(Event{Class: "x", Origin: "E-21"}); err == nil {
		t.Fatal("store failure not returned")
	}
}

// directObs is a NonBlocking observer for the test below.
type directObs struct {
	seen  []Event
	panic bool
}

func (d *directObs) Observe(e Event) {
	if d.panic {
		panic("observer bug")
	}
	d.seen = append(d.seen, e)
}
func (d *directObs) NonBlockingObserver() {}

// TestFanoutCallsNonBlockingObserversDirectly: a NonBlocking observer sees
// each event before the write returns, without a queue of its own; its
// panic is contained, and it is listed in Dropped with no drops.
func TestFanoutCallsNonBlockingObserversDirectly(t *testing.T) {
	m := &Memory{}
	f := NewFanout(m, nil)
	d, bad := &directObs{}, &directObs{panic: true}
	f.AddObserver("direct", d, 1)
	f.AddObserver("direct-panics", bad, 1)
	for i := 0; i < 3; i++ {
		if err := f.Record(Event{Class: "x", Origin: "E-21"}); err != nil {
			t.Fatal(err)
		}
		if len(d.seen) != i+1 || d.seen[i].EventID == "" {
			t.Fatalf("after write %d the observer saw %d events", i+1, len(d.seen))
		}
	}
	if dr := f.Dropped(); dr["direct"] != 0 || len(dr) != 2 {
		t.Fatalf("dropped %v", dr)
	}
	f.Close()
	if err := f.Record(Event{Class: "x", Origin: "E-21"}); err != nil || len(d.seen) != 3 {
		t.Fatalf("after Close: %v, %d events", err, len(d.seen))
	}
}
