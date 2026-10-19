package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// clock is a manual clock for the monitor.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// switchable is a check whose causes the test sets.
type switchable struct {
	mu     sync.Mutex
	causes []Cause
}

func (s *switchable) set(c ...Cause) { s.mu.Lock(); s.causes = c; s.mu.Unlock() }
func (s *switchable) check(time.Time) []Cause {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Cause(nil), s.causes...)
}

func newMonitor(t *testing.T) (*Monitor, *clock, *switchable, *audit.Memory) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	ev := &audit.Memory{}
	m := New(Options{Now: c.now, Evidence: ev, Log: diag.Discard()})
	s := &switchable{}
	m.Register("test", s.check)
	return m, c, s, ev
}

func causeNames(r Report) []string {
	var out []string
	for _, c := range r.Causes {
		out = append(out, c.Name)
	}
	return out
}

func TestStatesAndCauses(t *testing.T) {
	// FR-7.12: a non-critical fault gives degraded, a critical one
	// fail-closed, each with its causes; the gate follows fail-closed.
	reqtest.Verifies(t, "FR-7.12")
	m, c, s, ev := newMonitor(t)
	m.Evaluate()
	if m.State() != Healthy || len(m.Gate()) != 0 {
		t.Fatalf("initial %s %v", m.State(), m.Gate())
	}
	s.set(Cause{Name: CauseUnconfined})
	m.Evaluate()
	if r := m.Report(); r.State != Degraded || len(r.Causes) != 1 || r.Causes[0].Name != CauseUnconfined || len(m.Gate()) != 0 {
		t.Fatalf("degraded: %+v gate %v", r, m.Gate())
	}
	s.set(Cause{Name: CauseUnconfined}, Cause{Name: CauseAuditCapacity, Critical: true, Detail: "10 MiB free"})
	c.add(time.Second)
	m.Evaluate()
	r := m.Report()
	if r.State != FailClosed || len(m.Gate()) != 1 || m.Gate()[0] != CauseAuditCapacity {
		t.Fatalf("fail-closed: %+v gate %v", r, m.Gate())
	}
	if names := causeNames(r); len(names) != 2 || names[0] != CauseAuditCapacity || names[1] != CauseUnconfined {
		t.Fatalf("causes %v", names)
	}
	// State changes are evidence.
	var states []string
	for _, e := range ev.Events() {
		if e.Class == "health" {
			states = append(states, e.Outcome)
		}
	}
	if len(states) != 2 || states[0] != Degraded || states[1] != FailClosed {
		t.Fatalf("health events %v", states)
	}
}

func TestRecoveryNeedsTenClearSecondsAndAck(t *testing.T) {
	// FR-7.13: an availability cause clears automatically after 10
	// consecutive clear seconds; an integrity cause also needs an
	// administrator acknowledgment; a re-raise restarts the count.
	reqtest.Verifies(t, "FR-7.13")
	m, c, s, ev := newMonitor(t)
	step := func(d time.Duration) { c.add(d); m.Evaluate() }

	s.set(Cause{Name: CauseSigningLag, Critical: true})
	step(0)
	s.set()
	step(time.Second)
	step(5 * time.Second)
	if m.State() != FailClosed {
		t.Fatal("released before 10 s")
	}
	s.set(Cause{Name: CauseSigningLag, Critical: true}) // flaps back
	step(time.Second)
	s.set()
	step(time.Second)
	step(9 * time.Second)
	if m.State() != FailClosed {
		t.Fatal("re-raise did not restart the 10 s count")
	}
	step(time.Second)
	if m.State() != Healthy || len(m.Gate()) != 0 {
		t.Fatalf("availability cause not released: %s %v", m.State(), m.Gate())
	}

	s.set(Cause{Name: CauseEvidence, Critical: true, Integrity: true})
	step(time.Second)
	if err := m.Ack(CauseUnconfined, "admin:x"); !errors.Is(err, ErrNotLatched) {
		t.Fatalf("ack of an unlatched cause: %v", err)
	}
	s.set()
	step(time.Second)
	step(20 * time.Second)
	r := m.Report()
	if r.State != FailClosed || !r.Causes[0].AckRequired || r.Causes[0].Active {
		t.Fatalf("integrity cause released without acknowledgment: %+v", r)
	}
	if err := m.Ack(CauseEvidence, "admin:alice"); err != nil {
		t.Fatal(err)
	}
	step(time.Second)
	if m.State() != Healthy {
		t.Fatalf("acknowledged and clear for 20 s, still %s", m.State())
	}
	// The acknowledgment is evidence.
	acked := false
	for _, e := range ev.Events() {
		acked = acked || (e.ReasonCode == "HEALTH_ACK")
	}
	if !acked {
		t.Fatal("acknowledgment not recorded")
	}
	// An acknowledgment given while the cause is active still needs the
	// 10 clear seconds.
	s.set(Cause{Name: CauseTrustInvalid, Critical: true, Integrity: true})
	step(time.Second)
	_ = m.Ack(CauseTrustInvalid, "admin:alice")
	s.set()
	step(time.Second)
	step(5 * time.Second)
	if m.State() != FailClosed {
		t.Fatal("acknowledged integrity cause released before 10 s")
	}
	step(5 * time.Second)
	if m.State() != Healthy {
		t.Fatal("acknowledged integrity cause not released")
	}
}

type fakeJournal struct {
	err    error
	n      int
	oldest time.Time
	dir    string
}

func (f fakeJournal) Err() error                 { return f.err }
func (f fakeJournal) Unsigned() (int, time.Time) { return f.n, f.oldest }
func (f fakeJournal) Dir() string                { return f.dir }

type pinger func(context.Context) error

func (p pinger) Ping(ctx context.Context) error { return p(ctx) }

func one(t *testing.T, cs []Cause, name string, critical bool) {
	t.Helper()
	if len(cs) != 1 || cs[0].Name != name || cs[0].Critical != critical {
		t.Fatalf("want %s (critical %v), got %+v", name, critical, cs)
	}
}

func TestChecks(t *testing.T) {
	// FR-7.11: the critical causes snapshot currency, journal writability
	// and signing lag, mandatory-audit capacity, clock sanity and
	// trust-anchor validity, and the non-critical unconfined cause, with
	// test inputs. The vault, graph mirror, Observation Store and memory
	// stage checks are registered by their elements; every dependency is
	// faulted in a running Gateway by TestHealthFaultEachDependency
	// (internal/e2e). SR-6.11-1 and SR-7.10-1: the thresholds.
	reqtest.Partial(t, "FR-7.11", "SR-6.11-1", "SR-7.10-1", "FR-13.10")
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

	loaded := false
	one(t, PolicyLoaded(func() bool { return loaded })(now), CauseNoSnapshot, true)
	loaded = true
	if cs := PolicyLoaded(func() bool { return loaded })(now); len(cs) != 0 {
		t.Fatal(cs)
	}

	j := Journal(fakeJournal{err: errors.New("fsync failed")})
	if cs := j(now); len(cs) != 1 || cs[0].Name != CauseEvidence || !cs[0].Integrity {
		t.Fatalf("journal error %+v", cs)
	}
	one(t, Journal(fakeJournal{n: 3, oldest: now.Add(-61 * time.Second)})(now), CauseSigningLag, true)
	one(t, Journal(fakeJournal{n: 1001, oldest: now})(now), CauseSigningLag, true)
	if cs := Journal(fakeJournal{n: 1000, oldest: now.Add(-59 * time.Second)})(now); len(cs) != 0 {
		t.Fatalf("within CP-27: %+v", cs)
	}

	dir := t.TempDir()
	if cs := JournalWritable(dir)(now); len(cs) != 0 {
		t.Fatal(cs)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		_ = os.Mkdir(ro, 0o500)
		one(t, JournalWritable(ro)(now), CauseJournalWritable, true)
	}

	for _, c := range []struct {
		free uint64
		want string
	}{{100 << 20, CauseAuditCapacity}, {512 << 20, CauseDiskLow}, {2 << 30, ""}} {
		restore := SetFreeBytes(func(string) (uint64, error) { return c.free, nil })
		t.Cleanup(restore)
		cs := Disk(dir)(now)
		if c.want == "" {
			if len(cs) != 0 {
				t.Fatalf("%d free: %+v", c.free, cs)
			}
			continue
		}
		one(t, cs, c.want, c.want == CauseAuditCapacity)
	}
	SetFreeBytes(nil)()
	if free, err := FreeBytes(dir); err != nil || free == 0 {
		t.Fatalf("real free space %d %v", free, err)
	}

	clk := Clock()
	if cs := clk(time.Now()); len(cs) != 0 {
		t.Fatal(cs)
	}
	one(t, clk(time.Now().Add(10*time.Minute)), CauseClock, true) // wall jumped against the monotonic clock
	if cs := clk(time.Now().Add(10 * time.Minute)); len(cs) != 0 {
		t.Fatalf("steady after the jump: %+v", cs)
	}
	one(t, Clock()(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)), CauseClock, true)

	st := t.TempDir()
	if err := keys.Ensure(st, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	ta := TrustAnchors(filepath.Join(st, keys.CACertFile), filepath.Join(st, keys.ServerCertFile))
	if cs := ta(time.Now()); len(cs) != 0 {
		t.Fatal(cs)
	}
	one(t, ta(time.Now().Add(70*24*time.Hour)), CauseKeysExpiring, false)
	one(t, ta(time.Now().Add(100*24*time.Hour)), CauseTrustExpired, true)
	other := t.TempDir()
	_ = keys.Ensure(other, "127.0.0.1")
	if cs := TrustAnchors(filepath.Join(other, keys.CACertFile), filepath.Join(st, keys.ServerCertFile))(time.Now()); len(cs) != 1 || cs[0].Name != CauseTrustInvalid || !cs[0].Integrity {
		t.Fatalf("foreign CA %+v", cs)
	}

	b := Backends(func() map[string]Pinger {
		return map[string]Pinger{"ok": pinger(func(context.Context) error { return nil }), "down": pinger(func(context.Context) error { return errors.New("eof") })}
	}, time.Second)
	if cs := b(now); len(cs) != 1 || cs[0].Name != CauseBackend || cs[0].Detail != "down" || cs[0].Critical {
		t.Fatalf("backends %+v", cs)
	}
	one(t, Static(CauseUnconfined, "standalone", func() bool { return true })(now), CauseUnconfined, false)

	drops := map[string]uint64{"graph": 0}
	od := ObserverDrops(func() map[string]uint64 { return drops })
	if cs := od(now); len(cs) != 0 {
		t.Fatal(cs)
	}
	drops["graph"] = 3
	one(t, od(now), CauseObserverDropping, false)
	if cs := od(now); len(cs) != 0 {
		t.Fatal("drops reported twice")
	}
}

func TestPolicyCurrencyAndVaultChecks(t *testing.T) {
	reqtest.Partial(t, "FR-7.11")
	detail, integrity := "", false
	pc := PolicyCurrency(func() (string, bool) { return detail, integrity })
	if cs := pc(time.Now()); len(cs) != 0 {
		t.Fatal(cs)
	}
	detail = "active.json names r2, r1 is in force"
	if cs := pc(time.Now()); len(cs) != 1 || cs[0].Name != CauseSnapshotStale || !cs[0].Critical || cs[0].Integrity {
		t.Fatalf("%+v", cs)
	}
	integrity = true
	if cs := pc(time.Now()); len(cs) != 1 || !cs[0].Integrity {
		t.Fatalf("%+v", cs)
	}
	var verr error
	v := Vault(func() error { return verr })
	if cs := v(time.Now()); len(cs) != 0 {
		t.Fatal(cs)
	}
	verr = errors.New("vault store missing")
	one(t, v(time.Now()), CauseVault, true)
}

func TestEveryCachesAndPanicIsCritical(t *testing.T) {
	reqtest.Partial(t, "FR-7.11")
	calls := 0
	c := Every(10*time.Second, func(time.Time) []Cause { calls++; return nil })
	t0 := time.Now()
	c(t0)
	c(t0.Add(time.Second))
	c(t0.Add(11 * time.Second))
	if calls != 2 {
		t.Fatalf("calls %d", calls)
	}
	m := New(Options{Log: diag.Discard()})
	m.Register("bad", func(time.Time) []Cause { panic("bug") })
	m.Evaluate()
	if m.State() != FailClosed || m.Gate()[0] != "check_failed" {
		t.Fatalf("panicking check: %s %v", m.State(), m.Gate())
	}
}

func TestRunEvaluatesWithinTwoSeconds(t *testing.T) {
	// FR-7.11 timing: detection within 2 seconds at the 1 s interval.
	reqtest.Partial(t, "FR-7.11")
	m := New(Options{Log: diag.Discard()})
	s := &switchable{}
	m.Register("t", s.check)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	s.set(Cause{Name: CauseAuditCapacity, Critical: true})
	start := time.Now()
	for len(m.Gate()) == 0 {
		if time.Since(start) > 2*time.Second {
			t.Fatal("not detected within 2 s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
