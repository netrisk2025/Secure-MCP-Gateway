package e2e

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

// TestHealthFaultEachDependency (FR-7.11): a Gateway started the way smcpd
// starts it, with a monitor evaluating once per second, a secret vault, a
// graph mirror and the Observation Store registered as smcpd registers
// them. Each dependency is faulted in turn; the cause must be reported
// within 2 seconds of the fault, critical causes must make the Gateway
// fail-closed and refuse a call, and non-critical causes must leave it
// degraded and serving. The fault is then removed and the latch released
// before the next one.
//
// Faults: the signed policy-control record is altered (decision-snapshot
// currency); the journal directory is moved away (journal writability);
// the monitor's clock is advanced 61 s while the open segment holds
// unsigned events (signing lag beyond CP-27's 60 s); the free-space
// measurement reports 100 MiB (mandatory-audit capacity); the vault store
// file is moved away (vault availability); the monitor's clock jumps 5
// minutes (clock sanity); the CA bundle is overwritten (trust-anchor
// validity); the graph database fails (graph mirror reachability); the
// Observation Store directory is replaced by a file (Observation Store
// reachability); host memory is reported 5% available (memory degradation
// stage). `unconfined` is active from the start in the Standalone profile.
func TestHealthFaultEachDependency(t *testing.T) {
	reqtest.Verifies(t, "FR-7.11")
	var skew atomic.Int64
	now := func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	f := startOpsWith(t, "[observation]\nstore = \"jsonl\"\nflush_interval = \"50ms\"\n", nil,
		health.Options{Interval: time.Second, Recovery: time.Second, Now: now})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// E-19 vault, registered as cmd/smcpd registers it.
	vdir := filepath.Join(t.TempDir(), "vault")
	ks := secrets.Passphrase{Path: filepath.Join(vdir, secrets.MasterKeyFile), Passphrase: func() (string, error) { return "vault passphrase 1", nil }, WorkFactor: 10}
	if _, err := secrets.Init(vdir, ks); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.Open(vdir, ks, secrets.VaultOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f.mon.Register("vault", health.Vault(vault.Check))
	// E-25/E-26 graph mirror over the in-process engine.
	fake := graph.NewFake()
	mirror, err := graph.New(graph.Options{Config: f.cfg, Log: diag.Discard(), Backend: fake})
	if err != nil {
		t.Fatal(err)
	}
	mirror.Start(ctx, nil)
	t.Cleanup(mirror.Close)
	f.mon.Register("graph", mirror.HealthCheck())
	// E-27 Observation Store and the E-28 degradation stage.
	obs, err := analytics.New(analytics.Options{Config: f.cfg, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	obs.Start(ctx, f.app.Evidence, nil, func() uint64 { return 0 })
	t.Cleanup(obs.Close)
	f.mon.Register("observation", obs.HealthCheck())

	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)

	report := func() health.Report { return f.mon.Report() }
	active := func(name string) (health.CauseReport, bool) {
		for _, c := range report().Causes {
			if c.Name == name && c.Active {
				return c, true
			}
		}
		return health.CauseReport{}, false
	}
	waitFor := func(what string, limit time.Duration, cond func() bool) time.Duration {
		t.Helper()
		start := time.Now()
		for !cond() {
			if time.Since(start) > limit {
				t.Fatalf("%s: not reached within %v; report %+v", what, limit, report())
			}
			time.Sleep(20 * time.Millisecond)
		}
		return time.Since(start)
	}
	// Start: degraded by unconfined only, every dependency healthy.
	waitFor("ready mirror", 10*time.Second, func() bool { _, err := mirror.DAS(); return err == nil })
	waitFor("start state", 10*time.Second, func() bool {
		r := report()
		if r.State != health.Degraded || len(f.mon.Gate()) != 0 {
			return false
		}
		for _, c := range r.Causes {
			if c.Active && c.Name != health.CauseUnconfined && c.Name != health.CauseUnverified {
				return false
			}
		}
		return true
	})
	if c, ok := active(health.CauseUnconfined); !ok || c.Critical {
		t.Fatalf("unconfined: %+v %v", c, ok)
	}
	if err := f.echo(cs, "before"); err != nil {
		t.Fatal(err)
	}

	type fault struct {
		cause    string
		critical bool
		inject   func()
		remove   func()
	}
	move := func(from string) (inject, remove func()) {
		to := from + ".moved"
		return func() {
				if err := os.Rename(from, to); err != nil {
					t.Fatal(err)
				}
			}, func() {
				if err := os.Rename(to, from); err != nil {
					t.Fatal(err)
				}
			}
	}
	replace := func(path string, with []byte) (inject, remove func()) {
		var orig []byte
		return func() {
				var err error
				if orig, err = os.ReadFile(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, with, 0o600); err != nil {
					t.Fatal(err)
				}
			}, func() {
				if err := os.WriteFile(path, orig, 0o600); err != nil {
					t.Fatal(err)
				}
			}
	}
	var faults []fault
	add := func(cause string, critical bool, inject, remove func()) {
		faults = append(faults, fault{cause, critical, inject, remove})
	}
	// The journal directory first: the open segment is young, so the
	// journal does not need a new segment file while the directory is
	// away.
	in, out := move(filepath.Join(f.stateDir, "journal"))
	add(health.CauseJournalWritable, true, in, out)
	ctl := filepath.Join(f.stateDir, policystore.ControlFile)
	raw, err := os.ReadFile(ctl)
	if err != nil {
		t.Fatal(err)
	}
	in, out = replace(ctl, []byte(string(raw[:len(raw)-2])+` ,"actor":"tampered"}`+"\n"))
	add(health.CauseSnapshotStale, true, in, out)
	add(health.CauseSigningLag, true, func() { skew.Store(int64(61 * time.Second)) }, func() { skew.Store(0) })
	var restoreFree func()
	add(health.CauseAuditCapacity, true, func() {
		restoreFree = health.SetFreeBytes(func(string) (uint64, error) { return 100 << 20, nil })
	}, func() { restoreFree() })
	in, out = move(filepath.Join(vdir, secrets.StoreFile))
	add(health.CauseVault, true, in, out)
	add(health.CauseClock, true, func() { skew.Store(int64(5 * time.Minute)) }, func() { skew.Store(0) })
	in, out = replace(filepath.Join(f.stateDir, keys.CACertFile), []byte("not a certificate\n"))
	add(health.CauseTrustInvalid, true, in, out)
	add(health.CauseGraphUnavailable, false, func() { fake.Fail(graph.ErrUnavailable) }, func() { fake.Fail(nil) })
	// The store recreates a missing directory on its next write, so a
	// file takes the directory's place.
	store := filepath.Join(f.stateDir, "observation", "store")
	in, out = move(store)
	add(health.CauseObservationUnavailable, false, func() {
		in()
		if err := os.WriteFile(store, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}, func() {
		if err := os.Remove(store); err != nil {
			t.Fatal(err)
		}
		out()
	})
	var restoreMem func()
	add(analytics.CauseObservationDegraded, false, func() {
		restoreMem = analytics.SetHostAvailable(func() (float64, bool) { return 0.05, true })
	}, func() { restoreMem() })

	for _, fl := range faults {
		if fl.cause == health.CauseSigningLag {
			// An unsigned event in the open segment.
			if err := f.echo(cs, "lag"); err != nil {
				t.Fatal(err)
			}
		}
		fl.inject()
		took := waitFor(fl.cause+" detected", 5*time.Second, func() bool { _, ok := active(fl.cause); return ok })
		t.Logf("%s detected after %v", fl.cause, took.Round(time.Millisecond))
		if took > 2*time.Second {
			t.Errorf("%s detected after %v, more than 2 s", fl.cause, took)
		}
		c, _ := active(fl.cause)
		st := report().State
		if fl.critical {
			if !c.Critical || st != health.FailClosed || len(f.mon.Gate()) == 0 {
				t.Errorf("%s: critical %v, state %s, gate %v; want critical and fail-closed", fl.cause, c.Critical, st, f.mon.Gate())
			}
			if err := f.echo(cs, "during-"+fl.cause); err == nil {
				t.Errorf("%s: call accepted while fail-closed", fl.cause)
			}
		} else {
			if c.Critical || st != health.Degraded || len(f.mon.Gate()) != 0 {
				t.Errorf("%s: critical %v, state %s, gate %v; want non-critical and degraded", fl.cause, c.Critical, st, f.mon.Gate())
			}
			if err := f.echo(cs, "during-"+fl.cause); err != nil {
				t.Errorf("%s: call refused while degraded: %v", fl.cause, err)
			}
		}
		fl.remove()
		if c.Integrity {
			if err := f.mon.Ack(fl.cause, "test"); err != nil {
				t.Fatalf("ack %s: %v", fl.cause, err)
			}
		}
		waitFor(fl.cause+" cleared", 20*time.Second, func() bool {
			_, still := active(fl.cause)
			return !still && len(f.mon.Gate()) == 0
		})
	}
	if err := f.echo(cs, "after"); err != nil {
		t.Fatalf("call after every fault was removed: %v", err)
	}
}
