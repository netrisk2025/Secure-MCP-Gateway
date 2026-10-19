package health

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Cause names. Critical causes hold the Gateway fail-closed; integrity
// causes also need an administrator acknowledgment (docs/operations/health.md).
const (
	CauseNoSnapshot       = "no_decision_snapshot"    // critical
	CauseSnapshotStale    = "decision_snapshot_stale" // critical (integrity when a store file no longer verifies)
	CauseVault            = "vault_unavailable"       // critical
	CauseEvidence         = "evidence_unavailable"    // critical, integrity
	CauseJournalWritable  = "journal_not_writable"    // critical
	CauseSigningLag       = "signing_lag"             // critical
	CauseAuditCapacity    = "audit_capacity"          // critical
	CauseClock            = "clock_unsane"            // critical
	CauseTrustExpired     = "trust_anchor_expired"    // critical
	CauseTrustInvalid     = "trust_anchor_invalid"    // critical, integrity
	CauseDiskLow          = "disk_space_low"          // non-critical
	CauseKeysExpiring     = "keys_expiring"           // non-critical
	CauseBackend          = "backend_unreachable"     // non-critical
	CauseUnconfined       = "unconfined"              // non-critical
	CauseUnverified       = "unverified_manifests"    // non-critical
	CauseObserverDropping = "observer_events_dropped" // non-critical
	// CauseGraphUnavailable and CauseObservationUnavailable are reported by
	// the graph mirror (E-26) and the Observation Store (E-27); neither
	// ever gates enforcement.
	CauseGraphUnavailable       = "graph_mirror_unavailable"      // non-critical
	CauseObservationUnavailable = "observation_store_unavailable" // non-critical
)

// CP-27 and SR-7.10-1 thresholds.
const (
	SigningLagStop  = 60 * time.Second
	SigningLagCount = 1000
	AuditReserve    = 256 << 20
	DiskWarn        = 1 << 30
	ClockJump       = 2 * time.Minute
)

// PolicyLoaded is critical while no decision snapshot is loaded.
func PolicyLoaded(loaded func() bool) Check {
	return func(time.Time) []Cause {
		if !loaded() {
			return []Cause{{Name: CauseNoSnapshot, Critical: true, Detail: "no policy decision snapshot is loaded"}}
		}
		return nil
	}
}

// PolicyFault is critical while the Policy Store reports a fault (for
// example "policy_signature": the active revision failed verification at
// start, SR-1.1-2). The cause carries the fault's name.
func PolicyFault(fault func() string) Check {
	return func(time.Time) []Cause {
		if f := fault(); f != "" {
			return []Cause{{Name: f, Critical: true, Detail: "the Policy Store refused the active revision"}}
		}
		return nil
	}
}

// PolicyCurrency is critical while the decision snapshot in force is not
// the Policy Store's signed active revision: the control record or the
// revision file no longer verifies, is missing, or names another revision
// (FR-7.11). check returns an empty detail while the snapshot is current;
// integrity marks a store file that no longer verifies.
func PolicyCurrency(check func() (detail string, integrity bool)) Check {
	return func(time.Time) []Cause {
		if d, integrity := check(); d != "" {
			return []Cause{{Name: CauseSnapshotStale, Critical: true, Integrity: integrity, Detail: d}}
		}
		return nil
	}
}

// Vault is critical while the secret vault cannot be read or no longer
// matches the key the Gateway unlocked it with (FR-7.11). check returns
// nil while the vault is available.
func Vault(check func() error) Check {
	return func(time.Time) []Cause {
		if err := check(); err != nil {
			return []Cause{{Name: CauseVault, Critical: true, Detail: "secret vault unavailable: " + err.Error()}}
		}
		return nil
	}
}

// JournalState is what the journal checks read; *audit.Journal implements it.
type JournalState interface {
	Err() error
	Unsigned() (int, time.Time)
	Dir() string
}

// Journal checks the sticky journal error (integrity: a write or fsync
// failed, or the journal was found damaged) and the signing lag against
// CP-27 (oldest unsigned event older than 60 s, or more than 1,000
// unsigned events).
func Journal(j JournalState) Check {
	return func(now time.Time) []Cause {
		var out []Cause
		if err := j.Err(); err != nil {
			out = append(out, Cause{Name: CauseEvidence, Critical: true, Integrity: true, Detail: err.Error()})
		}
		n, oldest := j.Unsigned()
		if n > SigningLagCount || (n > 0 && now.Sub(oldest) > SigningLagStop) {
			out = append(out, Cause{Name: CauseSigningLag, Critical: true, Detail: fmt.Sprintf("%d unsigned events, oldest %s old", n, now.Sub(oldest).Round(time.Second))})
		}
		return out
	}
}

// JournalWritable probes the journal directory by creating, syncing and
// removing a file.
func JournalWritable(dir string) Check {
	return func(time.Time) []Cause {
		f, err := os.CreateTemp(dir, ".health-probe-*")
		if err == nil {
			_, err = f.Write([]byte("probe\n"))
			if serr := f.Sync(); err == nil {
				err = serr
			}
			f.Close()
			if rerr := os.Remove(f.Name()); err == nil {
				err = rerr
			}
		}
		if err != nil {
			return []Cause{{Name: CauseJournalWritable, Critical: true, Detail: err.Error()}}
		}
		return nil
	}
}

type freeFunc = func(string) (uint64, error)

var freeImpl atomic.Pointer[freeFunc]

// FreeBytes reports the space available to the Gateway on the file system
// holding path.
func FreeBytes(path string) (uint64, error) {
	if f := freeImpl.Load(); f != nil {
		return (*f)(path)
	}
	return freeBytes(path)
}

// SetFreeBytes replaces the free-space measurement (tests) and returns a
// function that restores the real one.
func SetFreeBytes(f func(string) (uint64, error)) (restore func()) {
	freeImpl.Store(&f)
	return func() { freeImpl.Store(nil) }
}

// Disk is critical when the free space for the journal falls below the
// 256 MiB mandatory-audit reserve (SR-7.10-1) and degraded below 1 GiB.
func Disk(dir string) Check {
	return func(time.Time) []Cause {
		free, err := FreeBytes(dir)
		switch {
		case err != nil:
			return []Cause{{Name: CauseAuditCapacity, Critical: true, Detail: "free space unknown: " + err.Error()}}
		case free < AuditReserve:
			return []Cause{{Name: CauseAuditCapacity, Critical: true, Detail: fmt.Sprintf("%d MiB free, reserve is 256 MiB", free>>20)}}
		case free < DiskWarn:
			return []Cause{{Name: CauseDiskLow, Detail: fmt.Sprintf("%d MiB free", free>>20)}}
		}
		return nil
	}
}

// Clock is critical when the wall clock jumps by more than two minutes
// against the monotonic clock between two evaluations, or reads a time
// before 2026, which no release of this Gateway can run at. The jump
// cause is active for the evaluation that saw it; the latch then holds
// for the recovery period.
func Clock() Check {
	var (
		mu       sync.Mutex
		lastWall time.Time
		lastMono time.Time
	)
	return func(now time.Time) []Cause {
		mu.Lock()
		defer mu.Unlock()
		wall := now.Round(0) // strip the monotonic reading
		mono := time.Now()
		var out []Cause
		if wall.Year() < 2026 {
			out = append(out, Cause{Name: CauseClock, Critical: true, Detail: "wall clock reads " + wall.UTC().Format(time.RFC3339)})
		}
		if !lastWall.IsZero() {
			drift := wall.Sub(lastWall) - mono.Sub(lastMono)
			if drift > ClockJump || drift < -ClockJump {
				out = append(out, Cause{Name: CauseClock, Critical: true, Detail: fmt.Sprintf("wall clock jumped %s", drift.Round(time.Second))})
			}
		}
		lastWall, lastMono = wall, mono
		return out
	}
}

// TrustAnchors checks the server CA bundle and the listener certificate:
// expired or not yet valid is critical; unreadable, or a listener
// certificate that does not chain to the active CA, is critical and an
// integrity cause; expiring within 30 days is non-critical.
func TrustAnchors(caFile, certFile string) Check {
	return func(now time.Time) []Cause {
		cas, err := readCerts(caFile)
		if err != nil {
			return []Cause{{Name: CauseTrustInvalid, Critical: true, Integrity: true, Detail: err.Error()}}
		}
		leaves, err := readCerts(certFile)
		if err != nil {
			return []Cause{{Name: CauseTrustInvalid, Critical: true, Integrity: true, Detail: err.Error()}}
		}
		leaf := leaves[0]
		if err := leaf.CheckSignatureFrom(cas[0]); err != nil {
			return []Cause{{Name: CauseTrustInvalid, Critical: true, Integrity: true, Detail: "listener certificate is not issued by the active server CA"}}
		}
		var out []Cause
		var expiring []string
		for _, c := range []struct {
			name string
			cert *x509.Certificate
		}{{"server CA", cas[0]}, {"listener certificate", leaf}} {
			switch {
			case now.After(c.cert.NotAfter) || now.Before(c.cert.NotBefore):
				out = append(out, Cause{Name: CauseTrustExpired, Critical: true, Detail: c.name + " is outside its validity period"})
			case now.Add(30 * 24 * time.Hour).After(c.cert.NotAfter):
				expiring = append(expiring, fmt.Sprintf("%s expires %s", c.name, c.cert.NotAfter.UTC().Format(time.RFC3339)))
			}
		}
		if len(expiring) > 0 {
			out = append(out, Cause{Name: CauseKeysExpiring, Detail: strings.Join(expiring, "; ")})
		}
		return out
	}
}

func readCerts(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no certificate", filepath.Base(path))
	}
	return out, nil
}

// Pinger is a backend that can be probed.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Backends pings every enabled server; one that does not answer within
// timeout makes the state degraded with cause backend_unreachable naming
// the aliases. Wrap it in Every: a ping is a round trip to each server.
func Backends(servers func() map[string]Pinger, timeout time.Duration) Check {
	return func(time.Time) []Cause {
		var down []string
		for alias, p := range servers() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			err := p.Ping(ctx)
			cancel()
			if err != nil {
				down = append(down, alias)
			}
		}
		if len(down) == 0 {
			return nil
		}
		sort.Strings(down)
		return []Cause{{Name: CauseBackend, Detail: strings.Join(down, ", ")}}
	}
}

// Static returns a fixed non-critical cause while active reports true, for
// conditions decided at startup (the Standalone profile's `unconfined`,
// unverified manifests).
func Static(name, detail string, active func() bool) Check {
	return func(time.Time) []Cause {
		if active() {
			return []Cause{{Name: name, Detail: detail}}
		}
		return nil
	}
}

// ObserverDrops is degraded while an evidence observer (graph mirror,
// Observation Collector) dropped events since the previous evaluation.
func ObserverDrops(dropped func() map[string]uint64) Check {
	var (
		mu   sync.Mutex
		last = map[string]uint64{}
	)
	return func(time.Time) []Cause {
		mu.Lock()
		defer mu.Unlock()
		var names []string
		for name, n := range dropped() {
			if n > last[name] {
				names = append(names, name)
			}
			last[name] = n
		}
		if len(names) == 0 {
			return nil
		}
		sort.Strings(names)
		return []Cause{{Name: CauseObserverDropping, Detail: strings.Join(names, ", ")}}
	}
}
