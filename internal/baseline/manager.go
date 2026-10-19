package baseline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Loader receives promoted snapshots: the Anomaly Scorer (E-31) over I-39.
// Load must verify the digest and replace its snapshot atomically.
type Loader interface {
	Load(*Snapshot) error
}

// ManagerOptions configure the snapshot lifecycle.
type ManagerOptions struct {
	Dir      string        // snapshots, promotion history and the state file
	Interval time.Duration // build at this interval when records were learned (0: off)
	Records  int64         // build after this many learned records (0: off)
	Auto     AutoLimits    // automatic promotion limits (zero: operator only)
	Loader   Loader
	Log      *slog.Logger
}

// Manager runs the baseline lifecycle (ArchitectureV2 §9.4): learn, build
// snapshots at the policy interval or record count or on command, report
// drift, promote by operator or within automatic limits, and roll back.
type Manager struct {
	*Engine
	store *SnapshotStore
	o     ManagerOptions

	buildMu sync.Mutex     // one build at a time, whatever its trigger
	bg      sync.WaitGroup // record-count builds running in the background

	mu          sync.Mutex
	rec         audit.Recorder
	sinceBuild  int64
	building    bool
	lastDrift   *DriftReport
	promotedErr error
}

// NewManager opens the snapshot store, restores the candidate state and
// loads the promoted snapshot into the Loader. A promoted snapshot whose
// digest does not verify is not loaded (SR-7-1); the error is kept and
// reported by Status and as an integrity event once a Recorder is set.
func NewManager(e *Engine, o ManagerOptions) (*Manager, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	st, err := OpenSnapshotStore(o.Dir)
	if err != nil {
		return nil, err
	}
	m := &Manager{Engine: e, store: st, o: o}
	if err := e.LoadState(m.statePath()); err != nil {
		o.Log.Warn("baseline candidate state not restored", "err", err)
	}
	id, err := st.Promoted()
	if err != nil {
		return nil, err
	}
	if id != "" {
		snap, err := st.Load(id)
		if err == nil && o.Loader != nil {
			err = o.Loader.Load(snap)
		}
		if err != nil {
			m.promotedErr = err
			o.Log.Error("promoted baseline snapshot refused", "snapshot", id, "err", err)
		}
	}
	return m, nil
}

func (m *Manager) statePath() string { return filepath.Join(m.o.Dir, "candidate-state.json") }

// Store returns the snapshot store.
func (m *Manager) Store() *SnapshotStore { return m.store }

// SetRecorder sets the evidence recorder and reports a refused promoted
// snapshot found at startup.
func (m *Manager) SetRecorder(rec audit.Recorder) {
	m.mu.Lock()
	m.rec = rec
	perr := m.promotedErr
	m.mu.Unlock()
	if perr != nil {
		m.integrity(perr)
	}
}

func (m *Manager) record(ev audit.Event) error {
	m.mu.Lock()
	rec := m.rec
	m.mu.Unlock()
	if rec == nil {
		return nil
	}
	ev.Origin, ev.PolicyStatus = "E-30", "not_evaluated"
	if ev.Class == "" {
		ev.Class = "baseline"
	}
	return rec.Commit(ev)
}

func (m *Manager) integrity(err error) {
	if rerr := m.record(audit.Event{Class: "integrity", Outcome: "refused", ReasonCode: "BASELINE_DIGEST_MISMATCH",
		Detail: map[string]any{"error": err.Error()}}); rerr != nil {
		m.o.Log.Error("evidence write failed", "err", rerr)
	}
}

// Learn learns a record and builds a snapshot when the record count is
// reached. It never blocks on the build: the build runs on its own
// goroutine.
func (m *Manager) Learn(s Sample, info LearnInfo) (bool, string) {
	ok, why := m.Engine.Learn(s, info)
	if !ok || m.o.Records <= 0 {
		return ok, why
	}
	m.mu.Lock()
	m.sinceBuild++
	due := m.sinceBuild >= m.o.Records && !m.building
	if due {
		m.building = true
	}
	m.mu.Unlock()
	if due {
		m.bg.Add(1)
		go func() {
			defer m.bg.Done()
			if _, err := m.BuildSnapshot("records", "E-30"); err != nil {
				m.o.Log.Error("baseline snapshot build failed", "err", err)
			}
		}()
	}
	return ok, why
}

// Run builds snapshots at the configured interval and saves the candidate
// state until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	iv := m.o.Interval
	if iv <= 0 {
		iv = time.Hour
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := m.SaveState(m.statePath()); err != nil {
				m.o.Log.Warn("baseline state not saved", "err", err)
			}
			return
		case <-t.C:
			m.mu.Lock()
			due := m.o.Interval > 0 && m.sinceBuild > 0 && !m.building
			if due {
				m.building = true
			}
			m.mu.Unlock()
			if due {
				if _, err := m.BuildSnapshot("interval", "E-30"); err != nil {
					m.o.Log.Error("baseline snapshot build failed", "err", err)
				}
			}
			if err := m.SaveState(m.statePath()); err != nil {
				m.o.Log.Warn("baseline state not saved", "err", err)
			}
		}
	}
}

// BuildResult is a built snapshot with its drift against the promoted one.
type BuildResult struct {
	Snapshot Summary     `json:"snapshot"`
	Drift    DriftReport `json:"drift"`
	Promoted bool        `json:"promoted"`
}

// BuildSnapshot freezes, seals and stores a snapshot, reports its drift and
// promotes it automatically when the automatic limits allow.
func (m *Manager) BuildSnapshot(trigger, actor string) (BuildResult, error) {
	m.buildMu.Lock()
	defer m.buildMu.Unlock()
	defer func() {
		m.mu.Lock()
		m.building = false
		m.mu.Unlock()
	}()
	m.mu.Lock()
	m.sinceBuild = 0
	m.mu.Unlock()
	snap, err := m.Build(trigger)
	if err != nil {
		return BuildResult{}, err
	}
	if err := m.store.Save(snap); err != nil {
		return BuildResult{}, err
	}
	if err := m.SaveState(m.statePath()); err != nil {
		m.o.Log.Warn("baseline state not saved", "err", err)
	}
	var prom *Snapshot
	if id, _ := m.store.Promoted(); id != "" {
		prom, _ = m.store.Load(id)
	}
	drift := Drift(snap, prom)
	m.mu.Lock()
	m.lastDrift = &drift
	m.mu.Unlock()
	res := BuildResult{Snapshot: snap.Summarize(), Drift: drift}
	if err := m.record(audit.Event{Outcome: "snapshot_built", Detail: map[string]any{"snapshot_id": snap.ID, "digest": snap.Digest, "trigger": trigger,
		"actor": actor, "contexts": len(snap.Contexts), "records": snap.Records, "max_abs_mean_shift_sigma": drift.MaxAbsShift,
		"max_sigma_factor": drift.MaxSigmaFactor, "new_contexts": len(drift.NewContexts)}}); err != nil {
		return res, err
	}
	// Automatic promotion needs a promoted snapshot to compare with: the
	// first snapshot is always promoted by an operator.
	if prom != nil && m.o.Auto.Within(drift) {
		if err := m.promote(snap, "E-30", "automatic"); err != nil {
			return res, err
		}
		res.Promoted = true
		res.Snapshot.Promoted = true
	}
	return res, nil
}

// LastDrift returns the drift report of the latest build.
func (m *Manager) LastDrift() *DriftReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastDrift
}

// DriftOf reports the drift of a stored snapshot against the promoted one.
func (m *Manager) DriftOf(id string) (DriftReport, error) {
	snap, err := m.store.Load(id)
	if err != nil {
		return DriftReport{}, err
	}
	var prom *Snapshot
	if pid, _ := m.store.Promoted(); pid != "" && pid != id {
		prom, _ = m.store.Load(pid)
	}
	return Drift(snap, prom), nil
}

// ErrAlreadyPromoted reports a promotion of the promoted snapshot.
var ErrAlreadyPromoted = errors.New("snapshot is already promoted")

// Promote promotes a stored snapshot by operator command. Promoting a
// snapshot older than the current one is a rollback (FR-10.21).
func (m *Manager) Promote(id, actor string) (Promotion, error) {
	snap, err := m.store.Load(id)
	if err != nil {
		if errors.Is(err, ErrDigest) {
			m.integrity(err)
		}
		return Promotion{}, err
	}
	cur, _ := m.store.Promoted()
	if cur == id {
		return Promotion{}, ErrAlreadyPromoted
	}
	mode := "operator"
	if cur != "" && id < cur {
		mode = "rollback"
	}
	if err := m.promote(snap, actor, mode); err != nil {
		return Promotion{}, err
	}
	h, _ := m.store.History()
	return h[len(h)-1], nil
}

func (m *Manager) promote(snap *Snapshot, actor, mode string) error {
	if m.o.Loader != nil {
		if err := m.o.Loader.Load(snap); err != nil {
			if errors.Is(err, ErrDigest) {
				m.integrity(err)
			}
			return fmt.Errorf("scorer refused snapshot %s: %w", snap.ID, err)
		}
	}
	p := Promotion{ID: snap.ID, At: time.Now().UTC(), By: actor, Mode: mode}
	if err := m.store.SetPromoted(p); err != nil {
		return err
	}
	m.mu.Lock()
	m.promotedErr = nil
	m.mu.Unlock()
	return m.record(audit.Event{Outcome: "promoted", ReasonCode: "BASELINE_" + map[string]string{"operator": "PROMOTED", "automatic": "AUTO_PROMOTED", "rollback": "ROLLED_BACK"}[mode],
		Detail: map[string]any{"snapshot_id": snap.ID, "digest": snap.Digest, "actor": actor, "mode": mode}})
}

// ManagerStatus is the lifecycle status.
type ManagerStatus struct {
	Status
	Promoted      string `json:"promoted,omitempty"`
	PromotedError string `json:"promoted_error,omitempty"`
	Snapshots     int    `json:"snapshots"`
	SinceBuild    int64  `json:"records_since_build"`
}

// LifecycleStatus reports the engine and snapshot status.
func (m *Manager) LifecycleStatus() ManagerStatus {
	st := ManagerStatus{Status: m.Engine.Status()}
	st.Promoted, _ = m.store.Promoted()
	if l, err := m.store.List(); err == nil {
		st.Snapshots = len(l)
	}
	m.mu.Lock()
	if m.promotedErr != nil {
		st.PromotedError = m.promotedErr.Error()
	}
	st.SinceBuild = m.sinceBuild
	m.mu.Unlock()
	return st
}

// Wait returns when the record-count builds started so far have finished
// (snapshot stored and its snapshot_built event recorded).
func (m *Manager) Wait() { m.bg.Wait() }

// Close waits for background builds, then saves the candidate state.
func (m *Manager) Close() error {
	m.Wait()
	return m.SaveState(m.statePath())
}
