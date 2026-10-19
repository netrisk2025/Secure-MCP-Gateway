// Package ops is the daemon-side operations runtime: it attaches the
// Health & Safety Monitor (E-23), the metrics endpoint, evidence export
// (FR-7.14), key and certificate maintenance and rotation (E-22, FR-17.7),
// online backups (FR-17.6, SR-7.7-1) and configuration reload (FR-17.9) to
// a started Gateway, and registers their control API routes:
//
//	GET  /api/v1/health/status   health report (FR-7.12)
//	POST /api/v1/health/ack      acknowledge a latched integrity cause (FR-7.13)
//	GET  /api/v1/keys            key inventory
//	POST /api/v1/keys/rotate     rotate the listener certificate, server CA or evidence key
//	GET  /api/v1/backup          recorded backups
//	POST /api/v1/backup          take an encrypted backup
//	POST /api/v1/config/reload   reload the configuration file
//
// docs/api/ops.md documents the request and response bodies.
package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/metrics"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
)

// UpgradeEventFile is written by `smcpctl upgrade` into the state directory
// and turned into an evidence event by the next Gateway that starts.
const UpgradeEventFile = "upgrade-event.json"

// UpgradeEvent is the content of UpgradeEventFile.
type UpgradeEvent struct {
	Outcome     string `json:"outcome"` // upgraded, upgrade_rolled_back
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Backup      string `json:"backup,omitempty"`
	Time        string `json:"time"`
}

// PrepareReport says what Prepare did.
type PrepareReport struct {
	EvidenceRotation string // "", "committed" or "discarded"
	CASwitched       bool
	InstallationID   string
}

// Prepare runs before app.Start: it finishes or discards an interrupted
// evidence-key rotation, completes a server CA rotation whose overlap has
// ended and makes sure the installation ID exists.
func Prepare(cfg *config.Config) (PrepareReport, error) {
	var rep PrepareReport
	next, err := audit.LastTransition(filepath.Join(cfg.State.Dir, "journal"))
	if err != nil {
		return rep, fmt.Errorf("journal: %w", err)
	}
	if rep.EvidenceRotation, err = keys.ResolvePendingEvidenceKey(cfg.State.Dir, next); err != nil {
		return rep, fmt.Errorf("pending evidence key: %w", err)
	}
	if rep.CASwitched, _, err = keys.AdvanceCARotation(cfg.State.Dir, time.Now(), ListenerNames(cfg)...); err != nil {
		return rep, fmt.Errorf("server CA rotation: %w", err)
	}
	if rep.InstallationID, err = keys.EnsureInstallationID(cfg.State.Dir); err != nil {
		return rep, err
	}
	return rep, nil
}

// ListenerNames are the names the listener certificate must cover.
func ListenerNames(cfg *config.Config) []string {
	var names []string
	for _, a := range []string{cfg.Listener.Address, cfg.AdminListener.Address} {
		if h, _, err := net.SplitHostPort(a); err == nil {
			names = append(names, h)
		}
	}
	if u, err := url.Parse(cfg.Listener.PublicURL); err == nil {
		names = append(names, u.Hostname())
	}
	return names
}

// Options configure Attach.
type Options struct {
	ConfigPath string
	Log        *slog.Logger
	// LogLevel is the daemon logger's level, changed by reload.
	LogLevel *slog.LevelVar
	// Monitor is the health monitor whose Gate was passed to app.Start;
	// Attach registers the checks and starts it. Nil creates one that
	// does not gate the edge (tests).
	Monitor *health.Monitor
	// KeyInterval is how often certificate expiry and CA overlap are
	// checked (default 1h).
	KeyInterval time.Duration
	// DrainTimeout bounds how long a backup waits for in-flight calls
	// (default 30s).
	DrainTimeout time.Duration
	// BackupWorkFactor overrides the scrypt work factor (tests only).
	BackupWorkFactor int
	// PendingApprovals reports the approval queue length for metrics; the
	// Approval Service (E-07) supplies it. Nil reports 0.
	PendingApprovals func() int
	// Elements, when set, is reported as info.elements in the health
	// status: the elements the daemon wired and their state (cmd/smcpd).
	Elements func() any
	// MetricsListener, when set, is the metrics listener bound before the
	// Gateway started (app.BindListeners); Attach serves it instead of
	// binding [metrics] address.
	MetricsListener net.Listener
}

// Runtime is the attached operations runtime.
type Runtime struct {
	app     *app.App
	cfgPath string
	log     *slog.Logger
	level   *slog.LevelVar
	mon     *health.Monitor
	metrics *metrics.Registry
	opts    Options

	opMu sync.Mutex // backup, rotation and reload are exclusive

	mu        sync.Mutex
	running   *config.Config // configuration in force, including reloaded keys
	exportErr error
	lastExp   audit.ExportResult

	cancel context.CancelFunc
	done   sync.WaitGroup
}

// Attach starts the operations runtime on a started Gateway and registers
// its routes. It fails when metrics are enabled on an address that cannot
// be bound or is not loopback.
func Attach(ctx context.Context, a *app.App, o Options) (*Runtime, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.LogLevel == nil {
		o.LogLevel = new(slog.LevelVar)
	}
	if o.KeyInterval <= 0 {
		o.KeyInterval = time.Hour
	}
	if o.DrainTimeout <= 0 {
		o.DrainTimeout = 30 * time.Second
	}
	if o.Monitor == nil {
		o.Monitor = health.New(health.Options{Log: o.Log})
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &Runtime{app: a, cfgPath: o.ConfigPath, log: o.Log, level: o.LogLevel, mon: o.Monitor, opts: o, running: a.Config, cancel: cancel}
	r.registerChecks()

	r.metrics = metrics.New(r.toolNames(), metrics.Sources{
		HealthState:    func() string { return r.Status().State },
		ActiveSessions: func() int { return len(a.Store.Active()) },
		Backends: func() []string {
			var out []string
			for alias := range a.Registry.Servers() {
				out = append(out, alias)
			}
			return out
		},
		PendingApproval: o.PendingApprovals,
	})
	a.Evidence.AddObserver("metrics", r.metrics, 4096)
	a.Journal.SetFlushObserver(r.metrics.Flush.Observe)
	if a.Config.Metrics.Enabled {
		ln := o.MetricsListener
		if ln == nil {
			var err error
			if ln, err = metrics.Listen(a.Config.Metrics.Address); err != nil {
				cancel()
				return nil, fmt.Errorf("metrics: %w", err)
			}
		}
		r.goRun(func() {
			if err := r.metrics.Serve(ctx, ln, o.Log); err != nil {
				o.Log.Error("metrics endpoint stopped", "err", err)
			}
		})
		o.Log.Info("metrics endpoint listening", "address", ln.Addr().String())
	}
	r.recordUpgradeEvent()
	// The first evaluation finishes before Attach returns, so the health
	// report has its causes by the time the listeners serve.
	r.mon.Evaluate()
	r.goRun(func() { r.mon.Run(ctx) })
	r.goRun(func() { r.keyLoop(ctx) })
	if iv := a.Config.Backup.Interval.Duration; iv > 0 {
		r.goRun(func() { r.backupLoop(ctx, iv) }) // FR-9.16
	}
	if a.Config.Evidence.ExportDir != "" {
		r.goRun(func() { r.exportLoop(ctx, a.Config.Evidence.ExportInterval.Duration) })
	}
	r.routes()
	return r, nil
}

func (r *Runtime) goRun(f func()) {
	r.done.Add(1)
	go func() { defer r.done.Done(); f() }()
}

// Close stops the runtime's goroutines. A final export runs so that the
// segment sealed at shutdown is exported by the next start at the latest.
func (r *Runtime) Close() {
	r.cancel()
	r.done.Wait()
	r.app.Journal.SetFlushObserver(nil)
}

// Monitor returns the health monitor.
func (r *Runtime) Monitor() *health.Monitor { return r.mon }

// Metrics returns the metrics registry.
func (r *Runtime) Metrics() *metrics.Registry { return r.metrics }

func (r *Runtime) registerChecks() {
	a := r.app
	stateDir := a.Config.State.Dir
	jdir := a.Journal.Dir()
	m := r.mon
	m.SetEvidence(a.Evidence)
	m.SetInfo(func() map[string]any {
		h := a.Gateway.Health()
		info := map[string]any{"profile": a.Profile.Profile, "release_label": a.Profile.Label, "version": backend.Version,
			"emergency_stop": a.Gateway.Stopped(), "sessions": h.Sessions}
		if h.PolicyRevision != "" {
			info["policy_revision"] = h.PolicyRevision
		}
		if r.opts.Elements != nil {
			info["elements"] = r.opts.Elements()
		}
		return info
	})
	m.Register("policy", health.PolicyLoaded(func() bool { return a.Decider.Snapshot() != nil }))
	if a.Policy != nil {
		m.Register("policy_store", health.PolicyFault(a.Policy.Fault))
		m.Register("policy_currency", health.PolicyCurrency(func() (string, bool) {
			c := a.Policy.CheckCurrency()
			return c.Detail, c.Integrity
		}))
	}
	// The critical checks run on every evaluation (once per second), so a
	// fault is detected within 2 seconds (FR-7.11).
	m.Register("journal", health.Journal(a.Journal))
	m.Register("journal_writable", health.JournalWritable(jdir))
	m.Register("disk", health.Disk(jdir))
	m.AddQuota(&health.Quota{Name: "journal", Dir: jdir, Limit: a.Config.Evidence.QuotaBytes}) // CP-26, FR-9.15
	m.Register("clock", health.Clock())
	m.Register("trust_anchors", health.TrustAnchors(filepath.Join(stateDir, keys.CACertFile), a.Config.Listener.TLSCert))
	m.Register("backends", health.Every(10*time.Second, health.Backends(func() map[string]health.Pinger {
		out := map[string]health.Pinger{}
		for alias, s := range a.Registry.Servers() {
			out[alias] = s
		}
		return out
	}, 2*time.Second)))
	if a.Profile.Profile == profile.Standalone {
		m.Register("profile", health.Static(health.CauseUnconfined, "standalone profile: server instances run unconfined", func() bool { return true }))
	}
	m.Register("manifests", health.Static(health.CauseUnverified, "tool lists come from live servers, not signed manifests", func() bool {
		for _, s := range a.Registry.Servers() {
			if !s.Verified {
				return true
			}
		}
		return false
	}))
	m.Register("observers", health.ObserverDrops(a.Evidence.Dropped))
	m.Register("export", func(time.Time) []health.Cause {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.exportErr != nil {
			return []health.Cause{{Name: "evidence_export_failed", Detail: r.exportErr.Error()}}
		}
		return nil
	})
}

// toolNames maps tool revisions to server alias and public tool name.
func (r *Runtime) toolNames() metrics.ToolName {
	idx := map[string][2]string{}
	for _, p := range r.app.Registry.PublicNames() {
		if ref := r.app.Registry.Resolve(p); ref != nil {
			idx[ref.Revision] = [2]string{ref.Server.Alias, p}
		}
	}
	return func(rev string) (string, string, bool) {
		v, ok := idx[rev]
		return v[0], v[1], ok
	}
}

// Status combines the monitor's report with the edge's own fail-closed
// conditions (emergency stop), which the monitor does not own.
type Status struct {
	health.Report
	Gateway any `json:"gateway"`
}

// Status returns the combined health status.
func (r *Runtime) Status() Status {
	rep := r.mon.Report()
	g := r.app.Gateway.Health()
	if rank(g.State) > rank(rep.State) {
		rep.State = g.State
	}
	return Status{Report: rep, Gateway: g}
}

func rank(s string) int {
	switch s {
	case health.FailClosed:
		return 2
	case health.Degraded:
		return 1
	}
	return 0
}

func (r *Runtime) keyLoop(ctx context.Context) {
	t := time.NewTicker(r.opts.KeyInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.maintainKeys(time.Now())
		}
	}
}

// maintainKeys reissues the listener certificate when 30 days remain
// (CP-53) and finishes a CA rotation whose overlap has ended.
func (r *Runtime) maintainKeys(now time.Time) {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	cfg := r.app.Config
	names := ListenerNames(cfg)
	if switched, st, err := keys.AdvanceCARotation(cfg.State.Dir, now, names...); err != nil {
		r.log.Error("server CA rotation could not finish", "err", err)
	} else if switched {
		r.log.Warn("server CA rotation finished; the new CA is active", "listener_not_after", st.LeafNotAfter)
		r.commit("key_rotated", "SERVER_CA_ACTIVATED", "system", map[string]any{"kind": "ca", "stage": "finished"})
	}
	st, err := keys.RotateIfDue(cfg.State.Dir, now, names...)
	if err != nil {
		r.log.Error("listener certificate check failed", "err", err)
		return
	}
	if st.LeafRotated {
		r.log.Warn("listener certificate reissued", "not_after", st.LeafNotAfter)
		r.commit("key_rotated", "LISTENER_CERT_RENEWED", "system", map[string]any{"kind": "tls", "not_after": st.LeafNotAfter})
	}
}

func (r *Runtime) commit(outcome, reason, actor string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["actor"] = actor
	if err := r.app.Evidence.Commit(audit.Event{Class: "admin", Origin: "E-22", Outcome: outcome, ReasonCode: reason, PolicyStatus: "not_evaluated", Detail: detail}); err != nil {
		r.log.Error("evidence write failed", "err", err)
	}
}

// backupLoop runs a scheduled backup every interval (FR-9.16) with the
// encryption of [backup]. Each run is the SR-7.7-1 procedure of an
// on-demand backup and records its result and checksum the same way. The
// interval is counted from the end of the previous run, so that dispatch,
// which a backup stops, runs for at least the interval between backups
// however long a backup takes.
func (r *Runtime) backupLoop(ctx context.Context, every time.Duration) {
	t := time.NewTimer(every)
	defer t.Stop()
	for ; ; t.Reset(every) {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cfg := r.app.Config.Backup
		req := BackupRequest{Recipients: cfg.Recipients}
		if cfg.PassphraseFile != "" {
			b, err := os.ReadFile(cfg.PassphraseFile)
			if err != nil {
				r.log.Error("scheduled backup: passphrase file", "err", err)
				r.commit("failed", "BACKUP_FAILED", "scheduler", map[string]any{"kind": "backup", "error": err.Error()})
				continue
			}
			req.Passphrase = strings.TrimRight(string(b), "\r\n")
		}
		if res, err := r.Backup(req, "scheduler"); err != nil {
			r.log.Error("scheduled backup failed", "err", err)
		} else {
			r.log.Info("scheduled backup written", "path", res.Path, "sha256", res.SHA256)
		}
	}
}

func (r *Runtime) exportLoop(ctx context.Context, every time.Duration) {
	cfg := r.app.Config
	ex := &audit.Exporter{JournalDir: r.app.Journal.Dir(), AnchorPath: r.app.Journal.AnchorPath(), ExportDir: cfg.Evidence.ExportDir,
		PublicKeys: map[string]string{"evidence.pub": filepath.Join(cfg.State.Dir, keys.EvidencePubFile),
			"evidence-genesis.pub": filepath.Join(cfg.State.Dir, keys.EvidenceGenesisFile)}}
	run := func() {
		res, err := ex.Sync()
		r.mu.Lock()
		r.exportErr, r.lastExp = err, res
		r.mu.Unlock()
		if err != nil {
			r.log.Error("evidence export failed", "err", err)
		} else if len(res.Copied) > 0 {
			r.log.Info("evidence exported", "segments", len(res.Copied), "anchor_segment", res.AnchorSegment)
		}
	}
	run()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// recordUpgradeEvent turns a marker left by `smcpctl upgrade` into an
// evidence event (FR-13.8 upgrade_rolled_back).
func (r *Runtime) recordUpgradeEvent() {
	p := filepath.Join(r.app.Config.State.Dir, UpgradeEventFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return
	} else if err != nil {
		r.log.Error("upgrade event unreadable", "err", err)
		return
	}
	var ev UpgradeEvent
	if err := json.Unmarshal(b, &ev); err != nil || ev.Outcome == "" {
		r.log.Error("upgrade event unreadable", "err", err)
		return
	}
	reason := "UPGRADE_COMPLETED"
	if ev.Outcome == "upgrade_rolled_back" {
		reason = "UPGRADE_ROLLED_BACK"
	}
	if err := r.app.Evidence.Commit(audit.Event{Class: "admin", Origin: "E-24", Outcome: ev.Outcome, ReasonCode: reason, PolicyStatus: "not_evaluated",
		Detail: map[string]any{"actor": "smcpctl upgrade", "from_version": ev.FromVersion, "to_version": ev.ToVersion, "reason": ev.Reason, "backup": ev.Backup, "time": ev.Time}}); err != nil {
		r.log.Error("evidence write failed", "err", err)
		return
	}
	if err := os.Remove(p); err != nil {
		r.log.Error("upgrade event not removed", "err", err)
	}
}

// ReloadResult reports a configuration reload (FR-17.9).
type ReloadResult struct {
	Changed         []string `json:"changed"`
	Applied         []string `json:"applied"`
	RestartRequired []string `json:"restart_required"`
	// NotApplied lists keys that CP-50 names reloadable but this build
	// applies only at restart.
	NotApplied []string `json:"not_applied_until_restart"`
}

// ErrReloadInvalid wraps a validation failure; the running configuration
// is kept.
var ErrReloadInvalid = errors.New("new configuration is invalid; the running configuration is kept")

// Reload validates the configuration file and applies the reloadable keys
// without ending sessions (SIGHUP and POST /api/v1/config/reload).
func (r *Runtime) Reload(actor string) (ReloadResult, error) {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	res := ReloadResult{Changed: []string{}, Applied: []string{}, RestartRequired: []string{}, NotApplied: []string{}}
	next, err := config.Load(r.cfgPath)
	if err != nil {
		r.log.Error("configuration reload rejected", "err", err)
		r.commitReload("rejected", "CONFIG_INVALID", actor, map[string]any{"error": err.Error()})
		return res, fmt.Errorf("%w: %w", ErrReloadInvalid, err)
	}
	r.mu.Lock()
	cur := r.running
	r.mu.Unlock()
	changed, err := config.Diff(cur, next)
	if err != nil {
		return res, err
	}
	res.Changed = append(res.Changed, changed...)
	upd := *cur
	for _, k := range changed {
		switch {
		case !config.ReloadableKey(k):
			res.RestartRequired = append(res.RestartRequired, k)
		case k == "log.level":
			if err := setLevel(r.level, next.Log.Level); err != nil {
				return res, err
			}
			upd.Log.Level = next.Log.Level
			res.Applied = append(res.Applied, k)
		case k == "limits.principal_calls_per_minute":
			r.app.Decider.SetDefaultRate(next.Limits.PrincipalCallsPerMin)
			upd.Limits.PrincipalCallsPerMin = next.Limits.PrincipalCallsPerMin
			res.Applied = append(res.Applied, k)
		case k == "limits.principal_call_burst":
			r.app.Decider.SetBurst(next.Limits.PrincipalCallBurst)
			upd.Limits.PrincipalCallBurst = next.Limits.PrincipalCallBurst
			res.Applied = append(res.Applied, k)
		default:
			res.NotApplied = append(res.NotApplied, k)
		}
	}
	r.mu.Lock()
	r.running = &upd
	r.mu.Unlock()
	r.log.Info("configuration reloaded", "applied", res.Applied, "restart_required", res.RestartRequired, "not_applied", res.NotApplied)
	r.commitReload("reloaded", "CONFIG_RELOADED", actor, map[string]any{"applied": res.Applied, "restart_required": res.RestartRequired, "not_applied": res.NotApplied})
	return res, nil
}

func (r *Runtime) commitReload(outcome, reason, actor string, detail map[string]any) {
	detail["actor"] = actor
	if err := r.app.Evidence.Commit(audit.Event{Class: "admin", Origin: "E-23", Outcome: outcome, ReasonCode: reason, PolicyStatus: "not_evaluated", Detail: detail}); err != nil {
		r.log.Error("evidence write failed", "err", err)
	}
}

// Running returns a copy of the configuration in force.
func (r *Runtime) Running() config.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return *r.running
}

func setLevel(lv *slog.LevelVar, s string) error {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return err
	}
	lv.Set(l)
	return nil
}
