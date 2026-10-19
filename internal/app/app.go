// Package app wires the Gateway's elements together from a validated
// configuration: the evidence journal and its observers, the policy
// decider, the session store and OAuth server, the backend registry, the
// enforcement edge and the control API. cmd/smcpd and the end-to-end tests
// both start the Gateway through it, so the wiring exists once.
//
// Elements built later plug in through Options (the seams of
// internal/pipeline, the approval queue of the control API and evidence
// observers) rather than by editing this file.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/egress"
	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policyadmin"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Options are the seams. Zero values select the defaults.
type Options struct {
	Log       *slog.Logger
	Launcher  pipeline.Launcher       // default SubprocessLauncher (standalone)
	Manifests pipeline.ManifestSource // default LiveManifest (unverified)
	Secrets   pipeline.SecretBroker   // default NoSecrets
	Approver  pipeline.Approver       // default RefuseApprover
	Filters   *pipeline.Filters       // default NewFilters (schema-validate)
	// ExtraFilters, when set, registers further filters on the inspection
	// chain after the built-in E-09/E-11 filters (SS-10 observation probes).
	ExtraFilters func(*pipeline.Filters) error
	Approvals    adminapi.Approvals // default none
	// Observers receive evidence after the journal accepts it (E-26, E-29).
	Observers map[string]audit.Observer
	// Host overrides host detection (tests).
	Host *profile.Host
	// GuardConfig bounds sign-in endpoints.
	GuardConfig authguard.Config
	// JanitorInterval is how often expired state is pruned (default 30s).
	JanitorInterval time.Duration
	// SessionContext returns the Observation Policy in force and its
	// baseline context dimensions; each new session records its context
	// key under them (FR-2.13).
	SessionContext func() (policyID string, dims []string)
	// AssertInterval is how often server-asserted text is recorded
	// (SR-6.18-1); zero means one second.
	AssertInterval time.Duration
	// ConsoleURL is the base of approval deep links (default the admin URL).
	ConsoleURL string
	// HealthGate is the Health & Safety Monitor's fail-closed gate (E-23,
	// internal/health); default none.
	HealthGate func() []string
	// ObservationContext returns the effective Audit Profile revision, the
	// Observation Policy ID and the Anomaly Response Policy revision, which
	// every permit carries as obligations (FR-3.12). Nil leaves them empty.
	ObservationContext func() (auditProfile, observationPolicy, anomalyResponse string)
	// Spans receives each tool call's stage timing spans (FR-10.2); the
	// Observation Collector (E-29) takes them. Nil records none.
	Spans pipeline.SpanSink
	// Packages is the Library Trust Verifier and Local Server Registry
	// (E-13, E-14; internal/library). Default none: [[server]] entries
	// naming a package are refused.
	Packages Packages
	// Listeners, when set, are the harness and admin listeners bound by
	// BindListeners before Start; Listen uses them instead of binding.
	Listeners *Listeners
}

// Packages is the seam for signed server packages (internal/library).
// Prepare resolves packaged [[server]] entries and may wrap the launcher;
// Started hands over the registry's suspend function (drift, revocation).
type Packages interface {
	pipeline.ManifestSource
	Prepare(rec audit.Recorder, servers []config.Server, l pipeline.Launcher, standalone bool) ([]config.Server, pipeline.Launcher, error)
	Started(suspend func(alias, reason string) bool)
	RegisterRoutes(s *adminapi.Server)
	Close() error
}

// App is a started Gateway.
type App struct {
	Config       *config.Config
	Journal      *audit.Journal
	Evidence     *audit.Fanout
	Decider      *policy.Decider
	Store        *session.Store
	OAuth        *session.OAuth
	Registry     *backend.Registry
	Gateway      *edge.Gateway
	Admin        *adminapi.Server
	Profile      profile.Report
	Capabilities *pipeline.Capabilities
	TLS          keys.TLSStatus
	Egress       *egress.Broker       // nil unless [egress] enabled = true
	Policy       *policyadmin.Service // E-05: signed Policy Store, /api/v1/policy*
	Inspector    *filters.Inspector
	Filters      *pipeline.Filters // the inspection chains the edge runs (E-09, E-11 and registered filters)

	log       *slog.Logger
	janitor   time.Duration
	packages  Packages
	harnessLn net.Listener
	adminLn   net.Listener
	udsLn     net.Listener // UDS Harness Profile socket; nil unless [uds] enabled
	prebound  *Listeners
	closeOnce sync.Once
}

func listenerNames(cfg *config.Config) []string {
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

// ErrJournal wraps the Start error when the Evidence Journal cannot be
// opened for writing. Nothing that Start was given has been used yet, so
// the caller may retry Start; smcpd answers harness requests with -31004
// until the journal is writable and then retries (FR-9.17,
// edge.ServeFailClosed).
var ErrJournal = errors.New("journal")

// Start builds every component. On error everything started so far is
// closed.
func Start(ctx context.Context, cfg *config.Config, o Options) (a *App, err error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.JanitorInterval <= 0 {
		o.JanitorInterval = 30 * time.Second
	}
	a = &App{Config: cfg, log: o.Log, janitor: o.JanitorInterval, prebound: o.Listeners}
	defer func() {
		if err != nil {
			a.Close()
			a = nil
		}
	}()
	if err := keys.CheckPrivate(cfg.State.Dir); err != nil {
		return a, err
	}
	evKey, err := keys.LoadEvidenceKey(cfg.State.Dir)
	if err != nil {
		return a, fmt.Errorf("evidence key (run `smcpctl bootstrap` first): %w", err)
	}
	if a.TLS, err = keys.RotateIfDue(cfg.State.Dir, time.Now(), listenerNames(cfg)...); err != nil {
		return a, fmt.Errorf("tls certificates: %w", err)
	}
	if policy.BrokenBuild {
		o.Log.Error("DELIBERATELY BROKEN BUILD (smcp_broken tag): rate limits and approval obligations are not enforced; for the FR-15.8 conformance check only")
	}
	if a.TLS.IPConstrained {
		o.Log.Warn("server CA has iPAddress name constraints, which BoringSSL-based clients (native Claude Code, OpenCode) reject; replace it with `smcpctl keys rotate ca`")
	}
	if a.TLS.LeafRotated {
		o.Log.Warn("listener certificate reissued", "not_after", a.TLS.LeafNotAfter)
	}
	// E-05: the active signed revision of the Policy Store, or the policy
	// file imported as the first revision. A revision that does not verify
	// starts the Gateway fail-closed (SR-1.1-2).
	pstore, err := policystore.Open(cfg.State.Dir)
	if err != nil {
		return a, fmt.Errorf("policy store: %w", err)
	}
	snap, imported, policyFault, policyErr := policyadmin.Load(pstore, cfg.Policy.File)
	if policyErr != nil && policyFault == "" {
		return a, fmt.Errorf("policy: %w", policyErr)
	}
	if policyFault != "" {
		o.Log.Error("active policy revision does not verify; refusing every call until a valid revision is published", "err", policyErr)
	}
	if a.Journal, err = audit.Open(filepath.Join(cfg.State.Dir, "journal"), evKey, audit.Options{}); err != nil {
		return a, fmt.Errorf("%w: %w", ErrJournal, err)
	}
	for _, r := range a.Journal.Recovered() {
		o.Log.Warn("journal segment recovered after a crash", "segment", r.Segment, "events", r.Events, "truncated_bytes", r.TruncatedBytes)
	}
	a.Evidence = audit.NewFanout(a.Journal, o.Log)
	for name, obs := range o.Observers {
		a.Evidence.AddObserver(name, obs, 0)
	}
	// A secret broker writes its own evidence (FR-6.11) from the first
	// launch on, before the edge exists.
	if s, ok := o.Secrets.(interface{ AttachEvidence(audit.Recorder) }); ok {
		s.AttachEvidence(a.Evidence)
	}

	if o.Launcher == nil {
		o.Launcher = pipeline.SubprocessLauncher{}
	}
	if a.Egress, err = egress.FromConfig(cfg, a.Evidence, o.Log); err != nil {
		return a, fmt.Errorf("egress broker: %w", err)
	}
	o.Launcher = a.Egress.Wrap(o.Launcher)
	// E-18 performs S1 header injection for the Secret Broker (E-20).
	if s, ok := o.Secrets.(interface {
		SetInjector(pipeline.SecretHeaderInjector)
	}); ok && a.Egress != nil {
		s.SetInjector(a.Egress)
	}
	host := profile.DetectHost()
	if o.Host != nil {
		host = *o.Host
	}
	if a.Profile, err = profile.Resolve(cfg.Profile.Mode, o.Launcher.Name(), o.Launcher.Confined(), host); err != nil {
		return a, err
	}
	if a.Profile.Profile == profile.Standalone {
		o.Log.Warn("standalone profile: server instances run unconfined; high-risk server classes are refused", "reasons", a.Profile.Reasons)
	}

	servers := cfg.Servers
	if o.Packages != nil {
		a.packages = o.Packages
		if servers, o.Launcher, err = o.Packages.Prepare(a.Evidence, cfg.Servers, o.Launcher, a.Profile.Profile == profile.Standalone); err != nil {
			return a, fmt.Errorf("packages: %w", err)
		}
		if o.Manifests == nil {
			o.Manifests = o.Packages
		}
		if er, ok := o.Packages.(interface {
			EgressRules(alias string) []packaging.EgressRule
		}); ok && a.Egress != nil {
			a.Egress.SetManifestLimits(manifestLimits(er.EgressRules)) // FR-5.38
		}
	} else {
		for _, s := range servers {
			if s.Package != "" {
				return a, fmt.Errorf("server %q names package %q but package support is not configured", s.Alias, s.Package)
			}
		}
	}
	// After the package source is chosen, so the metadata scan wraps the
	// signed manifests (SR-5.9-2 at import) rather than replacing them.
	if err = a.startInspection(cfg, &o); err != nil { // E-09, E-11, metadata scan (inspection.go)
		return a, err
	}
	a.Filters = o.Filters
	if a.Egress != nil && a.Inspector != nil {
		a.Egress.SetFingerprints(a.Inspector.Fingerprints()) // SR-5.8-2
	}
	// Delivered secret values join the inspector's registered fingerprints,
	// so the secret-fingerprint filter detects them in arguments and results.
	if s, ok := o.Secrets.(interface {
		ShareFingerprints(func(ref string, version int, value []byte))
	}); ok {
		fps := a.Inspector.Fingerprints()
		s.ShareFingerprints(func(ref string, version int, value []byte) {
			fps.RegisterBytes(fmt.Sprintf("%s@%d", ref, version), value) // no string copy (SR-2.13-2)
		})
	}
	// The secret broker's mandatory filters (E-20) join the chain after the
	// built-in filters are registered, so enabling [secrets] keeps E-09/E-11.
	if s, ok := o.Secrets.(interface {
		RegisterFilters(*pipeline.Filters) error
	}); ok {
		if err = s.RegisterFilters(o.Filters); err != nil {
			return a, fmt.Errorf("secret filters: %w", err)
		}
	}
	a.Capabilities = pipeline.NewCapabilities(2 * cfg.Limits.ClientDeadline.Duration)
	if a.Registry, err = backend.Start(ctx, servers, backend.Options{
		Limits: backend.Limits{PerPrincipal: cfg.Limits.ToolConcurrencyPerUser, Total: cfg.Limits.ToolConcurrencyTotal, Queue: cfg.Limits.ToolQueue,
			UpstreamTimeout: cfg.Limits.UpstreamTimeout.Duration, ResultBytes: cfg.Limits.ResultBytes},
		Launcher: o.Launcher, Manifests: o.Manifests, Secrets: o.Secrets, Capabilities: a.Capabilities, Log: o.Log,
		Asserted: a.recordAssertion, AssertInterval: o.AssertInterval,
	}); err != nil {
		return a, fmt.Errorf("backend servers: %w", err)
	}
	for alias, s := range a.Registry.Servers() {
		o.Log.Info("server enabled", "alias", alias, "revision", s.Revision, "era", s.Era, "tools", len(s.Tools), "verified", s.Verified)
		if s.Artifact != nil && s.Artifact.Digest != "" {
			// SR-3.6-1: the content address of a command-configured
			// server's files, which every relaunch must match.
			if err = a.Evidence.Commit(audit.Event{Class: "server", Origin: "E-15", Outcome: "artifact_recorded", ServerRevision: s.Revision,
				PolicyStatus: "not_evaluated", Detail: map[string]any{"alias": alias, "digest": s.Artifact.Digest, "files": s.Artifact.Files,
					"pinned": s.Artifact.Pinned}}); err != nil {
				return a, fmt.Errorf("journal: %w", err)
			}
		}
	}
	// FR-1.49: a revision whose tools cannot be presented is not enabled;
	// the rest of the Gateway runs.
	for alias, reason := range a.Registry.Disabled() {
		if err = a.Evidence.Commit(audit.Event{Class: "server", Origin: "E-14", Outcome: "not_enabled", ReasonCode: "SERVER_NOT_ENABLED",
			PolicyStatus: "not_evaluated", Detail: map[string]any{"alias": alias, "reason": reason}}); err != nil {
			return a, fmt.Errorf("journal: %w", err)
		}
	}

	a.Decider = policy.NewDecider(snap, cfg.Limits.PrincipalCallsPerMin)
	a.Decider.SetBurst(cfg.Limits.PrincipalCallBurst)
	a.Decider.SetContext(a.obligationContext(o)) // FR-3.12
	var secretBindings func([]string) any
	if sb, ok := o.Secrets.(interface{ BindingsFor([]string) any }); ok { // FR-6.5
		secretBindings = sb.BindingsFor
	}
	a.Policy = policyadmin.New(policyadmin.Options{Store: pstore, Evidence: a.Evidence, Active: a.Decider.Snapshot, SecretBindings: secretBindings,
		JournalDir: a.Journal.Dir(), DefaultRate: cfg.Limits.PrincipalCallsPerMin, Burst: cfg.Limits.PrincipalCallBurst, Fault: policyFault, Log: o.Log,
		ServerRiskClasses: func() map[string][]string { // SR-3.13-1
			m := map[string][]string{}
			for _, sv := range cfg.Servers {
				m[sv.Alias] = sv.RiskClasses
			}
			return m
		}})
	a.Policy.Started(imported, policyErr)
	a.Store = session.NewStore(cfg, a.Decider.Snapshot)
	if o.SessionContext != nil {
		a.Store.SetObservationContext(o.SessionContext) // FR-2.13
	}
	guard := authguard.New(o.GuardConfig)
	a.OAuth = session.NewOAuth(cfg, a.Store, a.Evidence, guard)
	if o.ConsoleURL == "" {
		o.ConsoleURL = cfg.AdminURL()
	}
	if a.Gateway, err = edge.New(edge.Deps{Config: cfg, Store: a.Store, OAuth: a.OAuth, Decider: a.Decider, Registry: a.Registry,
		Evidence: a.Evidence, EvidenceErr: a.Journal.Err, HealthGate: o.HealthGate, Log: o.Log, Profile: a.Profile, Approver: o.Approver, Filters: o.Filters,
		Capabilities: a.Capabilities, ConsoleURL: o.ConsoleURL, PolicyFault: a.Policy.Fault, Screen: a.Inspector, Spans: o.Spans}); err != nil {
		return a, err
	}
	a.Policy.Bind(a.Gateway)
	if o.Packages != nil {
		// A revision the library suspends or revokes leaves the registry
		// under the coordinator gate (SR-1.16-1).
		o.Packages.Started(func(alias, reason string) bool {
			var ok bool
			a.Gateway.Serialize(func() { ok = a.Registry.Suspend(alias, reason) })
			return ok
		})
	}
	if a.Admin, err = adminapi.New(adminapi.Options{Config: cfg, Controller: a.Policy, Evidence: a.Evidence, Guard: guard, Approvals: o.Approvals, Log: o.Log}); err != nil {
		return a, err
	}
	a.Egress.Register(a.Admin)
	a.Policy.Register(a.Admin)
	revision := ""
	if snap != nil {
		revision = snap.Revision
	}
	if o.Packages != nil {
		o.Packages.RegisterRoutes(a.Admin)
	}
	if err = a.Evidence.Commit(audit.Event{Class: "gateway", Origin: "E-23", Outcome: "started", PolicyRevision: revision, PolicyStatus: "not_evaluated",
		Detail: map[string]any{"version": backend.Version, "listener": cfg.Listener.Address, "admin_listener": cfg.AdminListener.Address,
			"profile": a.Profile.Profile, "release_label": a.Profile.Label}}); err != nil {
		return a, fmt.Errorf("journal: %w", err)
	}
	return a, nil
}

// Listen binds both listeners. Connections queue in the backlog until Serve
// runs, so callers may connect as soon as Listen returns.
func (a *App) Listen() error {
	var err error
	if p := a.prebound; p != nil && p.Harness != nil && p.Admin != nil {
		a.harnessLn, a.adminLn = p.Harness, p.Admin
	} else {
		if a.harnessLn, err = a.Gateway.Listen(); err != nil {
			return err
		}
		if a.adminLn, err = a.Admin.Listen(); err != nil {
			a.harnessLn.Close()
			return err
		}
	}
	if a.Config.UDS.Enabled { // CP-02 UDS harness listener (FR-1.1, FR-1.47)
		if a.udsLn, err = a.Gateway.ListenUDS(); err != nil {
			a.harnessLn.Close()
			a.adminLn.Close()
			return err
		}
	}
	return nil
}

// Serve runs both listeners and the janitors until ctx ends or a listener
// fails. Listen must have been called.
func (a *App) Serve(ctx context.Context) error {
	if a.harnessLn == nil || a.adminLn == nil {
		return errors.New("app: Listen first")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.Gateway.RunJanitors(ctx, a.janitor)
	n := 2
	errc := make(chan error, 3)
	go func() { errc <- a.Gateway.Serve(ctx, a.harnessLn) }()
	go func() { errc <- a.Admin.Serve(ctx, a.adminLn) }()
	if a.udsLn != nil {
		n++
		go func() { errc <- a.Gateway.ServeUDS(ctx, a.udsLn) }()
	}
	errs := []error{<-errc}
	cancel()
	for i := 1; i < n; i++ {
		errs = append(errs, <-errc)
	}
	return errors.Join(errs...)
}

// Close stops everything and seals the journal. It is safe to call more
// than once.
func (a *App) Close() {
	a.closeOnce.Do(func() {
		if a.Gateway != nil {
			a.Gateway.Close()
		}
		if a.Registry != nil {
			a.Registry.Close()
		}
		if err := a.Egress.Close(); err != nil {
			a.log.Error("egress broker close failed", "err", err)
		}
		if a.packages != nil {
			if err := a.packages.Close(); err != nil {
				a.log.Error("package registry close failed", "err", err)
			}
		}
		if a.Evidence != nil {
			if err := a.Evidence.Commit(audit.Event{Class: "gateway", Origin: "E-23", Outcome: "stopped", PolicyStatus: "not_evaluated"}); err != nil {
				a.log.Error("evidence write failed at shutdown", "err", err)
			}
			a.Evidence.Close()
		}
		if a.Journal != nil {
			if err := a.Journal.Close(); err != nil {
				a.log.Error("journal close failed", "err", err)
			}
		}
	})
}
