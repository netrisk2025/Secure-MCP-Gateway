package library

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

var aliasRE = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// RuntimeOptions configure the Gateway side of the library.
type RuntimeOptions struct {
	Interp packaging.Interpreters
	// RequireSigned refuses [[server]] entries that are not packages.
	RequireSigned bool
	// ScanInterval is the library polling interval (FR-5.3, default 300s).
	ScanInterval time.Duration
	Log          *slog.Logger
	// EgressGrants are the configured [[egress.grant]] entries; a packaged
	// server whose grants exceed its manifest's egress capabilities is
	// not started (CheckEgressCeiling).
	EgressGrants []config.EgressGrant
}

// Runtime connects a Library to a running Gateway: it resolves packaged
// [[server]] entries to launch specifications, re-verifies artifacts at
// launch, presents manifest tool definitions, detects drift and polls the
// library. It implements pipeline.ManifestSource and
// pipeline.ManifestWatcher.
type Runtime struct {
	lib  *Library
	o    RuntimeOptions
	log  *slog.Logger
	live pipeline.LiveManifest

	mu         sync.Mutex
	bindings   map[string]*Binding // by alias
	standalone bool
	suspend    func(alias, reason string) bool
	stop       chan struct{}
	done       chan struct{}

	trustMu sync.Mutex // serializes trust anchor changes (trust_api.go)
}

// Binding is the state of one packaged [[server]] entry.
type Binding struct {
	Alias      string `json:"alias"`
	Package    string `json:"package"`
	Revision   string `json:"revision,omitempty"`
	Status     string `json:"status"` // starting, running, suspended, not_started
	ReasonCode string `json:"reason_code,omitempty"`
	Reason     string `json:"reason,omitempty"`

	manifest *packaging.Manifest
	rev      Revision
}

// NewRuntime wraps an open Library.
func NewRuntime(lib *Library, o RuntimeOptions) *Runtime {
	if o.ScanInterval <= 0 {
		o.ScanInterval = 300 * time.Second
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Runtime{lib: lib, o: o, log: o.Log, bindings: map[string]*Binding{}}
}

// Library returns the underlying library.
func (rt *Runtime) Library() *Library { return rt.lib }

// Prepare runs at Gateway start, before servers launch: it binds the
// evidence recorder, scans the library once, resolves every packaged
// [[server]] entry to the launch specification of its enabled revision and
// wraps the launcher with the artifact digest check (SR-3-2). Servers that
// cannot start (no enabled revision, pin mismatch, high risk while
// unconfined) are left out with evidence; a non-package server under
// require_signed fails startup.
func (rt *Runtime) Prepare(rec audit.Recorder, servers []config.Server, l pipeline.Launcher, standalone bool) ([]config.Server, pipeline.Launcher, error) {
	rt.lib.SetRecorder(rec)
	rt.mu.Lock()
	rt.standalone = standalone
	rt.mu.Unlock()
	rep, _ := rt.lib.Scan("E-13")
	for _, s := range rep.Rejected {
		rt.log.Warn("library package rejected", "detail", s)
	}
	out := make([]config.Server, 0, len(servers))
	for _, sc := range servers {
		if sc.Package == "" {
			if rt.o.RequireSigned {
				return nil, nil, errf(ReasonUnsigned, "server %q is not a signed package and [packages] require_signed is set", sc.Alias)
			}
			out = append(out, sc)
			continue
		}
		resolved, err := rt.resolve(sc, l)
		if err != nil {
			rt.notStarted(sc, err)
			continue
		}
		out = append(out, resolved)
	}
	return out, &verifyingLauncher{inner: l, rt: rt}, nil
}

func (rt *Runtime) notStarted(sc config.Server, err error) {
	b := &Binding{Alias: sc.Alias, Package: sc.Package, Status: "not_started", ReasonCode: packaging.ReasonOf(err), Reason: err.Error()}
	rt.mu.Lock()
	rt.bindings[sc.Alias] = b
	rt.mu.Unlock()
	rt.log.Error("packaged server not started", "alias", sc.Alias, "package", sc.Package, "err", err)
	_ = rt.lib.evidence(audit.Event{Outcome: "server_not_started", ReasonCode: b.ReasonCode, ServerRevision: sc.Package,
		Detail: map[string]any{"alias": sc.Alias, "error": err.Error()}})
}

// enabledRevision returns the enabled revision of a server ID.
func (l *Library) enabledRevision(id string) (Revision, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.doc.Revisions {
		if r.ServerID == id && r.State == StateEnabled {
			return *r, true
		}
	}
	return Revision{}, false
}

func (rt *Runtime) resolve(sc config.Server, l pipeline.Launcher) (config.Server, error) {
	rev, ok := rt.lib.enabledRevision(sc.Package)
	if !ok {
		return sc, errf(ReasonNotEnabled, "package %s has no enabled revision; import it and enable it (smcpctl package list)", sc.Package)
	}
	if sc.PackageSHA256 != "" && sc.PackageSHA256 != rev.ArtifactSHA256 {
		return sc, errf(ReasonPinMismatch, "package %s enabled revision %s has artifact %s, not the configured package_sha256 %s", sc.Package, rev.Revision, rev.ArtifactSHA256, sc.PackageSHA256)
	}
	m, _, err := rt.lib.Manifest(rev.ServerID, rev.Revision)
	if err != nil {
		return sc, err
	}
	if err := CheckEgressCeiling(sc.Alias, rt.o.EgressGrants, m.Capabilities.Egress); err != nil {
		return sc, err
	}
	if m.HighestRisk() == "high" && !l.Confined() {
		return sc, errf(ReasonProfile, "package %s has risk class high and the launcher %s is unconfined (SR-4-1)", sc.Package, l.Name())
	}
	if err := rt.lib.ensureTree(rev); err != nil {
		return sc, err
	}
	work := rt.lib.path("work", sc.Alias)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return sc, err
	}
	in := packaging.LaunchInput{Manifest: m, Alias: sc.Alias, Slots: sc.Slots, Env: sc.Env, WorkDir: work, Interp: rt.o.Interp}
	if m.Artifact.Type == "oci" {
		in.Archive = rt.lib.ArtifactPath(rev.ArtifactSHA256)
	} else {
		in.Root = rt.lib.TreePath(rev.ArtifactSHA256)
	}
	spec, err := packaging.ResolveLaunch(in)
	if err != nil {
		return sc, err
	}
	if err := pipeline.CheckLaunchSpec(spec); err != nil {
		return sc, errf(packaging.ReasonUnpinnedLaunch, "%v", err)
	}
	rt.mu.Lock()
	rt.bindings[sc.Alias] = &Binding{Alias: sc.Alias, Package: sc.Package, Revision: rev.Revision, Status: "starting", manifest: m, rev: rev}
	rt.mu.Unlock()
	roots := make([]config.SlotRoot, 0, len(spec.Roots))
	for _, r := range spec.Roots {
		roots = append(roots, config.SlotRoot{Slot: r.Slot, Path: r.Path, Write: r.Write})
	}
	return config.Server{Alias: sc.Alias, Command: spec.Command, Args: spec.Args, Env: spec.Env, SecretEnv: sc.SecretEnv, Dir: spec.Dir,
		RiskClasses: sc.RiskClasses, Package: sc.Package, PackageSHA256: sc.PackageSHA256, Slots: sc.Slots,
		Runtime: spec.Runtime, ArtifactRoot: spec.ArtifactRoot, Roots: roots}, nil
}

// Resolve returns the launch configuration of a packaged [[server]] entry
// from its enabled revision without starting anything (smcpctl runtime
// spec). confined says whether the configured launcher confines servers,
// which decides whether a high-risk package may run (SR-4-1).
func (rt *Runtime) Resolve(sc config.Server, confined bool) (config.Server, error) {
	return rt.resolve(sc, inspectLauncher(confined))
}

// inspectLauncher stands in for the configured launcher during Resolve; it
// never launches.
type inspectLauncher bool

func (i inspectLauncher) Name() string   { return "inspect" }
func (i inspectLauncher) Confined() bool { return bool(i) }
func (i inspectLauncher) Launch(context.Context, pipeline.ServerSpec) (pipeline.Process, error) {
	return nil, errors.New("library: inspection launcher does not launch")
}

func (rt *Runtime) binding(alias string) *Binding {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b := rt.bindings[alias]
	if b == nil || b.manifest == nil {
		return nil
	}
	return b
}

// EgressRules returns the egress capabilities of the verified manifest of
// a packaged server alias, with the limits they declare (FR-5.38); nil
// for an alias without one.
func (rt *Runtime) EgressRules(alias string) []packaging.EgressRule {
	b := rt.binding(alias)
	if b == nil {
		return nil
	}
	return slices.Clone(b.manifest.Capabilities.Egress)
}

// Bindings returns the packaged server bindings.
func (rt *Runtime) Bindings() []Binding {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]Binding, 0, len(rt.bindings))
	for _, b := range rt.bindings {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// verifyArtifact re-checks the stored artifact and unpacked tree against
// the digests recorded at import (SR-3-2).
func (rt *Runtime) verifyArtifact(b *Binding) error {
	sum, _, err := packaging.FileSHA256(rt.lib.ArtifactPath(b.rev.ArtifactSHA256))
	if err != nil {
		return errf(ReasonTampered, "artifact %s unreadable: %v", b.rev.ArtifactSHA256, err)
	}
	if sum != b.rev.ArtifactSHA256 {
		return errf(ReasonTampered, "artifact digest is %s, the signed manifest names %s", sum, b.rev.ArtifactSHA256)
	}
	if b.rev.TreeSHA256 != "" {
		tree, err := packaging.TreeDigest(rt.lib.TreePath(b.rev.ArtifactSHA256))
		if err != nil {
			return errf(ReasonTampered, "unpacked artifact unreadable: %v", err)
		}
		if tree != b.rev.TreeSHA256 {
			return errf(ReasonTampered, "unpacked artifact tree digest is %s, recorded at import as %s", tree, b.rev.TreeSHA256)
		}
	}
	return nil
}

// suspendBinding suspends the revision behind a binding and records the
// evidence; it returns an error wrapping pipeline.ErrServerSuspended.
func (rt *Runtime) suspendBinding(b *Binding, cause error, detail map[string]any) error {
	reason := packaging.ReasonOf(cause)
	rt.mu.Lock()
	b.Status, b.ReasonCode, b.Reason = "suspended", reason, cause.Error()
	rt.mu.Unlock()
	if detail == nil {
		detail = map[string]any{}
	}
	detail["alias"] = b.Alias
	detail["error"] = cause.Error()
	ts := strings.NewReplacer(":", "", ".", "").Replace(rt.lib.now().UTC().Format(time.RFC3339Nano))
	file := rt.lib.path("evidence", fmt.Sprintf("%s-%s-%s.json", ts, b.Alias, strings.ToLower(reason)))
	if err := packaging.WriteJSON(file, map[string]any{"time": rt.lib.now().UTC(), "server_revision": b.rev.Key(), "reason_code": reason, "detail": detail}, 0o600); err == nil {
		if sum, _, err := packaging.FileSHA256(file); err == nil {
			detail["evidence_file"] = filepath.Base(file)
			detail["evidence_sha256"] = sum
		}
	}
	delete(detail, "observed_tools") // in the evidence file only; the event stays small
	rt.lib.mu.Lock()
	r := rt.lib.find(b.rev.ServerID, b.rev.Revision)
	if r != nil && allowed(r.State, StateSuspended) {
		rt.lib.setState(r, StateSuspended, reason+": "+cause.Error(), "E-14")
		_ = rt.lib.save()
	}
	evErr := rt.lib.evidence(audit.Event{Outcome: "suspended", ReasonCode: reason, ServerRevision: b.rev.Key(), Detail: detail})
	rt.lib.mu.Unlock()
	rt.log.Error("server revision suspended", "alias", b.Alias, "revision", b.rev.Key(), "reason", reason, "err", cause)
	if evErr != nil {
		return fmt.Errorf("%w: %w (evidence: %w)", pipeline.ErrServerSuspended, cause, evErr)
	}
	return fmt.Errorf("%w: %w", pipeline.ErrServerSuspended, cause)
}

// FeedStale reports whether the revocation feed is stale (SR-3-4).
func (rt *Runtime) FeedStale() (bool, string) { return rt.lib.FeedStale() }

// Tools implements pipeline.ManifestSource: the verified manifest's
// definitions after a drift check against the live list (FR-1.27,
// SR-3.8-1). Servers that are not packages get the live list, unverified.
func (rt *Runtime) Tools(ctx context.Context, spec pipeline.ServerSpec, live pipeline.LiveLister) (pipeline.ToolSet, error) {
	b := rt.binding(spec.Alias)
	if b == nil {
		if rt.o.RequireSigned {
			return pipeline.ToolSet{}, errf(ReasonUnsigned, "server %q is not a signed package", spec.Alias)
		}
		return rt.live.Tools(ctx, spec, live)
	}
	// FR-5.40: the instance must speak the era the signed manifest declares.
	if spec.NegotiatedEra != "" && b.manifest.Era != spec.NegotiatedEra {
		return pipeline.ToolSet{}, rt.suspendBinding(b, errf(ReasonDrift, "the instance negotiated protocol version %s; the signed manifest declares era %s", spec.NegotiatedEra, b.manifest.Era),
			map[string]any{"negotiated_era": spec.NegotiatedEra, "manifest_era": b.manifest.Era})
	}
	if err := rt.checkDrift(ctx, b, live); err != nil {
		return pipeline.ToolSet{}, err
	}
	tools, err := b.manifest.MCPTools()
	if err != nil {
		return pipeline.ToolSet{}, err
	}
	// The manifest's classes, tightened by operator overrides (SR-3.11-1).
	if cur, ok := rt.lib.Get(b.rev.ServerID, b.rev.Revision); ok {
		applyClassification(tools, &cur, func(name string) (string, string, bool) {
			if mt := b.manifest.Find(name); mt != nil {
				return mt.SideEffect, mt.SourceTrust, true
			}
			return "", "", false
		})
	}
	rt.mu.Lock()
	b.Status = "running"
	rt.mu.Unlock()
	return pipeline.ToolSet{Tools: tools, Revision: b.rev.Key(), Verified: true, Source: "manifest:" + b.rev.ManifestSHA256[:16]}, nil
}

// ListChanged implements pipeline.ManifestWatcher (SR-3.8-1).
func (rt *Runtime) ListChanged(ctx context.Context, spec pipeline.ServerSpec, live pipeline.LiveLister) error {
	b := rt.binding(spec.Alias)
	if b == nil {
		return nil
	}
	return rt.checkDrift(ctx, b, live)
}

func (rt *Runtime) checkDrift(ctx context.Context, b *Binding, live pipeline.LiveLister) error {
	tools, err := live(ctx)
	if err != nil {
		return err
	}
	got, err := packaging.CanonicalLive(tools)
	if err != nil {
		return rt.suspendBinding(b, errf(ReasonDrift, "live tool list unreadable: %v", err), nil)
	}
	diffs := packaging.Drift(b.manifest.CanonicalTools(), got)
	if len(diffs) == 0 {
		return nil
	}
	observed, _ := packaging.ToolsDigest(got)
	shown := diffs
	if len(shown) > 20 {
		shown = shown[:20]
	}
	return rt.suspendBinding(b, errf(ReasonDrift, "the live tool list differs from the signed manifest: %s", strings.Join(shown, "; ")),
		map[string]any{"differences": shown, "expected_tools_sha256": b.manifest.ToolsListSHA256, "observed_tools_sha256": observed, "observed_tools": got})
}

// Started receives the registry's suspend function and starts library
// polling (FR-5.3).
func (rt *Runtime) Started(suspend func(alias, reason string) bool) {
	rt.mu.Lock()
	rt.suspend = suspend
	if rt.stop != nil {
		rt.mu.Unlock()
		return
	}
	rt.stop, rt.done = make(chan struct{}), make(chan struct{})
	stop, done := rt.stop, rt.done
	rt.mu.Unlock()
	go func() {
		defer close(done)
		t := time.NewTicker(rt.o.ScanInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				rt.Scan("E-13")
			}
		}
	}()
}

// Scan scans the library now and tears down instances whose revision was
// revoked or expired.
func (rt *Runtime) Scan(actor string) ScanReport {
	rep, gone := rt.lib.Scan(actor)
	for _, alias := range gone {
		rt.teardown(alias, "revision left the enabled state")
	}
	return rep
}

func (rt *Runtime) teardown(alias, reason string) {
	rt.mu.Lock()
	fn := rt.suspend
	if b := rt.bindings[alias]; b != nil && b.Status == "running" {
		b.Status, b.Reason = "suspended", reason
	}
	rt.mu.Unlock()
	if fn != nil {
		fn(alias, reason)
	}
}

// Close stops polling and releases the registry lock.
func (rt *Runtime) Close() error {
	rt.mu.Lock()
	stop, done := rt.stop, rt.done
	rt.stop = nil
	rt.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	return rt.lib.Close()
}

// verifyingLauncher re-verifies a packaged server's artifact before every
// launch (SR-3-2) and suspends the revision when it changed.
type verifyingLauncher struct {
	inner pipeline.Launcher
	rt    *Runtime
}

func (v *verifyingLauncher) Name() string   { return v.inner.Name() }
func (v *verifyingLauncher) Confined() bool { return v.inner.Confined() }

func (v *verifyingLauncher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	if b := v.rt.binding(spec.Alias); b != nil {
		if err := v.rt.verifyArtifact(b); err != nil {
			return nil, v.rt.suspendBinding(b, err, map[string]any{"artifact_sha256": b.rev.ArtifactSHA256})
		}
		// FR-5.34: the manifest's declared behavior travels with the
		// launch, so the Runtime Monitor evaluates process creation
		// against it.
		if b.manifest != nil {
			spawns := b.manifest.Capabilities.SpawnsProcesses
			spec.SpawnsProcesses = &spawns
		}
	}
	return v.inner.Launch(ctx, spec)
}
