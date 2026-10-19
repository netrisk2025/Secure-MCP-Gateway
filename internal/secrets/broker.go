package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/posixacl"
)

// Reason codes of secret-use denials and withdrawals.
const (
	ReasonNotGranted      = "SECRET_NOT_GRANTED"
	ReasonNotFound        = "SECRET_NOT_FOUND"
	ReasonExpired         = "SECRET_EXPIRED"
	ReasonVersionRetired  = "SECRET_VERSION_RETIRED"
	ReasonOutsideWindow   = "SECRET_OUTSIDE_WINDOW"
	ReasonModeUnavailable = "SECRET_MODE_UNAVAILABLE"
	ReasonRateLimited     = "SECRET_RATE_LIMITED"
	ReasonPurpose         = "SECRET_PURPOSE_MISMATCH"
	ReasonApproval        = "SECRET_APPROVAL_REQUIRED"
	ReasonSuspended       = "SECRET_SUSPENDED"
	ReasonNoInstance      = "SECRET_NO_INSTANCE"
	ReasonStopped         = "EMERGENCY_STOP"
	ReasonUnavailable     = "SECRET_UNAVAILABLE"
	ReasonDeliveryFailed  = "SECRET_DELIVERY_FAILED"
	ReasonLeak            = "SECRET_LEAK"
	ReasonInArguments     = "SECRET_IN_ARGUMENTS"
)

// BrokerOptions configure a Broker.
type BrokerOptions struct {
	Vault        *Vault
	Fingerprints *Fingerprints
	Use          *UseSet
	Servers      []config.Server
	// RuntimeDir holds the instance-private secret files (S2, S3). It is
	// created with mode 0700 and emptied at start.
	RuntimeDir string
	// Injector is the Egress Broker's S1 seam; nil denies S1.
	Injector pipeline.SecretHeaderInjector
	Evidence audit.Recorder
	Log      *slog.Logger
	Now      func() time.Time
}

// Broker is the Secret Broker (E-20). It implements pipeline.SecretBroker
// for launch-time delivery (S1, S3, S4), request and response filters for
// per-call delivery (S2) and leak detection, and audit.Observer for
// emergency-stop withdrawal.
type Broker struct {
	vault      *Vault
	fp         *Fingerprints
	injector   pipeline.SecretHeaderInjector
	runtimeDir string
	log        *slog.Logger
	now        func() time.Time

	mu        sync.Mutex
	rec       audit.Recorder
	use       *UseSet
	servers   []config.Server
	instances map[string]*instance
	calls     map[string]*callFile   // path -> per-call file
	release   map[string][]func()    // correlation ID -> releases
	rates     map[string][]time.Time // use policy ID -> recent S2 deliveries
	suspended map[string]string      // secret ref -> reason
	stopped   bool
	revisions func() map[string]string // server alias -> revision
}

// delivery is one launch-time delivery held by an instance.
type delivery struct {
	b       *binding
	ref     string
	version int
	path    string // S3
	grantID string // S1
}

type instance struct {
	alias      string
	dir        string
	correlated string
	delivered  []*delivery
	s2         map[string]string // slot -> per-call file path
}

type callFile struct {
	path    string
	count   int
	ref     string
	version int
}

var _ pipeline.SecretBroker = (*Broker)(nil)

// NewBroker builds a broker and prepares its runtime directory.
func NewBroker(o BrokerOptions) (*Broker, error) {
	if o.Vault == nil || o.Use == nil {
		return nil, errors.New("secrets: broker needs a vault and a use policy")
	}
	if o.Fingerprints == nil {
		o.Fingerprints = NewFingerprints()
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RuntimeDir == "" {
		return nil, errors.New("secrets: broker needs a runtime directory")
	}
	if err := prepareRuntimeDir(o.RuntimeDir); err != nil {
		return nil, err
	}
	b := &Broker{vault: o.Vault, fp: o.Fingerprints, injector: o.Injector, runtimeDir: o.RuntimeDir, log: o.Log, now: o.Now,
		rec: o.Evidence, use: o.Use, servers: o.Servers, instances: map[string]*instance{}, calls: map[string]*callFile{},
		release: map[string][]func(){}, rates: map[string][]time.Time{}, suspended: map[string]string{}}
	o.Vault.OnRetire(b.onRetire)
	if o.Evidence != nil {
		o.Vault.SetEvidence(o.Evidence)
	}
	return b, nil
}

// prepareRuntimeDir creates the runtime directory owner-only and removes
// anything left by an earlier run (a crash leaves no files behind for
// long).
func prepareRuntimeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secrets runtime dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the search bit; owner only
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		_ = scrubTree(filepath.Join(dir, e.Name()))
	}
	return nil
}

// AttachEvidence sets the evidence recorder; app.Start calls it once the
// journal is open, before any server launches.
func (b *Broker) AttachEvidence(rec audit.Recorder) {
	b.mu.Lock()
	b.rec = rec
	b.mu.Unlock()
	b.vault.SetEvidence(rec)
}

// SetRevisions supplies server revisions for events and impact reports.
func (b *Broker) SetRevisions(f func() map[string]string) {
	b.mu.Lock()
	b.revisions = f
	b.mu.Unlock()
}

// Fingerprints returns the leak-detection set (pipeline.SecretFingerprints)
// for other filters and the Observation Collector.
func (b *Broker) Fingerprints() *Fingerprints { return b.fp }

// ShareFingerprints passes every secret version the broker delivers from
// now on to fn as well (app.Start registers the E-09/E-11 inspector's
// fingerprint set, so the secret-fingerprint filter detects delivered
// values). fn must not keep value.
func (b *Broker) ShareFingerprints(fn func(ref string, version int, value []byte)) {
	b.fp.OnRegister(fn)
}

// SetInjector sets the Egress Broker's S1 seam. app.Start calls it before
// any server launches, when [egress] is enabled.
func (b *Broker) SetInjector(i pipeline.SecretHeaderInjector) {
	b.mu.Lock()
	b.injector = i
	b.mu.Unlock()
}

// GrantedSlots returns the slots of server that the Secret Use Policy
// binds a secret to, sorted (an FR-3.12 obligation).
func (b *Broker) GrantedSlots(server string) []string {
	u := b.UsePolicy()
	if u == nil {
		return nil
	}
	var out []string
	for _, bd := range u.Bindings() {
		if bd.Server == server && !slices.Contains(out, bd.Slot) {
			out = append(out, bd.Slot)
		}
	}
	sort.Strings(out)
	return out
}

// Vault returns the vault.
func (b *Broker) Vault() *Vault { return b.vault }

// UsePolicy returns the active Secret Use Policy.
func (b *Broker) UsePolicy() *UseSet { b.mu.Lock(); defer b.mu.Unlock(); return b.use }

// BindingsFor returns the active Secret Use Policy bindings of the given
// servers (FR-6.5).
func (b *Broker) BindingsFor(servers []string) any { return b.UsePolicy().BindingsFor(servers) }

// SetUsePolicy activates a new Secret Use Policy. Deliveries already made
// stay until their instance or call ends; S2 deliveries follow the new
// policy from the next call.
func (b *Broker) SetUsePolicy(u *UseSet) {
	b.mu.Lock()
	b.use = u
	b.mu.Unlock()
}

// event is one secret-use event (FR-6.11): references and identifiers,
// never a value.
type event struct {
	outcome, reason      string
	b                    *binding
	server, slot, mode   string
	secret, ref          string
	version              int
	tool                 string
	corr, decision       string
	serverRev, policyRev string
	grant                string
	extra                map[string]any
}

func (b *Broker) auditEvent(e event) audit.Event {
	if e.b != nil {
		e.server, e.slot, e.mode, e.secret = e.b.Server, e.b.Slot, e.b.Mode, e.b.Secret
		// FR-6.11: a denial before the vault was opened still names the
		// secret reference and the version that would have been delivered
		// (from the vault's metadata; no value is read).
		if e.ref == "" && b.vault != nil {
			if m, err := b.vault.Get(e.b.Secret); err == nil {
				e.ref = m.Ref
				if e.version == 0 {
					e.version = e.b.Version
					if e.version == 0 {
						e.version = m.CurrentVersion
					}
				}
			}
		}
	}
	d := map[string]any{"secret": e.secret, "secret_ref": e.ref, "version": e.version, "slot": e.slot, "mode": e.mode, "server": e.server, "tool": e.tool}
	if e.b != nil {
		d["use_policy"] = e.b.ID
		d["purpose"] = e.b.Purpose
	}
	if e.grant != "" {
		d["grant_id"] = e.grant
	}
	for k, v := range e.extra {
		d[k] = v
	}
	return audit.Event{Class: "secret_use", Origin: "E-20", Outcome: e.outcome, ReasonCode: e.reason, CorrelationID: e.corr, DecisionID: e.decision,
		ServerRevision: e.serverRev, PolicyRevision: e.policyRev, PolicyStatus: "evaluated", Detail: d}
}

func (b *Broker) commit(e event) error {
	b.mu.Lock()
	rec := b.rec
	b.mu.Unlock()
	if rec == nil {
		return ErrNoEvidence
	}
	return rec.Commit(b.auditEvent(e))
}

func (b *Broker) record(e event) {
	b.mu.Lock()
	rec := b.rec
	b.mu.Unlock()
	if rec == nil {
		return
	}
	if err := rec.Record(b.auditEvent(e)); err != nil {
		b.log.Error("secret-use evidence write failed", "err", err)
	}
}

func (b *Broker) serverRevision(alias string) string {
	b.mu.Lock()
	f := b.revisions
	b.mu.Unlock()
	if f == nil {
		return ""
	}
	return f()[alias]
}

func reasonFor(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return ReasonNotFound
	case errors.Is(err, ErrExpired):
		return ReasonExpired
	case errors.Is(err, ErrRetired):
		return ReasonVersionRetired
	}
	return ReasonUnavailable
}

// DeniedError is returned when a secret-use decision denies a delivery.
// Its text names the server, slot and reason code, never a value.
type DeniedError struct {
	Server, Slot, Reason string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("secret delivery for server %s slot %s denied: %s", e.Server, e.Slot, e.Reason)
}

func slotFile(slot string) string { return strings.ReplaceAll(slot, "/", "_") }

// Resolve implements pipeline.SecretBroker: the launch-time secret-use
// decisions for one server instance. It writes S3 files, binds S1 headers
// through the Egress Broker, prepares the S2 file paths and returns the
// environment variables to add (S4 values and S2/S3 file paths). Every
// secret_env reference of the server must be granted by a Secret Use
// Policy; any denial fails the launch.
func (b *Broker) Resolve(ctx context.Context, req pipeline.SecretRequest) (map[string]string, error) {
	b.mu.Lock()
	use, stopped := b.use, b.stopped
	old := b.instances[req.Server]
	delete(b.instances, req.Server)
	b.mu.Unlock()
	if old != nil {
		b.teardown(old, "relaunch")
	}
	binds := slices.Clone(use.byServer[req.Server])
	sort.Slice(binds, func(i, j int) bool { return binds[i].Slot < binds[j].Slot })
	corr := ids.New()
	deny := func(bd *binding, server, slot, secret, ref string, version int, reason string) error {
		e := event{outcome: "denied", reason: reason, b: bd, server: server, slot: slot, mode: ModeS4, secret: secret, ref: ref, version: version,
			tool: "*", corr: corr, decision: ids.New(), policyRev: use.Revision}
		if err := b.commit(e); err != nil {
			return fmt.Errorf("evidence unavailable: %w", err)
		}
		return &DeniedError{Server: server, Slot: slot, Reason: reason}
	}
	envs := sortedKeys(req.Refs)
	for _, env := range envs {
		if !slices.ContainsFunc(binds, func(x *binding) bool { return x.Slot == env }) {
			return nil, deny(nil, req.Server, env, req.Refs[env], "", 0, ReasonNotGranted)
		}
	}
	if len(binds) == 0 {
		return nil, nil
	}
	dir, err := os.MkdirTemp(b.runtimeDir, req.Server+"-")
	if err != nil {
		return nil, fmt.Errorf("secrets: instance directory: %w", err)
	}
	inst := &instance{alias: req.Server, dir: dir, correlated: corr, s2: map[string]string{}}
	out := map[string]string{}
	for _, bd := range binds {
		if bd.Mode == ModeS2 {
			p := filepath.Join(dir, slotFile(bd.Slot))
			inst.s2[bd.Slot] = p
			out[bd.slot.FileEnv] = p
			continue
		}
		d, env, val, err := b.deliverLaunch(ctx, inst, bd, use.Revision, stopped)
		if err != nil {
			b.teardown(inst, "launch_denied")
			return nil, err
		}
		inst.delivered = append(inst.delivered, d)
		if env != "" {
			out[env] = val
		}
	}
	b.mu.Lock()
	b.instances[req.Server] = inst
	b.mu.Unlock()
	return out, nil
}

// deliverLaunch makes one S1, S3 or S4 delivery. It returns the variable
// and value to add to the launch environment.
func (b *Broker) deliverLaunch(ctx context.Context, inst *instance, bd *binding, policyRev string, stopped bool) (*delivery, string, string, error) {
	e := event{b: bd, tool: "*", corr: inst.correlated, decision: ids.New(), policyRev: policyRev, serverRev: b.serverRevision(inst.alias)}
	deny := func(reason string, ref string, version int) error {
		e.outcome, e.reason, e.ref, e.version = "denied", reason, ref, version
		if err := b.commit(e); err != nil {
			return fmt.Errorf("evidence unavailable: %w", err)
		}
		return &DeniedError{Server: bd.Server, Slot: bd.Slot, Reason: reason}
	}
	if stopped {
		return nil, "", "", deny(ReasonStopped, "", 0)
	}
	if !bd.inWindow(b.now()) {
		return nil, "", "", deny(ReasonOutsideWindow, "", 0)
	}
	if bd.Mode == ModeS1 && b.injector == nil {
		return nil, "", "", deny(ReasonModeUnavailable, "", 0)
	}
	op, err := b.vault.open(bd.Secret, bd.Version)
	if err != nil {
		return nil, "", "", deny(reasonFor(err), op.Ref, op.Version)
	}
	defer wipe(op.Value)
	b.mu.Lock()
	_, suspended := b.suspended[op.Ref]
	b.mu.Unlock()
	if suspended {
		return nil, "", "", deny(ReasonSuspended, op.Ref, op.Version)
	}
	// Fingerprints are registered before the value leaves the broker.
	b.fp.Register(op.Ref, op.Version, op.Value)
	d := &delivery{b: bd, ref: op.Ref, version: op.Version}
	e.ref, e.version = op.Ref, op.Version
	var env, val string
	switch bd.Mode {
	case ModeS3:
		d.path = filepath.Join(inst.dir, slotFile(bd.Slot))
		if err := writeSecretFile(d.path, op.Value); err != nil {
			return nil, "", "", deny(ReasonDeliveryFailed, op.Ref, op.Version)
		}
		env, val = bd.slot.FileEnv, d.path
	case ModeS4:
		env, val = bd.slot.Env, string(op.Value)
	case ModeS1:
		d.grantID = ids.New() // d is not shared yet
		e.grant = d.grantID
		if err := b.bindHeader(ctx, bd, d, d.grantID, op.Value); err != nil {
			return nil, "", "", deny(ReasonDeliveryFailed, op.Ref, op.Version)
		}
	}
	e.outcome = "delivered"
	if err := b.commit(e); err != nil {
		b.undo(d)
		return nil, "", "", fmt.Errorf("evidence unavailable: %w", err)
	}
	return d, env, val, nil
}

func (b *Broker) bindHeader(ctx context.Context, bd *binding, d *delivery, grant string, value []byte) error {
	tmpl := bd.slot.HeaderTemplate
	if tmpl == "" {
		tmpl = "{secret}"
	}
	return b.injector.BindHeader(ctx, pipeline.HeaderGrant{GrantID: grant, Server: bd.Server, Slot: bd.Slot, Destination: bd.Destination,
		Header: bd.slot.Header, Template: tmpl, SecretRef: d.ref, Version: d.version, Value: slices.Clone(value)})
}

// undo removes what one delivery left behind and returns the S1 grant it
// withdrew ("" when none).
func (b *Broker) undo(d *delivery) string {
	if d.path != "" {
		_ = scrubFile(d.path)
	}
	g := b.takeGrant(d)
	if g != "" && b.injector != nil {
		b.injector.Withdraw(g)
	}
	return g
}

// takeGrant clears and returns a delivery's S1 grant ID under the broker
// lock: an emergency stop and an instance teardown may withdraw at once.
func (b *Broker) takeGrant(d *delivery) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	g := d.grantID
	d.grantID = ""
	return g
}

func (b *Broker) setGrant(d *delivery, g string) {
	b.mu.Lock()
	d.grantID = g
	b.mu.Unlock()
}

// InstanceDir returns the directory holding the S2 and S3 files of the
// server's current instance, or "" when it has none. A confining launcher
// makes it readable inside the sandbox (pipeline.ServerSpec.SecretDir).
func (b *Broker) InstanceDir(alias string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if inst := b.instances[alias]; inst != nil {
		return inst.dir
	}
	return ""
}

// Teardown withdraws every delivery of a server instance (FR-6.8: the S3
// file is deleted at instance teardown). The launcher wrapper calls it when
// the instance's process closes.
func (b *Broker) Teardown(alias, reason string) {
	b.mu.Lock()
	inst := b.instances[alias]
	delete(b.instances, alias)
	b.mu.Unlock()
	if inst != nil {
		b.teardown(inst, reason)
	}
}

func (b *Broker) teardown(inst *instance, reason string) {
	for _, d := range inst.delivered {
		g := b.undo(d)
		b.record(event{outcome: "withdrawn", reason: strings.ToUpper(reason), b: d.b, ref: d.ref, version: d.version, tool: "*", corr: inst.correlated, grant: g})
	}
	b.mu.Lock()
	for _, p := range inst.s2 {
		delete(b.calls, p)
	}
	b.mu.Unlock()
	_ = scrubTree(inst.dir)
}

// Close tears down every instance's deliveries.
func (b *Broker) Close() {
	b.mu.Lock()
	insts := make([]*instance, 0, len(b.instances))
	for _, i := range b.instances {
		insts = append(insts, i)
	}
	b.instances = map[string]*instance{}
	b.mu.Unlock()
	for _, i := range insts {
		b.teardown(i, "gateway_stopped")
	}
}

// onRetire replaces launch-time deliveries of a retired version with the
// current version: S3 files are rewritten and S1 grants rebound, so a
// rotated secret stops being deliverable at the overlap limit (FR-6.3).
// An S4 value already in a process environment cannot be withdrawn; the
// instance keeps it until it restarts.
func (b *Broker) onRetire(ref string, version int) {
	b.mu.Lock()
	var todo []struct {
		inst *instance
		d    *delivery
	}
	for _, inst := range b.instances {
		for _, d := range inst.delivered {
			if d.ref == ref && d.version == version && d.b.Mode != ModeS4 {
				todo = append(todo, struct {
					inst *instance
					d    *delivery
				}{inst, d})
			}
		}
	}
	use := b.use
	b.mu.Unlock()
	for _, t := range todo {
		b.redeliver(t.inst, t.d, use.Revision, "VERSION_RETIRED")
	}
}

// redeliver replaces one S1 or S3 delivery with the binding's deliverable
// version, or withdraws it when none is.
func (b *Broker) redeliver(inst *instance, d *delivery, policyRev, reason string) {
	g := b.undo(d)
	b.record(event{outcome: "withdrawn", reason: reason, b: d.b, ref: d.ref, version: d.version, tool: "*", corr: inst.correlated, grant: g})
	op, err := b.vault.open(d.b.Secret, d.b.Version)
	if err != nil {
		_ = b.commit(event{outcome: "denied", reason: reasonFor(err), b: d.b, ref: op.Ref, version: op.Version, tool: "*", corr: inst.correlated, decision: ids.New(), policyRev: policyRev})
		return
	}
	defer wipe(op.Value)
	b.fp.Register(op.Ref, op.Version, op.Value)
	d.ref, d.version = op.Ref, op.Version
	e := event{outcome: "delivered", b: d.b, ref: op.Ref, version: op.Version, tool: "*", corr: inst.correlated, decision: ids.New(), policyRev: policyRev, serverRev: b.serverRevision(inst.alias)}
	switch d.b.Mode {
	case ModeS3:
		if err := writeSecretFile(d.path, op.Value); err != nil {
			b.log.Error("secret file rewrite failed", "server", inst.alias, "slot", d.b.Slot, "err", err)
			return
		}
	case ModeS1:
		if b.injector == nil {
			return
		}
		g := ids.New()
		b.setGrant(d, g)
		e.grant = g
		if err := b.bindHeader(context.Background(), d.b, d, g, op.Value); err != nil {
			b.log.Error("secret header rebind failed", "server", inst.alias, "slot", d.b.Slot, "err", err)
			return
		}
	}
	if err := b.commit(e); err != nil {
		b.undo(d)
	}
}

// Observe implements audit.Observer: emergency stop withdraws S1 grants and
// per-call files and refuses new deliveries until resume (FR-4.14,
// SR-7.x emergency stop); resume rebinds S1 grants.
func (b *Broker) Observe(ev audit.Event) {
	if ev.Class != "admin" {
		return
	}
	switch ev.Outcome {
	case "stopped":
		b.withdrawAll()
	case "resumed":
		b.resumeAll()
	}
}

func (b *Broker) withdrawAll() {
	b.mu.Lock()
	b.stopped = true
	var s1 []struct {
		inst  *instance
		d     *delivery
		grant string
	}
	for _, inst := range b.instances {
		for _, d := range inst.delivered {
			if d.b.Mode == ModeS1 && d.grantID != "" {
				// Cleared under the lock: an instance teardown running at the
				// same time must not withdraw the grant a second time.
				s1 = append(s1, struct {
					inst  *instance
					d     *delivery
					grant string
				}{inst, d, d.grantID})
				d.grantID = ""
			}
		}
	}
	files := make([]*callFile, 0, len(b.calls))
	for p, cf := range b.calls {
		files = append(files, cf)
		delete(b.calls, p)
	}
	b.mu.Unlock()
	for _, t := range s1 {
		if b.injector != nil {
			b.injector.Withdraw(t.grant)
		}
		b.record(event{outcome: "withdrawn", reason: ReasonStopped, b: t.d.b, ref: t.d.ref, version: t.d.version, tool: "*", corr: t.inst.correlated, grant: t.grant})
	}
	for _, cf := range files {
		_ = scrubFile(cf.path)
		b.record(event{outcome: "withdrawn", reason: ReasonStopped, mode: ModeS2, ref: cf.ref, version: cf.version})
	}
}

func (b *Broker) resumeAll() {
	b.mu.Lock()
	b.stopped = false
	var s1 []struct {
		inst *instance
		d    *delivery
	}
	for _, inst := range b.instances {
		for _, d := range inst.delivered {
			if d.b.Mode == ModeS1 && d.grantID == "" {
				s1 = append(s1, struct {
					inst *instance
					d    *delivery
				}{inst, d})
			}
		}
	}
	use := b.use
	b.mu.Unlock()
	for _, t := range s1 {
		b.redeliver(t.inst, t.d, use.Revision, "RESUMED")
	}
}

// Suspend refuses further S2 deliveries of a secret until Unsuspend. The
// response leak filter suspends a secret it finds in a result (ARCH §8.5).
func (b *Broker) Suspend(ref, reason string) {
	b.mu.Lock()
	b.suspended[ref] = reason
	b.mu.Unlock()
}

// Unsuspend lifts a suspension; it reports whether one existed.
func (b *Broker) Unsuspend(ref string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.suspended[ref]
	delete(b.suspended, ref)
	return ok
}

// Suspended returns the suspended secret references with their reasons.
func (b *Broker) Suspended() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]string, len(b.suspended))
	for k, v := range b.suspended {
		out[k] = v
	}
	return out
}

// InstanceFiles reports, per server alias, the S2 and S3 file paths of
// running instances (for health and tests; never the contents).
func (b *Broker) InstanceFiles() map[string][]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string][]string{}
	for alias, inst := range b.instances {
		for _, d := range inst.delivered {
			if d.path != "" {
				out[alias] = append(out[alias], d.path)
			}
		}
		for _, p := range inst.s2 {
			out[alias] = append(out[alias], p)
		}
		sort.Strings(out[alias])
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writeSecretFile writes value to a new owner-only file.
func writeSecretFile(path string, value []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(value); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := inheritReaders(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// inheritReaders gives a new secret file read access for every named user
// that the sandbox granted on its directory (posixacl entries with the
// search bit; see sandbox.GrantSecretReaders). An instance running under
// a subordinate UID or the separate server identity then reads S2 and S3
// files written after its launch, such as per-call files and rotated
// values. Without such entries the file stays owner-only.
func inheritReaders(path string) error {
	a, err := posixacl.Get(filepath.Dir(path))
	if errors.Is(err, posixacl.ErrUnsupported) {
		return nil
	}
	if err != nil {
		return err
	}
	for uid, perm := range a.Users() {
		if perm&posixacl.Execute == 0 {
			continue
		}
		if err := posixacl.AddUser(path, uid, posixacl.Read); err != nil {
			return fmt.Errorf("secret file reader %d: %w", uid, err)
		}
	}
	return nil
}

// scrubFile overwrites a file with zeros and removes it. On tmpfs the
// overwrite reaches the only copy; on a disk file system it is best effort.
func scrubFile(path string) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			_, _ = f.Write(make([]byte, fi.Size()))
			_ = f.Sync()
			f.Close()
		}
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// scrubTree scrubs every regular file under dir and removes it.
func scrubTree(dir string) error {
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			_ = scrubFile(p)
		}
		return nil
	})
	return os.RemoveAll(dir)
}
