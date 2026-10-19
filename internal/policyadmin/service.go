// Package policyadmin is the Policy Administration Service (E-05) as the
// running Gateway exposes it: it loads the active signed revision at start,
// publishes, rolls back, validates, compares and simulates revisions, and
// serves the /api/v1/policy* routes of the control API.
//
// Publication order (SR-1.15-1, SR-1.16-1): the document is validated and
// compiled; the signed revision file is written (policystore.Put); the
// publication is committed to the evidence journal; the signed control
// record is renamed over active.json and the directory flushed
// (policystore.Activate); only then does the Enforcement Coordinator swap
// the decision snapshot under its barrier (edge.Gateway.ActivatePolicy),
// which also notifies open listen streams that the tool list changed. When
// the swap fails the previous control record is restored.
//
// Service implements adminapi.Controller by delegation to the Gateway, so
// the existing POST /admin/v1/policy/reload route publishes the policy file
// through the store instead of bypassing it.
package policyadmin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
)

// Startup faults, reported as critical health causes (SR-1.1-2, SR-7.3-1):
// FaultSignature when the active revision or the control record does not
// verify, is missing or is not a revision file; FaultInvalid when it
// verifies but fails the schema, field, enumeration or cross-reference
// checks.
const (
	FaultSignature = "policy_signature"
	FaultInvalid   = "policy_invalid"
)

// Reason codes of policy administration evidence events.
const (
	ReasonPublished   = "POLICY_PUBLISHED"
	ReasonRolledBack  = "POLICY_ROLLED_BACK"
	ReasonImported    = "POLICY_IMPORTED"
	ReasonInvalid     = "POLICY_INVALID"
	ReasonConflict    = "POLICY_CONFLICT"
	ReasonSimulated   = "POLICY_SIMULATED"
	ReasonIntegrity   = "POLICY_SIGNATURE"
	ReasonActivateErr = "POLICY_ACTIVATION_FAILED"
)

// Errors returned by the service; the HTTP layer maps them to codes.
var (
	ErrInvalid        = errors.New("policy invalid")
	ErrParentMismatch = errors.New("the active revision is not the stated parent")
	ErrPublished      = errors.New("revision is already published and is not active; give the document a new revision ID or roll back to it")
	ErrAudit          = errors.New("evidence journal unavailable")
	ErrActivation     = errors.New("activation failed")
)

// reusedError reports a revision-ID conflict as policy.ErrRevisionReused to
// callers that only know that error (the reload route).
type reusedError struct{ err error }

func (e reusedError) Error() string        { return e.err.Error() }
func (e reusedError) Unwrap() error        { return e.err }
func (e reusedError) Is(target error) bool { return target == policy.ErrRevisionReused }

// Load returns the snapshot to start with. With an empty store the policy
// file is imported as the first signed revision and activated. When the
// active revision does not verify, Load returns a nil snapshot and the
// fault FaultSignature: the Gateway then starts fail-closed (SR-1.1-2).
func Load(store *policystore.Store, policyFile string) (snap *policy.Snapshot, imported *policystore.Record, fault string, err error) {
	rev, _, err := store.Active()
	switch {
	case err == nil:
		return rev.Snapshot, nil, "", nil
	case errors.Is(err, policystore.ErrInvalidDocument):
		return nil, nil, FaultInvalid, err
	case errors.Is(err, policystore.ErrIntegrity):
		return nil, nil, FaultSignature, err
	case !errors.Is(err, policystore.ErrNoActive):
		return nil, nil, "", err
	}
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, nil, "", err
	}
	if _, err := policy.Compile(raw); err != nil {
		return nil, nil, "", fmt.Errorf("%s: %w", policyFile, err)
	}
	actor := "file:" + policyFile
	rev, _, err = store.Put(raw, policystore.Meta{Actor: actor, Origin: "import"})
	if err != nil {
		return nil, nil, "", err
	}
	if _, err := store.Activate(rev, actor); err != nil {
		return nil, nil, "", err
	}
	return rev.Snapshot, &rev.Record, "", nil
}

// Options configure the service.
type Options struct {
	Store    *policystore.Store
	Evidence audit.Recorder
	// Active returns the snapshot the decider holds.
	Active func() *policy.Snapshot
	// JournalDir is read for simulation replay ("" disables journal replay).
	JournalDir string
	// ServerRiskClasses maps server aliases to their declared tool classes,
	// for the high-risk check at publication (SR-3.13-1); nil skips it.
	ServerRiskClasses func() map[string][]string
	// SecretBindings returns the Secret Use Policy bindings of the given
	// servers for the effective permission report (FR-6.5); nil omits them.
	SecretBindings func(servers []string) any
	// DefaultRate and Burst are the CP-11 values used in simulation.
	DefaultRate int
	Burst       int
	// Fault is the startup fault from Load ("" when none).
	Fault string
	Log   *slog.Logger
}

// Service is the running E-05.
type Service struct {
	o     Options
	gw    adminapi.Controller
	fault atomic.Value // string
	mu    sync.Mutex   // serializes publications

	currency atomic.Pointer[Currency] // last result of CheckCurrency
}

// Currency is the result of a decision-snapshot currency check: Detail is
// empty when the snapshot in force is the Policy Store's verified active
// revision; Integrity is set when a store file no longer verifies.
type Currency struct {
	Detail    string
	Integrity bool
}

// New returns the service; Bind must be called with the Gateway before use.
func New(o Options) *Service {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	s := &Service{o: o}
	s.fault.Store(o.Fault)
	return s
}

// Bind sets the Gateway that activates snapshots.
func (s *Service) Bind(gw adminapi.Controller) { s.gw = gw }

// Fault returns the current policy fault ("" when none). The edge reports it
// as a health cause.
func (s *Service) Fault() string { v, _ := s.fault.Load().(string); return v }

// CheckCurrency compares the decision snapshot in force with the signed
// control record and the revision file it names (FR-7.11). While a
// publication holds the service lock the control record and the snapshot
// may differ for a moment, so the previous result is returned instead.
func (s *Service) CheckCurrency() Currency {
	if !s.mu.TryLock() {
		if c := s.currency.Load(); c != nil {
			return *c
		}
		return Currency{}
	}
	defer s.mu.Unlock()
	var c Currency
	if cur := s.o.Active(); cur != nil && s.o.Store != nil {
		if err := s.o.Store.CheckActive(cur.Revision); err != nil {
			c = Currency{Detail: err.Error(), Integrity: errors.Is(err, policystore.ErrIntegrity)}
		}
	}
	s.currency.Store(&c)
	return c
}

// Health implements adminapi.Controller.
func (s *Service) Health() edge.Health { return s.gw.Health() }

// Stop implements adminapi.Controller.
func (s *Service) Stop(actor, reason string) error { return s.gw.Stop(actor, reason) }

// Resume implements adminapi.Controller.
func (s *Service) Resume(actor string) error { return s.gw.Resume(actor) }

// ActivatePolicy implements adminapi.Controller for the reload route: the
// document is published through the store.
func (s *Service) ActivatePolicy(actor string, snap *policy.Snapshot) (bool, error) {
	res, err := s.Publish(snap.Raw, PublishOptions{Actor: actor, Origin: "reload"})
	if errors.Is(err, policystore.ErrRevisionExists) || errors.Is(err, ErrPublished) {
		return false, reusedError{err}
	}
	return res.Changed, err
}

// Started records the startup outcome of Load in the journal.
func (s *Service) Started(imported *policystore.Record, loadErr error) {
	var ev audit.Event
	switch {
	case imported != nil:
		ev = event("imported", ReasonImported, imported.Actor, imported.Revision, map[string]any{"record": imported})
	case loadErr != nil:
		cause := s.Fault()
		if cause == "" {
			cause = FaultSignature
		}
		ev = event("refused", ReasonIntegrity, "gateway", "", map[string]any{"error": loadErr.Error(), "cause": cause})
	default:
		return
	}
	if err := s.o.Evidence.Commit(ev); err != nil {
		s.o.Log.Error("evidence write failed", "err", err)
	}
}

func event(outcome, reason, actor, revision string, detail map[string]any) audit.Event {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["actor"] = actor
	return audit.Event{Class: "admin", Origin: "E-05", Outcome: outcome, ReasonCode: reason, PolicyRevision: revision,
		PolicyStatus: "not_evaluated", Detail: detail}
}

func (s *Service) reject(actor, reason string, err error) {
	if aerr := s.o.Evidence.Commit(event("rejected", reason, actor, "", map[string]any{"error": err.Error()})); aerr != nil {
		s.o.Log.Error("evidence write failed", "err", aerr)
	}
}

// PublishOptions are the inputs of a publication.
type PublishOptions struct {
	Actor string
	// Parent, when set, must be the active revision (optimistic
	// concurrency: the draft was derived from it, FR-3.3).
	Parent        string
	SimulationRef string
	Origin        string // publish (default), reload, rollback
	RollbackOf    string
}

// PublishResult reports a publication.
type PublishResult struct {
	Record  policystore.Record `json:"record"`
	Created bool               `json:"created"`
	Changed bool               `json:"changed"`
}

// Publish validates, signs, stores and activates a document.
func (s *Service) Publish(raw []byte, o PublishOptions) (PublishResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o.Origin == "" {
		o.Origin = "publish"
	}
	snap, err := policy.Compile(raw)
	if err == nil && s.o.ServerRiskClasses != nil {
		err = snap.CheckHighRisk(s.o.ServerRiskClasses()) // SR-3.13-1
	}
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrInvalid, err)
		s.reject(o.Actor, ReasonInvalid, err)
		return PublishResult{}, err
	}
	cur := s.o.Active()
	curRev := ""
	if cur != nil {
		curRev = cur.Revision
	}
	if o.Parent != "" && o.Parent != curRev {
		err := fmt.Errorf("%w: active %q, stated parent %q", ErrParentMismatch, curRev, o.Parent)
		s.reject(o.Actor, ReasonConflict, err)
		return PublishResult{}, err
	}
	rev, created, err := s.o.Store.Put(raw, policystore.Meta{Parent: curRev, Actor: o.Actor, SimulationRef: o.SimulationRef, Origin: o.Origin, RollbackOf: o.RollbackOf})
	if err != nil {
		if errors.Is(err, policystore.ErrRevisionExists) {
			s.reject(o.Actor, ReasonConflict, err)
		}
		return PublishResult{}, err
	}
	res := PublishResult{Record: rev.Record, Created: created}
	if !created {
		if rev.Record.Revision == curRev {
			return res, nil // identical content republished: no change
		}
		err := fmt.Errorf("%w (%s)", ErrPublished, rev.Record.Revision)
		s.reject(o.Actor, ReasonConflict, err)
		return PublishResult{}, err
	}
	reason := ReasonPublished
	if o.Origin == "rollback" {
		reason = ReasonRolledBack
	}
	if err := s.o.Evidence.Commit(event("published", reason, o.Actor, rev.Record.Revision, map[string]any{"record": rev.Record})); err != nil {
		return PublishResult{}, fmt.Errorf("%w: %w", ErrAudit, err)
	}
	_, prevCtl, perr := s.o.Store.Active()
	if perr != nil {
		prevCtl = policystore.Control{}
	}
	if _, err := s.o.Store.Activate(rev, o.Actor); err != nil {
		return PublishResult{}, fmt.Errorf("%w: control record: %w", ErrActivation, err)
	}
	changed, err := s.gw.ActivatePolicy(o.Actor, rev.Snapshot)
	if err != nil {
		if rerr := s.o.Store.Restore(prevCtl); rerr != nil {
			s.o.Log.Error("restoring the previous policy-control record failed", "err", rerr)
		}
		_ = s.o.Evidence.Commit(event("rejected", ReasonActivateErr, o.Actor, rev.Record.Revision, map[string]any{"error": err.Error()}))
		return PublishResult{}, fmt.Errorf("%w: %w", ErrActivation, err)
	}
	s.fault.Store("")
	res.Changed = changed
	return res, nil
}

var revisionID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// RollbackID returns the default revision ID of a rollback to revision:
// "<revision>-rb<n>" with the smallest n not yet published, shortened to
// fit the 64-character revision pattern.
func (s *Service) RollbackID(to string) string {
	used := map[string]bool{}
	for _, r := range s.o.Store.List() {
		used[r.Revision] = true
	}
	for n := 1; ; n++ {
		suffix := "-rb" + strconv.Itoa(n)
		base := to
		if len(base)+len(suffix) > 64 {
			base = base[:64-len(suffix)]
		}
		if id := base + suffix; !used[id] {
			return id
		}
	}
}

// Rollback publishes the content of an earlier revision as a new revision
// (FR-3.9). newID "" picks RollbackID(to).
func (s *Service) Rollback(to, newID, actor string) (PublishResult, error) {
	rev, err := s.o.Store.Get(to)
	if err != nil {
		return PublishResult{}, err
	}
	if newID == "" {
		newID = s.RollbackID(to)
	}
	if !revisionID.MatchString(newID) {
		return PublishResult{}, fmt.Errorf("%w: revision ID %q does not match %s", ErrInvalid, newID, revisionID)
	}
	dec := json.NewDecoder(bytes.NewReader(rev.Snapshot.Raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return PublishResult{}, err
	}
	doc["revision"] = newID
	raw, err := json.Marshal(doc)
	if err != nil {
		return PublishResult{}, err
	}
	return s.Publish(raw, PublishOptions{Actor: actor, Origin: "rollback", RollbackOf: to})
}

// Summary describes a valid document.
type Summary struct {
	Revision  string `json:"revision"`
	Digest    string `json:"digest"`
	Profiles  int    `json:"framework_profiles"`
	Templates int    `json:"templates"`
	Rules     int    `json:"rules"`
	Grants    int    `json:"grants"`
}

// Summarize validates a document and summarizes it.
func Summarize(raw []byte) (*policy.Snapshot, Summary, error) {
	snap, err := policy.Compile(raw)
	if err != nil {
		return nil, Summary{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	doc := snap.Document()
	sum := Summary{Revision: snap.Revision, Digest: snap.Digest, Profiles: len(doc.FrameworkProfiles), Templates: len(doc.Templates)}
	for name, t := range doc.Templates {
		sum.Rules += len(t.Rules)
		sum.Grants += len(snap.Grants(name))
	}
	return snap, sum, nil
}

// SimulationResult is a simulation report with the ID of its evidence
// event; publish may cite it as simulation_ref (FR-3.4).
type SimulationResult struct {
	SimulationID string `json:"simulation_id"`
	Source       string `json:"source"`
	policy.SimReport
}

// DefaultJournalFixtures is how many recent journal calls a simulation
// replays when no limit is given.
const DefaultJournalFixtures = 1000

// Simulate replays fixtures (or, when fixtures is nil, the most recent
// limit calls of the journal) against the active revision and the
// candidate.
func (s *Service) Simulate(raw []byte, fixtures []policy.Fixture, limit int, all bool, actor string) (SimulationResult, error) {
	cand, err := policy.Compile(raw)
	if err != nil {
		return SimulationResult{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	source := "fixtures"
	if fixtures == nil {
		source = "journal"
		if fixtures, err = JournalFixtures(s.o.JournalDir, limit); err != nil {
			return SimulationResult{}, err
		}
	}
	rep, err := policy.Simulate(s.o.Active(), cand, fixtures, policy.SimOptions{DefaultRate: s.o.DefaultRate, Burst: s.o.Burst, All: all})
	if err != nil {
		return SimulationResult{}, err
	}
	res := SimulationResult{SimulationID: ids.New(), Source: source, SimReport: rep}
	if err := s.o.Evidence.Commit(event("simulated", ReasonSimulated, actor, rep.ActiveRevision, map[string]any{
		"simulation_id": res.SimulationID, "candidate_revision": rep.CandidateRevision, "candidate_digest": cand.Digest,
		"source": source, "fixtures": rep.Fixtures, "changed": rep.Changed, "counts": rep.Counts})); err != nil {
		return SimulationResult{}, fmt.Errorf("%w: %w", ErrAudit, err)
	}
	return res, nil
}

// JournalFixtures returns the most recent limit tool calls recorded in the
// journal as fixtures. A call is taken from its `requested` event, whose
// detail carries the server, tool, template and profile.
func JournalFixtures(dir string, limit int) ([]policy.Fixture, error) {
	if dir == "" {
		return nil, errors.New("journal replay is not available")
	}
	if limit <= 0 {
		limit = DefaultJournalFixtures
	}
	if limit > policy.MaxFixtures {
		limit = policy.MaxFixtures
	}
	evs, err := audit.ReadEvents(dir)
	if err != nil {
		return nil, err
	}
	var out []policy.Fixture
	for _, e := range evs {
		if e.Class != "call" || e.Phase != audit.PhaseRequested {
			continue
		}
		d, _ := e.Detail.(map[string]any)
		str := func(k string) string { v, _ := d[k].(string); return v }
		if str("server") == "" || str("tool") == "" || str("template") == "" {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, e.Time)
		out = append(out, policy.Fixture{Time: t, CorrelationID: e.CorrelationID, PrincipalID: e.PrincipalID, SessionID: e.SessionID,
			Profile: str("profile"), Template: str("template"), Server: str("server"), Tool: str("tool"),
			SideEffect: str("side_effect"), SourceTrust: str("source_trust")})
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	if len(out) == 0 {
		return nil, policy.ErrNoFixtures
	}
	return out, nil
}
