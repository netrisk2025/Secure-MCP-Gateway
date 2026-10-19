// Package obspolicy holds the observation control objects that the console
// publishes (G-03, G-04, G-06, G-08): the Audit Profile, the Observation
// Policy, the Anomaly Response Policy and the memory budget of the
// Observation Store. Each object is a sequence of immutable, numbered
// revisions with a SHA-256 digest, actor, time and reason, kept in
// state/observation-objects.json (mode 0600, written atomically). The last
// revision of each kind is the active one.
//
// A revision is validated before it is stored by resolving the complete
// observation settings it would produce (analytics.Resolve against the
// shipped Parameter Catalog), so a published object always starts.
//
// Apply overlays the active objects onto a copy of the configuration that
// smcpd gives to the analytics service at start. With an applier set
// (SetApplier, the analytics service's Update), a revision published while
// the Gateway runs is applied at once: the observation settings the active
// objects produce are handed to the applier, which changes what the running
// components allow and names the settings that wait for the next start
// (the baseline contexts and the memory budget). The status route reports
// which revision is in force, which is pending and why.
//
// What each object sets in [observation]:
//
//	audit_profile        retention, escalation_parameters (optional capture above the audit floor)
//	observation_policy   policy_id, parameters, sampling_rate, escalation_bands, baseline.contexts,
//	                     baseline.bands, baseline.feature
//	anomaly_response     scoring, escalate_capture_band, uncharacterized_action,
//	                     require_approval_band, withhold_band
//	memory_budget        memory_limit_bytes
//
// The mandatory audit floor (the evidence classes the journal always
// records) is not part of any object and cannot be changed.
package obspolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/principals"
)

// File is the store's path under the state directory.
const File = "observation-objects.json"

// Kinds of object.
const (
	KindAuditProfile      = "audit_profile"
	KindObservationPolicy = "observation_policy"
	KindAnomalyResponse   = "anomaly_response"
	KindMemoryBudget      = "memory_budget"
)

// Kinds lists every kind in display order.
var Kinds = []string{KindAuditProfile, KindObservationPolicy, KindAnomalyResponse, KindMemoryBudget}

// AuditProfile is the optional capture and retention above the audit floor
// (FR-8.5).
type AuditProfile struct {
	Retention            string   `json:"retention"`
	EscalationParameters []string `json:"escalation_parameters"`
}

// ObservationPolicy is what the collector captures and how the baseline is
// keyed and banded (FR-8.6 to FR-8.10). Escalation adds parameters for
// escalated calls of a band and every higher band; Features replaces the
// baselined features and their statistics options (transform, robust
// statistics, σ floor). Both are optional: absent, the [observation]
// settings stay in force.
type ObservationPolicy struct {
	PolicyID     string                      `json:"policy_id"`
	Parameters   []string                    `json:"parameters"`
	SamplingRate float64                     `json:"sampling_rate"`
	Contexts     []string                    `json:"contexts"`
	Bands        []float64                   `json:"bands"`
	Escalation   map[string][]string         `json:"escalation,omitempty"`
	Features     []config.ObservationFeature `json:"features,omitempty"`
	Scope        *config.ObservationScope    `json:"scope,omitempty"`
}

// AnomalyResponse maps the sigma bands and the uncharacterized state to
// restrict-only actions (FR-8.14): every band from elevated on alerts;
// escalate_capture_band, require_approval_band and withhold_band name the
// lowest band that also escalates capture, needs approval or has its
// result withheld ("off" for none; escalation defaults to elevated).
// Uncharacterized is the action for a call whose context has no baseline:
// record (default), escalate or approve. Approval and withholding need
// synchronous scoring.
type AnomalyResponse struct {
	Scoring             string `json:"scoring"`
	EscalateCaptureBand string `json:"escalate_capture_band,omitempty"`
	Uncharacterized     string `json:"uncharacterized,omitempty"`
	RequireApprovalBand string `json:"require_approval_band"`
	WithholdBand        string `json:"withhold_band"`
}

// MemoryBudget is the Observation Store's memory budget (FR-8.16, CP-33).
type MemoryBudget struct {
	ObservationMemoryLimitBytes int64 `json:"observation_memory_limit_bytes"`
}

// Revision is one published revision of an object.
type Revision struct {
	Kind        string          `json:"kind"`
	Number      int             `json:"number"`
	Digest      string          `json:"digest"`
	Body        json.RawMessage `json:"body"`
	PublishedBy string          `json:"published_by"`
	PublishedAt time.Time       `json:"published_at"`
	Reason      string          `json:"reason,omitempty"`
}

// Errors.
var (
	ErrInvalid     = errors.New("invalid object")
	ErrUnknownKind = errors.New("unknown object kind")
)

type state struct {
	Version   int                   `json:"version"`
	Revisions map[string][]Revision `json:"revisions"`
}

// Store is the object store.
type Store struct {
	path string
	cfg  *config.Config
	cat  *observe.Catalog
	now  func() time.Time

	mu       sync.Mutex
	st       state
	inForce  map[string]int      // revision numbers in force
	restart  map[string][]string // settings of a kind's active revision that wait for the next start
	applier  func(*config.Config) ([]string, error)
	applyErr error
}

// restartKind maps a setting the applier reports as needing a restart to
// the object kind that sets it.
var restartKind = map[string]string{"baseline.contexts": KindObservationPolicy, "memory_limit_bytes": KindMemoryBudget}

// SetApplier sets the function that applies published objects to the
// running observation components. It receives a copy of the configuration
// with every active object overlaid and returns the settings it could not
// change without a restart.
func (s *Store) SetApplier(f func(*config.Config) ([]string, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applier = f
}

// applyLocked hands the active objects to the applier and updates which
// revisions are in force.
func (s *Store) applyLocked() {
	if s.applier == nil {
		return
	}
	c := *s.cfg
	c.Observation.Baseline.Contexts = slices.Clone(c.Observation.Baseline.Contexts)
	act := s.activeLocked()
	for _, k := range Kinds {
		r, ok := act[k]
		if !ok {
			continue
		}
		trial := c
		v, err := decode(k, r.Body)
		if err == nil {
			err = overlay(&trial.Observation, v)
		}
		if err == nil {
			c.Observation = trial.Observation
		}
	}
	restart, err := s.applier(&c)
	s.applyErr = err
	if err != nil {
		return
	}
	s.restart = map[string][]string{}
	for _, f := range restart {
		if k, ok := restartKind[f]; ok {
			s.restart[k] = append(s.restart[k], f)
		}
	}
	for k, r := range act {
		if len(s.restart[k]) == 0 {
			s.inForce[k] = r.Number
		}
	}
}

// Open reads the store of cfg's state directory (an absent file is empty).
func Open(cfg *config.Config) (*Store, error) {
	s := &Store{path: filepath.Join(cfg.State.Dir, File), cfg: cfg, cat: observe.DefaultCatalog(), now: time.Now,
		st: state{Version: 1, Revisions: map[string][]Revision{}}, inForce: map[string]int{}}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	if s.st.Revisions == nil {
		s.st.Revisions = map[string][]Revision{}
	}
	return s, nil
}

// decode parses a body of a kind strictly.
func decode(kind string, raw []byte) (any, error) {
	var v any
	switch kind {
	case KindAuditProfile:
		v = &AuditProfile{}
	case KindObservationPolicy:
		v = &ObservationPolicy{}
	case KindAnomalyResponse:
		v = &AnomalyResponse{}
	case KindMemoryBudget:
		v = &MemoryBudget{}
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return v, nil
}

// overlay sets the fields of one object on o.
func overlay(o *config.Observation, v any) error {
	switch b := v.(type) {
	case *AuditProfile:
		d, err := time.ParseDuration(b.Retention)
		if err != nil || d < 24*time.Hour {
			return fmt.Errorf("%w: retention must be a duration of at least 24h, such as \"2160h\"", ErrInvalid)
		}
		o.Retention = config.Duration{Duration: d}
		o.EscalationParameters = slices.Clone(b.EscalationParameters)
	case *ObservationPolicy:
		if b.SamplingRate <= 0 || b.SamplingRate > 1 {
			return fmt.Errorf("%w: sampling_rate must be above 0 and at most 1", ErrInvalid)
		}
		if b.PolicyID == "" || len(b.PolicyID) > 64 {
			return fmt.Errorf("%w: policy_id must have 1 to 64 characters", ErrInvalid)
		}
		if len(b.Parameters) == 0 {
			return fmt.Errorf("%w: choose at least one parameter", ErrInvalid)
		}
		if len(b.Bands) != 0 && len(b.Bands) != 3 {
			return fmt.Errorf("%w: bands are the three |z| bounds of elevated, abnormal and critical", ErrInvalid)
		}
		rate := b.SamplingRate
		o.PolicyID, o.Parameters, o.SamplingRate = b.PolicyID, slices.Clone(b.Parameters), &rate
		o.Baseline.Contexts, o.Baseline.Bands = slices.Clone(b.Contexts), slices.Clone(b.Bands)
		if b.Escalation != nil {
			o.EscalationBands = map[string][]string{}
			for k, v := range b.Escalation {
				o.EscalationBands[k] = slices.Clone(v)
			}
		}
		if len(b.Features) > 0 {
			o.Baseline.Features = slices.Clone(b.Features)
		}
		if b.Scope != nil {
			for _, f := range b.Scope.Frameworks {
				if !slices.Contains(principals.Frameworks, f) {
					return fmt.Errorf("%w: scope framework %q is not a known framework type", ErrInvalid, f)
				}
			}
			o.Scope = *b.Scope
		}
	case *AnomalyResponse:
		for _, x := range []string{b.RequireApprovalBand, b.WithholdBand} {
			if !slices.Contains([]string{"off", "elevated", "abnormal", "critical"}, x) {
				return fmt.Errorf("%w: a band must be off, elevated, abnormal or critical", ErrInvalid)
			}
		}
		if b.EscalateCaptureBand != "" && !slices.Contains([]string{"off", "elevated", "abnormal", "critical"}, b.EscalateCaptureBand) {
			return fmt.Errorf("%w: escalate_capture_band must be off, elevated, abnormal or critical", ErrInvalid)
		}
		if b.Uncharacterized != "" && !slices.Contains([]string{"record", "escalate", "approve"}, b.Uncharacterized) {
			return fmt.Errorf("%w: uncharacterized must be record, escalate or approve", ErrInvalid)
		}
		if !slices.Contains([]string{"async", "sync", "off"}, b.Scoring) {
			return fmt.Errorf("%w: scoring must be async, sync or off", ErrInvalid)
		}
		o.Scoring, o.RequireApprovalBand, o.WithholdBand = b.Scoring, b.RequireApprovalBand, b.WithholdBand
		o.EscalateCaptureBand, o.UncharacterizedAction = b.EscalateCaptureBand, b.Uncharacterized
	case *MemoryBudget:
		if b.ObservationMemoryLimitBytes < 64<<20 || b.ObservationMemoryLimitBytes > 64<<30 {
			return fmt.Errorf("%w: observation_memory_limit_bytes must be between 64 MiB and 64 GiB", ErrInvalid)
		}
		o.MemoryLimitBytes = b.ObservationMemoryLimitBytes
	}
	return nil
}

// activeLocked returns the active revision of each kind.
func (s *Store) activeLocked() map[string]Revision {
	out := map[string]Revision{}
	for k, rs := range s.st.Revisions {
		if len(rs) > 0 {
			out[k] = rs[len(rs)-1]
		}
	}
	return out
}

// effective returns cfg's observation table with the given revisions
// applied, after resolving it like the analytics service does.
func (s *Store) effective(revs map[string]Revision) (config.Observation, error) {
	c := *s.cfg
	c.Observation.Baseline.Contexts = slices.Clone(c.Observation.Baseline.Contexts)
	for _, k := range Kinds {
		r, ok := revs[k]
		if !ok {
			continue
		}
		v, err := decode(k, r.Body)
		if err != nil {
			return config.Observation{}, err
		}
		if err := overlay(&c.Observation, v); err != nil {
			return config.Observation{}, err
		}
	}
	if _, err := analytics.Resolve(&c, s.cat); err != nil {
		return config.Observation{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return c.Observation, nil
}

// Apply overlays the active objects onto c (a copy of the configuration
// for the analytics service) and records them as in force. An active object
// that no longer resolves (for example after a catalog change) is skipped
// with an error, and the file's settings stay in effect for it.
func (s *Store) Apply(c *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, k := range Kinds {
		r, ok := s.activeLocked()[k]
		if !ok {
			continue
		}
		trial := *c
		v, err := decode(k, r.Body)
		if err == nil {
			err = overlay(&trial.Observation, v)
		}
		if err == nil {
			_, err = analytics.Resolve(&trial, s.cat)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s revision %d not applied: %w", k, r.Number, err))
			continue
		}
		c.Observation = trial.Observation
		s.inForce[k] = r.Number
	}
	return errors.Join(errs...)
}

// InForce names the revision of kind applied at start: "<kind>@<n>", or
// "<kind>@file" when the configuration file's settings are in force (an
// FR-3.12 obligation reference).
func (s *Store) InForce(kind string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.inForce[kind]; n > 0 {
		return fmt.Sprintf("%s@%d", kind, n)
	}
	return kind + "@file"
}

// Publish validates and stores a new revision of kind. The body must be the
// kind's JSON object.
func (s *Store) Publish(kind string, body []byte, actor, reason string) (Revision, error) {
	v, err := decode(kind, body)
	if err != nil {
		return Revision{}, err
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return Revision{}, err
	}
	sum := sha256.Sum256(canon)
	s.mu.Lock()
	defer s.mu.Unlock()
	revs := s.activeLocked()
	r := Revision{Kind: kind, Number: len(s.st.Revisions[kind]) + 1, Digest: "sha256:" + hex.EncodeToString(sum[:]), Body: canon,
		PublishedBy: actor, PublishedAt: s.now().UTC(), Reason: reason}
	revs[kind] = r
	if _, err := s.effective(revs); err != nil {
		return Revision{}, err
	}
	s.st.Revisions[kind] = append(s.st.Revisions[kind], r)
	if err := s.saveLocked(); err != nil {
		s.st.Revisions[kind] = s.st.Revisions[kind][:len(s.st.Revisions[kind])-1]
		return Revision{}, err
	}
	s.applyLocked()
	return r, nil
}

// Validate checks a body without storing it.
func (s *Store) Validate(kind string, body []byte) error {
	v, err := decode(kind, body)
	if err != nil {
		return err
	}
	canon, _ := json.Marshal(v)
	s.mu.Lock()
	defer s.mu.Unlock()
	revs := s.activeLocked()
	revs[kind] = Revision{Kind: kind, Body: canon}
	_, err = s.effective(revs)
	return err
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return keys.WriteFileAtomic(s.path, append(b, '\n'), 0o600)
}

// ObjectStatus is the state of one kind.
type ObjectStatus struct {
	Kind    string    `json:"kind"`
	Active  *Revision `json:"active,omitempty"`
	InForce int       `json:"in_force"` // revision number in force; 0 for the file's settings
	Pending bool      `json:"pending"`  // the active revision is not (wholly) in force yet
	// RestartRequired names the active revision's settings that take
	// effect at the next start; its other settings are in force.
	RestartRequired []string `json:"restart_required,omitempty"`
	Revisions       int      `json:"revisions"`
}

// Live reports whether published objects apply while the Gateway runs,
// and the last error from applying them.
func (s *Store) Live() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applier != nil, s.applyErr
}

// Status returns the state of every kind and the observation settings the
// active objects produce.
func (s *Store) Status() ([]ObjectStatus, config.Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	act := s.activeLocked()
	var out []ObjectStatus
	for _, k := range Kinds {
		st := ObjectStatus{Kind: k, InForce: s.inForce[k], Revisions: len(s.st.Revisions[k])}
		if r, ok := act[k]; ok {
			r := r
			st.Active = &r
			st.Pending = r.Number != s.inForce[k]
			st.RestartRequired = slices.Clone(s.restart[k])
		}
		out = append(out, st)
	}
	eff, err := s.effective(act)
	return out, eff, err
}

// Revisions returns the revisions of a kind, newest first.
func (s *Store) Revisions(kind string) ([]Revision, error) {
	if !slices.Contains(Kinds, kind) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.st.Revisions[kind])
	slices.Reverse(out)
	if out == nil {
		out = []Revision{}
	}
	return out, nil
}
