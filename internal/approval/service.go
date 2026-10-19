// Package approval is the Approval Service (E-07): human approval of tool
// calls whose decision carries an approval obligation (FR-3.14 to FR-3.24).
//
// An approval is a persisted record bound to the session, principal,
// server, tool and route revisions, canonical argument digest and policy
// revision of the call (SR-1.18-2), with a CP-17 lifetime and single use.
// A call that needs approval is held (parked) for up to the CP-45 hold
// bound while the edge sends keep-alives; an approval during the hold
// continues the same call, a denial ends it with -31001, and at the bound
// the call ends with -31002 while the approval stays pending until it
// expires, so a retry after approval consumes it (FR-3.15, FR-3.22).
//
// Approvers learn of a new approval through the control API watch stream
// (smcpctl approvals watch, the console) and an OS desktop notification
// that carries no argument values. Approve and deny take the Administrator
// or the Approver role (SRS Appendix C); Session Approver accounts cannot
// decide tool-call approvals.
//
// Every state change is evidence: approval events with outcome requested,
// approved, denied, expired and consumed are committed to the journal
// before the change takes effect.
package approval

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Appendix A defaults and bounds.
const (
	DefaultLifetime  = 5 * time.Minute  // CP-17
	MaxLifetime      = 5 * time.Minute  // CP-17
	DefaultKeepAlive = 10 * time.Second // CP-45
	// Retention is how long a decided, expired or consumed record is kept
	// after its expiry before it is pruned. The journal keeps the evidence.
	Retention = 24 * time.Hour
	// notifyTimeout bounds one desktop notification.
	notifyTimeout = 5 * time.Second
)

// Errors of Decide and the control API.
var (
	ErrNotFound    = errors.New("approval not found")
	ErrNotPending  = errors.New("approval is not pending")
	ErrAudit       = errors.New("evidence journal unavailable")
	ErrNotAttached = errors.New("approval service not started")
)

// Options configure a Service.
type Options struct {
	Config *config.Config
	Log    *slog.Logger
	// Notifier overrides the [approvals] notify selection (tests).
	Notifier Notifier
	// Now overrides the clock (tests).
	Now func() time.Time
	// JanitorInterval is how often expiry is applied (default 1s).
	JanitorInterval time.Duration
}

// Notice is one event of the watch stream.
type Notice struct {
	Type     string  `json:"type"` // requested, approved, denied, expired, consumed
	Approval Summary `json:"approval"`
}

type entry struct {
	r    Record
	done chan struct{} // closed when the record leaves pending
}

// Service is the Approval Service. It implements pipeline.Approver,
// adminapi.Approvals and adminapi.Authenticator.
type Service struct {
	cfg       *config.Config
	log       *slog.Logger
	now       func() time.Time
	lifetime  time.Duration
	keepAlive time.Duration
	janitor   time.Duration
	console   string
	notifier  Notifier
	guard     *authguard.Guard
	store     *store

	mu       sync.Mutex
	rec      audit.Recorder
	recs     map[string]*entry
	watchers map[chan Notice]struct{}
	// streams counts open watch streams of the control API (http.go).
	streams  atomic.Int32
	tokens   map[[32]byte]approverSession
	notifyWG sync.WaitGroup
}

// New builds the service and loads the records persisted in the state
// directory. Evidence and routes are attached by Start.
func New(o Options) (*Service, error) {
	if o.Config == nil {
		return nil, errors.New("approval: config required")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.JanitorInterval <= 0 {
		o.JanitorInterval = time.Second
	}
	ac := o.Config.Approvals
	s := &Service{cfg: o.Config, log: o.Log, now: o.Now, lifetime: ac.Lifetime.Duration, keepAlive: ac.KeepAlive.Duration,
		janitor: o.JanitorInterval, console: strings.TrimRight(ac.ConsoleURL, "/"), notifier: o.Notifier,
		guard: authguard.New(authguard.Config{}), recs: map[string]*entry{}, watchers: map[chan Notice]struct{}{}, tokens: map[[32]byte]approverSession{}}
	if s.lifetime == 0 {
		s.lifetime = DefaultLifetime
	}
	if s.lifetime < 0 || s.lifetime > MaxLifetime {
		return nil, fmt.Errorf("approvals.lifetime must be between 1s and %s (CP-17)", MaxLifetime)
	}
	if s.keepAlive == 0 {
		s.keepAlive = DefaultKeepAlive
	}
	if s.keepAlive < 0 {
		return nil, errors.New("approvals.keepalive must be positive (CP-45)")
	}
	if s.console == "" {
		s.console = o.Config.AdminURL()
	}
	if s.notifier == nil {
		n, err := NewNotifier(ac.Notify, ac.NotifyCommand)
		if err != nil {
			return nil, err
		}
		s.notifier = n
	}
	seen := map[string]bool{}
	for _, a := range ac.Accounts {
		if seen[a.Username] {
			return nil, fmt.Errorf("duplicate approvals account %q", a.Username)
		}
		seen[a.Username] = true
	}
	var err error
	if s.store, err = openStore(o.Config.State.Dir); err != nil {
		return nil, fmt.Errorf("approval store: %w", err)
	}
	recs, errs := s.store.load()
	for _, e := range errs {
		s.log.Warn("approval record skipped", "err", e)
	}
	for _, r := range recs {
		e := &entry{r: *r, done: make(chan struct{})}
		if r.State != StatePending {
			close(e.done)
		}
		s.recs[r.ID] = e
	}
	return s, nil
}

// Start attaches the evidence recorder, registers the control API routes
// (/api/v1/approvals*) and the harness status route (/smcp/v1/approvals/),
// and runs the expiry janitor until ctx ends. Calls that reach the service
// before Start are refused (fail closed).
func (s *Service) Start(ctx context.Context, rec audit.Recorder, admin *adminapi.Server, gw *edge.Gateway) {
	s.mu.Lock()
	s.rec = rec
	s.mu.Unlock()
	if admin != nil {
		s.Register(admin)
	}
	if gw != nil {
		gw.HandleSession("GET /smcp/v1/approvals/{id}", s.harnessStatus)
	}
	s.Expire()
	go s.run(ctx)
}

func (s *Service) run(ctx context.Context) {
	t := time.NewTicker(s.janitor)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Expire()
		}
	}
}

// Close waits for desktop notifications in progress.
func (s *Service) Close() { s.notifyWG.Wait() }

// URL is the console deep link of an approval (CP-45).
func (s *Service) URL(id string) string { return s.console + "/approvals/" + id }

// event builds an approval evidence event.
func event(r *Record, outcome, reason string, detail map[string]any) audit.Event {
	d := map[string]any{"approval_id": r.ID, "public_name": r.PublicName, "server": r.Server, "tool": r.Tool,
		"arguments_digest": r.ArgumentsDigest, "expires_at": r.ExpiresAt.UTC().Format(time.RFC3339)}
	for k, v := range detail {
		d[k] = v
	}
	ev := audit.Event{Class: "approval", Origin: "E-07", CorrelationID: r.CorrelationID, SessionID: r.SessionID, PrincipalID: r.PrincipalID,
		DecisionID: r.DecisionID, PolicyRevision: r.PolicyRevision, ServerRevision: r.ServerRevision, ToolRevision: r.ToolRevision,
		Outcome: outcome, ReasonCode: reason, PolicyStatus: "evaluated", Detail: d}
	channel.Origin{Channel: r.Channel, ClientID: r.ClientID, ClientAddress: r.ClientAddress}.Apply(&ev) // FR-16.8
	return ev
}

// broadcastLocked sends a notice to every watcher without blocking; a
// watcher whose buffer is full misses the notice.
func (s *Service) broadcastLocked(typ string, r *Record) {
	n := Notice{Type: typ, Approval: r.Summary()}
	for ch := range s.watchers {
		select {
		case ch <- n:
		default:
		}
	}
}

// Watch subscribes to notices. The returned cancel function unsubscribes.
func (s *Service) Watch() (<-chan Notice, func()) {
	ch := make(chan Notice, 64)
	s.mu.Lock()
	s.watchers[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.watchers, ch)
		s.mu.Unlock()
	}
}

// notifyDesktop sends the X-14 notification of a new approval. A failure
// is a diagnostic warning and never affects the approval.
func (s *Service) notifyDesktop(r Record) {
	if _, off := s.notifier.(Off); off {
		return
	}
	s.notifyWG.Add(1)
	go func() {
		defer s.notifyWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
		defer cancel()
		title, body := notificationText(&r)
		if err := s.notifier.Notify(ctx, title, body); err != nil {
			s.log.Warn("desktop notification failed; the approval is unaffected", "approval", r.ID, "err", err)
		}
	}()
}

// Request implements pipeline.Approver (FR-3.14, FR-3.15, FR-3.19 to
// FR-3.22).
func (s *Service) Request(ctx context.Context, req pipeline.ApprovalRequest) (pipeline.ApprovalResult, error) {
	canon, digest, err := Canonical(req.Arguments)
	if err != nil {
		return pipeline.ApprovalResult{}, err
	}
	b := bindingOf(req.Call, digest)
	s.mu.Lock()
	if s.rec == nil {
		s.mu.Unlock()
		return pipeline.ApprovalResult{}, ErrNotAttached
	}
	now := s.now()
	s.expireLocked(now)
	e := s.findLocked(b)
	if e != nil && e.r.State == StateApproved {
		res, err := s.consumeLocked(e, req.Call.CorrelationID, now)
		s.mu.Unlock()
		return res, err
	}
	if e == nil {
		id := ids.New()
		e = &entry{done: make(chan struct{}), r: Record{ID: id, State: StatePending, Binding: b, CreatedAt: now.UTC(), ExpiresAt: now.Add(s.lifetime).UTC(),
			URL: s.URL(id), Template: req.Call.Template, ManifestSource: req.Call.ManifestSource, CorrelationID: req.Call.CorrelationID,
			DecisionID: req.Call.DecisionID, DecisiveRules: append([]string{}, req.Call.DecisiveRules...), Arguments: canon,
			Anomaly: req.Call.Anomaly}}
		if org := channel.From(ctx); org.Channel == channel.Remote {
			e.r.Channel, e.r.ClientID, e.r.ClientAddress = org.Channel, org.ClientID, org.ClientAddress
		}
		if err := s.store.put(&e.r); err != nil {
			s.mu.Unlock()
			return pipeline.ApprovalResult{}, fmt.Errorf("approval store: %w", err)
		}
		if err := s.rec.Commit(event(&e.r, "requested", "APPROVAL_REQUESTED", map[string]any{"hold_seconds": req.Hold.Seconds()})); err != nil {
			_ = s.store.remove(e.r.ID)
			s.mu.Unlock()
			return pipeline.ApprovalResult{}, fmt.Errorf("%w: %w", ErrAudit, err)
		}
		s.recs[e.r.ID] = e
		s.broadcastLocked("requested", &e.r)
		s.notifyDesktop(e.r)
	}
	r := e.r
	s.mu.Unlock()
	return s.hold(ctx, e, r, req)
}

// findLocked returns the live record bound to b, preferring an approved
// one.
func (s *Service) findLocked(b Binding) *entry {
	var pending *entry
	for _, e := range s.recs {
		if e.r.Binding != b {
			continue
		}
		switch e.r.State {
		case StateApproved:
			return e
		case StatePending:
			if pending == nil || e.r.CreatedAt.Before(pending.r.CreatedAt) {
				pending = e
			}
		}
	}
	return pending
}

// consumeLocked marks an approved record consumed by the call with the
// given correlation ID. The record is burned in memory before it is
// persisted, so a store failure cannot make it reusable.
func (s *Service) consumeLocked(e *entry, corr string, now time.Time) (pipeline.ApprovalResult, error) {
	if e.r.State != StateApproved {
		return s.pendingResult(&e.r, ReasonConsumed), nil
	}
	if err := s.rec.Commit(event(&e.r, "consumed", "APPROVAL_CONSUMED", map[string]any{"consumed_correlation_id": corr, "approver": e.r.DecidedBy})); err != nil {
		return pipeline.ApprovalResult{}, fmt.Errorf("%w: %w", ErrAudit, err)
	}
	t := now.UTC()
	e.r.State, e.r.ConsumedAt, e.r.ConsumedCorrelation = StateConsumed, &t, corr
	s.broadcastLocked("consumed", &e.r)
	if err := s.store.put(&e.r); err != nil {
		s.log.Error("approval store write failed after consumption", "approval", e.r.ID, "err", err)
	}
	return pipeline.ApprovalResult{Outcome: pipeline.Approved, ApprovalID: e.r.ID, Approver: e.r.DecidedBy}, nil
}

// pendingResult is the -31002 answer for a record (FR-3.22, FR-1.51).
func (s *Service) pendingResult(r *Record, reason string) pipeline.ApprovalResult {
	text := "This call needs approval. Open " + r.URL + " to approve it, then run the same request again."
	switch reason {
	case ReasonExpired:
		text = "The approval for this call expired before it was used. Run the same request again to ask for a new approval."
	case ReasonConsumed:
		text = "The approval for this call was already used by an identical call. Run the same request again to ask for a new approval."
	}
	return pipeline.ApprovalResult{Outcome: pipeline.Pending, ApprovalID: r.ID, ReasonCode: reason, RetryText: text, ConsoleURL: r.URL, ExpiresAt: r.ExpiresAt}
}

// hold parks the call until a decision, the hold bound, the approval's
// expiry or the end of ctx (FR-3.19). It sends a keep-alive at once and
// then every keep-alive interval.
func (s *Service) hold(ctx context.Context, e *entry, r Record, req pipeline.ApprovalRequest) (pipeline.ApprovalResult, error) {
	bound := req.Hold
	if left := r.ExpiresAt.Sub(s.now()); bound > left {
		bound = left
	}
	if bound <= 0 {
		return s.pendingResult(&r, ReasonRequired), nil
	}
	progress := req.Progress
	if progress == nil {
		progress = func(string) {}
	}
	msg := "Waiting for a person to approve this call (approval " + r.ID + "). Open " + r.URL
	timer := time.NewTimer(bound)
	defer timer.Stop()
	tick := time.NewTicker(s.keepAlive)
	defer tick.Stop()
	progress(msg)
	for {
		select {
		case <-ctx.Done():
			return s.pendingResult(&r, ReasonRequired), nil
		case <-timer.C:
			s.mu.Lock()
			s.expireLocked(s.now())
			r = e.r
			s.mu.Unlock()
			if r.State == StateExpired {
				return s.pendingResult(&r, ReasonExpired), nil
			}
			if r.State != StatePending {
				return s.decided(ctx, e, req)
			}
			return s.pendingResult(&r, ReasonRequired), nil
		case <-tick.C:
			progress(msg)
		case <-e.done:
			return s.decided(ctx, e, req)
		}
	}
}

// decided answers a held call whose record has left pending.
func (s *Service) decided(_ context.Context, e *entry, req pipeline.ApprovalRequest) (pipeline.ApprovalResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)
	switch e.r.State {
	case StateApproved: // FR-3.20
		return s.consumeLocked(e, req.Call.CorrelationID, now)
	case StateDenied: // FR-3.21
		return pipeline.ApprovalResult{Outcome: pipeline.Denied, ApprovalID: e.r.ID, Approver: e.r.DecidedBy, ReasonCode: ReasonDenied}, nil
	case StateExpired:
		return s.pendingResult(&e.r, ReasonExpired), nil
	}
	return s.pendingResult(&e.r, ReasonConsumed), nil
}

// Decide records an approver's decision (FR-3.17). The evidence event is
// committed before the decision takes effect.
func (s *Service) Decide(_ context.Context, id string, approve bool, actor, comment string) error {
	_, err := s.decide(id, approve, actor, comment)
	return err
}

func (s *Service) decide(id string, approve bool, actor, comment string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rec == nil {
		return Record{}, ErrNotAttached
	}
	now := s.now()
	s.expireLocked(now)
	e := s.recs[id]
	if e == nil {
		return Record{}, ErrNotFound
	}
	if e.r.State != StatePending {
		return e.r, fmt.Errorf("%w (state %s)", ErrNotPending, e.r.State)
	}
	state, outcome, reason := StateDenied, "denied", ReasonDenied
	if approve {
		state, outcome, reason = StateApproved, "approved", "APPROVAL_GRANTED"
	}
	t := now.UTC()
	if err := s.rec.Commit(event(&e.r, outcome, reason, map[string]any{"approver": actor, "comment": comment, "decided_at": t.Format(time.RFC3339Nano)})); err != nil {
		return e.r, fmt.Errorf("%w: %w", ErrAudit, err)
	}
	e.r.State, e.r.DecidedBy, e.r.DecidedAt, e.r.Comment = state, actor, &t, comment
	close(e.done)
	s.broadcastLocked(outcome, &e.r)
	if err := s.store.put(&e.r); err != nil {
		s.log.Error("approval store write failed after decision", "approval", id, "err", err)
	}
	return e.r, nil
}

// Expire applies CP-17 expiry to every live record and prunes records
// past retention.
func (s *Service) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rec == nil {
		return
	}
	now := s.now()
	s.expireLocked(now)
	for id, e := range s.recs {
		if !e.r.live() && now.Sub(e.r.ExpiresAt) > Retention {
			delete(s.recs, id)
			if err := s.store.remove(id); err != nil {
				s.log.Warn("approval record not pruned", "approval", id, "err", err)
			}
		}
	}
}

// expireLocked marks live records past their expiry expired. When the
// evidence cannot be written the record still expires (the safe
// direction) and the failure is logged.
func (s *Service) expireLocked(now time.Time) {
	if s.rec == nil {
		return
	}
	for _, e := range s.recs {
		if !e.r.live() || now.Before(e.r.ExpiresAt) {
			continue
		}
		was := e.r.State
		if err := s.rec.Commit(event(&e.r, "expired", ReasonExpired, map[string]any{"previous_state": was})); err != nil {
			s.log.Error("evidence write failed for approval expiry", "approval", e.r.ID, "err", err)
		}
		e.r.State = StateExpired
		if was == StatePending {
			close(e.done)
		}
		s.broadcastLocked("expired", &e.r)
		if err := s.store.put(&e.r); err != nil {
			s.log.Error("approval store write failed after expiry", "approval", e.r.ID, "err", err)
		}
	}
}

// Get returns a record.
func (s *Service) Get(id string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(s.now())
	e := s.recs[id]
	if e == nil {
		return Record{}, false
	}
	return e.r, true
}

// List returns summaries, newest first. With state "" or "all" every
// record is listed; otherwise only records in that state.
func (s *Service) List(state string) []Summary {
	s.mu.Lock()
	s.expireLocked(s.now())
	out := []Summary{}
	for _, e := range s.recs {
		if state == "" || state == "all" || e.r.State == state {
			out = append(out, e.r.Summary())
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID > out[j].ID)
	})
	return out
}

// Pending implements adminapi.Approvals.
func (s *Service) Pending(context.Context) (any, error) { return s.List(StatePending), nil }
