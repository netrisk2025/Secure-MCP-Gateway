package graph

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// Defaults of the [graph] table.
const (
	DefaultURI               = "bolt://127.0.0.1:7687"
	DefaultUsername          = "smcp_graph"
	DefaultPasswordFile      = "graph/password" // relative to the state directory
	DefaultDatabase          = "neo4j"
	DefaultRetention         = 30 * 24 * time.Hour
	DefaultRetentionInterval = 24 * time.Hour
	DefaultCatchUpInterval   = 60 * time.Second
	DefaultMemoryInterval    = 5 * time.Second // FR-9.11
	DefaultBatchSize         = 500
	DefaultQueue             = 4096
	// BatchWindow bounds how long a live event waits for its batch.
	BatchWindow = 200 * time.Millisecond
	// ProbeInterval is how often a connected mirror checks that the
	// database still answers, so that an unreachable database is reported
	// to the Health & Safety Monitor (which evaluates once per second)
	// within 2 seconds even without traffic (FR-7.11).
	ProbeInterval = 500 * time.Millisecond
	// probeTimeout bounds one reachability probe.
	probeTimeout = time.Second
	// opTimeout bounds one database operation of the worker.
	opTimeout   = 30 * time.Second
	maxBackoff  = 60 * time.Second
	retainBatch = 1000
)

// Settings is the resolved [graph] configuration.
type Settings struct {
	Enabled           bool
	URI               string
	Username          string
	PasswordFile      string
	Database          string
	Retention         time.Duration
	RetentionInterval time.Duration
	CatchUpInterval   time.Duration
	MemoryInterval    time.Duration
	BatchSize         int
	Queue             int
	Budget            Budget
	RequireHardening  bool
}

// Resolve applies the defaults to the [graph] table and checks the rules
// the schema cannot express.
func Resolve(cfg *config.Config) (Settings, error) {
	g := cfg.Graph
	s := Settings{Enabled: g.Enabled, URI: g.URI, Username: g.Username, PasswordFile: g.PasswordFile, Database: g.Database,
		Retention: g.Retention.Duration, RetentionInterval: g.RetentionInterval.Duration, CatchUpInterval: g.CatchUpInterval.Duration,
		MemoryInterval: g.MemoryInterval.Duration, BatchSize: g.BatchSize, Queue: g.Queue,
		Budget: Budget{HeapBytes: g.HeapBytes, PageCacheBytes: g.PageCacheBytes}, RequireHardening: g.RequireHardening}
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	defd := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	def(&s.URI, DefaultURI)
	def(&s.Username, DefaultUsername)
	def(&s.PasswordFile, DefaultPasswordFile)
	def(&s.Database, DefaultDatabase)
	defd(&s.Retention, DefaultRetention)
	defd(&s.RetentionInterval, DefaultRetentionInterval)
	defd(&s.CatchUpInterval, DefaultCatchUpInterval)
	defd(&s.MemoryInterval, DefaultMemoryInterval)
	if s.BatchSize == 0 {
		s.BatchSize = DefaultBatchSize
	}
	if s.Queue == 0 {
		s.Queue = DefaultQueue
	}
	if s.Budget.HeapBytes == 0 {
		s.Budget.HeapBytes = DefaultHeapBytes
	}
	if s.Budget.PageCacheBytes == 0 {
		s.Budget.PageCacheBytes = DefaultPageCacheBytes
	}
	if !filepath.IsAbs(s.PasswordFile) {
		s.PasswordFile = filepath.Join(cfg.State.Dir, s.PasswordFile)
	}
	if s.RetentionInterval > 24*time.Hour {
		return s, errors.New("graph.retention_interval must be at most 24h (retention runs at least once per day)")
	}
	if s.Retention < time.Hour {
		return s, errors.New("graph.retention must be at least 1h")
	}
	for name, d := range map[string]time.Duration{"retention_interval": s.RetentionInterval, "catchup_interval": s.CatchUpInterval, "memory_interval": s.MemoryInterval} {
		if d < 100*time.Millisecond {
			return s, fmt.Errorf("graph.%s must be at least 100ms", name)
		}
	}
	return s, nil
}

// States of the mirror.
const (
	StateDisabled    = "disabled"
	StateConnecting  = "connecting"
	StateReady       = "ready"
	StateUnavailable = "unavailable"
	StateRefused     = "refused"
)

// Memory is the graph engine memory report (E-28).
type Memory struct {
	Budget              Budget `json:"budget"`
	HeapUsed            int64  `json:"heap_used"`
	HeapMax             int64  `json:"heap_max"`
	PageCacheConfigured int64  `json:"page_cache_configured"`
	Pressure            bool   `json:"pressure"`
	SampledAt           string `json:"sampled_at,omitempty"`
}

// Status is the mirror's state as reported by smcpctl graph status.
type Status struct {
	Enabled                bool             `json:"enabled"`
	State                  string           `json:"state"`
	Error                  string           `json:"error,omitempty"`
	URI                    string           `json:"uri"`
	Database               string           `json:"database"`
	SchemaVersion          int              `json:"schema_version"`
	SupportedSchemaVersion int              `json:"supported_schema_version"`
	TemplateSetVersion     string           `json:"template_set_version"`
	TemplateDigest         string           `json:"template_digest"`
	Checkpoint             Checkpoint       `json:"checkpoint"`
	LiveApplied            uint64           `json:"live_applied"`
	LiveDropped            uint64           `json:"live_dropped"`
	CatchUps               uint64           `json:"catch_ups"`
	LastCatchUp            string           `json:"last_catch_up,omitempty"`
	LastRetention          string           `json:"last_retention,omitempty"`
	RetentionDeleted       map[string]int64 `json:"retention_deleted,omitempty"`
	LastRebuild            string           `json:"last_rebuild,omitempty"`
	RebuildError           string           `json:"rebuild_error,omitempty"`
	Hardening              []Finding        `json:"hardening"`
	Memory                 Memory           `json:"memory"`
	Counts                 map[string]int64 `json:"counts,omitempty"`
	Schema                 []SchemaObject   `json:"schema,omitempty"`
}

// Options configure a Mirror.
type Options struct {
	Config *config.Config
	Log    *slog.Logger
	// Backend overrides the Neo4j connection built from the configuration
	// (tests). With a Backend the mirror is enabled regardless of
	// [graph] enabled.
	Backend Backend
	// Catalog overrides the embedded catalog (tests).
	Catalog *Catalog
	// JournalDir defaults to <state>/journal.
	JournalDir string
	Now        func() time.Time
}

type reqKind int

const (
	reqSync reqKind = iota
	reqRebuild
	reqRetain
)

type request struct {
	kind reqKind
	done chan error
}

// Mirror is the evidence graph mirror: an audit.Observer that projects
// journal events into the graph through the Data Access Service,
// idempotently by event ID, and catches up from the journal after any gap.
// It never blocks or fails the caller of Observe.
type Mirror struct {
	set     Settings
	log     *slog.Logger
	now     func() time.Time
	journal string
	cat     *Catalog
	backend Backend
	owned   bool // backend was opened here and is closed by Close
	open    func() (Backend, error)

	live    chan audit.Event
	reqs    chan request
	dropped atomic.Uint64
	applied atomic.Uint64

	mu      sync.Mutex
	st      Status
	das     *DAS // non-nil while ready
	rec     audit.Recorder
	pending bool // a rebuild is queued

	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// New validates the configuration and builds the mirror. It does not
// connect: Start does, in the background.
func New(o Options) (*Mirror, error) {
	if o.Config == nil {
		return nil, errors.New("graph: config required")
	}
	set, err := Resolve(o.Config)
	if err != nil {
		return nil, err
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Catalog == nil {
		o.Catalog = DefaultCatalog()
	}
	if o.JournalDir == "" {
		o.JournalDir = filepath.Join(o.Config.State.Dir, "journal")
	}
	if o.Backend != nil {
		set.Enabled = true
	}
	m := &Mirror{set: set, log: o.Log, now: o.Now, journal: o.JournalDir, cat: o.Catalog, backend: o.Backend,
		live: make(chan audit.Event, set.Queue), reqs: make(chan request, 4), done: make(chan struct{})}
	m.open = func() (Backend, error) {
		pw, err := readPassword(set.PasswordFile)
		if err != nil {
			return nil, err
		}
		return NewNeo4j(set.URI, set.Username, pw, set.Database)
	}
	m.st = Status{Enabled: set.Enabled, State: StateDisabled, URI: set.URI, Database: set.Database, SupportedSchemaVersion: o.Catalog.SchemaVersion(),
		TemplateSetVersion: TemplateSetVersion, TemplateDigest: o.Catalog.Digest(), Hardening: []Finding{}, Memory: Memory{Budget: set.Budget}}
	if set.Enabled {
		m.st.State = StateConnecting
	}
	return m, nil
}

func readPassword(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("graph password file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("graph password file %s must not be readable by group or others (mode %v)", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("graph password file: %w", err)
	}
	pw := strings.TrimRight(string(raw), "\r\n")
	if pw == "" {
		return "", errors.New("graph password file is empty")
	}
	return pw, nil
}

// Enabled reports whether the mirror runs.
func (m *Mirror) Enabled() bool { return m.set.Enabled }

// Observe implements audit.Observer. It only queues the event; when the
// queue is full the event is counted as dropped and the next catch-up
// recovers it from the journal.
func (m *Mirror) Observe(ev audit.Event) {
	if !m.set.Enabled {
		return
	}
	select {
	case m.live <- ev:
	default:
		m.dropped.Add(1)
	}
}

// Start runs the worker until Close. rec records control actions (rebuild)
// as evidence; it may be nil in tests.
func (m *Mirror) Start(ctx context.Context, rec audit.Recorder) {
	m.mu.Lock()
	m.rec = rec
	m.mu.Unlock()
	if !m.set.Enabled {
		close(m.done)
		return
	}
	ctx, m.cancel = context.WithCancel(ctx)
	go m.run(ctx)
}

// Close stops the worker and closes the connection.
func (m *Mirror) Close() {
	m.once.Do(func() {
		if m.cancel != nil {
			m.cancel()
		}
		<-m.done
		if m.backend != nil && m.owned {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = m.backend.Close(ctx)
			cancel()
		}
	})
}

func (m *Mirror) setState(state string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st.State = state
	m.st.Error = ""
	if err != nil {
		m.st.Error = err.Error()
	}
	if state != StateReady {
		m.das = nil
	}
}

func (m *Mirror) ready() *DAS {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.das
}

func (m *Mirror) run(ctx context.Context) {
	defer close(m.done)
	backoff := time.Second
	retryAt := time.Time{}
	needCatch, retainDue := true, true
	catchTick := time.NewTicker(m.set.CatchUpInterval)
	retainTick := time.NewTicker(m.set.RetentionInterval)
	memTick := time.NewTicker(m.set.MemoryInterval)
	probeTick := time.NewTicker(ProbeInterval)
	defer probeTick.Stop()
	defer catchTick.Stop()
	defer retainTick.Stop()
	defer memTick.Stop()
	var refused bool
	for {
		das := m.ready()
		if das == nil && !refused && !time.Now().Before(retryAt) {
			var err error
			if das, err = m.connect(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				if errors.Is(err, ErrSchemaTooNew) || errors.Is(err, ErrHardening) {
					refused = true
					m.setState(StateRefused, err)
					m.log.Error("graph mirror refused to start", "err", err)
				} else {
					m.setState(StateUnavailable, err)
					m.log.Warn("graph database unavailable; enforcement continues without the mirror", "err", err, "retry_in", backoff)
				}
				retryAt = time.Now().Add(backoff)
				backoff = min(2*backoff, maxBackoff)
			} else {
				backoff = time.Second
				needCatch = true
				m.log.Info("graph mirror connected", "uri", m.set.URI)
			}
		}
		if das != nil && needCatch {
			if err := m.catchUp(ctx, das); err != nil {
				m.fail(ctx, err)
				das = nil
			} else {
				needCatch = false
				if retainDue {
					retainDue = false
					_ = m.retain(ctx, das) // logged and reported in status
				}
				m.sampleMemory(ctx, das)
			}
		}
		var wait <-chan time.Time
		if das == nil && !refused {
			wait = time.After(time.Until(retryAt))
		}
		select {
		case <-ctx.Done():
			return
		case ev := <-m.live:
			batch := m.collect(ctx, ev)
			if das == nil || needCatch {
				needCatch = true // the journal has these events
				continue
			}
			if err := m.applyEvents(ctx, das, batch); err != nil {
				m.fail(ctx, err)
				needCatch = true
				continue
			}
			m.applied.Add(uint64(len(batch)))
		case <-catchTick.C:
			needCatch = true
		case <-retainTick.C:
			if das != nil {
				_ = m.retain(ctx, das) // logged and reported in status
			} else {
				retainDue = true
			}
		case <-memTick.C:
			if das != nil {
				m.sampleMemory(ctx, das)
			}
		case <-probeTick.C:
			if das != nil {
				pctx, cancel := context.WithTimeout(ctx, probeTimeout)
				err := das.Ping(pctx)
				cancel()
				if err != nil {
					m.fail(ctx, fmt.Errorf("%w: reachability probe: %w", ErrUnavailable, err))
					needCatch = true
				}
			}
		case r := <-m.reqs:
			r.done <- m.handle(ctx, das, r)
			if r.kind == reqRebuild {
				m.mu.Lock()
				m.pending = false
				m.mu.Unlock()
			}
		case <-wait:
		}
	}
}

func (m *Mirror) fail(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	m.setState(StateUnavailable, err)
	m.log.Warn("graph mirror write failed; will catch up from the journal", "err", err)
}

func (m *Mirror) handle(ctx context.Context, das *DAS, r request) error {
	if das == nil {
		return ErrUnavailable
	}
	switch r.kind {
	case reqSync:
		if err := m.catchUp(ctx, das); err != nil {
			m.fail(ctx, err)
			return err
		}
	case reqRebuild:
		err := m.rebuild(ctx, das)
		m.mu.Lock()
		m.st.LastRebuild = m.now().UTC().Format(time.RFC3339)
		m.st.RebuildError = ""
		if err != nil {
			m.st.RebuildError = err.Error()
		}
		m.mu.Unlock()
		if err != nil {
			m.fail(ctx, err)
		}
		return err
	case reqRetain:
		return m.retain(ctx, das)
	}
	return nil
}

func (m *Mirror) connect(ctx context.Context) (*DAS, error) {
	// A reconnection after a failure stays "unavailable" until it
	// succeeds, so the health cause does not lapse while retrying.
	m.mu.Lock()
	retrying := m.st.State == StateUnavailable
	m.mu.Unlock()
	if !retrying {
		m.setState(StateConnecting, nil)
	}
	if m.backend == nil {
		b, err := m.open()
		if err != nil {
			return nil, err
		}
		m.backend, m.owned = b, true
	}
	das := NewDAS(m.backend, m.cat, m.now)
	octx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	if err := das.Ping(octx); err != nil {
		return nil, err
	}
	settings, err := das.Settings(octx, checkedSettings)
	if err != nil {
		return nil, fmt.Errorf("read engine settings: %w", err)
	}
	findings := CheckSettings(settings, m.set.Budget)
	pc, _ := ParseSize(settings["server.memory.pagecache.size"])
	m.mu.Lock()
	m.st.Hardening = append([]Finding{}, findings...)
	m.st.Memory.PageCacheConfigured = pc
	m.mu.Unlock()
	for _, f := range findings {
		m.log.Warn("graph engine setting", "setting", f.Setting, "value", f.Value, "want", f.Want, "reason", f.Reason)
	}
	if len(findings) > 0 && m.set.RequireHardening {
		return nil, fmt.Errorf("%w: %d findings (see smcpctl graph status)", ErrHardening, len(findings))
	}
	from, to, err := das.Migrate(octx)
	m.mu.Lock()
	m.st.SchemaVersion = to
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if to != from {
		m.log.Info("graph schema migrated", "from", from, "to", to)
	}
	m.mu.Lock()
	m.das = das
	m.st.State = StateReady
	m.st.Error = ""
	m.mu.Unlock()
	return das, nil
}

// collect gathers more live events for one batch, up to BatchSize or
// BatchWindow after the first.
func (m *Mirror) collect(ctx context.Context, first audit.Event) []audit.Event {
	batch := []audit.Event{first}
	timer := time.NewTimer(BatchWindow)
	defer timer.Stop()
	for len(batch) < m.set.BatchSize {
		select {
		case ev := <-m.live:
			batch = append(batch, ev)
		case <-timer.C:
			return batch
		case <-ctx.Done():
			return batch
		}
	}
	return batch
}

func (m *Mirror) cutoff() int64 { return m.now().Add(-m.set.Retention).UnixNano() }

func (m *Mirror) applyEvents(ctx context.Context, das *DAS, evs []audit.Event) error {
	p := &projection{}
	cut := m.cutoff()
	for _, ev := range evs {
		if ts := eventTS(ev); ts != 0 && ts < cut {
			continue // already past retention; a rebuild must not resurrect it
		}
		p.add(ev)
	}
	octx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return das.apply(octx, p)
}

// catchUp applies every journal segment from the checkpoint on. Sealed
// segments advance the checkpoint; the open segment is applied again on
// the next catch-up, which is harmless because writes are idempotent.
func (m *Mirror) catchUp(ctx context.Context, das *DAS) error {
	octx, cancel := context.WithTimeout(ctx, opTimeout)
	cp, err := das.GetCheckpoint(octx)
	cancel()
	if err != nil {
		return err
	}
	segs, err := audit.Segments(m.journal)
	if errors.Is(err, os.ErrNotExist) {
		segs, err = nil, nil
	}
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	for _, s := range segs {
		if s.Seq < cp.Segment {
			continue
		}
		var batch []audit.Event
		var n int64
		var applyErr error
		sealed, err := audit.ScanSegment(m.journal, s, func(ev audit.Event) error {
			n++
			batch = append(batch, ev)
			if len(batch) >= m.set.BatchSize {
				applyErr = m.applyEvents(ctx, das, batch)
				batch = batch[:0]
			}
			return applyErr
		})
		if err != nil {
			return err
		}
		if len(batch) > 0 {
			if err := m.applyEvents(ctx, das, batch); err != nil {
				return err
			}
		}
		if sealed {
			cp.Segment, cp.Events = s.Seq+1, cp.Events+n
			octx, cancel := context.WithTimeout(ctx, opTimeout)
			err := das.SetCheckpoint(octx, cp)
			cancel()
			if err != nil {
				return err
			}
		}
	}
	m.mu.Lock()
	m.st.Checkpoint = cp
	m.st.CatchUps++
	m.st.LastCatchUp = m.now().UTC().Format(time.RFC3339)
	m.mu.Unlock()
	return nil
}

func (m *Mirror) rebuild(ctx context.Context, das *DAS) error {
	octx, cancel := context.WithTimeout(ctx, 10*opTimeout)
	n, err := das.Wipe(octx)
	cancel()
	if err != nil {
		return fmt.Errorf("wipe: %w", err)
	}
	m.log.Info("graph mirror wiped for rebuild", "nodes", n)
	return m.catchUp(ctx, das)
}

func (m *Mirror) retain(ctx context.Context, das *DAS) error {
	octx, cancel := context.WithTimeout(ctx, 10*opTimeout)
	defer cancel()
	deleted, err := das.Retain(octx, m.now().Add(-m.set.Retention), retainBatch)
	m.mu.Lock()
	m.st.LastRetention = m.now().UTC().Format(time.RFC3339)
	m.st.RetentionDeleted = deleted
	m.mu.Unlock()
	if err != nil {
		m.log.Warn("graph retention failed", "err", err)
	}
	return err
}

func (m *Mirror) sampleMemory(ctx context.Context, das *DAS) {
	octx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	h, err := das.HeapUse(octx)
	if err != nil {
		m.log.Debug("graph heap sample failed", "err", err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	was := m.st.Memory.Pressure
	m.st.Memory.HeapUsed, m.st.Memory.HeapMax = h.Used, h.Max
	m.st.Memory.SampledAt = m.now().UTC().Format(time.RFC3339)
	m.st.Memory.Pressure = m.set.Budget.HeapBytes > 0 && h.Used*10 > m.set.Budget.HeapBytes*9
	if m.st.Memory.Pressure && !was {
		m.log.Warn("graph engine heap above 90% of its budget", "used", h.Used, "budget", m.set.Budget.HeapBytes)
	}
}

func (m *Mirror) submit(ctx context.Context, kind reqKind) error {
	if !m.set.Enabled {
		return ErrDisabled
	}
	r := request{kind: kind, done: make(chan error, 1)}
	select {
	case m.reqs <- r:
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return ErrUnavailable
	}
	select {
	case err := <-r.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return ErrUnavailable
	}
}

// Sync catches up from the journal now and waits for it.
func (m *Mirror) Sync(ctx context.Context) error { return m.submit(ctx, reqSync) }

// Rebuild wipes the mirror and rebuilds it from the journal, and waits.
func (m *Mirror) Rebuild(ctx context.Context) error { return m.submit(ctx, reqRebuild) }

// RunRetention applies retention now and waits.
func (m *Mirror) RunRetention(ctx context.Context) error { return m.submit(ctx, reqRetain) }

// RequestRebuild queues a rebuild without waiting. It fails when the mirror
// is not ready or a rebuild is already queued.
func (m *Mirror) RequestRebuild() error {
	if !m.set.Enabled {
		return ErrDisabled
	}
	if m.ready() == nil {
		return ErrUnavailable
	}
	m.mu.Lock()
	if m.pending {
		m.mu.Unlock()
		return ErrRebuildRunning
	}
	m.pending = true
	m.mu.Unlock()
	r := request{kind: reqRebuild, done: make(chan error, 1)}
	select {
	case m.reqs <- r:
		return nil
	default:
		m.mu.Lock()
		m.pending = false
		m.mu.Unlock()
		return ErrRebuildRunning
	}
}

// DAS returns the Data Access Service while the mirror is ready.
func (m *Mirror) DAS() (*DAS, error) {
	if !m.set.Enabled {
		return nil, ErrDisabled
	}
	if d := m.ready(); d != nil {
		return d, nil
	}
	return nil, ErrUnavailable
}

// Status returns the mirror state. With detail it also reads node counts
// and the deployed schema (bounded by ctx).
func (m *Mirror) Status(ctx context.Context, detail bool) Status {
	m.mu.Lock()
	st := m.st
	st.Hardening = append([]Finding{}, m.st.Hardening...)
	das := m.das
	m.mu.Unlock()
	st.LiveApplied, st.LiveDropped = m.applied.Load(), m.dropped.Load()
	if detail && das != nil {
		octx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if c, err := das.Counts(octx); err == nil {
			st.Counts = c
		}
		if s, err := das.SchemaObjects(octx); err == nil {
			st.Schema = s
		}
	}
	return st
}

func (m *Mirror) recorder() audit.Recorder {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rec
}
