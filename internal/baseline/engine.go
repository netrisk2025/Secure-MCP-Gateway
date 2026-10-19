package baseline

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Dimensions a baseline context can be grouped by (ArchitectureV2 §9.3).
var Dimensions = []string{"principal", "framework_type", "session_template", "end_user", "server", "server_revision", "tool", "hour", "weekday"}

// sequenceExcluded are the dimensions that a tool-transition table is not
// keyed by: a transition is a move between tools (and so between servers).
var sequenceExcluded = map[string]bool{"tool": true, "server": true, "server_revision": true}

// FeatureSpec selects one baselined feature (Observation Policy
// "Statistics", ArchitectureV2 §9.5).
type FeatureSpec struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"` // numeric or categorical
	Transform  Transform `json:"transform"`
	Robust     bool      `json:"robust,omitempty"`
	SigmaFloor float64   `json:"sigma_floor"`
}

// Config configures the engine.
type Config struct {
	Dimensions  []string      `json:"dimensions"`
	Features    []FeatureSpec `json:"features"`
	NMin        int64         `json:"n_min"`
	HalfLife    time.Duration `json:"half_life"`
	Window      time.Duration `json:"learning_window"` // 0: no window
	Compression float64       `json:"compression"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if len(c.Dimensions) == 0 {
		return errors.New("baseline: no context dimensions")
	}
	known := map[string]bool{}
	for _, d := range Dimensions {
		known[d] = true
	}
	seen := map[string]bool{}
	for _, d := range c.Dimensions {
		if !known[d] {
			return fmt.Errorf("baseline: unknown context dimension %q (one of %s)", d, strings.Join(Dimensions, ", "))
		}
		if seen[d] {
			return fmt.Errorf("baseline: duplicate dimension %q", d)
		}
		seen[d] = true
	}
	fs := map[string]bool{}
	for i := range c.Features {
		f := &c.Features[i]
		if f.Kind == "" {
			f.Kind = "numeric"
		}
		if f.Kind != "numeric" && f.Kind != "categorical" {
			return fmt.Errorf("baseline: feature %s kind %q (numeric or categorical)", f.Name, f.Kind)
		}
		if f.Transform.Kind == "" {
			f.Transform.Kind = "none"
		}
		if f.SigmaFloor < 0 || math.IsNaN(f.SigmaFloor) {
			return fmt.Errorf("baseline: feature %s sigma_floor must be ≥ 0", f.Name)
		}
		if fs[f.Name] {
			return fmt.Errorf("baseline: duplicate feature %s", f.Name)
		}
		fs[f.Name] = true
	}
	if c.NMin <= 0 {
		c.NMin = 30 // CP-30
	}
	return nil
}

// ScoreName is the name under which a feature's statistics are kept: the
// feature itself for numeric features, "<name>:surprise" for categorical
// ones (their −ln p is what is baselined, FR-10.16).
func (f FeatureSpec) ScoreName() string {
	if f.Kind == "categorical" {
		return f.Name + ":surprise"
	}
	return f.Name
}

// Sample is one observation record as the engine sees it.
type Sample struct {
	Time        time.Time
	Session     string
	Dims        map[string]string // dimension -> value
	Numeric     map[string]float64
	Categorical map[string]string
	Tool        string // for transitions
	PrevTool    string // previous tool in the session ("" for the first call)
}

// Exclusion reasons (FR-10.17).
const (
	ExcludedDenied   = "denied"
	ExcludedBand     = "band"
	ExcludedFlagged  = "flagged_session"
	ExcludedWindow   = "outside_window"
	ExcludedNoValues = "no_features"
)

// LearnInfo carries the per-record facts that decide exclusion.
type LearnInfo struct {
	Denied bool
	Band   string
}

// featureState is the live state of one feature in one context.
type featureState struct {
	W      Welford
	Digest *TDigest         // robust features only
	Counts map[string]int64 // categorical features only
	Total  int64            // categorical observations
}

type contextState struct {
	dims     map[string]string
	count    int64
	features map[string]*featureState
	first    time.Time
	last     time.Time
}

type sequenceState struct {
	counts map[string]map[string]int64 // prev -> next -> count
	totals map[string]int64
}

// Engine maintains candidate statistics. It is safe for concurrent use.
type Engine struct {
	cfg Config
	now func() time.Time

	saveMu sync.Mutex // serializes SaveState writes

	mu       sync.Mutex
	contexts map[string]*contextState
	seq      map[string]*sequenceState
	flagged  map[string]time.Time
	learned  int64
	excluded map[string]int64
	from, to time.Time
}

// NewEngine returns an engine with a validated configuration.
func NewEngine(cfg Config, now func() time.Time) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Engine{cfg: cfg, now: now, contexts: map[string]*contextState{}, seq: map[string]*sequenceState{},
		flagged: map[string]time.Time{}, excluded: map[string]int64{}}, nil
}

// Config returns the engine configuration.
func (e *Engine) Config() Config { return e.cfg }

// ContextKey renders the context key of the selected dimensions, for
// example "principal=p1|tool=read". Values are escaped so that the key is
// unambiguous.
func ContextKey(dims []string, values map[string]string) string {
	parts := make([]string, len(dims))
	for i, d := range dims {
		parts[i] = d + "=" + keyEscaper.Replace(values[d])
	}
	return strings.Join(parts, "|")
}

// keyEscaper escapes context key values. It is built once: building a
// Replacer for every value, several times per call, was a tenth of the
// Observation Collector's time per call (FR-11.4).
var keyEscaper = strings.NewReplacer(`\`, `\\`, "|", `\|`, "=", `\=`)

// ContextKey returns the context key of a sample.
func (e *Engine) ContextKey(s Sample) string { return ContextKey(e.cfg.Dimensions, s.Dims) }

// SequenceKey returns the key of a sample's transition table: the context
// dimensions without tool and server.
func (e *Engine) SequenceKey(s Sample) string {
	var dims []string
	for _, d := range e.cfg.Dimensions {
		if !sequenceExcluded[d] {
			dims = append(dims, d)
		}
	}
	if len(dims) == 0 {
		return "*"
	}
	return ContextKey(dims, s.Dims)
}

// Flag excludes a session from learning (operator or Runtime Monitor flag).
func (e *Engine) Flag(session string) {
	e.mu.Lock()
	e.flagged[session] = e.now()
	e.mu.Unlock()
}

// Unflag removes a session flag.
func (e *Engine) Unflag(session string) {
	e.mu.Lock()
	delete(e.flagged, session)
	e.mu.Unlock()
}

// Flagged lists flagged sessions.
func (e *Engine) Flagged() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.flagged))
	for s := range e.flagged {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func surprise(c, total int64, distinct int) float64 {
	return -math.Log(float64(c+1) / float64(total+int64(distinct)+1))
}

// TransitionSurprise returns −ln p(tool | previous tool) from the current
// candidate frequencies of the sample's sequence context (P-061), with
// add-one smoothing: p = (c(prev→tool) + 1) / (c(prev) + V(prev) + 1),
// where V(prev) is the number of distinct tools seen after prev. ok is
// false for the first call of a session.
func (e *Engine) TransitionSurprise(s Sample) (float64, bool) {
	if s.PrevTool == "" || s.Tool == "" {
		return 0, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.seq[e.SequenceKey(s)]
	if st == nil {
		return surprise(0, 0, 0), true
	}
	next := st.counts[s.PrevTool]
	return surprise(next[s.Tool], st.totals[s.PrevTool], len(next)), true
}

// CategorySurprise returns −ln p of a category value in a context, with
// add-one smoothing as for transitions.
func (e *Engine) CategorySurprise(key, feature, value string) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.categorySurpriseLocked(key, feature, value)
}

func (e *Engine) categorySurpriseLocked(key, feature, value string) float64 {
	cs := e.contexts[key]
	if cs == nil || cs.features[feature] == nil {
		return surprise(0, 0, 0)
	}
	fs := cs.features[feature]
	return surprise(fs.Counts[value], fs.Total, len(fs.Counts))
}

// Learn updates the candidate statistics from one record unless it is
// excluded (FR-10.17). It returns whether the record was learned and, if
// not, the reason.
func (e *Engine) Learn(s Sample, info LearnInfo) (bool, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	reason := ""
	switch {
	case info.Denied:
		reason = ExcludedDenied
	case info.Band == "abnormal" || info.Band == "critical":
		reason = ExcludedBand
	case s.Session != "" && !e.flagged[s.Session].IsZero():
		reason = ExcludedFlagged
	case e.cfg.Window > 0 && s.Time.Before(e.now().Add(-e.cfg.Window)):
		reason = ExcludedWindow
	}
	if reason != "" {
		e.excluded[reason]++
		return false, reason
	}
	key := e.ContextKey(s)
	cs := e.contexts[key]
	if cs == nil {
		dims := map[string]string{}
		for _, d := range e.cfg.Dimensions {
			dims[d] = s.Dims[d]
		}
		cs = &contextState{dims: dims, features: map[string]*featureState{}, first: s.Time}
		e.contexts[key] = cs
	}
	learnedAny := false
	for _, f := range e.cfg.Features {
		switch f.Kind {
		case "numeric":
			x, ok := s.Numeric[f.Name]
			if !ok {
				continue
			}
			y, ok := f.Transform.Apply(x)
			if !ok {
				continue
			}
			fs := cs.feature(f.Name)
			fs.W.Add(y, s.Time, e.cfg.HalfLife)
			if f.Robust {
				if fs.Digest == nil {
					fs.Digest = NewTDigest(e.cfg.Compression)
				}
				fs.Digest.Add(y)
			}
			learnedAny = true
		case "categorical":
			v, ok := s.Categorical[f.Name]
			if !ok {
				continue
			}
			sv := e.categorySurpriseLocked(key, f.Name, v)
			fc := cs.feature(f.Name)
			if fc.Counts == nil {
				fc.Counts = map[string]int64{}
			}
			fc.Counts[v]++
			fc.Total++
			fsur := cs.feature(f.ScoreName())
			fsur.W.Add(sv, s.Time, e.cfg.HalfLife)
			if f.Robust {
				if fsur.Digest == nil {
					fsur.Digest = NewTDigest(e.cfg.Compression)
				}
				fsur.Digest.Add(sv)
			}
			learnedAny = true
		}
	}
	if s.PrevTool != "" && s.Tool != "" {
		sk := e.SequenceKey(s)
		st := e.seq[sk]
		if st == nil {
			st = &sequenceState{counts: map[string]map[string]int64{}, totals: map[string]int64{}}
			e.seq[sk] = st
		}
		if st.counts[s.PrevTool] == nil {
			st.counts[s.PrevTool] = map[string]int64{}
		}
		st.counts[s.PrevTool][s.Tool]++
		st.totals[s.PrevTool]++
		learnedAny = true
	}
	if !learnedAny {
		e.excluded[ExcludedNoValues]++
		return false, ExcludedNoValues
	}
	cs.count++
	if s.Time.After(cs.last) {
		cs.last = s.Time
	}
	e.learned++
	if e.from.IsZero() || s.Time.Before(e.from) {
		e.from = s.Time
	}
	if s.Time.After(e.to) {
		e.to = s.Time
	}
	return true, ""
}

func (cs *contextState) feature(name string) *featureState {
	fs := cs.features[name]
	if fs == nil {
		fs = &featureState{}
		cs.features[name] = fs
	}
	return fs
}

// Status summarizes the candidate statistics.
type Status struct {
	Contexts        int              `json:"contexts"`
	Characterized   int              `json:"characterized"`
	Learned         int64            `json:"learned"`
	Excluded        map[string]int64 `json:"excluded"`
	FlaggedSessions int              `json:"flagged_sessions"`
}

// Status reports counters.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Contexts: len(e.contexts), Learned: e.learned, Excluded: map[string]int64{}, FlaggedSessions: len(e.flagged)}
	for k, v := range e.excluded {
		st.Excluded[k] = v
	}
	for _, c := range e.contexts {
		if c.count >= e.cfg.NMin {
			st.Characterized++
		}
	}
	return st
}

// Learned is the number of records learned so far.
func (e *Engine) Learned() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.learned
}
