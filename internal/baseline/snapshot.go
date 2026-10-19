package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// FeatureStats are the frozen statistics of one feature in one context.
type FeatureStats struct {
	N         int64   `json:"n"`
	Weight    float64 `json:"weight"`
	Mean      float64 `json:"mean"`
	Variance  float64 `json:"variance"`
	Std       float64 `json:"std"`
	Median    float64 `json:"median,omitempty"`
	MAD       float64 `json:"mad,omitempty"`
	Robust    bool    `json:"robust,omitempty"`
	Transform string  `json:"transform"`
}

// ContextStats are the frozen statistics of one baseline context.
type ContextStats struct {
	Dims       map[string]string           `json:"dims"`
	Count      int64                       `json:"count"`
	Features   map[string]FeatureStats     `json:"features"`
	Categories map[string]map[string]int64 `json:"categories,omitempty"`
	First      time.Time                   `json:"first"`
	Last       time.Time                   `json:"last"`
}

// Window is the learning window a snapshot covers.
type Window struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Snapshot is an immutable, digest-sealed baseline (D-10, FR-10.18).
type Snapshot struct {
	ID        string                  `json:"id"`
	Digest    string                  `json:"digest"`
	CreatedAt time.Time               `json:"created_at"`
	Trigger   string                  `json:"trigger"` // interval, records or operator
	Window    Window                  `json:"window"`
	Config    Config                  `json:"config"`
	Records   int64                   `json:"records"`
	Contexts  map[string]ContextStats `json:"contexts"`
	// Transitions are tool-transition counts per sequence context:
	// key -> previous tool -> next tool -> count.
	Transitions map[string]map[string]map[string]int64 `json:"transitions,omitempty"`
}

// ComputeDigest returns "sha256:<hex>" over the canonical JSON of the
// snapshot with an empty Digest field.
func (s *Snapshot) ComputeDigest() (string, error) {
	c := *s
	c.Digest = ""
	raw, err := json.Marshal(&c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Verify checks the stored digest against the content (SR-7-1).
func (s *Snapshot) Verify() error {
	d, err := s.ComputeDigest()
	if err != nil {
		return err
	}
	if s.Digest == "" || d != s.Digest {
		return fmt.Errorf("%w: snapshot %s stores %q, content gives %q", ErrDigest, s.ID, s.Digest, d)
	}
	return nil
}

// Characterized reports whether a context has at least n_min samples.
func (s *Snapshot) Characterized(key string) bool {
	c, ok := s.Contexts[key]
	return ok && c.Count >= s.Config.NMin
}

// Build freezes the candidate statistics into a new sealed snapshot.
func (e *Engine) Build(trigger string) (*Snapshot, error) {
	e.mu.Lock()
	s := &Snapshot{ID: ids.New(), CreatedAt: e.now().UTC(), Trigger: trigger, Window: Window{From: e.from.UTC(), To: e.to.UTC()},
		Config: e.cfg, Records: e.learned, Contexts: make(map[string]ContextStats, len(e.contexts))}
	robust := map[string]bool{}
	for _, f := range e.cfg.Features {
		robust[f.ScoreName()] = f.Robust
	}
	transform := map[string]string{}
	for _, f := range e.cfg.Features {
		transform[f.Name] = f.Transform.String()
		if f.Kind == "categorical" {
			transform[f.ScoreName()] = "none"
		}
	}
	type pending struct {
		key, name string
		d         *TDigest
	}
	var digests []pending
	for key, c := range e.contexts {
		cs := ContextStats{Dims: copyMap(c.dims), Count: c.count, Features: map[string]FeatureStats{}, First: c.first.UTC(), Last: c.last.UTC()}
		for name, f := range c.features {
			if f.Counts != nil {
				if cs.Categories == nil {
					cs.Categories = map[string]map[string]int64{}
				}
				cs.Categories[name] = copyCounts(f.Counts)
				continue
			}
			cs.Features[name] = FeatureStats{N: f.W.N, Weight: f.W.W, Mean: f.W.Mean, Variance: f.W.Variance(), Std: f.W.Std(),
				Robust: robust[name], Transform: transform[name]}
			if robust[name] && f.Digest != nil {
				digests = append(digests, pending{key, name, f.Digest.Clone()})
			}
		}
		s.Contexts[key] = cs
	}
	if len(e.seq) > 0 {
		s.Transitions = map[string]map[string]map[string]int64{}
		for key, st := range e.seq {
			m := map[string]map[string]int64{}
			for prev, next := range st.counts {
				m[prev] = copyCounts(next)
			}
			s.Transitions[key] = m
		}
	}
	e.mu.Unlock()
	// Median and MAD come from cloned digests, outside the lock.
	for _, p := range digests {
		fs := s.Contexts[p.key].Features[p.name]
		fs.Median, fs.MAD = p.d.MedianMAD()
		if math.IsNaN(fs.Median) {
			fs.Median, fs.MAD = 0, 0
		}
		s.Contexts[p.key].Features[p.name] = fs
	}
	var err error
	if s.Digest, err = s.ComputeDigest(); err != nil {
		return nil, err
	}
	return s, nil
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyCounts(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SnapshotStore keeps sealed snapshots as read-only files and the promotion
// history next to them.
type SnapshotStore struct{ dir string }

// Promotion is one entry of the promotion history.
type Promotion struct {
	ID   string    `json:"id"`
	At   time.Time `json:"at"`
	By   string    `json:"by"`
	Mode string    `json:"mode"` // operator, automatic or rollback
}

type promotionFile struct {
	Promoted string      `json:"promoted"`
	History  []Promotion `json:"history"`
}

// ErrNotFound reports an unknown snapshot ID.
var ErrNotFound = errors.New("baseline snapshot not found")

var snapID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// OpenSnapshotStore opens (and creates) the snapshot directory.
func OpenSnapshotStore(dir string) (*SnapshotStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &SnapshotStore{dir: dir}, nil
}

func (st *SnapshotStore) path(id string) (string, error) {
	if !snapID.MatchString(id) {
		return "", fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	return filepath.Join(st.dir, id+".json"), nil
}

// Save writes a sealed snapshot. An existing snapshot is never replaced.
func (st *SnapshotStore) Save(s *Snapshot) error {
	if err := s.Verify(); err != nil {
		return err
	}
	p, err := st.path(s.ID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return fmt.Errorf("snapshot %s: %w", s.ID, err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Load reads a snapshot and verifies its digest.
func (st *SnapshotStore) Load(id string) (*Snapshot, error) {
	p, err := st.path(id)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%w: snapshot %s unreadable: %w", ErrDigest, id, err)
	}
	if s.ID != id {
		return nil, fmt.Errorf("%w: file %s holds snapshot %s", ErrDigest, id, s.ID)
	}
	if err := s.Verify(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Summary describes a stored snapshot without its statistics.
type Summary struct {
	ID            string    `json:"id"`
	Digest        string    `json:"digest"`
	CreatedAt     time.Time `json:"created_at"`
	Trigger       string    `json:"trigger"`
	Window        Window    `json:"window"`
	Records       int64     `json:"records"`
	Contexts      int       `json:"contexts"`
	Characterized int       `json:"characterized"`
	Promoted      bool      `json:"promoted"`
	Error         string    `json:"error,omitempty"`
}

// Summarize builds a summary.
func (s *Snapshot) Summarize() Summary {
	sum := Summary{ID: s.ID, Digest: s.Digest, CreatedAt: s.CreatedAt, Trigger: s.Trigger, Window: s.Window, Records: s.Records, Contexts: len(s.Contexts)}
	for k := range s.Contexts {
		if s.Characterized(k) {
			sum.Characterized++
		}
	}
	return sum
}

// List returns summaries of every stored snapshot, newest first. A
// snapshot that fails verification is listed with its error.
func (st *SnapshotStore) List() ([]Summary, error) {
	m, err := filepath.Glob(filepath.Join(st.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	prom, _ := st.Promoted()
	var out []Summary
	for _, p := range m {
		id := filepath.Base(p[:len(p)-len(".json")])
		if !snapID.MatchString(id) {
			continue
		}
		s, err := st.Load(id)
		if err != nil {
			out = append(out, Summary{ID: id, Error: err.Error()})
			continue
		}
		sum := s.Summarize()
		sum.Promoted = id == prom
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID }) // UUIDv7: time ordered
	return out, nil
}

func (st *SnapshotStore) readPromotion() (promotionFile, error) {
	var pf promotionFile
	raw, err := os.ReadFile(filepath.Join(st.dir, "promotion.json"))
	if errors.Is(err, os.ErrNotExist) {
		return pf, nil
	}
	if err != nil {
		return pf, err
	}
	return pf, json.Unmarshal(raw, &pf)
}

// Promoted returns the promoted snapshot ID ("" when none).
func (st *SnapshotStore) Promoted() (string, error) {
	pf, err := st.readPromotion()
	return pf.Promoted, err
}

// History returns the promotion history, oldest first.
func (st *SnapshotStore) History() ([]Promotion, error) {
	pf, err := st.readPromotion()
	return pf.History, err
}

// SetPromoted records a promotion atomically.
func (st *SnapshotStore) SetPromoted(p Promotion) error {
	pf, err := st.readPromotion()
	if err != nil {
		return err
	}
	pf.Promoted = p.ID
	pf.History = append(pf.History, p)
	raw, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(st.dir, "promotion.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(st.dir, "promotion.json"))
}
