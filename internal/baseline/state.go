package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The candidate statistics are kept across restarts in a state file. It is
// not evidence and not a snapshot; a lost or unreadable state file only
// restarts learning.

type featureJSON struct {
	W      Welford          `json:"welford"`
	Digest *TDigest         `json:"digest,omitempty"`
	Counts map[string]int64 `json:"counts,omitempty"`
	Total  int64            `json:"total,omitempty"`
}

type contextJSON struct {
	Dims     map[string]string       `json:"dims"`
	Count    int64                   `json:"count"`
	Features map[string]*featureJSON `json:"features"`
	First    time.Time               `json:"first"`
	Last     time.Time               `json:"last"`
}

type stateJSON struct {
	Version  int                                    `json:"version"`
	Config   Config                                 `json:"config"`
	Contexts map[string]*contextJSON                `json:"contexts"`
	Seq      map[string]map[string]map[string]int64 `json:"transitions"`
	Flagged  map[string]time.Time                   `json:"flagged"`
	Learned  int64                                  `json:"learned"`
	Excluded map[string]int64                       `json:"excluded"`
	From     time.Time                              `json:"from"`
	To       time.Time                              `json:"to"`
}

// SaveState writes the candidate statistics to path (0600, atomic).
func (e *Engine) SaveState(path string) error {
	// Saves run from the build goroutine, the interval loop and Close.
	// They are serialized (the state taken last is written last) and each
	// writes its own temporary file, so a rename never moves another
	// save's partly written file into place.
	e.saveMu.Lock()
	defer e.saveMu.Unlock()
	e.mu.Lock()
	st := stateJSON{Version: 1, Config: e.cfg, Contexts: map[string]*contextJSON{}, Seq: map[string]map[string]map[string]int64{},
		Flagged: map[string]time.Time{}, Learned: e.learned, Excluded: copyCounts(e.excluded), From: e.from, To: e.to}
	for k, c := range e.contexts {
		cj := &contextJSON{Dims: copyMap(c.dims), Count: c.count, Features: map[string]*featureJSON{}, First: c.first, Last: c.last}
		for n, f := range c.features {
			fj := &featureJSON{W: f.W, Total: f.Total}
			if f.Digest != nil {
				fj.Digest = f.Digest.Clone()
			}
			if f.Counts != nil {
				fj.Counts = copyCounts(f.Counts)
			}
			cj.Features[n] = fj
		}
		st.Contexts[k] = cj
	}
	for k, s := range e.seq {
		m := map[string]map[string]int64{}
		for p, n := range s.counts {
			m[p] = copyCounts(n)
		}
		st.Seq[k] = m
	}
	for s, t := range e.flagged {
		st.Flagged[s] = t
	}
	e.mu.Unlock()
	raw, err := json.Marshal(&st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(raw)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// LoadState restores candidate statistics saved by SaveState. A state file
// written with different dimensions or features is ignored (returns
// ErrStateMismatch), because its statistics describe other contexts.
func (e *Engine) LoadState(path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st stateJSON
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("baseline state %s: %w", path, err)
	}
	a, _ := json.Marshal(struct {
		D []string
		F []FeatureSpec
	}{st.Config.Dimensions, st.Config.Features})
	b, _ := json.Marshal(struct {
		D []string
		F []FeatureSpec
	}{e.cfg.Dimensions, e.cfg.Features})
	if string(a) != string(b) {
		return ErrStateMismatch
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.contexts = map[string]*contextState{}
	for k, cj := range st.Contexts {
		c := &contextState{dims: cj.Dims, count: cj.Count, features: map[string]*featureState{}, first: cj.First, last: cj.Last}
		for n, fj := range cj.Features {
			c.features[n] = &featureState{W: fj.W, Digest: fj.Digest, Counts: fj.Counts, Total: fj.Total}
		}
		e.contexts[k] = c
	}
	e.seq = map[string]*sequenceState{}
	for k, m := range st.Seq {
		s := &sequenceState{counts: m, totals: map[string]int64{}}
		for p, n := range m {
			for _, c := range n {
				s.totals[p] += c
			}
		}
		e.seq[k] = s
	}
	if st.Flagged != nil {
		e.flagged = st.Flagged
	}
	e.learned, e.from, e.to = st.Learned, st.From, st.To
	if st.Excluded != nil {
		e.excluded = st.Excluded
	}
	return nil
}

// ErrStateMismatch reports a state file of another configuration.
var ErrStateMismatch = errors.New("baseline state was written with other dimensions or features; learning restarts")
