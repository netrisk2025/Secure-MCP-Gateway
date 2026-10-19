// Package anomaly is the Anomaly Scorer (E-31): it holds the promoted
// baseline snapshot in memory, scores feature values by their distance from
// the baseline in standard deviations, combines the scores by maximum |z|
// and classifies the result into a sigma band (ArchitectureV2 §9.2,
// FR-10.22 to FR-10.29).
package anomaly

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"sync/atomic"

	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
)

// Bands, in increasing severity.
const (
	Uncharacterized = "uncharacterized"
	Normal          = "normal"
	Elevated        = "elevated"
	Abnormal        = "abnormal"
	Critical        = "critical"
)

// Rank orders bands: uncharacterized and normal 0, elevated 1, abnormal 2,
// critical 3; unknown -1.
func Rank(band string) int {
	switch band {
	case Uncharacterized, Normal:
		return 0
	case Elevated:
		return 1
	case Abnormal:
		return 2
	case Critical:
		return 3
	}
	return -1
}

// Thresholds are the lower |z| bounds of elevated, abnormal and critical
// (CP-30: 2, 3, 4).
type Thresholds struct {
	Elevated float64 `json:"elevated"`
	Abnormal float64 `json:"abnormal"`
	Critical float64 `json:"critical"`
}

// DefaultThresholds are the CP-30 bands.
var DefaultThresholds = Thresholds{Elevated: 2, Abnormal: 3, Critical: 4}

// Validate checks 0 < elevated < abnormal < critical.
func (t Thresholds) Validate() error {
	if !(t.Elevated > 0 && t.Elevated < t.Abnormal && t.Abnormal < t.Critical) {
		return fmt.Errorf("anomaly thresholds must satisfy 0 < elevated < abnormal < critical (got %v, %v, %v)", t.Elevated, t.Abnormal, t.Critical)
	}
	return nil
}

// Classify maps a combined score to a band (FR-10.26).
func (t Thresholds) Classify(z float64) string {
	a := math.Abs(z)
	switch {
	case a >= t.Critical:
		return Critical
	case a >= t.Abnormal:
		return Abnormal
	case a >= t.Elevated:
		return Elevated
	}
	return Normal
}

// FeatureScore is one feature's score.
type FeatureScore struct {
	Feature     string  `json:"feature"`
	Value       float64 `json:"value"`
	Transformed float64 `json:"transformed"`
	Z           float64 `json:"z"`
	Robust      bool    `json:"robust,omitempty"`
}

// Result is the scoring record of FR-10.29 (without the resulting actions,
// which the caller adds).
type Result struct {
	SnapshotID  string         `json:"snapshot_id,omitempty"`
	Context     string         `json:"context"`
	Features    []FeatureScore `json:"features"`
	Combined    float64        `json:"combined"`
	Contributor string         `json:"contributing_feature,omitempty"`
	Band        string         `json:"band"`
	Actions     []string       `json:"actions,omitempty"`
}

// Input is what a call contributes to scoring.
type Input struct {
	Context     string
	Numeric     map[string]float64
	Categorical map[string]string
	// Surprise values computed by the caller for categorical features, by
	// score name ("<feature>:surprise"); when absent they are computed from
	// the snapshot's category counts.
	Surprise map[string]float64
}

type loaded struct {
	snap *baseline.Snapshot
	spec map[string]baseline.FeatureSpec
}

// Scorer scores against the loaded snapshot. Load replaces it atomically;
// concurrent scores use either the old or the new snapshot, never a mix.
type Scorer struct {
	cur        atomic.Pointer[loaded]
	thresholds atomic.Pointer[Thresholds]
}

// New returns a scorer without a snapshot (every context uncharacterized).
func New(t Thresholds) (*Scorer, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	s := &Scorer{}
	s.thresholds.Store(&t)
	return s, nil
}

// ErrNoSnapshot is returned by Load(nil).
var ErrNoSnapshot = errors.New("no snapshot")

// Load verifies the snapshot digest and replaces the loaded snapshot
// (FR-10.22, SR-7-1). A snapshot that does not verify is refused and the
// previous one stays loaded.
func (s *Scorer) Load(snap *baseline.Snapshot) error {
	if snap == nil {
		return ErrNoSnapshot
	}
	if err := snap.Verify(); err != nil {
		return err
	}
	l := &loaded{snap: snap, spec: map[string]baseline.FeatureSpec{}}
	for _, f := range snap.Config.Features {
		l.spec[f.Name] = f
	}
	s.cur.Store(l)
	return nil
}

// SnapshotID returns the loaded snapshot ID ("" when none).
func (s *Scorer) SnapshotID() string {
	if l := s.cur.Load(); l != nil {
		return l.snap.ID
	}
	return ""
}

// Snapshot returns the loaded snapshot (nil when none). Callers must not
// modify it.
func (s *Scorer) Snapshot() *baseline.Snapshot {
	if l := s.cur.Load(); l != nil {
		return l.snap
	}
	return nil
}

// SetThresholds replaces the band thresholds; scores computed after the
// call use them (a published Observation Policy applies without a
// restart).
func (s *Scorer) SetThresholds(t Thresholds) error {
	if err := t.Validate(); err != nil {
		return err
	}
	s.thresholds.Store(&t)
	return nil
}

// Thresholds returns the band thresholds.
func (s *Scorer) Thresholds() Thresholds { return *s.thresholds.Load() }

// Z is the standard score of FR-10.23: (x − μ) / max(σ, σ_floor). A zero
// denominator gives 0 for x = μ and ±MaxFloat64 otherwise.
func Z(x, mean, std, floor float64) float64 {
	return safeDiv(x-mean, math.Max(std, floor))
}

// RobustZ is the score of FR-10.24: 0.6745 (x − median) / max(MAD, σ_floor).
func RobustZ(x, median, mad, floor float64) float64 {
	return safeDiv(0.6745*(x-median), math.Max(mad, floor))
}

func safeDiv(num, den float64) float64 {
	if den > 0 {
		return num / den
	}
	switch {
	case num > 0:
		return math.MaxFloat64
	case num < 0:
		return -math.MaxFloat64
	}
	return 0
}

// Score scores one call. The context is uncharacterized, and no feature
// scores are computed, when it has fewer than n_min samples in the loaded
// snapshot or when no snapshot is loaded (FR-10.27).
func (s *Scorer) Score(in Input) Result {
	r := Result{Context: in.Context, Band: Uncharacterized, Features: []FeatureScore{}}
	l := s.cur.Load()
	if l == nil {
		return r
	}
	r.SnapshotID = l.snap.ID
	cs, ok := l.snap.Contexts[in.Context]
	if !ok || cs.Count < l.snap.Config.NMin {
		return r
	}
	for _, f := range l.snap.Config.Features {
		var x float64
		switch f.Kind {
		case "categorical":
			v, ok := in.Categorical[f.Name]
			if !ok {
				continue
			}
			if sv, ok := in.Surprise[f.ScoreName()]; ok {
				x = sv
			} else {
				x = categorySurprise(cs.Categories[f.Name], v)
			}
		default:
			v, ok := in.Numeric[f.Name]
			if !ok {
				continue
			}
			x = v
		}
		st, ok := cs.Features[f.ScoreName()]
		if !ok || st.N == 0 {
			continue
		}
		tf := f.Transform
		if f.Kind == "categorical" {
			tf = baseline.Transform{Kind: "none"}
		}
		y, ok := tf.Apply(x)
		if !ok {
			continue
		}
		fs := FeatureScore{Feature: f.ScoreName(), Value: x, Transformed: y, Robust: f.Robust}
		if f.Robust {
			fs.Z = RobustZ(y, st.Median, st.MAD, f.SigmaFloor)
		} else {
			fs.Z = Z(y, st.Mean, st.Std, f.SigmaFloor)
		}
		r.Features = append(r.Features, fs)
	}
	// FR-10.25: maximum |z|; ties go to the feature named first.
	sort.SliceStable(r.Features, func(i, j int) bool { return r.Features[i].Feature < r.Features[j].Feature })
	for _, fs := range r.Features {
		if math.Abs(fs.Z) > math.Abs(r.Combined) || r.Contributor == "" {
			r.Combined, r.Contributor = fs.Z, fs.Feature
		}
	}
	r.Band = s.Thresholds().Classify(r.Combined)
	return r
}

func categorySurprise(counts map[string]int64, v string) float64 {
	var total int64
	for _, c := range counts {
		total += c
	}
	return -math.Log(float64(counts[v]+1) / float64(total+int64(len(counts))+1))
}
