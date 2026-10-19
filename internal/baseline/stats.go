// Package baseline is the Behavior Baseline Engine (E-30): streaming
// per-context statistics of observation features (Welford with optional
// exponential decay, t-digest for robust median and MAD, category and
// tool-transition frequencies), immutable digest-sealed snapshots, drift
// reports, promotion and rollback (ArchitectureV2 §9.2 to §9.4,
// FR-10.12 to FR-10.21).
package baseline

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Welford holds count, mean and M2 for one feature in one context using
// Welford's online algorithm. With a half-life, every earlier observation's
// weight decays by 0.5^(Δt/halfLife) before the next one is added (West's
// weighted form); W is then the effective weight. Without decay W equals N
// and Variance is the sample variance M2/(N-1).
type Welford struct {
	N    int64     `json:"n"`
	W    float64   `json:"w"`
	Mean float64   `json:"mean"`
	M2   float64   `json:"m2"`
	Last time.Time `json:"last"`
}

// Add folds x observed at t into the statistics.
func (s *Welford) Add(x float64, t time.Time, halfLife time.Duration) {
	if halfLife > 0 && s.N > 0 && t.After(s.Last) {
		f := math.Exp2(-float64(t.Sub(s.Last)) / float64(halfLife))
		s.W *= f
		s.M2 *= f
	}
	s.N++
	s.W++
	d := x - s.Mean
	s.Mean += d / s.W
	s.M2 += d * (x - s.Mean)
	if t.After(s.Last) {
		s.Last = t
	}
}

// Variance is M2/(W-1), the sample variance when there is no decay; 0
// until the effective weight exceeds 1.
func (s Welford) Variance() float64 {
	if s.W <= 1 {
		return 0
	}
	v := s.M2 / (s.W - 1)
	if v < 0 {
		return 0
	}
	return v
}

// Std is the square root of Variance.
func (s Welford) Std() float64 { return math.Sqrt(s.Variance()) }

// Transform is a per-feature transform applied before learning and scoring
// (FR-10.14).
type Transform struct {
	Kind   string  `json:"kind"` // none, log1p, box-cox
	Lambda float64 `json:"lambda,omitempty"`
}

// ParseTransform parses "none", "log1p" or "box-cox(λ)".
func ParseTransform(s string) (Transform, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "none":
		return Transform{Kind: "none"}, nil
	case s == "log1p":
		return Transform{Kind: "log1p"}, nil
	case strings.HasPrefix(s, "box-cox(") && strings.HasSuffix(s, ")"):
		l, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimPrefix(s, "box-cox("), ")"), 64)
		if err != nil || math.IsNaN(l) || math.IsInf(l, 0) || math.Abs(l) > 5 {
			return Transform{}, fmt.Errorf("box-cox lambda in %q must be a number in [-5, 5]", s)
		}
		return Transform{Kind: "box-cox", Lambda: l}, nil
	}
	return Transform{}, fmt.Errorf("unknown transform %q (none, log1p, box-cox(λ))", s)
}

// String renders the transform in ParseTransform form.
func (t Transform) String() string {
	if t.Kind == "box-cox" {
		return "box-cox(" + strconv.FormatFloat(t.Lambda, 'g', -1, 64) + ")"
	}
	if t.Kind == "" {
		return "none"
	}
	return t.Kind
}

// Apply transforms x. ok is false when x is outside the transform's domain
// (log1p needs x > -1, box-cox needs x > 0); such a value is neither
// learned nor scored for that feature.
func (t Transform) Apply(x float64) (float64, bool) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return 0, false
	}
	switch t.Kind {
	case "log1p":
		if x <= -1 {
			return 0, false
		}
		return math.Log1p(x), true
	case "box-cox":
		if x <= 0 {
			return 0, false
		}
		if t.Lambda == 0 {
			return math.Log(x), true
		}
		return (math.Pow(x, t.Lambda) - 1) / t.Lambda, true
	}
	return x, true
}

// Centroid is one t-digest centroid.
type Centroid struct {
	Mean   float64 `json:"m"`
	Weight float64 `json:"w"`
}

// TDigest is a merging t-digest (Dunning) with the k1 scale function. It
// estimates quantiles with error that is smallest at the tails.
type TDigest struct {
	Compression float64    `json:"compression"`
	Centroids   []Centroid `json:"centroids"`
	Total       float64    `json:"total"`
	Min         float64    `json:"min"`
	Max         float64    `json:"max"`
	buf         []Centroid
}

// NewTDigest returns an empty digest; compression 0 selects 200.
func NewTDigest(compression float64) *TDigest {
	if compression <= 0 {
		compression = 200
	}
	return &TDigest{Compression: compression, Min: math.Inf(1), Max: math.Inf(-1)}
}

// Add records one value.
func (d *TDigest) Add(x float64) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return
	}
	d.buf = append(d.buf, Centroid{x, 1})
	if x < d.Min {
		d.Min = x
	}
	if x > d.Max {
		d.Max = x
	}
	if len(d.buf) >= int(5*d.Compression) {
		d.compress()
	}
}

func (d *TDigest) k(q float64) float64 {
	return d.Compression / (2 * math.Pi) * math.Asin(2*q-1)
}

func (d *TDigest) compress() {
	if len(d.buf) == 0 {
		return
	}
	all := append(d.Centroids, d.buf...)
	d.buf = nil
	sort.Slice(all, func(i, j int) bool { return all[i].Mean < all[j].Mean })
	total := 0.0
	for _, c := range all {
		total += c.Weight
	}
	out := make([]Centroid, 0, int(d.Compression))
	cur := all[0]
	before := 0.0
	kLeft := d.k(0)
	for _, c := range all[1:] {
		q := (before + cur.Weight + c.Weight) / total
		if d.k(q)-kLeft <= 1 {
			w := cur.Weight + c.Weight
			cur.Mean += (c.Mean - cur.Mean) * c.Weight / w
			cur.Weight = w
			continue
		}
		before += cur.Weight
		kLeft = d.k(before / total)
		out = append(out, cur)
		cur = c
	}
	out = append(out, cur)
	d.Centroids, d.Total = out, total
}

// Quantile estimates the q-quantile (0 ≤ q ≤ 1).
func (d *TDigest) Quantile(q float64) float64 {
	d.compress()
	cs := d.Centroids
	if len(cs) == 0 {
		return math.NaN()
	}
	if len(cs) == 1 || q <= 0 {
		if q >= 1 {
			return d.Max
		}
		if len(cs) == 1 && q > 0 {
			return cs[0].Mean
		}
		return d.Min
	}
	if q >= 1 {
		return d.Max
	}
	target := q * d.Total
	// Centroid i covers weight centered at cum_i + w_i/2.
	cum := 0.0
	for i, c := range cs {
		mid := cum + c.Weight/2
		if target < mid {
			if i == 0 {
				// Between the minimum and the first centroid's center.
				return interp(target, 0, mid, d.Min, c.Mean)
			}
			p := cs[i-1]
			pmid := cum - p.Weight/2
			return interp(target, pmid, mid, p.Mean, c.Mean)
		}
		cum += c.Weight
	}
	last := cs[len(cs)-1]
	return interp(target, d.Total-last.Weight/2, d.Total, last.Mean, d.Max)
}

// CDF estimates P(X ≤ x).
func (d *TDigest) CDF(x float64) float64 {
	d.compress()
	cs := d.Centroids
	if len(cs) == 0 {
		return math.NaN()
	}
	if x < d.Min {
		return 0
	}
	if x >= d.Max {
		return 1
	}
	cum := 0.0
	prevMean, prevMid := d.Min, 0.0
	for _, c := range cs {
		mid := cum + c.Weight/2
		if x < c.Mean {
			return interp(x, prevMean, c.Mean, prevMid, mid) / d.Total
		}
		prevMean, prevMid = c.Mean, mid
		cum += c.Weight
	}
	return interp(x, prevMean, d.Max, prevMid, d.Total) / d.Total
}

func interp(x, x0, x1, y0, y1 float64) float64 {
	if x1 == x0 {
		return (y0 + y1) / 2
	}
	return y0 + (x-x0)/(x1-x0)*(y1-y0)
}

// MedianMAD derives the median and the median absolute deviation from the
// digest: MAD is the d for which CDF(m+d) − CDF(m−d) = 1/2, found by
// bisection.
func (d *TDigest) MedianMAD() (median, mad float64) {
	d.compress()
	if d.Total == 0 {
		return math.NaN(), math.NaN()
	}
	m := d.Quantile(0.5)
	lo, hi := 0.0, math.Max(d.Max-m, m-d.Min)
	if hi <= 0 {
		return m, 0
	}
	for i := 0; i < 100 && hi-lo > 1e-12*math.Max(1, hi); i++ {
		mid := (lo + hi) / 2
		if d.CDF(m+mid)-d.CDF(m-mid) < 0.5 {
			lo = mid
		} else {
			hi = mid
		}
	}
	return m, (lo + hi) / 2
}

// Clone returns an independent copy.
func (d *TDigest) Clone() *TDigest {
	d.compress()
	c := *d
	c.Centroids = append([]Centroid(nil), d.Centroids...)
	c.buf = nil
	return &c
}

// ErrDigest reports a snapshot whose digest does not match its content.
var ErrDigest = errors.New("baseline snapshot digest mismatch")
