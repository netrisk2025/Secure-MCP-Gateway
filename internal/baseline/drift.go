package baseline

import (
	"math"
	"sort"
)

// FeatureDrift is one feature's change between snapshots.
type FeatureDrift struct {
	Feature string `json:"feature"`
	// MeanShift is (μ_candidate − μ_promoted) / max(σ_promoted, σ_floor).
	MeanShift float64 `json:"mean_shift_sigma"`
	// SigmaRatio is max(σ_candidate, σ_floor) / max(σ_promoted, σ_floor)
	// (1 when both are 0).
	SigmaRatio float64 `json:"sigma_ratio"`
}

// ContextDrift is one context's change.
type ContextDrift struct {
	Context  string         `json:"context"`
	Features []FeatureDrift `json:"features"`
}

// DriftReport compares a candidate with the promoted snapshot (FR-10.19).
type DriftReport struct {
	Candidate   string         `json:"candidate"`
	Promoted    string         `json:"promoted,omitempty"`
	Contexts    []ContextDrift `json:"contexts"`
	NewContexts []string       `json:"new_contexts"`
	// MaxAbsShift and MaxSigmaFactor summarize the report:
	// MaxSigmaFactor is the largest of r and 1/r over every σ ratio r.
	MaxAbsShift    float64 `json:"max_abs_mean_shift_sigma"`
	MaxSigmaFactor float64 `json:"max_sigma_factor"`
}

// Drift reports the per-context mean shift in promoted-σ units, the σ ratio
// and the newly characterized contexts of cand against prom (nil prom: every
// characterized context is new). Only contexts characterized in both
// snapshots are compared.
func Drift(cand, prom *Snapshot) DriftReport {
	r := DriftReport{Candidate: cand.ID, Contexts: []ContextDrift{}, NewContexts: []string{}, MaxSigmaFactor: 1}
	floors := map[string]float64{}
	for _, f := range cand.Config.Features {
		floors[f.ScoreName()] = f.SigmaFloor
	}
	if prom != nil {
		r.Promoted = prom.ID
	}
	keys := make([]string, 0, len(cand.Contexts))
	for k := range cand.Contexts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !cand.Characterized(k) {
			continue
		}
		if prom == nil || !prom.Characterized(k) {
			r.NewContexts = append(r.NewContexts, k)
			continue
		}
		cc, pc := cand.Contexts[k], prom.Contexts[k]
		cd := ContextDrift{Context: k}
		names := make([]string, 0, len(cc.Features))
		for n := range cc.Features {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			pf, ok := pc.Features[n]
			if !ok {
				continue
			}
			cf := cc.Features[n]
			den := math.Max(pf.Std, floors[n])
			num := math.Max(cf.Std, floors[n])
			ratio := 1.0
			if den == 0 {
				den = 1e-12
				if num > 0 {
					ratio = num / den
				}
			} else {
				ratio = num / den
			}
			fd := FeatureDrift{Feature: n, MeanShift: (cf.Mean - pf.Mean) / den, SigmaRatio: ratio}
			cd.Features = append(cd.Features, fd)
			r.MaxAbsShift = math.Max(r.MaxAbsShift, math.Abs(fd.MeanShift))
			factor := fd.SigmaRatio
			if factor > 0 && factor < 1 {
				factor = 1 / factor
			}
			if factor == 0 {
				factor = math.MaxFloat64 // σ collapsed to 0; JSON has no infinity
			}
			r.MaxSigmaFactor = math.Max(r.MaxSigmaFactor, factor)
		}
		r.Contexts = append(r.Contexts, cd)
	}
	return r
}

// AutoLimits are the automatic-promotion limits; zero values disable
// automatic promotion.
type AutoLimits struct {
	MaxMeanShift   float64 `json:"max_mean_shift_sigma"`
	MaxSigmaFactor float64 `json:"max_sigma_factor"`
}

// Within reports whether every drift value is within the limits.
func (l AutoLimits) Within(r DriftReport) bool {
	if l.MaxMeanShift <= 0 || l.MaxSigmaFactor < 1 {
		return false
	}
	return r.MaxAbsShift <= l.MaxMeanShift && r.MaxSigmaFactor <= l.MaxSigmaFactor
}
