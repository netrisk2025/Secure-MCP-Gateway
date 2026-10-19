package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"time"
)

// Fixture is one recorded or scripted call that a simulation replays
// (FR-3.5). It is the canonical request plus the time of the call, which
// drives the rate windows during replay. Fixtures come from the evidence
// journal (`requested` call events) or from a JSON Lines scenario file with
// one fixture object per line.
type Fixture struct {
	Time          time.Time `json:"time,omitzero"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	PrincipalID   string    `json:"principal"`
	SessionID     string    `json:"session"`
	Profile       string    `json:"profile,omitempty"`
	Template      string    `json:"template"`
	Server        string    `json:"server"`
	Tool          string    `json:"tool"`
	SideEffect    string    `json:"side_effect,omitempty"`
	SourceTrust   string    `json:"source_trust,omitempty"`
}

// MaxFixtures bounds one simulation.
const MaxFixtures = 10000

// ParseFixtures reads a JSON Lines scenario. Blank lines and lines starting
// with '#' are skipped; unknown fields are an error so that a typo cannot
// silently change a fixture.
func ParseFixtures(r io.Reader) ([]Fixture, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []Fixture
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 || b[0] == '#' {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var f Fixture
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("scenario line %d: %w", line, err)
		}
		if f.Template == "" || f.Server == "" || f.Tool == "" {
			return nil, fmt.Errorf("scenario line %d: template, server and tool are required", line)
		}
		if f.PrincipalID == "" {
			f.PrincipalID = "simulated"
		}
		if f.SessionID == "" {
			f.SessionID = "simulated"
		}
		out = append(out, f)
		if len(out) > MaxFixtures {
			return nil, fmt.Errorf("scenario has more than %d fixtures", MaxFixtures)
		}
	}
	return out, sc.Err()
}

// SimOutcome is the decision one side of the simulation made.
type SimOutcome struct {
	Outcome        string   `json:"outcome"`
	ReasonCode     string   `json:"reason_code"`
	DecisiveRules  []string `json:"decisive_rules,omitempty"`
	Approval       bool     `json:"approval,omitempty"`
	ApprovalReason string   `json:"approval_reason,omitempty"`
	Filters        []string `json:"filters,omitempty"`
	CallsPerMinute int      `json:"calls_per_minute,omitempty"`
	// EgressLimits is the rule's egress-limit obligation (FR-5.38).
	EgressLimits *EgressLimits `json:"egress_limits,omitempty"`
}

func outcomeOf(d Decision) SimOutcome {
	o := SimOutcome{Outcome: d.Outcome, ReasonCode: d.ReasonCode, DecisiveRules: d.DecisiveRules}
	if d.Outcome == Permit {
		o.Approval, o.ApprovalReason, o.Filters, o.CallsPerMinute = d.Obligations.Approval, d.Obligations.ApprovalReason, d.Obligations.Filters, d.Obligations.CallsPerMinute
		o.EgressLimits = d.Obligations.EgressLimits
	}
	return o
}

// Change classes of a simulated fixture.
const (
	SimUnchanged    = "unchanged"
	SimPermitToDeny = "permit_to_deny"
	SimDenyToPermit = "deny_to_permit"
	SimReason       = "reason_changed"
	SimObligations  = "obligations_changed"
)

func classify(a, b SimOutcome) string {
	switch {
	case a.Outcome == Permit && b.Outcome != Permit:
		return SimPermitToDeny
	case a.Outcome != Permit && b.Outcome == Permit:
		return SimDenyToPermit
	case a.ReasonCode != b.ReasonCode:
		return SimReason
	case a.Approval != b.Approval || a.ApprovalReason != b.ApprovalReason || a.CallsPerMinute != b.CallsPerMinute ||
		!slices.Equal(a.Filters, b.Filters) || !sameEgressLimits(a.EgressLimits, b.EgressLimits):
		return SimObligations
	}
	return SimUnchanged
}

func sameEgressLimits(a, b *EgressLimits) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// SimResult is one fixture's decision under each revision.
type SimResult struct {
	Index     int        `json:"index"`
	Fixture   Fixture    `json:"fixture"`
	Active    SimOutcome `json:"active"`
	Candidate SimOutcome `json:"candidate"`
	Change    string     `json:"change"`
}

// SimReport is the FR-3.5 report: per fixture the decision under the
// candidate, under the active revision and the difference.
type SimReport struct {
	ActiveRevision    string         `json:"active_revision"`
	CandidateRevision string         `json:"candidate_revision"`
	Fixtures          int            `json:"fixtures"`
	Changed           int            `json:"changed"`
	Counts            map[string]int `json:"counts"`
	Results           []SimResult    `json:"results"`
}

// SimOptions configure a replay. DefaultRate and Burst are the CP-11 values
// of the running Gateway; All includes unchanged fixtures in Results.
type SimOptions struct {
	DefaultRate int
	Burst       int
	All         bool
}

// ErrNoFixtures is returned when there is nothing to replay.
var ErrNoFixtures = errors.New("no fixtures to replay")

// Simulate replays fixtures in time order against the active and the
// candidate snapshot, each with its own fresh decider. Rate windows run on
// the fixtures' recorded times, and a permitted call of an untrusted-source
// tool taints its session on that side, so later fixtures of the session
// see the taint obligation as they would live. active may be nil (no
// revision loaded: every fixture is denied with NO_SNAPSHOT on that side).
func Simulate(active, candidate *Snapshot, fixtures []Fixture, o SimOptions) (SimReport, error) {
	if candidate == nil {
		return SimReport{}, errors.New("no candidate revision")
	}
	if len(fixtures) == 0 {
		return SimReport{}, ErrNoFixtures
	}
	if len(fixtures) > MaxFixtures {
		return SimReport{}, fmt.Errorf("more than %d fixtures", MaxFixtures)
	}
	if o.DefaultRate <= 0 {
		o.DefaultRate = 60
	}
	order := make([]int, len(fixtures))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return fixtures[order[i]].Time.Before(fixtures[order[j]].Time) })
	rep := SimReport{CandidateRevision: candidate.Revision, Fixtures: len(fixtures), Counts: map[string]int{}, Results: []SimResult{}}
	if active != nil {
		rep.ActiveRevision = active.Revision
	}
	var now time.Time
	clock := func() time.Time { return now }
	mk := func(s *Snapshot) *Decider {
		d := NewDecider(s, o.DefaultRate)
		d.SetBurst(o.Burst)
		d.SetNow(clock)
		d.SetBounds(DefaultCandidateBound, 0) // replay time is not the live deadline
		return d
	}
	da, dc := mk(active), mk(candidate)
	base := time.Unix(0, 0)
	for _, i := range order {
		f := fixtures[i]
		if f.PrincipalID == "" {
			f.PrincipalID = "simulated"
		}
		if f.SessionID == "" {
			f.SessionID = "simulated"
		}
		now = f.Time
		if now.IsZero() {
			now = base
		}
		req := Request{PrincipalID: f.PrincipalID, SessionID: f.SessionID, Profile: f.Profile, Template: f.Template,
			Server: f.Server, Tool: f.Tool, SideEffect: f.SideEffect, SourceTrust: f.SourceTrust}
		a, c := da.Decide(req), dc.Decide(req)
		for _, side := range []struct {
			d   *Decider
			dec Decision
		}{{da, a}, {dc, c}} {
			if side.dec.Outcome == Permit && side.dec.TaintsSession {
				side.d.Taint(f.SessionID)
			}
		}
		r := SimResult{Index: i, Fixture: f, Active: outcomeOf(a), Candidate: outcomeOf(c)}
		r.Change = classify(r.Active, r.Candidate)
		rep.Counts[r.Change]++
		if r.Change != SimUnchanged {
			rep.Changed++
		}
		if o.All || r.Change != SimUnchanged {
			rep.Results = append(rep.Results, r)
		}
	}
	return rep, nil
}
