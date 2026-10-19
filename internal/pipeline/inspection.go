package pipeline

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Stage names a filter chain.
const (
	StageRequest  = "request"
	StageResponse = "response"
)

// DefaultFilterDeadline is CP-14: the bound on one chain run.
const DefaultFilterDeadline = 2 * time.Second

// Finding is one detection by a filter (FR-4.4, FR-4.16). It names the rule
// and the rule-set version that matched and where; it never carries the
// matched content, so it is safe to return to the harness and to record as
// evidence.
type Finding struct {
	Filter         string  `json:"filter"`
	RuleSet        string  `json:"ruleSet,omitempty"`
	RuleSetVersion string  `json:"ruleSetVersion,omitempty"`
	Rule           string  `json:"rule,omitempty"`
	Location       string  `json:"location,omitempty"` // JSON pointer or content surface
	Score          float64 `json:"score,omitempty"`
	// Tag marks an annotate-only finding: it is reported in provenance and
	// never changes the disposition (FR-4.17).
	Tag bool `json:"tag,omitempty"`
}

// FilterRun is the record of one filter execution: the outcome, findings,
// duration and filter version (FR-4.4, FR-4.7).
type FilterRun struct {
	Stage      string        `json:"stage"`
	Filter     string        `json:"filter"`
	Version    string        `json:"version"`
	Action     Action        `json:"-"`
	ReasonCode string        `json:"reasonCode,omitempty"`
	Findings   []Finding     `json:"findings,omitempty"`
	Duration   time.Duration `json:"-"`
	// Start is when the filter began (monotonic) and CPU the thread CPU
	// time it used (FR-10.2); CPU is zero where it cannot be measured.
	Start time.Time     `json:"-"`
	CPU   time.Duration `json:"-"`
}

// String is the FR-4.4 name of an action.
func (a Action) String() string {
	switch a {
	case Pass:
		return "pass"
	case Transform:
		return "transform"
	default:
		return "block"
	}
}

// Versioned is implemented by filters that report a version. Filters that
// do not are reported as version "1".
type Versioned interface {
	Version() string
}

func versionOf(f any) string {
	if v, ok := f.(Versioned); ok && v.Version() != "" {
		return v.Version()
	}
	return "1"
}

// FilterObserver receives the runs of one chain execution after it ends,
// including the run that blocked. It runs on the call's goroutine and must
// not block; E-29 and the evidence recorder attach here.
type FilterObserver func(call *Call, stage string, runs []FilterRun)

// Observe adds an observer of chain runs.
func (f *Filters) Observe(o FilterObserver) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.obs = append(f.obs, o)
}

func (f *Filters) observe(call *Call, stage string, runs []FilterRun) {
	f.mu.RLock()
	obs := slices.Clone(f.obs)
	f.mu.RUnlock()
	for _, o := range obs {
		o(call, stage, runs)
	}
}

// SetDeadline sets the bound on one chain run (CP-14). Zero or negative
// restores the default.
func (f *Filters) SetDeadline(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline = d
}

func (f *Filters) deadlineLocked() time.Duration {
	if f.deadline <= 0 {
		return DefaultFilterDeadline
	}
	return f.deadline
}

// RegisteredFilter describes one registered filter.
type RegisteredFilter struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Order     int    `json:"order"`
	Mandatory bool   `json:"mandatory"`
}

// Registered lists the filters of a chain (StageRequest or StageResponse)
// in execution order.
func (f *Filters) Registered(stage string) []RegisteredFilter {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var out []RegisteredFilter
	if stage == StageRequest {
		for _, e := range f.req {
			out = append(out, RegisteredFilter{ID: e.id, Version: versionOf(e.f), Order: e.reg.Order, Mandatory: e.reg.Mandatory})
		}
		return out
	}
	for _, e := range f.resp {
		out = append(out, RegisteredFilter{ID: e.id, Version: versionOf(e.f), Order: e.reg.Order, Mandatory: e.reg.Mandatory})
	}
	return out
}

// Inspection accumulates the filter runs of one call. Its methods are safe
// on a nil receiver.
type Inspection struct {
	mu   sync.Mutex
	runs []FilterRun
}

func (c *Call) inspection() *Inspection {
	if c.Inspection == nil {
		c.Inspection = &Inspection{}
	}
	return c.Inspection
}

func (i *Inspection) add(r FilterRun) {
	i.mu.Lock()
	i.runs = append(i.runs, r)
	i.mu.Unlock()
}

// Runs returns a copy of the recorded runs.
func (i *Inspection) Runs() []FilterRun {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.runs)
}

// Tags returns the tag-only findings of both chains (FR-4.17).
func (i *Inspection) Tags() []Finding {
	var out []Finding
	for _, r := range i.Runs() {
		for _, f := range r.Findings {
			if f.Tag {
				out = append(out, f)
			}
		}
	}
	return out
}

// Disposition is the FR-4.11 release disposition of a result that was not
// withheld: "redact" when a response filter transformed it and gave a
// reason code (a removal or replacement of content), otherwise "release".
// A transform without a reason code (such as delimiting) only adds
// framing.
func (i *Inspection) Disposition() string {
	for _, r := range i.Runs() {
		if r.Stage == StageResponse && r.Action == Transform && r.ReasonCode != "" {
			return "redact"
		}
	}
	return "release"
}

// ToolScreen decides, before a tool is presented in a session catalog,
// whether it may be shown (FR-1.52). A non-nil error omits the tool; the
// screen records its own evidence. The default (nil) presents every tool.
type ToolScreen interface {
	Present(ctx context.Context, server, serverRevision string, tool *mcp.Tool) error
}
