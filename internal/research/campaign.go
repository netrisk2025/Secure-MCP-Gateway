// Package research is the Research Dataset Service (E-32): research
// capture campaigns with a governed life cycle, dataset extraction from the
// Observation Store, pseudonymization under a per-dataset HMAC-SHA-256 key,
// and export in Parquet, CSV, JSON Lines and GraphML with a data
// dictionary, a provenance manifest and a checksum file (ArchitectureV2
// §4 E-32, §18.5; FR-10.30 to FR-10.36; SR-6-1, SR-6-2).
package research

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
)

// Campaign states (FR-10.30).
const (
	Draft     = "draft"
	Submitted = "submitted"
	Approved  = "approved"
	Active    = "active"
	Completed = "completed"
	Exported  = "exported"
	Expired   = "expired"
)

// Scope selects the calls a campaign captures; an empty list matches all.
type Scope struct {
	Principals []string `json:"principals,omitempty"`
	Servers    []string `json:"servers,omitempty"` // server aliases
	Tools      []string `json:"tools,omitempty"`
}

// Matches reports whether a record is in scope.
func (s Scope) Matches(principal, server, tool string) bool {
	in := func(list []string, v string) bool { return len(list) == 0 || slices.Contains(list, v) }
	return in(s.Principals, principal) && in(s.Servers, server) && in(s.Tools, tool)
}

// Transition is one state change.
type Transition struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
	Reason string    `json:"reason,omitempty"`
}

// Campaign is a research capture campaign (D-01).
type Campaign struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Purpose     string       `json:"purpose,omitempty"`
	State       string       `json:"state"`
	Scope       Scope        `json:"scope"`
	Parameters  []string     `json:"parameters"`
	Sampling    float64      `json:"sampling"`
	Start       time.Time    `json:"start"`
	End         time.Time    `json:"end"`
	QuotaBytes  int64        `json:"quota_bytes"`
	UsedBytes   int64        `json:"used_bytes"`
	Records     int64        `json:"records"`
	RawExport   bool         `json:"raw_export_grant"`
	CreatedBy   string       `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
	History     []Transition `json:"history"`
	LastDataset string       `json:"last_dataset,omitempty"`
}

// Spec is the operator-supplied part of a campaign.
type Spec struct {
	Name       string    `json:"name"`
	Purpose    string    `json:"purpose"`
	Scope      Scope     `json:"scope"`
	Parameters []string  `json:"parameters"`
	Sampling   *float64  `json:"sampling"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	QuotaBytes int64     `json:"quota_bytes"`
	RawExport  bool      `json:"raw_export_grant"`
}

// Errors with their API codes.
var (
	ErrNotFound   = errors.New("campaign not found")
	ErrTransition = errors.New("transition not allowed from this state")
	ErrInvalid    = errors.New("invalid campaign")
)

// Campaigns manages campaign records in a JSON file.
type Campaigns struct {
	path    string
	catalog *observe.Catalog
	now     func() time.Time

	mu sync.Mutex
	m  map[string]*Campaign
}

// OpenCampaigns loads (or creates) the campaign file.
func OpenCampaigns(path string, cat *observe.Catalog, now func() time.Time) (*Campaigns, error) {
	if now == nil {
		now = time.Now
	}
	c := &Campaigns{path: path, catalog: cat, now: now, m: map[string]*Campaign{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, os.MkdirAll(filepath.Dir(path), 0o700)
	}
	if err != nil {
		return nil, err
	}
	var list []*Campaign
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("campaigns %s: %w", path, err)
	}
	for _, cp := range list {
		c.m[cp.ID] = cp
	}
	return c, nil
}

func (c *Campaigns) saveLocked() error {
	list := make([]*Campaign, 0, len(c.m))
	for _, cp := range c.m {
		list = append(list, cp)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func (c *Campaigns) validate(s Spec) error {
	if s.Name == "" || len(s.Name) > 128 {
		return fmt.Errorf("%w: name is required (at most 128 characters)", ErrInvalid)
	}
	if len(s.Parameters) == 0 {
		return fmt.Errorf("%w: parameters are required", ErrInvalid)
	}
	for _, p := range s.Parameters {
		par, ok := c.catalog.Lookup(p)
		if !ok {
			return fmt.Errorf("%w: unknown parameter %q", ErrInvalid, p)
		}
		if par.Sensitivity == "S3" && !s.RawExport {
			return fmt.Errorf("%w: %s is an S3 raw-payload parameter and needs raw_export_grant", ErrInvalid, par.ID)
		}
	}
	if s.Start.IsZero() || s.End.IsZero() || !s.End.After(s.Start) {
		return fmt.Errorf("%w: start and end are required and end must be after start", ErrInvalid)
	}
	if s.QuotaBytes <= 0 {
		return fmt.Errorf("%w: quota_bytes must be positive", ErrInvalid)
	}
	if s.Sampling != nil && (*s.Sampling <= 0 || *s.Sampling > 1 || math.IsNaN(*s.Sampling)) {
		return fmt.Errorf("%w: sampling must be in (0, 1]", ErrInvalid)
	}
	return nil
}

// Create records a new campaign in the draft state.
func (c *Campaigns) Create(s Spec, actor string) (Campaign, error) {
	if err := c.validate(s); err != nil {
		return Campaign{}, err
	}
	names, _ := c.catalog.Resolve(s.Parameters)
	rate := 1.0
	if s.Sampling != nil {
		rate = *s.Sampling
	}
	now := c.now().UTC()
	cp := &Campaign{ID: ids.New(), Name: s.Name, Purpose: s.Purpose, State: Draft, Scope: s.Scope, Parameters: names, Sampling: rate,
		Start: s.Start.UTC(), End: s.End.UTC(), QuotaBytes: s.QuotaBytes, RawExport: s.RawExport, CreatedBy: actor, CreatedAt: now,
		History: []Transition{{To: Draft, At: now, By: actor}}}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[cp.ID] = cp
	return *cp, c.saveLocked()
}

// Get returns a campaign.
func (c *Campaigns) Get(id string) (Campaign, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.m[id]
	if !ok {
		return Campaign{}, ErrNotFound
	}
	out := *cp
	out.History = append([]Transition(nil), cp.History...)
	return out, nil
}

// List returns every campaign, newest first.
func (c *Campaigns) List() []Campaign {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Campaign, 0, len(c.m))
	for _, cp := range c.m {
		out = append(out, *cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// operator actions and the states they move between.
var actions = map[string]struct {
	from []string
	to   string
}{
	"submit":  {[]string{Draft}, Submitted},
	"approve": {[]string{Submitted}, Approved},
	"reject":  {[]string{Submitted}, Draft},
	"stop":    {[]string{Active}, Completed},
	"expire":  {[]string{Approved, Completed, Exported}, Expired},
}

// Act applies an operator action: submit, approve, reject, stop or expire.
func (c *Campaigns) Act(id, action, actor, reason string) (Campaign, error) {
	a, ok := actions[action]
	if !ok {
		return Campaign{}, fmt.Errorf("%w: unknown action %q", ErrInvalid, action)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.m[id]
	if !ok {
		return Campaign{}, ErrNotFound
	}
	if !slices.Contains(a.from, cp.State) {
		return *cp, fmt.Errorf("%w: %s from %s", ErrTransition, action, cp.State)
	}
	c.moveLocked(cp, a.to, actor, reason)
	return *cp, c.saveLocked()
}

func (c *Campaigns) moveLocked(cp *Campaign, to, actor, reason string) {
	cp.History = append(cp.History, Transition{From: cp.State, To: to, At: c.now().UTC(), By: actor, Reason: reason})
	cp.State = to
}

// Tick activates approved campaigns at their start time and completes
// active ones at their end time (FR-10.31). It returns the transitions made.
func (c *Campaigns) Tick() ([]Transition, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Transition
	for _, cp := range c.m {
		switch {
		case cp.State == Approved && !now.Before(cp.End):
			c.moveLocked(cp, Expired, "E-32", "end passed before activation")
		case cp.State == Approved && !now.Before(cp.Start):
			c.moveLocked(cp, Active, "E-32", "start time")
		case cp.State == Active && !now.Before(cp.End):
			c.moveLocked(cp, Completed, "E-32", "end time")
		default:
			continue
		}
		out = append(out, cp.History[len(cp.History)-1])
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, c.saveLocked()
}

// Account adds a captured record's size to every listed active campaign
// and completes a campaign whose quota is reached (FR-10.31). It returns
// the IDs of campaigns completed by this record.
func (c *Campaigns) Account(campaignIDs []string, bytes int64) []string {
	if len(campaignIDs) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var done []string
	for _, id := range campaignIDs {
		cp, ok := c.m[id]
		if !ok || cp.State != Active {
			continue
		}
		cp.UsedBytes += bytes
		cp.Records++
		if cp.UsedBytes >= cp.QuotaBytes {
			c.moveLocked(cp, Completed, "E-32", "storage quota reached")
			done = append(done, id)
		}
	}
	if len(done) > 0 {
		_ = c.saveLocked() // the transition is retried with the next save
	}
	return done
}

// Flush persists counters.
func (c *Campaigns) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

// MarkExported moves a completed campaign to exported (or keeps it
// exported) and records the dataset.
func (c *Campaigns) MarkExported(id, dataset, actor string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.m[id]
	if !ok {
		return ErrNotFound
	}
	if cp.State == Completed {
		c.moveLocked(cp, Exported, actor, "dataset "+dataset)
	}
	cp.LastDataset = dataset
	return c.saveLocked()
}

// Active returns the capture contributions of active campaigns for the
// collector.
func (c *Campaigns) Active() []observe.Campaign {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []observe.Campaign
	for _, cp := range c.m {
		if cp.State != Active {
			continue
		}
		scope := cp.Scope
		out = append(out, observe.Campaign{ID: cp.ID, Parameters: append([]string(nil), cp.Parameters...), Rate: cp.Sampling,
			Matches: func(r *observe.Record) bool {
				return scope.Matches(r.Str("principal_id"), r.ServerID, r.Str("tool_name"))
			}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
