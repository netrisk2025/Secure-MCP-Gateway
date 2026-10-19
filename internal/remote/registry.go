package remote

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"
	"sync"
	"time"
)

// Registration states (FR-16.5).
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusRevoked  = "revoked"
)

// Registration is one RFC 7591 dynamic client registration.
type Registration struct {
	ClientID                string     `json:"client_id"`
	ClientName              string     `json:"client_name,omitempty"`
	RedirectURIs            []string   `json:"redirect_uris"`
	GrantTypes              []string   `json:"grant_types"`
	TokenEndpointAuthMethod string     `json:"token_endpoint_auth_method"`
	SecretHash              string     `json:"secret_hash,omitempty"`
	SoftwareID              string     `json:"software_id,omitempty"`
	SoftwareVersion         string     `json:"software_version,omitempty"`
	Status                  string     `json:"status"`
	Principal               string     `json:"principal,omitempty"`
	RegisteredAt            time.Time  `json:"registered_at"`
	SourceAddress           string     `json:"source_address,omitempty"`
	DecidedBy               string     `json:"decided_by,omitempty"`
	DecidedAt               *time.Time `json:"decided_at,omitempty"`
}

// View is the control API form (no secret hash).
func (r Registration) View() map[string]any {
	v := map[string]any{"client_id": r.ClientID, "client_name": r.ClientName, "redirect_uris": r.RedirectURIs, "grant_types": r.GrantTypes,
		"token_endpoint_auth_method": r.TokenEndpointAuthMethod, "status": r.Status, "principal": r.Principal,
		"registered_at": r.RegisteredAt.UTC().Format(time.RFC3339), "source_address": r.SourceAddress, "source_address_source": "server-asserted",
		"registration": "dynamic", "software_id": r.SoftwareID, "software_version": r.SoftwareVersion, "decided_by": r.DecidedBy}
	if r.DecidedAt != nil {
		v["decided_at"] = r.DecidedAt.UTC().Format(time.RFC3339)
	}
	return v
}

// registry persists dynamic registrations in <state>/remote/clients.json.
type registry struct {
	path         string
	maxPending   int
	maxPerSource int

	mu   sync.Mutex
	regs map[string]*Registration
}

var (
	errNotFound    = errors.New("registration not found")
	errTooMany     = errors.New("too many pending registrations")
	errSourceQuota = errors.New("too many pending registrations from this caller address")
	errWrongStatus = errors.New("registration is not in a state that allows this")
)

// loadRegistry opens the registry. maxPerSource bounds the pending
// registrations whose source address has the same rate key (IPv6 /64); a
// value above maxPending (or zero) is treated as maxPending.
func loadRegistry(path string, maxPending, maxPerSource int) (*registry, error) {
	if maxPerSource <= 0 || maxPerSource > maxPending {
		maxPerSource = maxPending
	}
	r := &registry{path: path, maxPending: maxPending, maxPerSource: maxPerSource, regs: map[string]*Registration{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*Registration
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, g := range list {
		r.regs[g.ClientID] = g
	}
	return r, nil
}

func (r *registry) saveLocked() error {
	list := make([]*Registration, 0, len(r.regs))
	for _, g := range r.regs {
		list = append(list, g)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].RegisteredAt.Before(list[j].RegisteredAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(r.path, b)
}

// full reports why no further pending registration from source can be
// stored: errTooMany when every pending slot is taken, errSourceQuota when
// the source's quota is, or nil.
func (r *registry) full(source string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fullLocked(source)
}

func (r *registry) fullLocked(source string) error {
	if r.pendingLocked() >= r.maxPending {
		return errTooMany
	}
	key, n := rateKey(source), 0
	for _, x := range r.regs {
		if x.Status == StatusPending && rateKey(x.SourceAddress) == key {
			n++
		}
	}
	if n >= r.maxPerSource {
		return errSourceQuota
	}
	return nil
}

func (r *registry) pendingLocked() int {
	n := 0
	for _, x := range r.regs {
		if x.Status == StatusPending {
			n++
		}
	}
	return n
}

func (r *registry) add(g *Registration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.fullLocked(g.SourceAddress); err != nil {
		return err
	}
	r.regs[g.ClientID] = g
	if err := r.saveLocked(); err != nil {
		delete(r.regs, g.ClientID)
		return err
	}
	return nil
}

func (r *registry) get(id string) (Registration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.regs[id]
	if !ok {
		return Registration{}, false
	}
	c := *g
	c.RedirectURIs, c.GrantTypes = slices.Clone(g.RedirectURIs), slices.Clone(g.GrantTypes)
	return c, true
}

func (r *registry) list() []Registration {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Registration, 0, len(r.regs))
	for _, g := range r.regs {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RegisteredAt.After(out[j].RegisteredAt) })
	return out
}

func (r *registry) countStatus(st string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, g := range r.regs {
		if g.Status == st {
			n++
		}
	}
	return n
}

// decide moves a registration to status. Approve and deny need a pending
// registration; revoke needs an approved one.
func (r *registry) decide(id, status, principal, actor string, now time.Time) (Registration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.regs[id]
	if !ok {
		return Registration{}, errNotFound
	}
	switch status {
	case StatusApproved, StatusDenied:
		if g.Status != StatusPending {
			return *g, errWrongStatus
		}
	case StatusRevoked:
		if g.Status != StatusApproved {
			return *g, errWrongStatus
		}
	}
	prev := *g
	g.Status, g.DecidedBy = status, actor
	t := now.UTC()
	g.DecidedAt = &t
	if status == StatusApproved {
		g.Principal = principal
	}
	if err := r.saveLocked(); err != nil {
		*g = prev
		return prev, err
	}
	return *g, nil
}

// prunePending drops pending registrations older than maxAge.
func (r *registry) prunePending(now time.Time, maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for id, g := range r.regs {
		if g.Status == StatusPending && now.Sub(g.RegisteredAt) > maxAge {
			delete(r.regs, id)
			changed = true
		}
	}
	if changed {
		_ = r.saveLocked()
	}
}

// validRedirect accepts https URIs and http loopback URIs without user
// information or a fragment (RFC 8252 for native clients).
func validRedirect(s string) bool {
	if len(s) > 2048 {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// redirectMatches compares a presented redirect URI with the registered
// ones; a loopback http URI matches on any port (RFC 8252 section 7.3).
func redirectMatches(registered []string, presented string) bool {
	if slices.Contains(registered, presented) {
		return true
	}
	pu, err := url.Parse(presented)
	if err != nil || pu.Scheme != "http" {
		return false
	}
	for _, r := range registered {
		ru, err := url.Parse(r)
		if err != nil || ru.Scheme != "http" {
			continue
		}
		if ru.Hostname() == pu.Hostname() && (pu.Hostname() == "127.0.0.1" || pu.Hostname() == "::1" || pu.Hostname() == "localhost") &&
			ru.Path == pu.Path && ru.RawQuery == pu.RawQuery && pu.Fragment == "" && pu.User == nil {
			return true
		}
	}
	return false
}
