// Package principals manages framework principals and their OAuth client
// credentials from the control API (FR-8.19, G-11), in addition to the
// [[principal]] and [[client]] tables of the configuration file.
//
// The directory is a JSON file in the state directory
// (state/principals.json, mode 0600, written atomically). It holds the
// principals created from the console, the credentials issued to any
// principal, and the file principals that were suspended. It is attached to
// the configuration with config.SetDirectory, so the OAuth authorization
// server, the session API, the remote profile and every other element find
// these principals and clients through config.FindPrincipal and FindClient.
//
// A credential is an OAuth client bound to one principal (FR-2.18): a
// generated client ID, its redirect URIs, and for a confidential client an
// Argon2id hash of a 256-bit secret that is shown once. Revoking a
// credential makes the client unknown and terminates its sessions.
// Suspending a principal refuses new sessions and suspends its active ones;
// enabling it again lets it sign in, and its suspended sessions are resumed
// one by one from the session list.
//
// Routes (docs/api/console.md):
//
//	GET  /api/v1/principals                        principals of the file and the directory, with credentials
//	POST /api/v1/principals                        {id, framework, display_name, profile}
//	POST /api/v1/principals/{id}/suspend           {reason}
//	POST /api/v1/principals/{id}/enable            {reason}
//	POST /api/v1/principals/{id}/credentials       {redirect_uris, confidential} -> client_id, client_secret once
//	POST /api/v1/credentials/{client_id}/revoke    {reason}
//	GET  /api/v1/approvers                         Session Approver accounts of the file and the directory
//	POST /api/v1/approvers                         {username, password}
//	POST /api/v1/approvers/{username}/remove       {reason}
//
// Session Approver accounts (FR-2.23) approve harness sign-ins at the OAuth
// authorization endpoint and nothing else. The Administrator creates them
// here in addition to the [[approver]] entries of the file; the password is
// stored as an Argon2id hash and must differ from the Administrator's.
package principals

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// File is the directory's path under the state directory.
const File = "principals.json"

// Frameworks are the framework types a principal may have (the
// configuration schema's enum).
var Frameworks = []string{"claude-code", "codex", "hermes", "opencode", "gemini-cli", "goose", "grok-build", "grok-bot", "chatgpt", "meta-muse", "cursor", "other"}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Errors of the mutations.
var (
	ErrInvalid  = errors.New("invalid request")
	ErrExists   = errors.New("already exists")
	ErrNotFound = errors.New("not found")
	ErrFromFile = errors.New("defined in the configuration file")
)

// Principal is a principal created from the control API.
type Principal struct {
	ID          string    `json:"id"`
	Framework   string    `json:"framework"`
	DisplayName string    `json:"display_name,omitempty"`
	Profile     string    `json:"profile"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// Credential is an OAuth client issued from the control API.
type Credential struct {
	ClientID     string     `json:"client_id"`
	Principal    string     `json:"principal"`
	SecretHash   string     `json:"secret_hash,omitempty"`
	RedirectURIs []string   `json:"redirect_uris"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// Suspension records that a principal is suspended.
type Suspension struct {
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason,omitempty"`
}

type state struct {
	Version     int                   `json:"version"`
	Principals  []Principal           `json:"principals"`
	Credentials []Credential          `json:"credentials"`
	Suspended   map[string]Suspension `json:"suspended"`
	Approvers   []Approver            `json:"approvers,omitempty"`
}

// Directory is the run-time principal directory. It implements
// config.Directory.
type Directory struct {
	cfg  *config.Config
	path string
	now  func() time.Time

	mu sync.RWMutex
	st state
}

// Open reads the directory of cfg's state directory (an absent file is an
// empty directory). It does not attach it; call cfg.SetDirectory.
func Open(cfg *config.Config) (*Directory, error) {
	d := &Directory{cfg: cfg, path: filepath.Join(cfg.State.Dir, File), now: time.Now, st: state{Version: 1, Suspended: map[string]Suspension{}}}
	b, err := os.ReadFile(d.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return d, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &d.st); err != nil {
		return nil, fmt.Errorf("%s: %w", d.path, err)
	}
	if d.st.Suspended == nil {
		d.st.Suspended = map[string]Suspension{}
	}
	return d, nil
}

func (d *Directory) saveLocked() error {
	b, err := json.MarshalIndent(d.st, "", "  ")
	if err != nil {
		return err
	}
	return keys.WriteFileAtomic(d.path, append(b, '\n'), 0o600)
}

// Principal implements config.Directory for directory principals.
func (d *Directory) Principal(id string) (config.Principal, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, p := range d.st.Principals {
		if p.ID == id {
			on := true
			if _, s := d.st.Suspended[id]; s {
				on = false
			}
			return config.Principal{ID: p.ID, Framework: p.Framework, DisplayName: p.DisplayName, Profile: p.Profile, Enabled: &on}, true
		}
	}
	return config.Principal{}, false
}

// Client implements config.Directory: an issued credential that is not
// revoked.
func (d *Directory) Client(id string) (config.Client, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, c := range d.st.Credentials {
		if c.ClientID == id && c.RevokedAt == nil {
			return config.Client{ClientID: c.ClientID, ClientSecretHash: c.SecretHash, Principal: c.Principal, RedirectURIs: slices.Clone(c.RedirectURIs)}, true
		}
	}
	return config.Client{}, false
}

// Suspended implements config.Directory.
func (d *Directory) Suspended(id string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.st.Suspended[id]
	return ok
}

// known reports whether a principal exists in the file or the directory.
// Callers hold d.mu.
func (d *Directory) knownLocked(id string) (fromFile, ok bool) {
	for _, p := range d.cfg.Principals {
		if p.ID == id {
			return true, true
		}
	}
	for _, p := range d.st.Principals {
		if p.ID == id {
			return false, true
		}
	}
	return false, false
}

// AddPrincipal creates a principal. profiles are the framework profiles of
// the active policy; the principal's profile must be one of them.
func (d *Directory) AddPrincipal(p Principal, profiles []string, actor string) (Principal, error) {
	p, err := d.validate(p, profiles)
	if err != nil {
		return Principal{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.knownLocked(p.ID); ok {
		return Principal{}, fmt.Errorf("%w: principal %s", ErrExists, p.ID)
	}
	p.CreatedBy, p.CreatedAt = actor, d.now().UTC()
	d.st.Principals = append(d.st.Principals, p)
	if err := d.saveLocked(); err != nil {
		d.st.Principals = d.st.Principals[:len(d.st.Principals)-1]
		return Principal{}, err
	}
	return p, nil
}

// known reports whether a principal exists and whether it is from the file.
func (d *Directory) known(id string) (fromFile, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.knownLocked(id)
}

// validate checks a new principal without changing the directory.
func (d *Directory) validate(p Principal, profiles []string) (Principal, error) {
	p.ID, p.DisplayName, p.Profile = strings.TrimSpace(p.ID), strings.TrimSpace(p.DisplayName), strings.TrimSpace(p.Profile)
	switch {
	case !idPattern.MatchString(p.ID):
		return Principal{}, fmt.Errorf("%w: id must match %s", ErrInvalid, idPattern)
	case !slices.Contains(Frameworks, p.Framework):
		return Principal{}, fmt.Errorf("%w: framework must be one of %s", ErrInvalid, strings.Join(Frameworks, ", "))
	case len(p.DisplayName) > 128:
		return Principal{}, fmt.Errorf("%w: display_name is longer than 128 characters", ErrInvalid)
	case !slices.Contains(profiles, p.Profile):
		return Principal{}, fmt.Errorf("%w: profile %q is not a framework profile of the active policy (%s)", ErrInvalid, p.Profile, strings.Join(profiles, ", "))
	}
	if _, ok := d.known(p.ID); ok {
		return Principal{}, fmt.Errorf("%w: principal %s", ErrExists, p.ID)
	}
	return p, nil
}

// SetSuspended suspends or enables a principal of the file or the
// directory.
func (d *Directory) SetSuspended(id string, suspend bool, actor, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.knownLocked(id); !ok {
		return fmt.Errorf("%w: principal %s", ErrNotFound, id)
	}
	prev, was := d.st.Suspended[id]
	if suspend {
		d.st.Suspended[id] = Suspension{By: actor, At: d.now().UTC(), Reason: reason}
	} else {
		delete(d.st.Suspended, id)
	}
	if err := d.saveLocked(); err != nil {
		if was {
			d.st.Suspended[id] = prev
		} else {
			delete(d.st.Suspended, id)
		}
		return err
	}
	return nil
}

// Issue creates a credential for a principal. A confidential credential
// gets a secret, returned once and stored as an Argon2id hash.
func (d *Directory) Issue(principal string, redirectURIs []string, confidential bool, actor string) (Credential, string, error) {
	if err := validRedirects(redirectURIs); err != nil {
		return Credential{}, "", err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Credential{}, "", err
	}
	c := Credential{ClientID: "smcp-client-" + hex.EncodeToString(b[:]), Principal: principal, RedirectURIs: slices.Clone(redirectURIs), CreatedBy: actor}
	secret := ""
	if confidential {
		secret = ids.Secret()
		h, err := keys.HashPassword(secret)
		if err != nil {
			return Credential{}, "", err
		}
		c.SecretHash = h
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.knownLocked(principal); !ok {
		return Credential{}, "", fmt.Errorf("%w: principal %s", ErrNotFound, principal)
	}
	c.CreatedAt = d.now().UTC()
	d.st.Credentials = append(d.st.Credentials, c)
	if err := d.saveLocked(); err != nil {
		d.st.Credentials = d.st.Credentials[:len(d.st.Credentials)-1]
		return Credential{}, "", err
	}
	return c, secret, nil
}

// Revoke revokes an issued credential. Clients of the file cannot be
// revoked here.
// CredentialRevoked reports whether clientID is a credential of the
// directory that was revoked (SR-1.17-1).
func (d *Directory) CredentialRevoked(clientID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.st.Credentials {
		if c.ClientID == clientID {
			return c.RevokedAt != nil
		}
	}
	return false
}

func (d *Directory) Revoke(clientID, actor string) (Credential, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.st.Credentials {
		c := &d.st.Credentials[i]
		if c.ClientID != clientID {
			continue
		}
		if c.RevokedAt != nil {
			return *c, fmt.Errorf("%w: credential %s is already revoked", ErrInvalid, clientID)
		}
		at := d.now().UTC()
		c.RevokedAt, c.RevokedBy = &at, actor
		if err := d.saveLocked(); err != nil {
			c.RevokedAt, c.RevokedBy = nil, ""
			return Credential{}, err
		}
		return *c, nil
	}
	for _, c := range d.cfg.Clients {
		if c.ClientID == clientID {
			return Credential{}, fmt.Errorf("%w: client %s is in [[client]] of smcp.toml; remove it there", ErrFromFile, clientID)
		}
	}
	return Credential{}, fmt.Errorf("%w: credential %s", ErrNotFound, clientID)
}

// View is one principal as the console lists it.
type View struct {
	ID          string           `json:"id"`
	Framework   string           `json:"framework"`
	DisplayName string           `json:"display_name,omitempty"`
	Profile     string           `json:"profile"`
	Source      string           `json:"source"` // "file" or "console"
	Enabled     bool             `json:"enabled"`
	Suspension  *Suspension      `json:"suspension,omitempty"`
	CreatedBy   string           `json:"created_by,omitempty"`
	CreatedAt   *time.Time       `json:"created_at,omitempty"`
	Credentials []CredentialView `json:"credentials"`
}

// CredentialView is a credential without its secret hash.
type CredentialView struct {
	ClientID     string     `json:"client_id"`
	Source       string     `json:"source"`
	Confidential bool       `json:"confidential"`
	RedirectURIs []string   `json:"redirect_uris"`
	CreatedBy    string     `json:"created_by,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// List returns every principal with its credentials, sorted by ID.
func (d *Directory) List() []View {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []View
	add := func(v View) {
		if s, ok := d.st.Suspended[v.ID]; ok {
			s := s
			v.Suspension, v.Enabled = &s, false
		}
		for _, c := range d.cfg.Clients {
			if c.Principal == v.ID {
				v.Credentials = append(v.Credentials, CredentialView{ClientID: c.ClientID, Source: "file", Confidential: c.ClientSecretHash != "", RedirectURIs: slices.Clone(c.RedirectURIs)})
			}
		}
		for _, c := range d.st.Credentials {
			if c.Principal == v.ID {
				at := c.CreatedAt
				v.Credentials = append(v.Credentials, CredentialView{ClientID: c.ClientID, Source: "console", Confidential: c.SecretHash != "", RedirectURIs: slices.Clone(c.RedirectURIs),
					CreatedBy: c.CreatedBy, CreatedAt: &at, RevokedBy: c.RevokedBy, RevokedAt: c.RevokedAt})
			}
		}
		if v.Credentials == nil {
			v.Credentials = []CredentialView{}
		}
		out = append(out, v)
	}
	for _, p := range d.cfg.Principals {
		add(View{ID: p.ID, Framework: p.Framework, DisplayName: p.DisplayName, Profile: p.Profile, Source: "file", Enabled: p.Enabled == nil || *p.Enabled})
	}
	for _, p := range d.st.Principals {
		at := p.CreatedAt
		add(View{ID: p.ID, Framework: p.Framework, DisplayName: p.DisplayName, Profile: p.Profile, Source: "console", Enabled: true, CreatedBy: p.CreatedBy, CreatedAt: &at})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// validRedirects checks the redirect URIs of a new credential: 1 to 10
// absolute URLs without a fragment, https or loopback http (RFC 8252).
func validRedirects(uris []string) error {
	if len(uris) == 0 || len(uris) > 10 {
		return fmt.Errorf("%w: give 1 to 10 redirect URIs", ErrInvalid)
	}
	for _, u := range uris {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" || pu.Fragment != "" {
			return fmt.Errorf("%w: redirect URI %q must be an absolute http or https URL without a fragment", ErrInvalid, u)
		}
		if pu.Scheme == "http" && !isLoopback(pu.Hostname()) {
			return fmt.Errorf("%w: redirect URI %q: http is allowed only for loopback hosts", ErrInvalid, u)
		}
	}
	return nil
}

func isLoopback(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
