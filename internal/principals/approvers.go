package principals

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// Password bounds of a Session Approver account, the same as smcpctl
// bootstrap applies to the accounts it writes.
const (
	MinApproverPassword = 12
	MaxApproverPassword = 1024
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Approver is a Session Approver account created from the control API.
type Approver struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// ApproverView is a Session Approver account without its password hash.
type ApproverView struct {
	Username  string     `json:"username"`
	Source    string     `json:"source"` // "file" or "console"
	CreatedBy string     `json:"created_by,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// Approvers implements config.ApproverDirectory.
func (d *Directory) Approvers() []config.Approver {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]config.Approver, 0, len(d.st.Approvers))
	for _, a := range d.st.Approvers {
		out = append(out, config.Approver{Username: a.Username, PasswordHash: a.PasswordHash})
	}
	return out
}

// ListApprovers returns the Session Approver accounts of the file and the
// directory, sorted by username.
func (d *Directory) ListApprovers() []ApproverView {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := []ApproverView{}
	for _, a := range d.cfg.Approvers {
		out = append(out, ApproverView{Username: a.Username, Source: "file"})
	}
	for _, a := range d.st.Approvers {
		at := a.CreatedAt
		out = append(out, ApproverView{Username: a.Username, Source: "console", CreatedBy: a.CreatedBy, CreatedAt: &at})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// usernameTakenLocked reports why a username cannot be used for a new
// Session Approver, "" when it can. Callers hold d.mu.
func (d *Directory) usernameTakenLocked(u string) string {
	if strings.EqualFold(u, d.cfg.Admin.Username) {
		return "the Administrator's username"
	}
	for _, a := range d.cfg.Approvers {
		if strings.EqualFold(a.Username, u) {
			return "a Session Approver of [[approver]] in smcp.toml"
		}
	}
	for _, a := range d.st.Approvers {
		if strings.EqualFold(a.Username, u) {
			return "a Session Approver of the directory"
		}
	}
	for _, a := range d.cfg.Console.Accounts {
		if strings.EqualFold(a.Username, u) {
			return "a console account of [[console.account]]"
		}
	}
	for _, a := range d.cfg.Approvals.Accounts {
		if strings.EqualFold(a.Username, u) {
			return "an Approver of [[approvals.account]]"
		}
	}
	return ""
}

// CheckApprover validates a new Session Approver without changing the
// directory. adminHash is the Administrator's password hash; the password
// must not verify against it (FR-2.23).
func (d *Directory) CheckApprover(username, password, adminHash string) error {
	switch {
	case !usernamePattern.MatchString(username):
		return fmt.Errorf("%w: username must match %s", ErrInvalid, usernamePattern)
	case len(password) < MinApproverPassword:
		return fmt.Errorf("%w: password must be at least %d characters", ErrInvalid, MinApproverPassword)
	case len(password) > MaxApproverPassword:
		return fmt.Errorf("%w: password must be at most %d characters", ErrInvalid, MaxApproverPassword)
	}
	d.mu.RLock()
	why := d.usernameTakenLocked(username)
	d.mu.RUnlock()
	if why != "" {
		return fmt.Errorf("%w: username %s is %s", ErrExists, username, why)
	}
	if adminHash != "" && keys.VerifyPassword(adminHash, password) {
		return fmt.Errorf("%w: the password is the Administrator's password; a Session Approver needs its own", ErrInvalid)
	}
	return nil
}

// AddApprover creates a Session Approver account.
func (d *Directory) AddApprover(username, password, adminHash, actor string) (ApproverView, error) {
	if err := d.CheckApprover(username, password, adminHash); err != nil {
		return ApproverView{}, err
	}
	h, err := keys.HashPassword(password)
	if err != nil {
		return ApproverView{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if why := d.usernameTakenLocked(username); why != "" {
		return ApproverView{}, fmt.Errorf("%w: username %s is %s", ErrExists, username, why)
	}
	a := Approver{Username: username, PasswordHash: h, CreatedBy: actor, CreatedAt: d.now().UTC()}
	d.st.Approvers = append(d.st.Approvers, a)
	if err := d.saveLocked(); err != nil {
		d.st.Approvers = d.st.Approvers[:len(d.st.Approvers)-1]
		return ApproverView{}, err
	}
	at := a.CreatedAt
	return ApproverView{Username: a.Username, Source: "console", CreatedBy: actor, CreatedAt: &at}, nil
}

// RemoveApprover deletes a Session Approver account of the directory.
// Accounts of the file are removed by editing smcp.toml.
func (d *Directory) RemoveApprover(username string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, a := range d.st.Approvers {
		if a.Username != username {
			continue
		}
		prev := append([]Approver(nil), d.st.Approvers...)
		d.st.Approvers = append(d.st.Approvers[:i], d.st.Approvers[i+1:]...)
		if err := d.saveLocked(); err != nil {
			d.st.Approvers = prev
			return err
		}
		return nil
	}
	for _, a := range d.cfg.Approvers {
		if a.Username == username {
			return fmt.Errorf("%w: Session Approver %s is in [[approver]] of smcp.toml; remove it there", ErrFromFile, username)
		}
	}
	return fmt.Errorf("%w: Session Approver %s", ErrNotFound, username)
}

// hasApprover reports whether the directory holds the account.
func (d *Directory) hasApprover(username string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, a := range d.st.Approvers {
		if a.Username == username {
			return true
		}
	}
	return false
}
