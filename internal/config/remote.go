package config

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Remote configures the Remote Access Profile (FR-16). The table only sets
// how the profile behaves when it is enabled; enabling it is an
// Administrator action through the control API (`smcpctl remote enable`),
// recorded as a remote_access_enabled event and kept in the state
// directory (FR-16.11). A configuration without the table, as written by
// `smcpctl bootstrap`, leaves the profile disabled.
type Remote struct {
	// Address is the CP-48 loopback listener the tunnel forwards to.
	// Default 127.0.0.1:8444, or 127.0.0.1:8445 when the admin listener
	// already uses 8444.
	Address string `toml:"address" json:"address"`
	// PublicURL is the tunnel's public HTTPS origin (https://name). It is
	// usually supplied by `smcpctl remote enable`; this key is the default
	// when the enable request names none.
	PublicURL string `toml:"public_url" json:"public_url"`
	// Clients are [[client]] IDs (pre-registered clients) that may sign in
	// through the remote listener. Dynamically registered clients are added
	// by operator approval and are not listed here.
	Clients []string `toml:"clients" json:"clients"`
	// DefaultPrincipal is the principal an approved dynamic registration is
	// bound to when the approval names none.
	DefaultPrincipal string `toml:"default_principal" json:"default_principal"`
	// Templates are the Session Allow Policy templates remote sessions may
	// use; each must also be marked remote_allowed in the principal's
	// Framework Profile (FR-16.12). Empty means no remote session can be
	// created.
	Templates []string `toml:"templates" json:"templates"`
	// ClientAddressHeader names the header the tunnel connector sets to the
	// caller's address (default X-Forwarded-For; Cloudflare also sets
	// Cf-Connecting-Ip). Its value is recorded as server-asserted.
	ClientAddressHeader string `toml:"client_address_header" json:"client_address_header"`
	// MaxPendingRegistrations bounds stored pending dynamic registrations.
	MaxPendingRegistrations int `toml:"max_pending_registrations" json:"max_pending_registrations"`
	// MaxPendingPerSource bounds the pending registrations from one caller
	// address (an IPv6 address counts as its /64), so one unauthenticated
	// caller cannot take every pending slot (CP-49).
	MaxPendingPerSource int `toml:"max_pending_per_source" json:"max_pending_per_source"`
	// PendingLifetime is how long a pending registration is kept before it
	// is dropped (CP-49).
	PendingLifetime Duration     `toml:"pending_registration_lifetime" json:"pending_registration_lifetime"`
	Limits          RemoteLimits `toml:"limits" json:"limits"`
}

// RemoteLimits are the CP-49 remote limits. A zero value takes the
// Appendix A default.
type RemoteLimits struct {
	CallsPerMinute       int      `toml:"calls_per_minute" json:"calls_per_minute"`
	CallsBurst           int      `toml:"calls_burst" json:"calls_burst"`
	OAuthPerSecond       int      `toml:"oauth_per_second" json:"oauth_per_second"`
	OAuthBurst           int      `toml:"oauth_burst" json:"oauth_burst"`
	LockoutFailures      int      `toml:"lockout_failures" json:"lockout_failures"`
	Lockout              Duration `toml:"lockout" json:"lockout"`
	BodyBytes            int64    `toml:"body_bytes" json:"body_bytes"`
	HeaderBytes          int      `toml:"header_bytes" json:"header_bytes"`
	ConcurrencyPerClient int      `toml:"concurrency_per_client" json:"concurrency_per_client"`
	ConcurrencyTotal     int      `toml:"concurrency_total" json:"concurrency_total"`
	SessionMaxLifetime   Duration `toml:"session_max_lifetime" json:"session_max_lifetime"`
	SessionIdleTimeout   Duration `toml:"session_idle_timeout" json:"session_idle_timeout"`
}

func (r *Remote) applyDefaults(adminAddr string) {
	if r.Address == "" {
		r.Address = "127.0.0.1:8444"
		if sameHostPort(r.Address, adminAddr) {
			r.Address = "127.0.0.1:8445"
		}
	}
	if r.ClientAddressHeader == "" {
		r.ClientAddressHeader = "X-Forwarded-For"
	}
	if r.MaxPendingRegistrations == 0 {
		r.MaxPendingRegistrations = 32
	}
	if r.MaxPendingPerSource == 0 {
		r.MaxPendingPerSource = 4
	}
	if r.PendingLifetime.Duration == 0 {
		r.PendingLifetime.Duration = 24 * time.Hour
	}
	l := &r.Limits
	setInt := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	setInt(&l.CallsPerMinute, 30)
	setInt(&l.CallsBurst, 5)
	setInt(&l.OAuthPerSecond, 10)
	setInt(&l.OAuthBurst, 20)
	setInt(&l.LockoutFailures, 5)
	setInt(&l.HeaderBytes, 8<<10)
	setInt(&l.ConcurrencyPerClient, 4)
	setInt(&l.ConcurrencyTotal, 16)
	if l.BodyBytes == 0 {
		l.BodyBytes = 256 << 10
	}
	setDur := func(p *Duration, v time.Duration) {
		if p.Duration == 0 {
			p.Duration = v
		}
	}
	setDur(&l.Lockout, 15*time.Minute)
	setDur(&l.SessionMaxLifetime, 2*time.Hour)
	setDur(&l.SessionIdleTimeout, 15*time.Minute)
}

// CheckPublicURL validates a Remote Access public URL: https, a host name,
// no path, query, fragment or user information.
func CheckPublicURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("public URL %q must be https://<name>[:port] with no path", s)
	}
	return nil
}

func (c *Config) checkRemote() error {
	r := &c.Remote
	host, _, err := net.SplitHostPort(r.Address)
	if err != nil {
		return fmt.Errorf("remote.address: %w", err)
	}
	if ip := net.ParseIP(host); (ip == nil && host != "localhost") || (ip != nil && !ip.IsLoopback()) {
		return fmt.Errorf("remote.address %q is not loopback (SR-2.9-3): the tunnel connector forwards to it", r.Address)
	}
	if sameHostPort(r.Address, c.Listener.Address) || sameHostPort(r.Address, c.AdminListener.Address) {
		return fmt.Errorf("remote.address must differ from listener.address and admin_listener.address (FR-16.1)")
	}
	if r.PublicURL != "" {
		if err := CheckPublicURL(r.PublicURL); err != nil {
			return fmt.Errorf("remote.public_url: %w", err)
		}
		r.PublicURL = strings.TrimSuffix(r.PublicURL, "/")
	}
	if r.DefaultPrincipal != "" && c.FindPrincipal(r.DefaultPrincipal) == nil {
		return fmt.Errorf("remote.default_principal names unknown principal %q", r.DefaultPrincipal)
	}
	for _, id := range r.Clients {
		if c.FindClient(id) == nil {
			return fmt.Errorf("remote.clients names unknown client %q", id)
		}
	}
	if r.PendingLifetime.Duration < time.Minute || r.PendingLifetime.Duration > 7*24*time.Hour {
		return fmt.Errorf("remote.pending_registration_lifetime must be between 1m and 168h")
	}
	if slices.Contains(r.Templates, "") {
		return fmt.Errorf("remote.templates has an empty entry")
	}
	return nil
}
