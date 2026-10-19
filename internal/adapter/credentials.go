// Package adapter is the Harness Adapter Kit (E-33) shared by smcp-session
// (FR-12.12), smcp-stdio (FR-12.13) and smcp-connect (FR-16.9): the CP-43
// credential file, session acquisition and refresh against the Gateway,
// the RFC 8628 device sign-in for remote access, and the stdio-to-HTTP
// JSON-RPC relay.
package adapter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Credentials is the CP-43 credential file. Only the adapter reads and
// writes it; it holds the principal credential (client secret) and the
// session's tokens, so it must be mode 0600 (SR-2.3-2).
type Credentials struct {
	Gateway GatewaySection `toml:"gateway"`
	Client  ClientSection  `toml:"client"`
	Session SessionSection `toml:"session"`

	path string
}

// GatewaySection says where the Gateway is.
type GatewaySection struct {
	// URL is the MCP endpoint: https://127.0.0.1:8443/mcp locally, or the
	// Remote Access public URL followed by /mcp.
	URL string `toml:"url"`
	// CAFile is the Gateway server CA. When set, it is the only trust root
	// (FR-12.13); remote access through a public tunnel leaves it empty and
	// uses the system roots.
	CAFile string `toml:"ca_file,omitempty"`
	// Socket is the UDS harness socket, used instead of the URL when the
	// UDS Harness Profile is enabled (smcp-stdio only; RunUDS).
	Socket string `toml:"socket,omitempty"`
	// UDSKey is the bearer key registered for this user in [[uds.peer]].
	UDSKey string `toml:"uds_key,omitempty"`
}

// ClientSection is the OAuth client of the principal.
type ClientSection struct {
	ID       string `toml:"id"`
	Secret   string `toml:"secret,omitempty"`
	Template string `toml:"template,omitempty"`
	Purpose  string `toml:"purpose,omitempty"`
	Project  string `toml:"project,omitempty"`
	EndUser  string `toml:"end_user,omitempty"`
}

// SessionSection holds the current session's tokens.
type SessionSection struct {
	ID           string    `toml:"id,omitempty"`
	AccessToken  string    `toml:"access_token,omitempty"`
	RefreshToken string    `toml:"refresh_token,omitempty"`
	IssuedAt     time.Time `toml:"issued_at,omitzero"`
	ExpiresIn    int       `toml:"expires_in,omitempty"`
}

// DefaultPath is $SMCP_CREDENTIALS, else
// $XDG_CONFIG_HOME/smcp/credentials.toml, else
// ~/.config/smcp/credentials.toml (CP-43).
func DefaultPath() string {
	if p := os.Getenv("SMCP_CREDENTIALS"); p != "" {
		return p
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "smcp", "credentials.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "smcp", "credentials.toml")
	}
	return filepath.Join(home, ".config", "smcp", "credentials.toml")
}

// ErrPermissions is returned when the credential file is readable or
// writable by other users.
var ErrPermissions = errors.New("credential file is readable or writable by other users; run chmod 600 on it")

// CheckMode refuses a credential file that group or other users can read
// or write (SR-2.3-2).
func CheckMode(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o066 != 0 {
		return fmt.Errorf("%s (mode %04o): %w", path, fi.Mode().Perm(), ErrPermissions)
	}
	return nil
}

// Load reads the credential file after the mode check.
func Load(path string) (*Credentials, error) {
	if err := CheckMode(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Credentials{path: path}
	if err := toml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// LoadOrNew loads the file, or returns empty credentials for path when it
// does not exist (smcp-connect creates it at sign-in).
func LoadOrNew(path string) (*Credentials, error) {
	c, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Credentials{path: path}, nil
	}
	return c, err
}

// Path is the file the credentials were read from.
func (c *Credentials) Path() string { return c.path }

// Save writes the file atomically with mode 0600, creating its directory
// with mode 0700.
func (c *Credentials) Save() error {
	if c.path == "" {
		return errors.New("credentials have no path")
	}
	b, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	header := "# Secure MCP Gateway adapter credentials (CP-43). Keep this file mode 0600.\n"
	if _, err := tmp.WriteString(header); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, c.path)
}

// fresh reports whether the access token is usable without refresh: it
// exists and less than half its lifetime has passed (CP-43).
func (s SessionSection) fresh(now time.Time) bool {
	if s.AccessToken == "" || s.IssuedAt.IsZero() || s.ExpiresIn <= 0 {
		return false
	}
	return now.Before(s.IssuedAt.Add(time.Duration(s.ExpiresIn) * time.Second / 2))
}
