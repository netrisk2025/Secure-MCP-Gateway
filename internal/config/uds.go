package config

import (
	"fmt"
	"strings"
)

// UDS configures the optional UDS Harness Profile (CP-02, FR-1.47,
// FR-2.15, SR-2.8-3): MCP as newline-delimited JSON-RPC over a
// Unix-domain socket for harnesses on the same host. A connection is
// accepted only from a registered peer UID that also presents the bearer
// key registered for it.
type UDS struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	// Path is the socket path (CP-02 default /run/smcp/harness.sock).
	Path string `toml:"path" json:"path"`
	// Group owns the socket, which is created with mode 0660
	// (SR-2.8-3; default smcp-harness).
	Group string    `toml:"group" json:"group"`
	Peers []UDSPeer `toml:"peer" json:"peer"`
}

// UDSPeer registers one local user ID for a principal (FR-2.15).
type UDSPeer struct {
	UID       int    `toml:"uid" json:"uid"`
	Principal string `toml:"principal" json:"principal"`
	// KeyHash is the Argon2id hash of the principal's bearer key on the
	// socket (smcpctl hash-password produces one).
	KeyHash string `toml:"key_hash" json:"key_hash"`
	// Template is the Session Allow Policy Template of the sessions this
	// peer creates; empty means the profile's default template.
	Template string `toml:"template" json:"template"`
}

// CP-02 UDS defaults.
const (
	DefaultUDSPath  = "/run/smcp/harness.sock"
	DefaultUDSGroup = "smcp-harness"
)

// applyDefaults fills CP-02 defaults; Load resolves a relative path
// against the configuration directory.
func (u *UDS) applyDefaults() {
	if u.Path == "" {
		u.Path = DefaultUDSPath
	}
	if u.Group == "" {
		u.Group = DefaultUDSGroup
	}
}

// Peer returns the peer registered for uid.
func (u *UDS) Peer(uid int) (UDSPeer, bool) {
	for _, p := range u.Peers {
		if p.UID == uid {
			return p, true
		}
	}
	return UDSPeer{}, false
}

func (c *Config) checkUDS() error {
	u := c.UDS
	if !u.Enabled {
		return nil
	}
	if len(u.Peers) == 0 {
		return fmt.Errorf("uds: enabled without any [[uds.peer]]")
	}
	seen := map[int]bool{}
	for i, p := range u.Peers {
		if seen[p.UID] {
			return fmt.Errorf("uds.peer[%d]: uid %d registered twice", i, p.UID)
		}
		seen[p.UID] = true
		if c.FindPrincipal(p.Principal) == nil {
			return fmt.Errorf("uds.peer[%d]: unknown principal %q", i, p.Principal)
		}
		if !strings.HasPrefix(p.KeyHash, "$argon2id$") {
			return fmt.Errorf("uds.peer[%d]: key_hash is not an Argon2id hash", i)
		}
	}
	return nil
}
