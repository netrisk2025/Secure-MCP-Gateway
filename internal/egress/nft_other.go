//go:build !linux

package egress

import (
	"errors"
	"net/netip"
)

// ErrNoEnforcement is returned when a sandbox network is attached on a
// platform without nftables.
var ErrNoEnforcement = errors.New("egress enforcement needs Linux nftables; this platform runs the standalone profile")

type unsupportedRules struct{}

func defaultRules() RuleInstaller { return unsupportedRules{} }

func (unsupportedRules) Install(string, []netip.AddrPort) (func() error, error) {
	return nil, ErrNoEnforcement
}
