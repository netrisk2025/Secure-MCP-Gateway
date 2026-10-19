package remote

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

// ReapplyRevocations marks the given dynamic client registrations (client
// ID mapped to the revocation time) revoked in the registry of an offline
// state directory, as `smcpctl restore` does with the DCR_REVOKED events
// recorded in the restored and the current journal before service starts
// (SR-7.8-1). A registration the restored registry does not hold has no
// credential to revoke. It returns the number of registrations changed.
// The Gateway must not be running.
func ReapplyRevocations(stateDir string, revoked map[string]time.Time) (int, error) {
	if len(revoked) == 0 {
		return 0, nil
	}
	path := filepath.Join(stateDir, "remote", "clients.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	reg, err := loadRegistry(path, 1, 1)
	if err != nil {
		return 0, err
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	n := 0
	for id, at := range revoked {
		g, ok := reg.regs[id]
		if !ok || g.Status == StatusRevoked {
			continue
		}
		t := at.UTC()
		g.Status, g.DecidedBy, g.DecidedAt = StatusRevoked, "restore", &t
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n, reg.saveLocked()
}
