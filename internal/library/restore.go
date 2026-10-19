package library

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// ReapplyRevocations marks the given revisions ("<server-id>@<revision>",
// mapped to their revocation time) revoked in the registry of an offline
// state directory, as `smcpctl restore` does with the package revocations
// recorded in the restored and the current journal before service starts
// (SR-7.8-1). A revision that is already revoked or retired is left as it
// is; a revision the registry does not hold is still recorded as revoked,
// so a later import of it is refused. It returns the number of revisions
// whose state changed. The Gateway must not be running.
func ReapplyRevocations(stateDir string, revoked map[string]string, now time.Time) (int, error) {
	if len(revoked) == 0 {
		return 0, nil
	}
	path := filepath.Join(stateDir, packagesDir, registryFile)
	doc := registryDoc{Version: 1}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return 0, err
	default:
		if err := json.Unmarshal(raw, &doc); err != nil {
			return 0, fmt.Errorf("package registry: %w", err)
		}
	}
	if doc.Revocations == nil {
		doc.Revocations = map[string]string{}
	}
	changed, recorded := 0, false
	for key, at := range revoked {
		if _, done := doc.Revocations[key]; !done {
			doc.Revocations[key] = at
			recorded = true
		}
		for _, r := range doc.Revisions {
			if r.Key() == key && r.State != StateRevoked && r.State != StateRetired {
				r.State, r.StateReason, r.StateActor, r.StateChangedAt = StateRevoked, "revocation re-applied from the journal at restore", "restore", now.UTC()
				changed++
			}
		}
	}
	if changed == 0 && !recorded {
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	return changed, packaging.WriteJSON(path, doc, 0o600)
}
